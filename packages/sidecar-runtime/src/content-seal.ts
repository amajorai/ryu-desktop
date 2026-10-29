// Per-value content sealing for an app's SQLite store (phase-2 at-rest
// design, sections 3, 11 and 13), shared by the TypeScript satellites that
// seal a bun:sqlite store (forms, sites, video-studio, mpp).
//
// - Values are sealed per column: TEXT as `encb:v1:`, BLOB as `RYU-CB01`, under
//   the plugin subkey's content key for this store, with the AAD binding the
//   store, `<table>.<column>` and the row's stable ids.
// - Reads accept legacy plaintext; a sealed value that does not open is an
//   error for a get-by-id and a counted, skipped row for lists.
// - The key state (sealing, compat under an older Core, mismatch, no key) is
//   recorded in `ryu_content_seal` next to the data, so a different key never
//   re-seals or resets a store.
// - Migration runs on open: cursor-paginated, compare-and-swap per row,
//   resumable, a no-op the second time; freed plaintext pages are scrubbed
//   (`secure_delete`, WAL truncate, free pages zero-filled and VACUUM, each
//   only when disk space allows and never failing the open).

import type { Database } from "bun:sqlite";
import { statSync } from "node:fs";
import { dirname } from "node:path";
import {
	ContentCipher,
	ContentContext,
	ContentSealError,
	isContentSealError,
} from "./content.ts";
import type { PluginKeys, StoreKeyStatus } from "./seal.ts";
import { availableSpace } from "./sealed-file.ts";

/** Lowest reader format that understands this store's sealed values. */
export const SEAL_MIN_READER = 2;
const STORE_ITEM = "__store__";
const BATCH = 500;
const VACUUM_HEADROOM = 256 * 1024 * 1024;
/** Any Ryu envelope prefix: `encb:v<n>:` text, `RYU-XX00` bytes. */
const TEXT_ENVELOPE = /^encb:v\d+:/u;
const BYTES_MAGIC = /^RYU-[A-Z]{2}\d{2}$/u;
/**
 * Largest zero-filled row written at once while scrubbing freed pages. Each
 * chunk is its own transaction followed by a WAL truncate, so the WAL never
 * grows past about one chunk.
 */
const SCRUB_CHUNK = 64 * 1024 * 1024;
/** Free disk space kept beyond one scrub chunk before the scrub runs. */
const SCRUB_HEADROOM = 256 * 1024 * 1024;
/** `__store__` state: free pages were zero-filled; only the VACUUM is pending. */
const SCRUBBED = "scrubbed";
const VACUUM_PENDING = "vacuum_pending";

/** One sealed column: its purpose and the row columns bound into the AAD. */
export interface SealedColumn {
	/** Row columns bound into the AAD, in order; each name is also its label. */
	readonly bind: readonly string[];
	readonly column: string;
	readonly kind: "bytes" | "text";
	/** A stable order key for the migration cursor (TEXT id or explicit INTEGER PK). */
	readonly orderKey: string;
	readonly table: string;
}

export type RowIds = Readonly<Record<string, string | number | bigint | null>>;

/** Overrides for tests. */
export interface StoreSealOptions {
	/** Free bytes on the volume holding `dir` (defaults to `statfs`). */
	readonly freeSpace?: (dir: string) => number;
}

/**
 * Raised on open when a newer build sealed the store under a reader format this
 * build does not understand: the app must not start, or it would skip rows it
 * cannot read and write plaintext into a store it cannot fully read.
 */
export class NewerStoreFormatError extends Error {
	override readonly name = "NewerStoreFormatError";
}

/** Raised when the store refuses a write because no usable key is held. */
export class SealUnavailableError extends Error {
	override readonly name = "SealUnavailableError";
}

export interface StoreSealHealth {
	/** `ok`, `waiting for a Ryu update` (compat), `key mismatch` or `no key`. */
	sealing: string;
	state: StoreKeyStatus["state"] | "unmanaged";
	store: string;
	unreadableRows: number;
	vacuumPending: boolean;
}

export interface MigrationReport {
	resealed: number;
	unreadable: number;
}

interface StateRow {
	cursor: string | null;
	kcv: string | null;
	state: string;
}

function purposeOf(column: SealedColumn): string {
	return `${column.table}.${column.column}`;
}

function contextFor(column: SealedColumn, ids: RowIds): ContentContext {
	let context = new ContentContext(purposeOf(column));
	for (const name of column.bind) {
		const value = ids[name];
		if (value === undefined) {
			throw new Error(`missing AAD id '${name}' for ${purposeOf(column)}`);
		}
		// A NULL id (legacy rows with an optional key part) binds as "".
		context = context.with(name, value ?? "");
	}
	return context;
}

function toBytes(value: unknown): Uint8Array {
	if (value instanceof Uint8Array) {
		return value;
	}
	if (typeof value === "string") {
		return new TextEncoder().encode(value);
	}
	throw new TypeError("expected a BLOB value");
}

/**
 * The sealing state of one SQLite store. Construct with {@link StoreSeal.open}
 * before the store serves requests.
 */
export class StoreSeal {
	readonly status: StoreKeyStatus | null;
	readonly store: string;
	readonly #cipher: ContentCipher | null;
	readonly #columns: readonly SealedColumn[];
	readonly #db: Database;
	readonly #freeSpace: (dir: string) => number;
	readonly #path: string | null;
	/** Free pages already zero-filled since the last reseal; VACUUM may still be pending. */
	#scrubbed = false;
	/**
	 * Sealed under a retired key: every column is rescanned and resealed under
	 * the current key; the store records the current KCV only once nothing is
	 * left that does not open (then this clears).
	 */
	#retiredLeft: boolean;
	#unreadable = 0;
	#vacuumPending = false;

	private constructor(
		db: Database,
		path: string | null,
		store: string,
		columns: readonly SealedColumn[],
		status: StoreKeyStatus | null,
		cipher: ContentCipher | null,
		freeSpace: (dir: string) => number
	) {
		this.#db = db;
		this.#freeSpace = freeSpace;
		this.#path = path;
		this.store = store;
		this.#columns = columns;
		this.status = status;
		this.#cipher = cipher;
		this.#retiredLeft = status?.state === "retired";
	}

	/**
	 * Resolve the key state of `store` from its recorded KCV and data, migrate
	 * legacy plaintext when a key is held, and scrub freed pages. `keys` null
	 * (tests and tools that never seal) keeps the plaintext behaviour.
	 * Call after the schema exists; `path` is the database file (null for
	 * `:memory:`).
	 */
	static open(
		db: Database,
		path: string | null,
		store: string,
		keys: PluginKeys | null,
		columns: readonly SealedColumn[],
		options: StoreSealOptions = {}
	): StoreSeal {
		const freeSpace = options.freeSpace ?? availableSpace;
		db.exec("PRAGMA secure_delete=ON");
		db.exec(`CREATE TABLE IF NOT EXISTS ryu_content_seal (
			store TEXT NOT NULL,
			item TEXT NOT NULL,
			state TEXT NOT NULL,
			cursor TEXT,
			kcv TEXT,
			min_reader INTEGER NOT NULL DEFAULT ${SEAL_MIN_READER},
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(store, item)
		)`);
		refuseNewerFormat(db, store);
		if (keys === null) {
			return new StoreSeal(db, path, store, columns, null, null, freeSpace);
		}
		const recorded = readState(db, store, STORE_ITEM);
		const status = keys.storeKeyState(
			recorded?.kcv ?? null,
			holdsSealedData(db, store)
		);
		const cipher = status.sealing ? keys.contentCipher(store) : null;
		const seal = new StoreSeal(
			db,
			path,
			store,
			columns,
			status,
			cipher,
			freeSpace
		);
		// The first key for this store (or an unfinished scrub): free pages and
		// WAL frames may still hold plaintext written before sealing, or rows
		// deleted under an older version without secure_delete.
		if (
			recorded?.state === VACUUM_PENDING ||
			recorded?.state === SCRUBBED ||
			status.state === "record"
		) {
			seal.#vacuumPending = true;
			seal.#scrubbed = recorded?.state === SCRUBBED;
		}
		if (status.sealing) {
			seal.migrate();
		}
		return seal;
	}

	/** Whether new writes are sealed (false in compat or unmanaged mode). */
	get sealing(): boolean {
		return this.#cipher !== null;
	}

	/** Rows skipped by lists because their sealed value does not open. */
	get unreadableRows(): number {
		return this.#unreadable;
	}

	health(): StoreSealHealth {
		const state = this.status?.state ?? "unmanaged";
		let sealing = "ok";
		if (this.status?.state === "compat") {
			sealing = this.status.health;
		} else if (this.status?.state === "mismatch") {
			sealing = "key mismatch";
		} else if (this.status?.state === "no_key") {
			sealing = "no key";
		} else if (this.status === null) {
			sealing = "unmanaged";
		}
		return {
			store: this.store,
			state,
			sealing,
			unreadableRows: this.#unreadable,
			vacuumPending: this.#vacuumPending,
		};
	}

	#refuse(): never {
		const state = this.status?.state ?? "unmanaged";
		throw new SealUnavailableError(
			state === "mismatch"
				? `${this.store} was sealed under a different key; writes are refused until that key is restored`
				: `${this.store} holds sealed data but no sealing key was delivered; writes are refused`
		);
	}

	#writable(): boolean {
		if (this.#cipher) {
			return true;
		}
		if (this.status === null || this.status.state === "compat") {
			return false;
		}
		return this.#refuse();
	}

	/**
	 * A plaintext write that looks like a Ryu envelope would later read as
	 * sealed data (refusing every write once no key is held, and never being
	 * sealed when one arrives), so compat mode refuses it.
	 */
	#refuseLookalike(looksSealed: boolean): void {
		if (looksSealed && this.status?.state === "compat") {
			throw new ContentSealError("already_a_ryu_envelope");
		}
	}

	/**
	 * Seal a TEXT value for writing (plaintext in compat/unmanaged mode; in
	 * compat mode a value that starts like an envelope is refused).
	 */
	sealText(column: SealedColumn, ids: RowIds, value: string): string {
		if (!this.#writable()) {
			this.#refuseLookalike(TEXT_ENVELOPE.test(value));
			return value;
		}
		return (this.#cipher as ContentCipher).sealText(
			value,
			contextFor(column, ids)
		);
	}

	/**
	 * Seal a BLOB value for writing (plaintext in compat/unmanaged mode; in
	 * compat mode bytes that start with a Ryu magic are refused).
	 */
	sealBytes(column: SealedColumn, ids: RowIds, value: Uint8Array): Uint8Array {
		if (!this.#writable()) {
			this.#refuseLookalike(
				value.length >= 8 &&
					BYTES_MAGIC.test(new TextDecoder().decode(value.subarray(0, 8)))
			);
			return value;
		}
		return (this.#cipher as ContentCipher).sealBytes(
			value,
			contextFor(column, ids)
		);
	}

	/** Open a stored TEXT value; throws {@link ContentSealError} if it does not open. */
	openText(column: SealedColumn, ids: RowIds, stored: string): string {
		if (!ContentCipher.isSealedText(stored)) {
			if (/^encb:v\d+:/u.test(stored)) {
				throw new ContentSealError("unknown_version");
			}
			return stored;
		}
		if (!this.#cipher) {
			throw new ContentSealError("does_not_open", "no sealing key held");
		}
		return this.#cipher.openText(stored, contextFor(column, ids)).value;
	}

	/** Open a stored BLOB value; throws {@link ContentSealError} if it does not open. */
	openBytes(column: SealedColumn, ids: RowIds, stored: unknown): Uint8Array {
		const bytes = toBytes(stored);
		if (!ContentCipher.isSealedBytes(bytes)) {
			if (this.#cipher) {
				return this.#cipher.openBytes(bytes, contextFor(column, ids)).value;
			}
			return bytes;
		}
		if (!this.#cipher) {
			throw new ContentSealError("does_not_open", "no sealing key held");
		}
		return this.#cipher.openBytes(bytes, contextFor(column, ids)).value;
	}

	/** For lists: open, or count the row as unreadable and return null. */
	tryOpenText(
		column: SealedColumn,
		ids: RowIds,
		stored: string
	): string | null {
		try {
			return this.openText(column, ids, stored);
		} catch (error) {
			return this.skip(error);
		}
	}

	/** For lists: open, or count the row as unreadable and return null. */
	tryOpenBytes(
		column: SealedColumn,
		ids: RowIds,
		stored: unknown
	): Uint8Array | null {
		try {
			return this.openBytes(column, ids, stored);
		} catch (error) {
			return this.skip(error);
		}
	}

	/**
	 * Count a row whose sealed value did not open (rethrows anything else), for
	 * lists that open several columns per row themselves.
	 */
	skip(error: unknown): null {
		if (!isContentSealError(error)) {
			throw error;
		}
		this.#unreadable += 1;
		console.warn(
			`[content-seal] ${this.store}: skipped an unreadable sealed row (${this.#unreadable} so far): ${error.code}`
		);
		return null;
	}

	/**
	 * Seal every legacy plaintext value, one column at a time, with a persisted
	 * cursor (resumable after a crash) and compare-and-swap writes (a concurrent
	 * write is never overwritten). Values that do not open are counted and left
	 * alone. A finished column is skipped on later runs unless it holds a value
	 * without an envelope prefix: an older build run after sealing (a rollback)
	 * writes plaintext, which the rescan then seals.
	 */
	migrate(): MigrationReport {
		const report: MigrationReport = { resealed: 0, unreadable: 0 };
		const cipher = this.#cipher;
		if (!cipher) {
			return report;
		}
		for (const column of this.#columns) {
			const item = purposeOf(column);
			const state = readState(this.#db, this.store, item);
			if (state?.state === "sealed" && !this.#retiredLeft) {
				if (!holdsPlaintext(this.#db, column)) {
					continue;
				}
				console.warn(
					`[content-seal] ${this.store}: ${item} holds plaintext written after it was sealed (an older version ran); sealing it again`
				);
			}
			let cursor: unknown = state?.cursor ? JSON.parse(state.cursor) : null;
			const selected = [
				...new Set([column.orderKey, ...column.bind, column.column]),
			]
				.map((name) => `"${name}"`)
				.join(", ");
			const select = this.#db.query(
				`SELECT ${selected} FROM "${column.table}"
				 WHERE ?1 IS NULL OR "${column.orderKey}" > ?1
				 ORDER BY "${column.orderKey}" LIMIT ${BATCH}`
			);
			const update = this.#db.query(
				`UPDATE "${column.table}" SET "${column.column}"=?1
				 WHERE "${column.orderKey}"=?2 AND "${column.column}" IS ?3`
			);
			for (;;) {
				const rows = select.all(cursor as string | number | null) as Record<
					string,
					unknown
				>[];
				if (rows.length === 0) {
					break;
				}
				this.#db.transaction(() => {
					for (const row of rows) {
						const stored = row[column.column];
						if (stored === null || stored === undefined) {
							continue;
						}
						const ids = row as RowIds;
						const resealed = resealValue(cipher, column, ids, stored);
						if (resealed === "unreadable") {
							report.unreadable += 1;
							continue;
						}
						if (resealed !== null) {
							update.run(
								resealed as string | Uint8Array,
								row[column.orderKey] as string | number,
								stored as string | Uint8Array
							);
							report.resealed += 1;
						}
					}
					cursor = rows.at(-1)?.[column.orderKey] ?? cursor;
					writeState(this.#db, this.store, item, {
						state: "sealing",
						cursor: JSON.stringify(cursor),
						kcv: cipher.kcv,
					});
				})();
			}
			writeState(this.#db, this.store, item, {
				state: "sealed",
				cursor: null,
				kcv: cipher.kcv,
			});
		}
		this.#unreadable += report.unreadable;
		if (this.#retiredLeft && report.unreadable === 0) {
			console.warn(
				`[content-seal] ${this.store}: resealed from a retired key under the current key`
			);
			this.#retiredLeft = false;
		}
		if (report.unreadable > 0) {
			console.warn(
				`[content-seal] ${this.store}: ${report.unreadable} stored value(s) do not open and were left as they are`
			);
		}
		if (report.resealed > 0) {
			// The reseal freed new plaintext pages: scrub them again.
			this.#vacuumPending = true;
			this.#scrubbed = false;
		}
		this.#writeStoreState();
		if (this.#vacuumPending) {
			this.#finish();
		}
		return report;
	}

	#writeStoreState(): void {
		let state = "sealed";
		if (this.#vacuumPending) {
			state = this.#scrubbed ? SCRUBBED : VACUUM_PENDING;
		}
		// Under a retired key with values that still do not open, keep the
		// retired KCV so the next start rescans instead of calling it current.
		const kcv =
			this.#retiredLeft && this.status?.state === "retired"
				? this.status.recorded
				: (this.#cipher?.kcv ?? null);
		writeState(this.#db, this.store, STORE_ITEM, {
			state,
			cursor: null,
			kcv,
		});
	}

	/**
	 * Scrub plaintext freed by the migration or left by deletes made before
	 * sealing: checkpoint and truncate the WAL, overwrite every free page with
	 * zeros, then VACUUM. Each step is best-effort and never fails the open:
	 * the zero fill runs only with one chunk plus headroom free (the fill passes
	 * through the WAL one chunk at a time) and is recorded as done (`scrubbed`)
	 * so a deferred VACUUM does not repeat it; the VACUUM runs only with 2x the
	 * database + 256 MiB free. Anything skipped or failed keeps the store
	 * pending and is retried at the next start.
	 */
	#finish(): void {
		try {
			this.#db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
		} catch (error) {
			this.#warn("could not truncate the write-ahead log", error);
			return;
		}
		if (!(this.#scrubbed || this.#scrub())) {
			return;
		}
		if (!this.#hasRoom((size) => 2 * size + VACUUM_HEADROOM)) {
			console.warn(
				`[content-seal] ${this.store}: not enough free disk space to compact; free pages are zero-filled and the compaction is retried at a later start`
			);
			return;
		}
		try {
			this.#db.exec("VACUUM");
			this.#db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
		} catch (error) {
			this.#warn("compaction failed; it is retried at a later start", error);
			return;
		}
		this.#vacuumPending = false;
		this.#scrubbed = false;
		this.#writeStoreState();
	}

	/** Zero-fill free pages; true when done (and recorded as `scrubbed`). */
	#scrub(): boolean {
		if (!this.#hasRoom(() => SCRUB_CHUNK + SCRUB_HEADROOM)) {
			console.warn(
				`[content-seal] ${this.store}: not enough free disk space to zero-fill freed pages; retried at a later start`
			);
			return false;
		}
		try {
			scrubFreePages(this.#db);
		} catch (error) {
			dropScrubTable(this.#db);
			this.#warn(
				"zero-filling freed pages failed; it is retried at a later start",
				error
			);
			return false;
		}
		this.#scrubbed = true;
		this.#writeStoreState();
		return true;
	}

	/** Whether the store's volume has `needed(databaseSize)` bytes free (true for `:memory:`). */
	#hasRoom(needed: (size: number) => number): boolean {
		if (this.#path === null) {
			return true;
		}
		try {
			const size = statSync(this.#path).size;
			return this.#freeSpace(dirname(this.#path)) >= needed(size);
		} catch {
			return false;
		}
	}

	#warn(message: string, error: unknown): void {
		const detail = error instanceof Error ? error.message : String(error);
		console.warn(`[content-seal] ${this.store}: ${message} (${detail})`);
	}
}

/** The resealed value, null when it is already current, or "unreadable". */
function resealValue(
	cipher: ContentCipher,
	column: SealedColumn,
	ids: RowIds,
	stored: unknown
): string | Uint8Array | null | "unreadable" {
	const context = contextFor(column, ids);
	try {
		if (column.kind === "text") {
			const text = String(stored);
			const opened = cipher.openText(text, context);
			return opened.needsReseal ? cipher.sealText(opened.value, context) : null;
		}
		const opened = cipher.openBytes(toBytes(stored), context);
		return opened.needsReseal ? cipher.sealBytes(opened.value, context) : null;
	} catch (error) {
		if (isContentSealError(error)) {
			return "unreadable";
		}
		throw error;
	}
}

/**
 * Whether this store was ever sealed: a key check value recorded for it (the
 * store, or a column a migration started). Values that merely look sealed do
 * not count: compat-mode plaintext from a visitor or a remote server could
 * start with an envelope prefix and would otherwise lock the store.
 */
function holdsSealedData(db: Database, store: string): boolean {
	return (
		db
			.query(
				"SELECT 1 AS hit FROM ryu_content_seal WHERE store=? AND kcv IS NOT NULL LIMIT 1"
			)
			.get(store) !== null
	);
}

/**
 * Refuse a store a newer build sealed under a reader format this build does
 * not support (design section 13: rolling back past it must not silently
 * skip its rows).
 */
function refuseNewerFormat(db: Database, store: string): void {
	const row = db
		.query(
			"SELECT MAX(min_reader) AS reader FROM ryu_content_seal WHERE store=?"
		)
		.get(store) as { reader: number | null } | null;
	const reader = row?.reader ?? null;
	if (reader !== null && reader > SEAL_MIN_READER) {
		throw new NewerStoreFormatError(
			`${store} was written by a newer Ryu (needs reader format ${reader}, this build reads ${SEAL_MIN_READER}); update the app`
		);
	}
}

/** `encb:v` and `RYU-`, the prefixes every Ryu envelope starts with. */
const TEXT_PREFIX_HEX = "656E63623A76";
const BYTES_PREFIX_HEX = "5259552D";

/**
 * Whether a column marked sealed still holds a non-empty value without an
 * envelope prefix (written by an older build after sealing). Values with an
 * unknown envelope version count as sealed, so they do not force a rescan on
 * every start.
 */
function holdsPlaintext(db: Database, column: SealedColumn): boolean {
	const hex = column.kind === "text" ? TEXT_PREFIX_HEX : BYTES_PREFIX_HEX;
	const name = `"${column.column}"`;
	return (
		db
			.query(
				`SELECT 1 AS hit FROM "${column.table}"
				 WHERE length(${name}) > 0
				 AND substr(CAST(${name} AS BLOB), 1, ${hex.length / 2}) <> X'${hex}'
				 LIMIT 1`
			)
			.get() !== null
	);
}

/**
 * Overwrite every page on the freelist with zeros: zero-filled scratch rows
 * take the free pages, one chunk per transaction with a WAL truncate after
 * each (so the WAL stays near one chunk), then the scratch table is dropped.
 * The dropped pages already hold zeros, so the drop runs without
 * `secure_delete` and does not write them through the WAL again.
 */
function scrubFreePages(db: Database): void {
	// A scratch table left by an interrupted scrub holds only zeros.
	dropScrubTable(db);
	const free = (
		db.query("PRAGMA freelist_count").get() as { freelist_count: number }
	).freelist_count;
	if (free <= 0) {
		return;
	}
	const pageSize = (db.query("PRAGMA page_size").get() as { page_size: number })
		.page_size;
	let remaining = free * pageSize;
	db.exec("CREATE TABLE ryu_content_seal_scrub (fill BLOB)");
	const insert = db.query(
		"INSERT INTO ryu_content_seal_scrub(fill) VALUES (zeroblob(?1))"
	);
	while (remaining > 0) {
		const size = Math.min(remaining, SCRUB_CHUNK);
		insert.run(size);
		db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
		remaining -= size;
	}
	dropScrubTable(db);
}

/** Drop the zero-filled scratch table without rewriting its pages. */
function dropScrubTable(db: Database): void {
	try {
		db.exec("PRAGMA secure_delete=OFF");
		db.exec("DROP TABLE IF EXISTS ryu_content_seal_scrub");
		db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
	} catch {
		// Best-effort: a leftover table holds only zeros and is dropped next time.
	} finally {
		db.exec("PRAGMA secure_delete=ON");
	}
}

function readState(db: Database, store: string, item: string): StateRow | null {
	return db
		.query(
			"SELECT state, cursor, kcv FROM ryu_content_seal WHERE store=? AND item=?"
		)
		.get(store, item) as StateRow | null;
}

function writeState(
	db: Database,
	store: string,
	item: string,
	value: { cursor: string | null; kcv: string | null; state: string }
): void {
	db.query(
		`INSERT INTO ryu_content_seal(store, item, state, cursor, kcv, min_reader, updated_at)
		 VALUES(?1, ?2, ?3, ?4, ?5, ${SEAL_MIN_READER}, ?6)
		 ON CONFLICT(store, item) DO UPDATE SET state=excluded.state,
		   cursor=excluded.cursor, kcv=excluded.kcv,
		   min_reader=MAX(min_reader, excluded.min_reader),
		   updated_at=excluded.updated_at`
	).run(store, item, value.state, value.cursor, value.kcv, Date.now());
}
