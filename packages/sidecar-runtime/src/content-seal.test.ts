import { Database } from "bun:sqlite";
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	NewerStoreFormatError,
	type SealedColumn,
	SealUnavailableError,
	StoreSeal,
} from "./content-seal.ts";
import { capturePluginKeys, type PluginKeys } from "./seal.ts";

// Generic tests of the shared bun:sqlite store sealing helper.

const PLUGIN = "@ryu/content-seal-test";
const STORE = "test.sqlite";
const NOTE: SealedColumn = {
	table: "notes",
	column: "body",
	kind: "text",
	orderKey: "id",
	bind: ["id"],
};
const BLOB: SealedColumn = {
	table: "notes",
	column: "data",
	kind: "bytes",
	orderKey: "id",
	bind: ["id"],
};

function keyB64(fill: number): string {
	return Buffer.from(new Uint8Array(32).fill(fill)).toString("base64");
}

function keysFor(fill: number): PluginKeys {
	return capturePluginKeys(PLUGIN, {
		RYU_SEAL_KEY: keyB64(fill),
		RYU_SEAL_SCOPE: `plugin:${PLUGIN}`,
	});
}

function compatKeys(dir: string): PluginKeys {
	return capturePluginKeys(PLUGIN, { RYU_PLUGIN_DATA_DIR: dir });
}

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) {
		rmSync(root, { recursive: true, force: true });
	}
});

function openDb(): { db: Database; path: string; dir: string } {
	const dir = mkdtempSync(join(tmpdir(), "ryu-content-seal-"));
	roots.push(dir);
	const path = join(dir, STORE);
	const db = new Database(path, { create: true });
	db.exec("PRAGMA journal_mode=WAL");
	db.exec(
		"CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, body TEXT, data BLOB)"
	);
	return { db, path, dir };
}

function rawBytes(path: string): string {
	let text = readFileSync(path).toString("latin1");
	try {
		text += readFileSync(`${path}-wal`).toString("latin1");
	} catch {
		// No WAL file.
	}
	return text;
}

function storeState(db: Database): string | undefined {
	return (
		db
			.query(
				"SELECT state FROM ryu_content_seal WHERE store=? AND item='__store__'"
			)
			.get(STORE) as { state: string } | null
	)?.state;
}

/** Delete overflow-sized plaintext without secure_delete; returns the page count. */
function withFreedPlaintext(db: Database, marker: string): number {
	db.exec("PRAGMA secure_delete=OFF");
	db.query("INSERT INTO notes(id, body) VALUES ('gone', ?)").run(
		`${"y".repeat(4000)}${marker}${"y".repeat(40_000)}`
	);
	db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
	db.exec("DELETE FROM notes");
	db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
	return (db.query("PRAGMA page_count").get() as { page_count: number })
		.page_count;
}

describe("StoreSeal", () => {
	test("migrates legacy plaintext, twice is a no-op, and leaves no plaintext on disk", () => {
		const { db, path } = openDb();
		db.query("INSERT INTO notes VALUES (?, ?, ?)").run(
			"a",
			"secret legacy note",
			new TextEncoder().encode("legacy blob payload")
		);
		const seal = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE, BLOB]);
		const row = db.query("SELECT body, data FROM notes WHERE id='a'").get() as {
			body: string;
			data: Uint8Array;
		};
		expect(row.body.startsWith("encb:v1:")).toBe(true);
		expect(Buffer.from(row.data).subarray(0, 8).toString()).toBe("RYU-CB01");
		expect(seal.openText(NOTE, { id: "a" }, row.body)).toBe(
			"secret legacy note"
		);
		expect(
			new TextDecoder().decode(seal.openBytes(BLOB, { id: "a" }, row.data))
		).toBe("legacy blob payload");
		expect(seal.migrate()).toEqual({ resealed: 0, unreadable: 0 });
		const again = db.query("SELECT body FROM notes WHERE id='a'").get() as {
			body: string;
		};
		expect(again.body).toBe(row.body);
		db.close();
		const disk = rawBytes(path);
		expect(disk).not.toContain("secret legacy note");
		expect(disk).not.toContain("legacy blob payload");
	});

	test("a value copied to another row does not open (AAD binds the id)", () => {
		const { db, path } = openDb();
		const seal = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]);
		const sealed = seal.sealText(NOTE, { id: "a" }, "bound to a");
		expect(() => seal.openText(NOTE, { id: "b" }, sealed)).toThrow();
		db.query("INSERT INTO notes(id, body) VALUES ('b', ?)").run(sealed);
		expect(seal.tryOpenText(NOTE, { id: "b" }, sealed)).toBeNull();
		expect(seal.unreadableRows).toBe(1);
		db.close();
	});

	test("a different key is refused instead of resealing the store", () => {
		const { db, path } = openDb();
		const first = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]);
		db.query("INSERT INTO notes(id, body) VALUES ('a', ?)").run(
			first.sealText(NOTE, { id: "a" }, "kept")
		);
		const second = StoreSeal.open(db, path, STORE, keysFor(4), [NOTE]);
		expect(second.health().sealing).toBe("key mismatch");
		expect(() => second.sealText(NOTE, { id: "b" }, "new")).toThrow(
			SealUnavailableError
		);
		const stored = (
			db.query("SELECT body FROM notes WHERE id='a'").get() as { body: string }
		).body;
		expect(
			StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]).openText(
				NOTE,
				{ id: "a" },
				stored
			)
		).toBe("kept");
		db.close();
	});

	test("a store sealed under a retired key still opens, is resealed and stays writable", () => {
		const { db, path } = openDb();
		const old = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE, BLOB]);
		db.query("INSERT INTO notes(id, body, data) VALUES ('a', ?, ?)").run(
			old.sealText(NOTE, { id: "a" }, "sealed under the old key"),
			old.sealBytes(BLOB, { id: "a" }, new TextEncoder().encode("old blob"))
		);
		// A backup import or `keys adopt` retired key 3; Core now delivers key 4
		// with key 3's subkey in RYU_SEAL_RETIRED_KEYS.
		const env: Record<string, string | undefined> = {
			RYU_SEAL_KEY: keyB64(4),
			RYU_SEAL_SCOPE: `plugin:${PLUGIN}`,
			RYU_SEAL_RETIRED_KEYS: `${keyB64(9)},${keyB64(3)}`,
		};
		const rotated = capturePluginKeys(PLUGIN, env);
		expect(env.RYU_SEAL_RETIRED_KEYS).toBeUndefined();
		const seal = StoreSeal.open(db, path, STORE, rotated, [NOTE, BLOB]);
		expect(seal.status?.state).toBe("retired");
		expect(seal.health().sealing).toBe("ok");
		const row = db.query("SELECT body, data FROM notes WHERE id='a'").get() as {
			body: string;
			data: Uint8Array;
		};
		expect(seal.openText(NOTE, { id: "a" }, row.body)).toBe(
			"sealed under the old key"
		);
		db.query("INSERT INTO notes(id, body) VALUES ('b', ?)").run(
			seal.sealText(NOTE, { id: "b" }, "written after the import")
		);
		// Everything was resealed under the current key, which is now recorded:
		// the store opens without the retired key.
		const current = StoreSeal.open(db, path, STORE, keysFor(4), [NOTE, BLOB]);
		expect(current.status?.state).toBe("current");
		const after = db
			.query("SELECT body, data FROM notes WHERE id='a'")
			.get() as {
			body: string;
			data: Uint8Array;
		};
		expect(current.openText(NOTE, { id: "a" }, after.body)).toBe(
			"sealed under the old key"
		);
		expect(
			new TextDecoder().decode(current.openBytes(BLOB, { id: "a" }, after.data))
		).toBe("old blob");
		db.close();
	});

	test("a retired-key store with values that do not open keeps the retired key recorded", () => {
		const { db, path } = openDb();
		const old = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]);
		db.query("INSERT INTO notes(id, body) VALUES ('a', ?)").run(
			old.sealText(NOTE, { id: "a" }, "opens")
		);
		// A value bound to another row never opens.
		db.query("INSERT INTO notes(id, body) VALUES ('b', ?)").run(
			old.sealText(NOTE, { id: "elsewhere" }, "does not open")
		);
		const rotated = capturePluginKeys(PLUGIN, {
			RYU_SEAL_KEY: keyB64(4),
			RYU_SEAL_SCOPE: `plugin:${PLUGIN}`,
			RYU_SEAL_RETIRED_KEYS: keyB64(3),
		});
		const seal = StoreSeal.open(db, path, STORE, rotated, [NOTE]);
		expect(seal.unreadableRows).toBe(1);
		// Without the retired key the store is still a mismatch, not "current".
		const without = StoreSeal.open(db, path, STORE, keysFor(4), [NOTE]);
		expect(without.status?.state).toBe("mismatch");
		db.close();
	});

	test("compat mode keeps plaintext for a never-sealed store and refuses a sealed one", () => {
		const { db, path, dir } = openDb();
		const compat = StoreSeal.open(db, path, STORE, compatKeys(dir), [NOTE]);
		expect(compat.health().sealing).toBe("waiting for a Ryu update");
		expect(compat.sealText(NOTE, { id: "a" }, "plain")).toBe("plain");
		db.query("INSERT INTO notes(id, body) VALUES ('a', 'plain')").run();
		// A key arrives (Core updated): the compat rows are sealed.
		StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]);
		const stored = (
			db.query("SELECT body FROM notes WHERE id='a'").get() as { body: string }
		).body;
		expect(stored.startsWith("encb:v1:")).toBe(true);
		// Losing the key again never falls back to plaintext writes.
		const lost = StoreSeal.open(db, path, STORE, compatKeys(dir), [NOTE]);
		expect(lost.health().sealing).toBe("no key");
		expect(() => lost.sealText(NOTE, { id: "b" }, "x")).toThrow(
			SealUnavailableError
		);
		db.close();
	});

	test("a legacy value that looks sealed is counted, never double sealed", () => {
		const { db, path } = openDb();
		db.query("INSERT INTO notes(id, body) VALUES ('a', 'encb:v1:AAAA')").run();
		const seal = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]);
		expect(seal.unreadableRows).toBe(1);
		const stored = (
			db.query("SELECT body FROM notes WHERE id='a'").get() as { body: string }
		).body;
		expect(stored).toBe("encb:v1:AAAA");
		db.close();
	});

	test("rows deleted before the first key leave no plaintext in free pages or the WAL", () => {
		const { db, path } = openDb();
		// An older version: no secure_delete, so deletes keep the bytes.
		db.exec("PRAGMA secure_delete=OFF");
		const insert = db.query("INSERT INTO notes(id, body) VALUES (?, ?)");
		for (let index = 0; index < 50; index += 1) {
			insert.run(
				`gone-${index}`,
				`deleted-plaintext-${index}-${"z".repeat(900)}`
			);
		}
		db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
		db.exec("DELETE FROM notes");
		insert.run("kept", "kept-value");
		expect(rawBytes(path)).toContain("deleted-plaintext-7-");
		// Nothing is left to reseal except one row; the store is still scrubbed.
		StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]);
		db.close();
		const disk = rawBytes(path);
		expect(disk).not.toContain("deleted-plaintext-");
		expect(disk).not.toContain("kept-value");
	});

	test("a store with nothing to reseal is still scrubbed when its key is first recorded", () => {
		const { db, path } = openDb();
		db.exec("PRAGMA secure_delete=OFF");
		db.query("INSERT INTO notes(id, body) VALUES ('a', ?)").run(
			`only-deleted-${"q".repeat(2000)}`
		);
		db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
		db.exec("DELETE FROM notes");
		const seal = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]);
		expect(seal.health().vacuumPending).toBe(false);
		db.close();
		expect(rawBytes(path)).not.toContain("only-deleted-");
	});

	test("a failing free-page scrub never fails the open and stays pending", () => {
		const { db, path } = openDb();
		const leftover = withFreedPlaintext(db, "scrub-fails-");
		// The zero fill needs a few pages more than the freelist holds.
		db.exec(`PRAGMA max_page_count=${leftover}`);
		const seal = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]);
		expect(seal.health().vacuumPending).toBe(true);
		expect(storeState(db)).toBe("vacuum_pending");
		expect(
			db
				.query(
					"SELECT name FROM sqlite_master WHERE name LIKE 'ryu_content_seal_scrub'"
				)
				.get()
		).toBeNull();
		// The next start with room finishes the scrub and the compaction.
		db.exec("PRAGMA max_page_count=1073741823");
		const retried = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]);
		expect(retried.health().vacuumPending).toBe(false);
		expect(storeState(db)).toBe("sealed");
		db.close();
		expect(rawBytes(path)).not.toContain("scrub-fails-");
	});

	test("the scrub waits for disk space and is not repeated while the VACUUM is deferred", () => {
		const { db, path } = openDb();
		withFreedPlaintext(db, "scrub-space-");
		const none = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE], {
			freeSpace: () => 0,
		});
		expect(none.health().vacuumPending).toBe(true);
		expect(storeState(db)).toBe("vacuum_pending");
		expect(rawBytes(path)).toContain("scrub-space-");

		// Room for the scrub (first check) but not for the VACUUM (second).
		const answers = [Number.MAX_SAFE_INTEGER, 0];
		StoreSeal.open(db, path, STORE, keysFor(3), [NOTE], {
			freeSpace: () => answers.shift() ?? 0,
		});
		expect(storeState(db)).toBe("scrubbed");
		expect(rawBytes(path)).not.toContain("scrub-space-");

		// A later start with the VACUUM still deferred only checks for VACUUM room.
		let checks = 0;
		const deferred = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE], {
			freeSpace: () => {
				checks += 1;
				return 0;
			},
		});
		expect(checks).toBe(1);
		expect(deferred.health().vacuumPending).toBe(true);
		expect(storeState(db)).toBe("scrubbed");

		const done = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE], {
			freeSpace: () => Number.MAX_SAFE_INTEGER,
		});
		expect(done.health().vacuumPending).toBe(false);
		expect(storeState(db)).toBe("sealed");
		db.close();
	});

	test("compat mode refuses lookalike envelopes and stays writable", () => {
		const { db, path, dir } = openDb();
		const compat = StoreSeal.open(db, path, STORE, compatKeys(dir), [
			NOTE,
			BLOB,
		]);
		expect(() =>
			compat.sealText(NOTE, { id: "a" }, "encb:v1:not-really-sealed")
		).toThrow("already start with a Ryu");
		expect(() =>
			compat.sealBytes(
				BLOB,
				{ id: "a" },
				new TextEncoder().encode("RYU-CB01 visitor upload")
			)
		).toThrow("already start with a Ryu");
		// A lookalike stored by an older version does not lock the store.
		db.query("INSERT INTO notes(id, body, data) VALUES ('old', ?, ?)").run(
			"encb:v1:from-an-older-version",
			new TextEncoder().encode("RYU-CB01 older upload")
		);
		const reopened = StoreSeal.open(db, path, STORE, compatKeys(dir), [
			NOTE,
			BLOB,
		]);
		expect(reopened.health().sealing).toBe("waiting for a Ryu update");
		expect(reopened.sealText(NOTE, { id: "b" }, "plain")).toBe("plain");
		db.close();
	});
	test("plaintext written by an older build after sealing is sealed on the next keyed open", () => {
		const { db, path } = openDb();
		db.query("INSERT INTO notes(id, body, data) VALUES ('a', 'first', ?)").run(
			new TextEncoder().encode("first blob")
		);
		StoreSeal.open(db, path, STORE, keysFor(3), [NOTE, BLOB]);
		// A rollback: the older build writes plaintext and ignores the seal table.
		db.query("INSERT INTO notes(id, body, data) VALUES ('b', ?, ?)").run(
			"SECRET-DOWNGRADE",
			new TextEncoder().encode("SECRET-DOWNGRADE-BLOB")
		);
		const seal = StoreSeal.open(db, path, STORE, keysFor(3), [NOTE, BLOB]);
		const row = db.query("SELECT body, data FROM notes WHERE id='b'").get() as {
			body: string;
			data: Uint8Array;
		};
		expect(row.body.startsWith("encb:v1:")).toBe(true);
		expect(Buffer.from(row.data).subarray(0, 8).toString()).toBe("RYU-CB01");
		expect(seal.openText(NOTE, { id: "b" }, row.body)).toBe("SECRET-DOWNGRADE");
		db.close();
		expect(rawBytes(path)).not.toContain("SECRET-DOWNGRADE");
	});

	test("a store a newer build raised min_reader on is refused on open", () => {
		const { db, path } = openDb();
		StoreSeal.open(db, path, STORE, keysFor(3), [NOTE]);
		db.query("UPDATE ryu_content_seal SET min_reader=3 WHERE store=?").run(
			STORE
		);
		expect(() => StoreSeal.open(db, path, STORE, keysFor(3), [NOTE])).toThrow(
			NewerStoreFormatError
		);
		expect(() => StoreSeal.open(db, path, STORE, null, [NOTE])).toThrow(
			"written by a newer Ryu"
		);
		db.close();
	});
});
