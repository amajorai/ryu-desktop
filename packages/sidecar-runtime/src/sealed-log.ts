/**
 * `RYU-SL01` append-only sealed logs (meeting audio, open capture segments).
 * Byte-compatible with `crates/core/crypto/src/sealed_log.rs`.
 *
 * ```text
 * header (32 B) = "RYU-SL01" | version u8 = 1 | flags u8 = 0 | reserved [0; 2] | salt [20]
 * K_l           = HKDF-SHA256(K_s, salt = header.salt,
 *                             info = "ryu-sealed-log-v1" || AAD(context))
 * record j      = u32 BE body_len || nonce12 (random) || ct || tag16,
 *                 AAD = header || u64 BE j, body_len <= 16 MiB
 * ```
 *
 * Records are never rewritten. Opening for append scans and verifies to the
 * end; a torn tail (a short length/body, or a final record that does not open)
 * never formed a committed record and is truncated before appending, while a
 * failing record followed by more data is corruption. Truncation exactly at a
 * record boundary is not detectable: callers that need completeness persist the
 * committed record count next to the log.
 */

import {
	closeSync,
	existsSync,
	fsyncSync,
	ftruncateSync,
	openSync,
	readFileSync,
	readSync,
	rmSync,
	writeSync,
} from "node:fs";
import { dirname } from "node:path";

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";

import {
	type ContentCipher,
	type ContentContext,
	ContentSealError,
	concatBytes,
	hasMagic,
	NONCE_LENGTH,
	SEALED_LOG_MAGIC,
	TAG_LENGTH,
	utf8,
} from "./content.ts";
import { type SealedFileOptions, SealedFileWriter } from "./sealed-file.ts";

/** Length of the `RYU-SL01` header. */
export const SEALED_LOG_HEADER_LENGTH = 32;
/** Largest record body (nonce + ciphertext + tag). */
export const MAX_RECORD_BODY = 16 * 1024 * 1024;

const SALT_LENGTH = 20;
const LOG_VERSION = 1;
const LOG_KDF_INFO = "ryu-sealed-log-v1";
const PRIVATE_FILE_MODE = 0o600;

type Tail = "clean" | "short" | "final_failed";

interface Scan {
	committedEnd: number;
	count: number;
	records: Uint8Array[];
	tail: Tail;
}

function recordAad(header: Uint8Array, index: number): Uint8Array {
	const aad = new Uint8Array(SEALED_LOG_HEADER_LENGTH + 8);
	aad.set(header, 0);
	new DataView(aad.buffer).setBigUint64(
		SEALED_LOG_HEADER_LENGTH,
		BigInt(index),
		false
	);
	return aad;
}

function checkHeader(header: Uint8Array): void {
	if (!hasMagic(header, SEALED_LOG_MAGIC)) {
		throw new ContentSealError("malformed", "not an RYU-SL01 sealed log");
	}
	if (
		header[8] !== LOG_VERSION ||
		header[9] !== 0 ||
		header[10] !== 0 ||
		header[11] !== 0
	) {
		throw new ContentSealError(
			"unknown_version",
			"unsupported RYU-SL01 header (written by a newer Ryu?)"
		);
	}
}

function allZero(bytes: Uint8Array): boolean {
	return bytes.every((byte) => byte === 0);
}

function scanWith(
	bytes: Uint8Array,
	header: Uint8Array,
	key: Uint8Array,
	keepRecords: boolean
): Scan {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const records: Uint8Array[] = [];
	let position = SEALED_LOG_HEADER_LENGTH;
	let index = 0;
	const finish = (tail: Tail): Scan => ({
		committedEnd: position,
		count: index,
		records,
		tail,
	});
	for (;;) {
		if (position === bytes.length) {
			return finish("clean");
		}
		if (bytes.length - position < 4) {
			return finish("short");
		}
		const bodyLength = view.getUint32(position, false);
		const bodyStart = position + 4;
		if (
			bodyLength < NONCE_LENGTH + TAG_LENGTH ||
			bodyLength > MAX_RECORD_BODY
		) {
			if (allZero(bytes.subarray(position))) {
				return finish("short");
			}
			throw new ContentSealError(
				"malformed",
				`sealed log record ${index} has an invalid length`
			);
		}
		if (bytes.length - bodyStart < bodyLength) {
			return finish("short");
		}
		const end = bodyStart + bodyLength;
		const nonce = bytes.subarray(bodyStart, bodyStart + NONCE_LENGTH);
		let plain: Uint8Array | null = null;
		try {
			plain = chacha20poly1305(key, nonce, recordAad(header, index)).decrypt(
				bytes.subarray(bodyStart + NONCE_LENGTH, end)
			);
		} catch {
			if (end === bytes.length) {
				return finish("final_failed");
			}
			throw new ContentSealError(
				"does_not_open",
				`sealed log record ${index} does not open and is followed by more data`
			);
		}
		if (keepRecords) {
			records.push(plain);
		}
		position = end;
		index += 1;
	}
}

interface OpenedLog {
	header: Uint8Array;
	key: Uint8Array;
	retired: boolean;
	scan: Scan;
}

function openLog(
	bytes: Uint8Array,
	cipher: ContentCipher,
	context: ContentContext,
	keepRecords: boolean
): OpenedLog {
	if (bytes.length < SEALED_LOG_HEADER_LENGTH) {
		throw new ContentSealError(
			"malformed",
			"sealed log is shorter than its header"
		);
	}
	const header = bytes.slice(0, SEALED_LOG_HEADER_LENGTH);
	checkHeader(header);
	const candidates = cipher.deriveCandidates(
		header.subarray(12),
		LOG_KDF_INFO,
		context.associatedData(cipher.store)
	);
	let firstError: unknown = null;
	for (const candidate of candidates) {
		try {
			const scan = scanWith(bytes, header, candidate.key, keepRecords);
			// A lone failing first record means "wrong key", not a torn tail.
			if (
				scan.tail === "final_failed" &&
				scan.committedEnd === SEALED_LOG_HEADER_LENGTH
			) {
				continue;
			}
			return { header, key: candidate.key, retired: candidate.retired, scan };
		} catch (error) {
			firstError ??= error;
		}
	}
	throw (
		firstError ??
		new ContentSealError(
			"does_not_open",
			"sealed log does not open (another key, store or record)"
		)
	);
}

/** Every record of a complete sealed log held in memory; a torn tail is an error. */
export function readLogBytes(
	bytes: Uint8Array,
	cipher: ContentCipher,
	context: ContentContext
): Uint8Array[] {
	const opened = openLog(bytes, cipher, context, true);
	if (opened.scan.tail !== "clean") {
		throw new ContentSealError(
			"malformed",
			"sealed log ends in an incomplete record"
		);
	}
	return opened.scan.records;
}

/** Every record of a complete sealed log on disk; a torn tail is an error. */
export function readLog(
	path: string,
	cipher: ContentCipher,
	context: ContentContext
): Uint8Array[] {
	return readLogBytes(readFileSync(path), cipher, context);
}

/** The committed records of a log that may end in a torn tail. */
export interface RecoveredLog {
	/** True when the opening key is retired: compact the log under the current key. */
	needsReseal: boolean;
	records: Uint8Array[];
	tornTail: boolean;
}

/** Read the committed records, tolerating a torn tail (crash recovery). */
export function openRecovering(
	path: string,
	cipher: ContentCipher,
	context: ContentContext
): RecoveredLog {
	const opened = openLog(readFileSync(path), cipher, context, true);
	return {
		records: opened.scan.records,
		tornTail: opened.scan.tail !== "clean",
		needsReseal: opened.retired,
	};
}

/** Whether the file at `path` starts with the `RYU-SL01` magic. */
export function isSealedLog(path: string): boolean {
	const fd = openSync(path, "r");
	try {
		const magic = new Uint8Array(8);
		return (
			readSync(fd, magic, 0, 8, 0) === 8 && hasMagic(magic, SEALED_LOG_MAGIC)
		);
	} finally {
		closeSync(fd);
	}
}

function writeAllSync(fd: number, bytes: Uint8Array): void {
	let offset = 0;
	while (offset < bytes.length) {
		offset += writeSync(fd, bytes, offset, bytes.length - offset);
	}
}

function fsyncDir(path: string): void {
	try {
		const fd = openSync(dirname(path), "r");
		try {
			fsyncSync(fd);
		} finally {
			closeSync(fd);
		}
	} catch {
		// Directory fsync is unsupported on some platforms (Windows).
	}
}

/** Appends records to one `RYU-SL01` log. Not safe for concurrent writers. */
export class SealedLogWriter {
	readonly #header: Uint8Array;
	readonly #key: Uint8Array;
	#fd: number | null;
	#position: number;
	#nextIndex: number;

	private constructor(
		fd: number,
		header: Uint8Array,
		key: Uint8Array,
		position: number,
		nextIndex: number
	) {
		this.#fd = fd;
		this.#header = header;
		this.#key = key;
		this.#position = position;
		this.#nextIndex = nextIndex;
	}

	/** Create a new log (0600; fails if `path` exists). */
	static create(
		path: string,
		cipher: ContentCipher,
		context: ContentContext
	): SealedLogWriter {
		const salt = randomBytes(SALT_LENGTH);
		const header = new Uint8Array(SEALED_LOG_HEADER_LENGTH);
		header.set(utf8(SEALED_LOG_MAGIC), 0);
		header[8] = LOG_VERSION;
		header.set(salt, 12);
		const [current] = cipher.deriveCandidates(
			salt,
			LOG_KDF_INFO,
			context.associatedData(cipher.store)
		);
		if (!current) {
			throw new Error("content cipher has no current key");
		}
		const fd = openSync(path, "wx", PRIVATE_FILE_MODE);
		try {
			writeAllSync(fd, header);
			fsyncSync(fd);
		} catch (error) {
			closeSync(fd);
			rmSync(path, { force: true });
			throw error;
		}
		fsyncDir(path);
		return new SealedLogWriter(
			fd,
			header,
			current.key,
			SEALED_LOG_HEADER_LENGTH,
			0
		);
	}

	/**
	 * Open a log for appending (creating it when missing). Verifies every record,
	 * truncates a torn tail, and refuses a log written under a retired key
	 * (compact it under the current key first).
	 */
	static openAppend(
		path: string,
		cipher: ContentCipher,
		context: ContentContext
	): SealedLogWriter {
		if (!existsSync(path)) {
			return SealedLogWriter.create(path, cipher, context);
		}
		const bytes = readFileSync(path);
		const opened = openLog(bytes, cipher, context, false);
		if (opened.retired) {
			throw new ContentSealError(
				"does_not_open",
				"sealed log was written under a retired key; compact it before appending"
			);
		}
		const fd = openSync(path, "r+");
		try {
			if (opened.scan.tail !== "clean") {
				ftruncateSync(fd, opened.scan.committedEnd);
				fsyncSync(fd);
			}
		} catch (error) {
			closeSync(fd);
			throw error;
		}
		return new SealedLogWriter(
			fd,
			opened.header,
			opened.key,
			opened.scan.committedEnd,
			opened.scan.count
		);
	}

	/** Records committed so far (including those found on open). */
	get recordCount(): number {
		return this.#nextIndex;
	}

	/** Append one record; returns its index. Call {@link sync} to make it durable. */
	append(record: Uint8Array): number {
		if (this.#fd === null) {
			throw new Error("sealed log writer is closed");
		}
		if (record.length + NONCE_LENGTH + TAG_LENGTH > MAX_RECORD_BODY) {
			throw new RangeError("sealed log records are limited to 16 MiB");
		}
		const index = this.#nextIndex;
		const nonce = randomBytes(NONCE_LENGTH);
		const sealed = chacha20poly1305(
			this.#key,
			nonce,
			recordAad(this.#header, index)
		).encrypt(record);
		const length = new Uint8Array(4);
		new DataView(length.buffer).setUint32(
			0,
			NONCE_LENGTH + sealed.length,
			false
		);
		const frame = concatBytes(length, nonce, sealed);
		let offset = 0;
		while (offset < frame.length) {
			offset += writeSync(
				this.#fd,
				frame,
				offset,
				frame.length - offset,
				this.#position + offset
			);
		}
		this.#position += frame.length;
		this.#nextIndex += 1;
		return index;
	}

	/** fsync the appended records. */
	sync(): void {
		if (this.#fd !== null) {
			fsyncSync(this.#fd);
		}
	}

	/** fsync and close (idempotent). */
	close(): void {
		if (this.#fd === null) {
			return;
		}
		try {
			fsyncSync(this.#fd);
		} finally {
			closeSync(this.#fd);
			this.#fd = null;
		}
	}
}

/**
 * Convert a closed log into a `RYU-SF01` file at `destination` (records
 * concatenated; temp + rename; verified before the rename). The log itself is
 * left in place: delete it once the caller has recorded the new file.
 */
export function compactToSealedFile(
	logPath: string,
	destination: string,
	cipher: ContentCipher,
	logContext: ContentContext,
	fileContext: ContentContext,
	options: SealedFileOptions = {}
): number {
	const records = readLog(logPath, cipher, logContext);
	const tempPath = `${destination}.sealing`;
	rmSync(tempPath, { force: true });
	const writer = SealedFileWriter.create(destination, cipher, fileContext, {
		...options,
		tempPath,
		verify: true,
	});
	try {
		for (const record of records) {
			writer.write(record);
		}
	} catch (error) {
		writer.abort();
		throw error;
	}
	return writer.finish().plaintextLength;
}
