/**
 * `RYU-SF01` write-once sealed files with random-access reads. Byte-compatible
 * with `crates/core/crypto/src/sealed_file.rs`.
 *
 * ```text
 * header (32 B, AAD of every chunk) = "RYU-SF01" | chunk_log2 u8 (10..=20)
 *                                    | flags u8 = 0 | reserved [0; 2] | salt [20]
 * K_f   = HKDF-SHA256(K_s, salt = header.salt,
 *                     info = "ryu-sealed-file-v1" || AAD(context))
 * chunk i = ChaCha20-Poly1305(K_f, nonce = i as 11-byte BE || last ? 1 : 0)
 * ```
 *
 * Files are WRITE-ONCE: every modification writes a new file (new random salt,
 * so a new `K_f`) into an owner-only temp file and renames it over the old one,
 * so each `(K_f, nonce)` pair encrypts exactly one plaintext. Readers verify the
 * final chunk on open (a truncated file is refused and the plaintext length is
 * trustworthy for `Content-Length`), then decrypt only the chunks a range
 * touches.
 */

import {
	closeSync,
	fstatSync,
	fsyncSync,
	openSync,
	readSync,
	renameSync,
	rmSync,
	statfsSync,
	statSync,
	writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { Readable } from "node:stream";

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";

import {
	type ContentCipher,
	type ContentContext,
	ContentSealError,
	concatBytes,
	hasMagic,
	SEALED_FILE_MAGIC,
	TAG_LENGTH,
	toHex,
	utf8,
} from "./content.ts";

/** Length of the `RYU-SF01` header. */
export const SEALED_FILE_HEADER_LENGTH = 32;
/** Default chunk size: 64 KiB. */
export const DEFAULT_CHUNK_LOG2 = 16;
/** Free space required on top of the file size before sealing in place. */
export const SEAL_IN_PLACE_HEADROOM = 64 * 1024 * 1024;

const SALT_LENGTH = 20;
const FILE_KDF_INFO = "ryu-sealed-file-v1";
const MIN_CHUNK_LOG2 = 10;
const MAX_CHUNK_LOG2 = 20;
const COPY_BUFFER = 1 << 16;
const PRIVATE_FILE_MODE = 0o600;

/** Raised when a directory has less free space than an operation needs. */
export class InsufficientSpaceError extends Error {
	override readonly name = "InsufficientSpaceError";
	readonly available: number;
	readonly dir: string;
	readonly needed: number;

	constructor(dir: string, needed: number, available: number) {
		super(
			`not enough free disk space in ${dir}: need ${needed} bytes, ${available} available`
		);
		this.dir = dir;
		this.needed = needed;
		this.available = available;
	}
}

/** Bytes available to this user in the filesystem holding `dir`. */
export function availableSpace(dir: string): number {
	const stats = statfsSync(dir);
	return Number(stats.bavail) * Number(stats.bsize);
}

/** Throw {@link InsufficientSpaceError} unless `dir` has `needed` bytes free. */
export function ensureFreeSpace(dir: string, needed: number): void {
	const available = availableSpace(dir);
	if (available < needed) {
		throw new InsufficientSpaceError(dir, needed, available);
	}
}

function chunkNonce(index: number, last: boolean): Uint8Array {
	const nonce = new Uint8Array(12);
	new DataView(nonce.buffer).setBigUint64(3, BigInt(index), false);
	nonce[11] = last ? 1 : 0;
	return nonce;
}

function buildHeader(chunkLog2: number, salt: Uint8Array): Uint8Array {
	const header = new Uint8Array(SEALED_FILE_HEADER_LENGTH);
	header.set(utf8(SEALED_FILE_MAGIC), 0);
	header[8] = chunkLog2;
	header.set(salt, 12);
	return header;
}

function checkChunkLog2(chunkLog2: number): void {
	if (
		!Number.isInteger(chunkLog2) ||
		chunkLog2 < MIN_CHUNK_LOG2 ||
		chunkLog2 > MAX_CHUNK_LOG2
	) {
		throw new RangeError(
			`sealed file chunk_log2 must be 10..=20, got ${chunkLog2}`
		);
	}
}

/** Options of a sealed file writer. */
export interface SealedFileOptions {
	/** log2 of the plaintext chunk size, 10..=20 (default 16, 64 KiB). */
	chunkLog2?: number;
}

/** The plaintext summary of a finished sealed file. */
export interface SealedFileSummary {
	plaintextLength: number;
	/** Lower-case hex SHA-256 of the plaintext. */
	plaintextSha256: string;
}

/**
 * Streaming `RYU-SF01` encoder without I/O: feed plaintext, collect sealed
 * bytes. It buffers one chunk so it knows which chunk is last.
 */
export class SealedFileEncoder {
	readonly header: Uint8Array;
	readonly #key: Uint8Array;
	readonly #chunkSize: number;
	readonly #hash = sha256.create();
	#buffer: Uint8Array;
	#filled = 0;
	#nextIndex = 0;
	#plaintextLength = 0;
	#finished = false;

	constructor(
		cipher: ContentCipher,
		context: ContentContext,
		options: SealedFileOptions = {}
	) {
		const chunkLog2 = options.chunkLog2 ?? DEFAULT_CHUNK_LOG2;
		checkChunkLog2(chunkLog2);
		const salt = randomBytes(SALT_LENGTH);
		this.header = buildHeader(chunkLog2, salt);
		const [current] = cipher.deriveCandidates(
			salt,
			FILE_KDF_INFO,
			context.associatedData(cipher.store)
		);
		if (!current) {
			throw new Error("content cipher has no current key");
		}
		this.#key = current.key;
		this.#chunkSize = 2 ** chunkLog2;
		this.#buffer = new Uint8Array(this.#chunkSize);
	}

	#sealChunk(last: boolean): Uint8Array {
		const sealed = chacha20poly1305(
			this.#key,
			chunkNonce(this.#nextIndex, last),
			this.header
		).encrypt(this.#buffer.subarray(0, this.#filled));
		this.#nextIndex += 1;
		this.#filled = 0;
		return sealed;
	}

	/** Add plaintext; returns the sealed chunks completed by it (maybe none). */
	push(data: Uint8Array): Uint8Array[] {
		if (this.#finished) {
			throw new Error("sealed file encoder is already finished");
		}
		this.#hash.update(data);
		this.#plaintextLength += data.length;
		const out: Uint8Array[] = [];
		let offset = 0;
		while (offset < data.length) {
			if (this.#filled === this.#chunkSize) {
				out.push(this.#sealChunk(false));
			}
			const take = Math.min(
				this.#chunkSize - this.#filled,
				data.length - offset
			);
			this.#buffer.set(data.subarray(offset, offset + take), this.#filled);
			this.#filled += take;
			offset += take;
		}
		return out;
	}

	/** Seal the final chunk (possibly empty) and return it. */
	finish(): { finalChunk: Uint8Array; summary: SealedFileSummary } {
		if (this.#finished) {
			throw new Error("sealed file encoder is already finished");
		}
		const finalChunk = this.#sealChunk(true);
		this.#finished = true;
		this.#buffer = new Uint8Array(0);
		return {
			finalChunk,
			summary: {
				plaintextLength: this.#plaintextLength,
				plaintextSha256: toHex(this.#hash.digest()),
			},
		};
	}
}

/** Seal a whole plaintext in memory into `RYU-SF01` bytes. */
export function sealFileBytes(
	plaintext: Uint8Array,
	cipher: ContentCipher,
	context: ContentContext,
	options: SealedFileOptions = {}
): Uint8Array {
	const encoder = new SealedFileEncoder(cipher, context, options);
	const chunks = encoder.push(plaintext);
	const { finalChunk } = encoder.finish();
	return concatBytes(encoder.header, ...chunks, finalChunk);
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

function writeAllSync(fd: number, bytes: Uint8Array): void {
	let offset = 0;
	while (offset < bytes.length) {
		offset += writeSync(fd, bytes, offset, bytes.length - offset);
	}
}

/** Options of {@link SealedFileWriter.create}. */
export interface SealedFileWriterOptions extends SealedFileOptions {
	/**
	 * Temp path to write before the rename (same directory as the destination).
	 * Default: `<destination>.<random>.sealing`.
	 */
	tempPath?: string;
	/**
	 * Re-open the temp file before the rename and compare the SHA-256 of its
	 * decrypted stream with the plaintext written (default false).
	 */
	verify?: boolean;
}

/**
 * Write a `RYU-SF01` file: plaintext goes to an owner-only (0600) temp file,
 * `finish()` fsyncs it and renames it over `destination`. Nothing plaintext is
 * ever written to disk. Call `abort()` on failure to delete the temp file.
 */
export class SealedFileWriter {
	readonly destination: string;
	readonly tempPath: string;
	readonly #cipher: ContentCipher;
	readonly #context: ContentContext;
	readonly #encoder: SealedFileEncoder;
	readonly #verify: boolean;
	#fd: number | null;

	private constructor(
		destination: string,
		cipher: ContentCipher,
		context: ContentContext,
		options: SealedFileWriterOptions
	) {
		this.destination = destination;
		this.tempPath =
			options.tempPath ??
			join(
				dirname(destination),
				`${basename(destination)}.${toHex(randomBytes(6))}.sealing`
			);
		this.#cipher = cipher;
		this.#context = context;
		this.#verify = options.verify ?? false;
		this.#encoder = new SealedFileEncoder(cipher, context, options);
		this.#fd = openSync(this.tempPath, "wx", PRIVATE_FILE_MODE);
		try {
			writeAllSync(this.#fd, this.#encoder.header);
		} catch (error) {
			this.abort();
			throw error;
		}
	}

	/** Start a sealed file that will replace `destination` on `finish()`. */
	static create(
		destination: string,
		cipher: ContentCipher,
		context: ContentContext,
		options: SealedFileWriterOptions = {}
	): SealedFileWriter {
		return new SealedFileWriter(destination, cipher, context, options);
	}

	#requireFd(): number {
		if (this.#fd === null) {
			throw new Error("sealed file writer is closed");
		}
		return this.#fd;
	}

	/** Append plaintext. */
	write(data: Uint8Array): void {
		const fd = this.#requireFd();
		for (const chunk of this.#encoder.push(data)) {
			writeAllSync(fd, chunk);
		}
	}

	/** Seal the final chunk, fsync, (verify,) and rename over the destination. */
	finish(): SealedFileSummary {
		const fd = this.#requireFd();
		try {
			const { finalChunk, summary } = this.#encoder.finish();
			writeAllSync(fd, finalChunk);
			fsyncSync(fd);
			closeSync(fd);
			this.#fd = null;
			if (this.#verify) {
				const digest = SealedFileReader.digestPath(
					this.tempPath,
					this.#cipher,
					this.#context
				);
				if (digest !== summary.plaintextSha256) {
					throw new Error("sealed copy does not verify");
				}
			}
			renameSync(this.tempPath, this.destination);
			fsyncDir(this.destination);
			return summary;
		} catch (error) {
			this.abort();
			throw error;
		}
	}

	/** Close and delete the temp file (idempotent). */
	abort(): void {
		if (this.#fd !== null) {
			try {
				closeSync(this.#fd);
			} catch {
				// Already closed.
			}
			this.#fd = null;
		}
		rmSync(this.tempPath, { force: true });
	}
}

/** Random-access byte source for a reader (a file descriptor or memory). */
interface ByteSource {
	close(): void;
	read(offset: number, length: number): Uint8Array;
	readonly size: number;
}

function memorySource(bytes: Uint8Array): ByteSource {
	return {
		size: bytes.length,
		read: (offset, length) => bytes.subarray(offset, offset + length),
		close: () => undefined,
	};
}

function fileSource(path: string): ByteSource {
	const fd = openSync(path, "r");
	let open = true;
	return {
		size: fstatSync(fd).size,
		read: (offset, length) => {
			const out = new Uint8Array(length);
			let filled = 0;
			while (filled < length) {
				const read = readSync(
					fd,
					out,
					filled,
					length - filled,
					offset + filled
				);
				if (read === 0) {
					throw new Error("sealed file changed while it was read");
				}
				filled += read;
			}
			return out;
		},
		close: () => {
			if (open) {
				open = false;
				closeSync(fd);
			}
		},
	};
}

/** Inclusive byte range options, as `fs.createReadStream` takes them. */
export interface RangeOptions {
	/** Close the reader once the stream ends or fails (default false). */
	autoClose?: boolean;
	/** Last plaintext byte, inclusive (default: the end). */
	end?: number;
	/** First plaintext byte (default 0). */
	start?: number;
}

/**
 * Reads a `RYU-SF01` file. `open` verifies the final chunk (so truncation is
 * detected up front and {@link plaintextLength} is trustworthy), then each read
 * decrypts only the chunks it touches.
 */
export class SealedFileReader {
	/** True when the file opened under a retired key: re-seal it. */
	readonly needsReseal: boolean;
	readonly plaintextLength: number;
	readonly #source: ByteSource;
	readonly #header: Uint8Array;
	readonly #key: Uint8Array;
	readonly #chunkSize: number;
	readonly #chunkCount: number;
	#cached: { index: number; plain: Uint8Array } | null = null;

	private constructor(
		source: ByteSource,
		header: Uint8Array,
		key: Uint8Array,
		layout: { chunkSize: number; chunkCount: number; plaintextLength: number },
		retired: boolean
	) {
		this.#source = source;
		this.#header = header;
		this.#key = key;
		this.#chunkSize = layout.chunkSize;
		this.#chunkCount = layout.chunkCount;
		this.plaintextLength = layout.plaintextLength;
		this.needsReseal = retired;
	}

	/** Open a sealed file on disk. Call `close()` when done. */
	static open(
		path: string,
		cipher: ContentCipher,
		context: ContentContext
	): SealedFileReader {
		const source = fileSource(path);
		try {
			return SealedFileReader.#openSource(source, cipher, context);
		} catch (error) {
			source.close();
			throw error;
		}
	}

	/** Open sealed bytes held in memory. */
	static fromBytes(
		sealed: Uint8Array,
		cipher: ContentCipher,
		context: ContentContext
	): SealedFileReader {
		return SealedFileReader.#openSource(memorySource(sealed), cipher, context);
	}

	/** SHA-256 (hex) of the decrypted stream of a sealed file on disk. */
	static digestPath(
		path: string,
		cipher: ContentCipher,
		context: ContentContext
	): string {
		const reader = SealedFileReader.open(path, cipher, context);
		try {
			const hash = sha256.create();
			for (const chunk of reader.chunks()) {
				hash.update(chunk);
			}
			return toHex(hash.digest());
		} finally {
			reader.close();
		}
	}

	static #openSource(
		source: ByteSource,
		cipher: ContentCipher,
		context: ContentContext
	): SealedFileReader {
		const size = source.size;
		if (size < SEALED_FILE_HEADER_LENGTH + TAG_LENGTH) {
			throw new ContentSealError(
				"malformed",
				`sealed file is truncated (${size} bytes)`
			);
		}
		const header = source.read(0, SEALED_FILE_HEADER_LENGTH).slice();
		if (!hasMagic(header, SEALED_FILE_MAGIC)) {
			throw new ContentSealError("malformed", "not an RYU-SF01 sealed file");
		}
		const chunkLog2 = header[8] ?? 0;
		if (
			chunkLog2 < MIN_CHUNK_LOG2 ||
			chunkLog2 > MAX_CHUNK_LOG2 ||
			header[9] !== 0 ||
			header[10] !== 0 ||
			header[11] !== 0
		) {
			throw new ContentSealError(
				"unknown_version",
				"unsupported RYU-SF01 header"
			);
		}
		const chunkSize = 2 ** chunkLog2;
		const body = size - SEALED_FILE_HEADER_LENGTH;
		const sealedChunk = chunkSize + TAG_LENGTH;
		const full = Math.floor(body / sealedChunk);
		const rem = body % sealedChunk;
		if (rem > 0 && rem < TAG_LENGTH) {
			throw new ContentSealError(
				"malformed",
				"sealed file is truncated or malformed"
			);
		}
		const layout =
			rem === 0
				? { chunkSize, chunkCount: full, plaintextLength: full * chunkSize }
				: {
						chunkSize,
						chunkCount: full + 1,
						plaintextLength: full * chunkSize + (rem - TAG_LENGTH),
					};
		const candidates = cipher.deriveCandidates(
			header.subarray(12),
			FILE_KDF_INFO,
			context.associatedData(cipher.store)
		);
		for (const candidate of candidates) {
			const reader = new SealedFileReader(
				source,
				header,
				candidate.key,
				layout,
				candidate.retired
			);
			try {
				reader.#loadChunk(layout.chunkCount - 1);
				return reader;
			} catch {
				// Try the next (retired) key.
			}
		}
		throw new ContentSealError(
			"does_not_open",
			"sealed file is truncated, altered, or sealed under another key"
		);
	}

	#loadChunk(index: number): Uint8Array {
		if (this.#cached?.index === index) {
			return this.#cached.plain;
		}
		if (index < 0 || index >= this.#chunkCount) {
			throw new RangeError(`chunk ${index} out of range`);
		}
		const last = index + 1 === this.#chunkCount;
		const sealedChunk = this.#chunkSize + TAG_LENGTH;
		const offset = SEALED_FILE_HEADER_LENGTH + index * sealedChunk;
		const length = last
			? this.plaintextLength - index * this.#chunkSize + TAG_LENGTH
			: sealedChunk;
		const sealed = this.#source.read(offset, length);
		let plain: Uint8Array;
		try {
			plain = chacha20poly1305(
				this.#key,
				chunkNonce(index, last),
				this.#header
			).decrypt(sealed);
		} catch {
			throw new ContentSealError(
				"does_not_open",
				`sealed file chunk ${index} does not open`
			);
		}
		this.#cached = { index, plain };
		return plain;
	}

	/** Plaintext chunks covering `[start, endExclusive)`, decrypting lazily. */
	*chunks(
		start = 0,
		endExclusive = this.plaintextLength
	): Generator<Uint8Array> {
		const end = Math.min(endExclusive, this.plaintextLength);
		let position = Math.max(0, start);
		while (position < end) {
			const index = Math.floor(position / this.#chunkSize);
			const chunk = this.#loadChunk(index);
			const within = position - index * this.#chunkSize;
			const take = Math.min(end - position, chunk.length - within);
			yield chunk.slice(within, within + take);
			position += take;
		}
	}

	/** Read `length` plaintext bytes from `start` (clamped to the end). */
	readRange(start: number, length: number): Uint8Array {
		return concatBytes(...this.chunks(start, start + length));
	}

	/** The whole plaintext. */
	readAll(): Uint8Array {
		return concatBytes(...this.chunks());
	}

	/**
	 * A Node readable stream of the plaintext in the inclusive range
	 * `[start, end]`, like `fs.createReadStream`. Suitable for HTTP Range
	 * responses (`Readable.toWeb` converts it to a web stream).
	 */
	createReadStream(options: RangeOptions = {}): Readable {
		const start = options.start ?? 0;
		const endExclusive =
			options.end === undefined ? this.plaintextLength : options.end + 1;
		const iterator = this.chunks(start, endExclusive);
		const stream = Readable.from(iterator, { objectMode: false });
		if (options.autoClose) {
			stream.once("close", () => this.close());
		}
		return stream;
	}

	/** Release the file descriptor. */
	close(): void {
		this.#cached = null;
		this.#source.close();
	}
}

/** Open whole `RYU-SF01` bytes held in memory. */
export function openFileBytes(
	sealed: Uint8Array,
	cipher: ContentCipher,
	context: ContentContext
): Uint8Array {
	return SealedFileReader.fromBytes(sealed, cipher, context).readAll();
}

/** Whether the file at `path` starts with the `RYU-SF01` magic. */
export function isSealedFile(path: string): boolean {
	const fd = openSync(path, "r");
	try {
		const magic = new Uint8Array(8);
		const read = readSync(fd, magic, 0, 8, 0);
		return read === 8 && hasMagic(magic, SEALED_FILE_MAGIC);
	} finally {
		closeSync(fd);
	}
}

/** Outcome of {@link sealFileInPlace}. */
export type SealInPlaceResult =
	| { status: "already_sealed" }
	| { status: "sealed"; plaintextLength: number };

/**
 * Seal a plaintext file in place: require `size + 64 MiB` free, write
 * `<name>.sealing` (0600), fsync, re-open it and compare the SHA-256 of the
 * decrypted stream with the original, then rename it over the original. The
 * plaintext is never removed before the sealed copy is verified; an interrupted
 * run leaves the original untouched (a stale `.sealing` file is replaced on the
 * next run). Idempotent: a sealed file is left alone.
 */
export function sealFileInPlace(
	path: string,
	cipher: ContentCipher,
	context: ContentContext,
	options: SealedFileOptions = {}
): SealInPlaceResult {
	if (isSealedFile(path)) {
		return { status: "already_sealed" };
	}
	const size = statSync(path).size;
	ensureFreeSpace(dirname(path), size + SEAL_IN_PLACE_HEADROOM);
	const tempPath = `${path}.sealing`;
	rmSync(tempPath, { force: true });
	const writer = SealedFileWriter.create(path, cipher, context, {
		...options,
		tempPath,
		verify: true,
	});
	let fd: number | null = null;
	try {
		fd = openSync(path, "r");
		const buffer = new Uint8Array(COPY_BUFFER);
		let position = 0;
		for (;;) {
			const read = readSync(fd, buffer, 0, buffer.length, position);
			if (read === 0) {
				break;
			}
			writer.write(buffer.subarray(0, read));
			position += read;
		}
		closeSync(fd);
		fd = null;
	} catch (error) {
		if (fd !== null) {
			closeSync(fd);
		}
		writer.abort();
		throw error;
	}
	const summary = writer.finish();
	return { status: "sealed", plaintextLength: summary.plaintextLength };
}
