import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
	existsSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	truncateSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buffer } from "node:stream/consumers";

import { ContentCipher, ContentContext, ContentSealError } from "./content.ts";
import {
	ensureFreeSpace,
	InsufficientSpaceError,
	isSealedFile,
	openFileBytes,
	SEALED_FILE_HEADER_LENGTH,
	SealedFileReader,
	SealedFileWriter,
	sealFileBytes,
	sealFileInPlace,
} from "./sealed-file.ts";

const cipher = ContentCipher.fromRoot(new Uint8Array(32).fill(6), "files.db");
const context = ContentContext.forId("blob", "abc123");
const pattern = (length: number) =>
	Uint8Array.from({ length }, (_, index) => (index * 13 + 5) % 251);
const MARKER = "PLAINTEXT-MARKER-0123456789";

let dir = "";
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "ryu-sealed-file-"));
});
afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

describe("RYU-SF01 sealed files", () => {
	test("round-trips every size around chunk boundaries", () => {
		for (const length of [0, 1, 1023, 1024, 1025, 2048, 5000]) {
			const plain = pattern(length);
			const sealed = sealFileBytes(plain, cipher, context, { chunkLog2: 10 });
			expect(openFileBytes(sealed, cipher, context)).toEqual(plain);
			const reader = SealedFileReader.fromBytes(sealed, cipher, context);
			expect(reader.plaintextLength).toBe(length);
		}
	});

	test("range reads equal plaintext slices and decrypt lazily", () => {
		const plain = pattern(10_000);
		const sealed = sealFileBytes(plain, cipher, context, { chunkLog2: 10 });
		const reader = SealedFileReader.fromBytes(sealed, cipher, context);
		for (const [start, length] of [
			[0, 1],
			[1023, 2],
			[1024, 1024],
			[9990, 100],
			[5000, 0],
			[20_000, 5],
		] as const) {
			expect(reader.readRange(start, length)).toEqual(
				plain.slice(start, Math.min(start + length, plain.length))
			);
		}
	});

	test("truncation, a dropped final chunk and tampering are detected", () => {
		const plain = pattern(3000);
		const sealed = sealFileBytes(plain, cipher, context, { chunkLog2: 10 });
		// Cut inside the final chunk.
		expect(() =>
			SealedFileReader.fromBytes(
				sealed.subarray(0, sealed.length - 5),
				cipher,
				context
			)
		).toThrow(ContentSealError);
		// Cut exactly at a chunk boundary: the new last chunk lacks the final flag.
		expect(() =>
			SealedFileReader.fromBytes(
				sealed.subarray(0, SEALED_FILE_HEADER_LENGTH + 2 * (1024 + 16)),
				cipher,
				context
			)
		).toThrow(ContentSealError);
		const tampered = sealed.slice();
		tampered[SEALED_FILE_HEADER_LENGTH + 3] ^= 1;
		const reader = SealedFileReader.fromBytes(tampered, cipher, context);
		expect(() => reader.readRange(0, 10)).toThrow(ContentSealError);
		expect(() =>
			SealedFileReader.fromBytes(
				sealed,
				cipher,
				ContentContext.forId("blob", "other")
			)
		).toThrow(ContentSealError);
	});

	test("the writer leaves only sealed bytes on disk, 0600, via a temp file", async () => {
		const destination = join(dir, "doc.bin");
		const writer = SealedFileWriter.create(destination, cipher, context);
		writer.write(new TextEncoder().encode(`${MARKER} first`));
		writer.write(new TextEncoder().encode(" second"));
		expect(existsSync(destination)).toBe(false);
		const summary = writer.finish();
		expect(summary.plaintextLength).toBe(MARKER.length + 13);
		expect(readdirSync(dir)).toEqual(["doc.bin"]);
		expect(readFileSync(destination).includes(MARKER)).toBe(false);
		expect(isSealedFile(destination)).toBe(true);
		if (process.platform !== "win32") {
			expect(statSync(destination).mode & 0o777).toBe(0o600);
		}
		const reader = SealedFileReader.open(destination, cipher, context);
		try {
			const streamed = await buffer(
				reader.createReadStream({ start: 6, end: 10 })
			);
			expect(streamed.toString()).toBe(MARKER.slice(6, 11));
			const whole = await buffer(reader.createReadStream());
			expect(whole.toString()).toBe(`${MARKER} first second`);
		} finally {
			reader.close();
		}
	});

	test("an aborted writer removes its temp file and keeps the old file", () => {
		const destination = join(dir, "doc.bin");
		writeFileSync(destination, "old");
		const writer = SealedFileWriter.create(destination, cipher, context);
		writer.write(new TextEncoder().encode("new"));
		writer.abort();
		expect(readdirSync(dir)).toEqual(["doc.bin"]);
		expect(readFileSync(destination, "utf8")).toBe("old");
	});

	test("sealing in place is verified, idempotent and keeps legacy data readable", () => {
		const path = join(dir, "legacy.bin");
		const plain = new TextEncoder().encode(`${MARKER} ${"x".repeat(200_000)}`);
		writeFileSync(path, plain);
		writeFileSync(`${path}.sealing`, "stale temp from a crash");
		expect(sealFileInPlace(path, cipher, context)).toEqual({
			status: "sealed",
			plaintextLength: plain.length,
		});
		expect(readFileSync(path).includes(MARKER)).toBe(false);
		expect(existsSync(`${path}.sealing`)).toBe(false);
		expect(sealFileInPlace(path, cipher, context)).toEqual({
			status: "already_sealed",
		});
		const reader = SealedFileReader.open(path, cipher, context);
		try {
			expect(reader.readAll()).toEqual(plain);
		} finally {
			reader.close();
		}
	});

	test("a truncated sealed file on disk is refused", () => {
		const path = join(dir, "cut.bin");
		writeFileSync(path, pattern(70_000));
		sealFileInPlace(path, cipher, context);
		truncateSync(path, statSync(path).size - 1);
		expect(() => SealedFileReader.open(path, cipher, context)).toThrow(
			ContentSealError
		);
	});

	test("refuses to seal when free space is short", () => {
		expect(() => ensureFreeSpace(dir, Number.MAX_SAFE_INTEGER)).toThrow(
			InsufficientSpaceError
		);
		expect(() => ensureFreeSpace(dir, 1)).not.toThrow();
	});

	test("retired roots open files and flag them for resealing", () => {
		const oldRoot = new Uint8Array(32).fill(8);
		const sealed = sealFileBytes(
			pattern(100),
			ContentCipher.fromRoot(oldRoot, "files.db"),
			context
		);
		const rotated = ContentCipher.fromRoot(
			new Uint8Array(32).fill(9),
			"files.db"
		).withRetiredRoots([oldRoot]);
		const reader = SealedFileReader.fromBytes(sealed, rotated, context);
		expect(reader.needsReseal).toBe(true);
		expect(reader.readAll()).toEqual(pattern(100));
	});
});
