import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
	appendFileSync,
	existsSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	truncateSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
	ContentCipher,
	ContentContext,
	ContentSealError,
	NONCE_LENGTH,
} from "./content.ts";
import { SealedFileReader } from "./sealed-file.ts";
import {
	compactToSealedFile,
	isSealedLog,
	openRecovering,
	readLog,
	SEALED_LOG_HEADER_LENGTH,
	SealedLogWriter,
} from "./sealed-log.ts";

const cipher = ContentCipher.fromRoot(
	new Uint8Array(32).fill(4),
	"meetings.db"
);
const context = ContentContext.forId("log", "meeting-1");
const text = (value: string) => new TextEncoder().encode(value);
const decode = (records: Uint8Array[]) =>
	records.map((record) => new TextDecoder().decode(record));
const MARKER = "PCM-PLAINTEXT-MARKER";

let dir = "";
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "ryu-sealed-log-"));
});
afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

function nonces(bytes: Uint8Array): string[] {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const out: string[] = [];
	let position = SEALED_LOG_HEADER_LENGTH;
	while (position + 4 + NONCE_LENGTH <= bytes.length) {
		const length = view.getUint32(position, false);
		out.push(
			Buffer.from(
				bytes.subarray(position + 4, position + 4 + NONCE_LENGTH)
			).toString("hex")
		);
		position += 4 + length;
	}
	return out;
}

describe("RYU-SL01 sealed logs", () => {
	test("appends across reopenings and reads back in order, sealed on disk", () => {
		const path = join(dir, "audio.log");
		const first = SealedLogWriter.create(path, cipher, context);
		expect(first.append(text(`${MARKER} 1`))).toBe(0);
		expect(first.append(text(""))).toBe(1);
		first.close();
		const second = SealedLogWriter.openAppend(path, cipher, context);
		expect(second.recordCount).toBe(2);
		expect(second.append(text("three"))).toBe(2);
		second.close();
		expect(decode(readLog(path, cipher, context))).toEqual([
			`${MARKER} 1`,
			"",
			"three",
		]);
		expect(readFileSync(path).includes(MARKER)).toBe(false);
		expect(isSealedLog(path)).toBe(true);
		if (process.platform !== "win32") {
			expect(statSync(path).mode & 0o777).toBe(0o600);
		}
	});

	test("two appends never reuse a (key, nonce) pair", () => {
		const path = join(dir, "n.log");
		const writer = SealedLogWriter.create(path, cipher, context);
		for (let index = 0; index < 50; index += 1) {
			writer.append(text("same record"));
		}
		writer.close();
		const reopened = SealedLogWriter.openAppend(path, cipher, context);
		reopened.append(text("same record"));
		reopened.close();
		const seen = nonces(readFileSync(path));
		expect(seen).toHaveLength(51);
		expect(new Set(seen).size).toBe(51);
	});

	test("a torn tail is reported, then truncated before the next append", () => {
		const path = join(dir, "torn.log");
		const writer = SealedLogWriter.create(path, cipher, context);
		writer.append(text("kept"));
		writer.close();
		const committed = statSync(path).size;
		appendFileSync(path, Uint8Array.from([0, 0, 0, 40, 1, 2, 3]));
		expect(() => readLog(path, cipher, context)).toThrow(ContentSealError);
		const recovered = openRecovering(path, cipher, context);
		expect(recovered.tornTail).toBe(true);
		expect(decode(recovered.records)).toEqual(["kept"]);
		const appender = SealedLogWriter.openAppend(path, cipher, context);
		expect(statSync(path).size).toBe(committed);
		appender.append(text("next"));
		appender.close();
		expect(decode(readLog(path, cipher, context))).toEqual(["kept", "next"]);
	});

	test("a final record that does not open is a torn tail; one followed by data is corruption", () => {
		const path = join(dir, "bad.log");
		const writer = SealedLogWriter.create(path, cipher, context);
		writer.append(text("one"));
		writer.append(text("two"));
		writer.close();
		const bytes = readFileSync(path);
		bytes[bytes.length - 1] ^= 1;
		writeFileSync(path, bytes);
		expect(decode(openRecovering(path, cipher, context).records)).toEqual([
			"one",
		]);
		const middle = readFileSync(path);
		middle[SEALED_LOG_HEADER_LENGTH + 20] ^= 1;
		middle[middle.length - 1] ^= 1;
		writeFileSync(path, middle);
		expect(() => openRecovering(path, cipher, context)).toThrow(
			ContentSealError
		);
	});

	test("another key, store or log id does not open", () => {
		const path = join(dir, "k.log");
		const writer = SealedLogWriter.create(path, cipher, context);
		writer.append(text("x"));
		writer.close();
		const other = ContentCipher.fromRoot(
			new Uint8Array(32).fill(5),
			"meetings.db"
		);
		expect(() => readLog(path, other, context)).toThrow(ContentSealError);
		expect(() =>
			readLog(path, cipher, ContentContext.forId("log", "meeting-2"))
		).toThrow(ContentSealError);
	});

	test("compaction converts a closed log into a RYU-SF01 file", () => {
		const path = join(dir, "c.log");
		const writer = SealedLogWriter.create(path, cipher, context);
		writer.append(text("ab"));
		writer.append(text("cd"));
		writer.close();
		const destination = join(dir, "c.sf");
		const fileContext = ContentContext.forId("file", "meeting-1");
		expect(
			compactToSealedFile(path, destination, cipher, context, fileContext)
		).toBe(4);
		expect(existsSync(`${destination}.sealing`)).toBe(false);
		const reader = SealedFileReader.open(destination, cipher, fileContext);
		try {
			expect(new TextDecoder().decode(reader.readAll())).toBe("abcd");
		} finally {
			reader.close();
		}
	});

	test("a header-only log opens empty and truncation to a short length recovers", () => {
		const path = join(dir, "empty.log");
		SealedLogWriter.create(path, cipher, context).close();
		expect(readLog(path, cipher, context)).toEqual([]);
		const writer = SealedLogWriter.openAppend(path, cipher, context);
		writer.append(text("one"));
		writer.close();
		truncateSync(path, statSync(path).size - 2);
		expect(openRecovering(path, cipher, context).records).toEqual([]);
	});
});
