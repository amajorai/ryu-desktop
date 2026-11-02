import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { BlindIndex, TERMS_FIELD, tokenizeTerms } from "./blind-index.ts";
import {
	CONTENT_TEXT_PREFIX,
	ContentCipher,
	ContentContext,
	ContentSealError,
	concatBytes,
	fromBase64,
	isContentSealError,
	kcv,
	toBase64,
	toHex,
	utf8,
} from "./content.ts";
import { openFileBytes, SealedFileReader } from "./sealed-file.ts";
import { readLogBytes } from "./sealed-log.ts";

const fixturePath = join(import.meta.dir, "__fixtures__", "content-v1.json");
const rustFixturePath = join(
	import.meta.dir,
	"..",
	"..",
	"..",
	"crates",
	"core",
	"crypto",
	"tests",
	"vectors",
	"content-v1.json"
);

interface Vectors {
	aad_hex: string;
	blind_index: { field: string; normalized: string; token: string };
	bytes: { plaintext_hex: string; sealed_hex: string };
	content_key_b64: string;
	fts_term: { field: string; term: string; token: string };
	kcv: { kcv_hex: string };
	root_key_b64: string;
	sealed_file: {
		chunk_log2: number;
		file_len: number;
		file_sha256: string;
		header_hex: string;
		salt_hex: string;
	};
	sealed_log: {
		context: { fields: [string, string][]; purpose: string };
		file_hex: string;
		file_len: number;
		records_utf8: string[];
	};
	store: string;
	subkey: { key_b64: string; label: string };
	text: {
		fields: [string, string][];
		nonce_hex: string;
		plaintext: string;
		purpose: string;
		sealed: string;
	};
	tokenizer: {
		cases: { terms: string[]; text: string; tokens: string[] }[];
		field: string;
		store: string;
	};
}

const vectors = JSON.parse(readFileSync(fixturePath, "utf8")) as Vectors;

function fromHex(hex: string): Uint8Array {
	const out = new Uint8Array(hex.length / 2);
	for (let index = 0; index < out.length; index += 1) {
		out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
	}
	return out;
}

function b64(value: string): Uint8Array {
	const decoded = fromBase64(value);
	if (!decoded) {
		throw new Error("bad base64 in fixture");
	}
	return decoded;
}

const root = b64(vectors.root_key_b64);
const cipher = ContentCipher.fromRoot(root, vectors.store);
const textContext = vectors.text.fields.reduce(
	(context, [label, value]) => context.with(label, value),
	new ContentContext(vectors.text.purpose)
);

function deriveContentKey(rootKey: Uint8Array, store: string): Uint8Array {
	return hkdf(
		sha256,
		rootKey,
		utf8("ryu-content-crypto-v1"),
		utf8(`ryu-content-crypto-v1:${store}`),
		32
	);
}

describe("content-v1 vectors", () => {
	test("the fixture is the same JSON as the Rust crate's vectors", () => {
		if (!existsSync(rustFixturePath)) {
			return;
		}
		expect(JSON.parse(readFileSync(rustFixturePath, "utf8"))).toEqual(vectors);
	});

	test("derives the content key, AAD and key check value", () => {
		expect(toBase64(deriveContentKey(root, vectors.store))).toBe(
			vectors.content_key_b64
		);
		expect(toHex(textContext.associatedData(vectors.store))).toBe(
			vectors.aad_hex
		);
		expect(kcv(root)).toBe(vectors.kcv.kcv_hex);
		expect(cipher.kcv).toBe(vectors.kcv.kcv_hex);
	});

	test("opens and reproduces the encb:v1 text vector", () => {
		expect(cipher.openText(vectors.text.sealed, textContext)).toEqual({
			value: vectors.text.plaintext,
			needsReseal: false,
		});
		const key = b64(vectors.content_key_b64);
		const nonce = fromHex(vectors.text.nonce_hex);
		const expected = chacha20poly1305(
			key,
			nonce,
			fromHex(vectors.aad_hex)
		).encrypt(utf8(vectors.text.plaintext));
		expect(
			`${CONTENT_TEXT_PREFIX}${toBase64(concatBytes(nonce, expected))}`
		).toBe(vectors.text.sealed);
	});

	test("opens the RYU-CB01 bytes vector", () => {
		const opened = cipher.openBytes(
			fromHex(vectors.bytes.sealed_hex),
			textContext
		);
		expect(toHex(opened.value)).toBe(vectors.bytes.plaintext_hex);
		expect(opened.needsReseal).toBe(false);
	});

	test("derives the sub key", () => {
		const sub = cipher.subcipher(vectors.subkey.label);
		const expected = b64(vectors.subkey.key_b64);
		const context = ContentContext.forId("events.record", 1);
		const nonce = new Uint8Array(12).fill(5);
		const sealed = chacha20poly1305(
			expected,
			nonce,
			context.associatedData(vectors.store)
		).encrypt(utf8("segment"));
		const stored = `${CONTENT_TEXT_PREFIX}${toBase64(concatBytes(nonce, sealed))}`;
		expect(sub.openText(stored, context).value).toBe("segment");
		expect(() => cipher.openText(stored, context)).toThrow(ContentSealError);
	});

	test("reproduces the blind index, FTS term and tokenizer vectors", () => {
		const equality = BlindIndex.fromRoot(
			root,
			vectors.store,
			vectors.blind_index.field
		);
		expect(equality.token(vectors.blind_index.normalized)).toBe(
			vectors.blind_index.token
		);
		const fts = BlindIndex.fromRoot(
			root,
			vectors.store,
			vectors.fts_term.field
		);
		expect(fts.termToken(vectors.fts_term.term)).toBe(vectors.fts_term.token);
		const terms = BlindIndex.fromRoot(
			root,
			vectors.tokenizer.store,
			vectors.tokenizer.field
		);
		expect(vectors.tokenizer.field).toBe(TERMS_FIELD);
		for (const sample of vectors.tokenizer.cases) {
			expect(tokenizeTerms(sample.text)).toEqual(sample.terms);
			expect(terms.termTokens(sample.text)).toEqual(sample.tokens);
		}
	});

	test("opens a RYU-SF01 file rebuilt from the vector parameters", () => {
		const spec = vectors.sealed_file;
		const plain = Uint8Array.from(
			{ length: 2500 },
			(_, index) => (index * 31 + 7) % 256
		);
		const context = ContentContext.forId("blob", toHex(sha256(plain)));
		const header = fromHex(spec.header_hex);
		const fileKey = hkdf(
			sha256,
			b64(vectors.content_key_b64),
			fromHex(spec.salt_hex),
			concatBytes(
				utf8("ryu-sealed-file-v1"),
				context.associatedData(vectors.store)
			),
			32
		);
		const chunkSize = 2 ** spec.chunk_log2;
		const parts: Uint8Array[] = [header];
		const chunkCount = Math.ceil(plain.length / chunkSize);
		for (let index = 0; index < chunkCount; index += 1) {
			const nonce = new Uint8Array(12);
			new DataView(nonce.buffer).setBigUint64(3, BigInt(index), false);
			nonce[11] = index === chunkCount - 1 ? 1 : 0;
			parts.push(
				chacha20poly1305(fileKey, nonce, header).encrypt(
					plain.subarray(index * chunkSize, (index + 1) * chunkSize)
				)
			);
		}
		const file = concatBytes(...parts);
		expect(file.length).toBe(spec.file_len);
		expect(toHex(sha256(file))).toBe(spec.file_sha256);
		expect(openFileBytes(file, cipher, context)).toEqual(plain);
		const reader = SealedFileReader.fromBytes(file, cipher, context);
		expect(reader.plaintextLength).toBe(plain.length);
		expect(reader.readRange(1000, 100)).toEqual(plain.subarray(1000, 1100));
	});

	test("reads the RYU-SL01 log vector", () => {
		const spec = vectors.sealed_log;
		const context = spec.context.fields.reduce(
			(acc, [label, value]) => acc.with(label, value),
			new ContentContext(spec.context.purpose)
		);
		const bytes = fromHex(spec.file_hex);
		expect(bytes.length).toBe(spec.file_len);
		const records = readLogBytes(bytes, cipher, context).map((record) =>
			new TextDecoder().decode(record)
		);
		expect(records).toEqual(spec.records_utf8);
	});
});

describe("content cipher", () => {
	const store = ContentCipher.fromRoot(new Uint8Array(32).fill(1), "notes.db");
	const row = (id: string) => ContentContext.forId("notes.body", id);

	test("round-trips text and keeps plaintext out of the stored form", () => {
		const sealed = store.sealText("meeting with Alice", row("n1"));
		expect(sealed.startsWith(CONTENT_TEXT_PREFIX)).toBe(true);
		expect(sealed).not.toContain("Alice");
		expect(store.sealText("meeting with Alice", row("n1"))).not.toBe(sealed);
		expect(store.openText(sealed, row("n1"))).toEqual({
			value: "meeting with Alice",
			needsReseal: false,
		});
	});

	test("a value copied to another row, column or store does not open", () => {
		const sealed = store.sealText("secret", row("n1"));
		expect(() => store.openText(sealed, row("n2"))).toThrow(ContentSealError);
		expect(() =>
			store.openText(sealed, ContentContext.forId("notes.title", "n1"))
		).toThrow(ContentSealError);
		const other = ContentCipher.fromRoot(new Uint8Array(32).fill(1), "mail.db");
		expect(() => other.openText(sealed, row("n1"))).toThrow(ContentSealError);
		const otherRoot = ContentCipher.fromRoot(
			new Uint8Array(32).fill(2),
			"notes.db"
		);
		try {
			otherRoot.openText(sealed, row("n1"));
			throw new Error("expected a refusal");
		} catch (error) {
			expect(isContentSealError(error)).toBe(true);
			expect((error as ContentSealError).code).toBe("does_not_open");
		}
	});

	test("legacy plaintext passes through and asks to be resealed", () => {
		expect(store.openText("plain note", row("n1"))).toEqual({
			value: "plain note",
			needsReseal: true,
		});
		expect(store.openText("", row("n1"))).toEqual({
			value: "",
			needsReseal: false,
		});
		// Another scheme's envelope is someone else's plaintext (an app value).
		expect(store.openText("encp:v1:abc", row("n1")).needsReseal).toBe(true);
	});

	test("unknown envelope versions and malformed envelopes are refused", () => {
		expect(() => store.openText("encb:v2:AAAA", row("n1"))).toThrow(
			ContentSealError
		);
		expect(() => store.openText("encb:v1:not base64!", row("n1"))).toThrow(
			ContentSealError
		);
		expect(() => store.openText("encb:v1:AAAA", row("n1"))).toThrow(
			ContentSealError
		);
		expect(() =>
			store.openBytes(utf8("RYU-CB02 something longer"), row("n1"))
		).toThrow(ContentSealError);
		// "encb:" without a version is ordinary user text.
		expect(store.openText("encb: notes", row("n1")).value).toBe("encb: notes");
	});

	test("seals any string, including one that looks like an envelope", () => {
		const tricky = store.sealText("encb:v1:AAAA", row("n1"));
		expect(store.openText(tricky, row("n1")).value).toBe("encb:v1:AAAA");
	});

	test("bytes round-trip, legacy bytes pass through, Ryu magics are refused", () => {
		const blob = Uint8Array.from([9, 8, 7, 6]);
		const sealed = store.sealBytes(blob, row("b1"));
		expect(ContentCipher.isSealedBytes(sealed)).toBe(true);
		expect(store.openBytes(sealed, row("b1"))).toEqual({
			value: blob,
			needsReseal: false,
		});
		expect(store.openBytes(blob, row("b1")).needsReseal).toBe(true);
		expect(store.openBytes(new Uint8Array(0), row("b1")).needsReseal).toBe(
			false
		);
		for (const magic of ["RYU-CB01", "RYU-SF01", "RYU-SL01"]) {
			try {
				store.sealBytes(utf8(`${magic}payload`), row("b1"));
				throw new Error("expected a refusal");
			} catch (error) {
				expect((error as ContentSealError).code).toBe("already_a_ryu_envelope");
			}
		}
	});

	test("retired roots open with needsReseal and match their KCV", () => {
		const oldRoot = new Uint8Array(32).fill(3);
		const newRoot = new Uint8Array(32).fill(4);
		const old = ContentCipher.fromRoot(oldRoot, "notes.db");
		const sealedOld = old.sealText("kept", row("n1"));
		const current = ContentCipher.fromRoot(
			newRoot,
			"notes.db"
		).withRetiredRoots([oldRoot]);
		expect(current.openText(sealedOld, row("n1"))).toEqual({
			value: "kept",
			needsReseal: true,
		});
		expect(current.matchKcv(kcv(oldRoot))).toBe("retired");
		expect(current.matchKcv(kcv(newRoot))).toBe("current");
		expect(current.matchKcv("00")).toBe("unknown");
		const subOld = old.subcipher("a").subcipher("b");
		const subCurrent = current.subcipher("a").subcipher("b");
		const sealedSub = subOld.sealText("deep", row("n1"));
		expect(subCurrent.openText(sealedSub, row("n1"))).toEqual({
			value: "deep",
			needsReseal: true,
		});
		const lateRetired = ContentCipher.fromRoot(newRoot, "notes.db")
			.subcipher("a")
			.subcipher("b")
			.withRetiredRoots([oldRoot]);
		expect(lateRetired.openText(sealedSub, row("n1")).value).toBe("deep");
	});

	test("rejects bad store names and key lengths", () => {
		expect(() => ContentCipher.fromRoot(new Uint8Array(32), "")).toThrow();
		expect(() => ContentCipher.fromRoot(new Uint8Array(32), "a b")).toThrow();
		expect(() => ContentCipher.fromRoot(new Uint8Array(16), "x.db")).toThrow();
	});

	test("base64 helpers are strict and round-trip", () => {
		for (const length of [0, 1, 2, 3, 4, 5, 31, 32]) {
			const bytes = Uint8Array.from({ length }, (_, index) => index * 7);
			expect(fromBase64(toBase64(bytes))).toEqual(bytes);
			expect(toBase64(bytes)).toBe(Buffer.from(bytes).toString("base64"));
		}
		expect(fromBase64("abc")).toBeNull();
		expect(fromBase64("a=bc")).toBeNull();
		expect(fromBase64("ab!c")).toBeNull();
	});
});
