import { describe, expect, test } from "bun:test";

import {
	BLIND_TOKEN_PREFIX,
	BlindIndex,
	casefold,
	normalizeEmail,
	TERMS_FIELD,
	tokenizeTerms,
} from "./blind-index.ts";

const root = (fill: number) => new Uint8Array(32).fill(fill);

describe("blind index", () => {
	test("tokens are deterministic and separated by root, store and field", () => {
		const index = BlindIndex.fromRoot(root(1), "crm.db", "email");
		const token = index.token("x@y.z");
		expect(token).toBe(index.token("x@y.z"));
		expect(token.startsWith(BLIND_TOKEN_PREFIX)).toBe(true);
		expect(token).toHaveLength(36);
		for (const other of [
			BlindIndex.fromRoot(root(1), "crm.db", "phone"),
			BlindIndex.fromRoot(root(1), "mail.db", "email"),
			BlindIndex.fromRoot(root(2), "crm.db", "email"),
		]) {
			expect(other.token("x@y.z")).not.toBe(token);
		}
		expect(index.tokenCasefold("  X@Y.Z  ")).toBe(token);
		expect(index.token("secret")).not.toContain("secret");
	});

	test("normalizes with NFKC, lowercase and Unicode trimming", () => {
		expect(casefold(" Ｂob ")).toBe("bob");
		expect(normalizeEmail(" Alice@Example.COM ")).toBe("alice@example.com");
	});

	test("the tokenizer drops short terms and stopwords and truncates", () => {
		expect(tokenizeTerms("The cat, the CAT and a dog!")).toEqual([
			"cat",
			"dog",
		]);
		expect(tokenizeTerms("the and of")).toEqual([]);
		expect(tokenizeTerms("x".repeat(100))).toEqual(["x".repeat(64)]);
		expect(tokenizeTerms("snake_case kebab-case")).toEqual([
			"case",
			"kebab",
			"snake",
		]);
		// Code points, not UTF-16 units: one astral letter is one character.
		expect(tokenizeTerms("\u{10428} \u{10428}\u{10428}")).toEqual([
			"\u{10428}\u{10428}",
		]);
	});

	test("terms sort by UTF-8 bytes, not UTF-16 units", () => {
		// U+FA0E (3 UTF-8 bytes) sorts before U+10428 (4 bytes) by bytes, but
		// after it by UTF-16 code units.
		const terms = tokenizeTerms("\u{10428}\u{10428} \ufa0e\ufa0e ab");
		expect(terms).toEqual(["ab", "\ufa0e\ufa0e", "\u{10428}\u{10428}"]);
	});

	test("FTS documents and queries share tokens and never hold the words", () => {
		const index = BlindIndex.fromRoot(root(3), "message-fts.db", TERMS_FIELD);
		const document = index.ftsDocument("Quarterly revenue report");
		const query = index.ftsQuery("REVENUE report");
		expect(query).not.toBeNull();
		for (const token of (query ?? "").split(" AND ")) {
			expect(document.split(" ")).toContain(token);
		}
		expect(document).not.toContain("revenue");
		expect(index.ftsQuery("the of")).toBeNull();
		expect(index.ftsQuery("")).toBeNull();
	});
});
