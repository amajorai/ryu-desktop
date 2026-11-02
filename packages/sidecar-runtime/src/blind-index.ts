/**
 * Blind indexes: keyed, deterministic tokens that find rows by a sealed value
 * without storing the value. Byte-compatible with the Rust
 * `ryu_crypto::BlindIndex` (`crates/core/crypto/src/blind_index.rs`).
 *
 * ```text
 * K_bi  = HKDF-SHA256(root, salt "ryu-blind-index-v1",
 *                     info "ryu-blind-index-v1:" || store || 0x00 || field)
 * token = "bi1:" + hex(HMAC-SHA256(K_bi, normalized value)[..16])   (equality)
 * term  =          hex(HMAC-SHA256(K_bi(field = "terms"), term)[..16]) (full text)
 * ```
 *
 * Leakage (state it in the store's docs row): tokens are deterministic per
 * install, store and field, so they reveal which rows share a value (or a
 * word), how often, and for terms the global term frequencies. Phrase, prefix
 * and NEAR queries are impossible; stopword-only queries return nothing.
 *
 * No `node:` imports: React Native can use it.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { hkdf32, KEY_LENGTH, toHex, utf8 } from "./content.ts";

/** Prefix of an equality token. */
export const BLIND_TOKEN_PREFIX = "bi1:";
/** The field name full-text term indexes use for their key. */
export const TERMS_FIELD = "terms";
/** Fixed stopword list. Editing it changes every term index: rebuild them all. */
export const STOPWORDS: readonly string[] = Object.freeze(
	"a an and are as at be but by for from has have he her his i if in into is it its me my no not of on or our she so that the their them there they this to was we were what when which who will with you your".split(
		" "
	)
);

const BLIND_KDF_SALT = "ryu-blind-index-v1";
const BLIND_KDF_INFO_PREFIX = "ryu-blind-index-v1:";
const MIN_TERM_CHARS = 2;
const MAX_TERM_CHARS = 64;
const STOPWORD_SET = new Set(STOPWORDS);
const NON_TERM_CHARS = /[^\p{L}\p{M}\p{N}]+/u;
const EDGE_WHITESPACE = /^\p{White_Space}+|\p{White_Space}+$/gu;
const ZERO = new Uint8Array([0]);

/** The keyed token generator for one `(store, field)`. */
export class BlindIndex {
	readonly store: string;
	readonly field: string;
	readonly #key: Uint8Array;

	private constructor(key: Uint8Array, store: string, field: string) {
		this.#key = key;
		this.store = store;
		this.field = field;
	}

	/** The blind index of `(store, field)` under the root a store's cipher uses. */
	static fromRoot(root: Uint8Array, store: string, field: string): BlindIndex {
		if (root.length !== KEY_LENGTH) {
			throw new RangeError("a root key must be exactly 32 bytes");
		}
		return new BlindIndex(
			hkdf32(root, BLIND_KDF_SALT, BLIND_KDF_INFO_PREFIX, store, ZERO, field),
			store,
			field
		);
	}

	#mac16(value: string): string {
		return toHex(hmac(sha256, this.#key, utf8(value)).subarray(0, 16));
	}

	/**
	 * The equality token of an ALREADY NORMALIZED value (`"bi1:" + 32 hex`).
	 * Normalize first ({@link casefold}, {@link normalizeEmail}, or the store's
	 * own rule) and use one rule per field.
	 */
	token(normalized: string): string {
		return `${BLIND_TOKEN_PREFIX}${this.#mac16(normalized)}`;
	}

	/** {@link token} of the {@link casefold} of `value`. */
	tokenCasefold(value: string): string {
		return this.token(casefold(value));
	}

	/** The bare 32-hex token of one term (build term indexes with `field = "terms"`). */
	termToken(term: string): string {
		return this.#mac16(term);
	}

	/** {@link tokenizeTerms}, then {@link termToken} each, in term order. */
	termTokens(text: string): string[] {
		return tokenizeTerms(text).map((term) => this.termToken(term));
	}

	/** The term tokens of `text` joined by single spaces (an FTS5 row). */
	ftsDocument(text: string): string {
		return this.termTokens(text).join(" ");
	}

	/**
	 * The FTS5 `MATCH` expression for rows containing every term of `query`, or
	 * `null` when the query has no indexable term (such a query finds nothing).
	 */
	ftsQuery(query: string): string | null {
		const tokens = this.termTokens(query);
		return tokens.length === 0 ? null : tokens.join(" AND ");
	}
}

function nfkcLowerNfkc(value: string): string {
	return value.normalize("NFKC").toLowerCase().normalize("NFKC");
}

/**
 * The case-folded normalization for equality tokens:
 * `NFKC(lowercase(NFKC(trim(value))))`, trimming Unicode White_Space as Rust's
 * `str::trim` does.
 */
export function casefold(value: string): string {
	return nfkcLowerNfkc(value.replace(EDGE_WHITESPACE, ""));
}

/** The normalization for email addresses (the {@link casefold} of the address). */
export function normalizeEmail(value: string): string {
	return casefold(value);
}

function compareUtf8(left: string, right: string): number {
	const a = utf8(left);
	const b = utf8(right);
	const length = Math.min(a.length, b.length);
	for (let index = 0; index < length; index += 1) {
		const difference = (a[index] ?? 0) - (b[index] ?? 0);
		if (difference !== 0) {
			return difference;
		}
	}
	return a.length - b.length;
}

/**
 * The shared term tokenizer: `NFKC(lowercase(NFKC(text)))`, split on every
 * character whose general category is not L*, M* or N*, keep terms of 2 or
 * more code points truncated to 64, drop {@link STOPWORDS}, de-duplicate and
 * sort by UTF-8 bytes.
 */
export function tokenizeTerms(text: string): string[] {
	const terms = new Set<string>();
	for (const raw of nfkcLowerNfkc(text).split(NON_TERM_CHARS)) {
		const chars = Array.from(raw);
		if (chars.length < MIN_TERM_CHARS) {
			continue;
		}
		const term = chars.slice(0, MAX_TERM_CHARS).join("");
		if (STOPWORD_SET.has(term)) {
			continue;
		}
		terms.add(term);
	}
	return [...terms].sort(compareUtf8);
}
