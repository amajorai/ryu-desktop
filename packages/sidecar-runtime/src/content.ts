/**
 * Phase-2 content sealing: user content and PII at rest, bound to where it
 * lives. Byte-compatible with the Rust `ryu_crypto::ContentCipher`
 * (`crates/core/crypto/src/content.rs`); `__fixtures__/content-v1.json` pins
 * every format.
 *
 * ```text
 * content key K_s   = HKDF-SHA256(root, salt "ryu-content-crypto-v1",
 *                                 info "ryu-content-crypto-v1:" || store)
 * sub key     K_sub = HKDF-SHA256(K_s, salt "ryu-content-sub-v1",
 *                                 info "ryu-content-sub-v1:" || label)
 * key check   KCV   = hex(HMAC-SHA256(root, "ryu-kcv-v1")[..16])
 * ```
 *
 * Values are sealed with ChaCha20-Poly1305 under `K_s` and the associated data
 * of a {@link ContentContext} (store, purpose and the stable ids of the record):
 *
 * - TEXT: `"encb:v1:" + base64(nonce12 || ciphertext || tag16)`;
 * - BLOB: `"RYU-CB01" || nonce12 || ciphertext || tag16`.
 *
 * Reads accept legacy plaintext (`needsReseal` is then true), refuse unknown
 * envelope versions and fall back to retired roots on an AEAD failure.
 *
 * This module has NO `node:` imports: the React Native app imports it. It needs
 * `globalThis.crypto.getRandomValues` (install a polyfill such as expo-crypto's
 * on React Native) and `TextEncoder`/`TextDecoder`.
 */

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

/** TEXT envelope prefix for content sealed under a store's content key. */
export const CONTENT_TEXT_PREFIX = "encb:v1:";
/** BLOB envelope magic for content sealed under a store's content key. */
export const CONTENT_BYTES_MAGIC = "RYU-CB01";
/** Magic of a write-once sealed file (`./sealed-file`). */
export const SEALED_FILE_MAGIC = "RYU-SF01";
/** Magic of an append-only sealed log (`./sealed-log`). */
export const SEALED_LOG_MAGIC = "RYU-SL01";
/** Magics no plaintext passed to `sealBytes` may start with. */
export const RYU_MAGICS = [
	CONTENT_BYTES_MAGIC,
	SEALED_FILE_MAGIC,
	SEALED_LOG_MAGIC,
] as const;

/** Length of every root, content and derived key. */
export const KEY_LENGTH = 32;
/** ChaCha20-Poly1305 nonce length. */
export const NONCE_LENGTH = 12;
/** ChaCha20-Poly1305 tag length. */
export const TAG_LENGTH = 16;

const CONTENT_TEXT_FAMILY = "encb:";
const CONTENT_KDF_SALT = "ryu-content-crypto-v1";
const CONTENT_KDF_INFO_PREFIX = "ryu-content-crypto-v1:";
const SUB_KDF_SALT = "ryu-content-sub-v1";
const SUB_KDF_INFO_PREFIX = "ryu-content-sub-v1:";
const CONTENT_AAD_LABEL = "ryu-content-seal-v1";
const KCV_LABEL = "ryu-kcv-v1";
const VERSIONED_FAMILY_PATTERN = /^encb:v\d+:/u;
const RYU_MAGIC_PATTERN = /^RYU-[A-Z]{2}\d{2}$/u;
const MAX_STORE_NAME = 128;

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true });

/** Why a content value was refused. Never carries key or plaintext material. */
export type ContentSealErrorCode =
	/** The value uses a content envelope version this build does not know. */
	| "unknown_version"
	/** Well formed, but opens under no current or retired key for this context. */
	| "does_not_open"
	/** Truncated, not valid base64, or not UTF-8 where text was expected. */
	| "malformed"
	/** `sealBytes` was given bytes that already start with a Ryu magic. */
	| "already_a_ryu_envelope";

const ERROR_MESSAGES: Record<ContentSealErrorCode, string> = {
	unknown_version:
		"sealed content uses an envelope version this build cannot read (written by a newer Ryu?)",
	does_not_open:
		"sealed content does not open for this store, record and key (it was moved, altered, or sealed under another key)",
	malformed: "sealed content has a malformed envelope",
	already_a_ryu_envelope:
		"refusing to seal bytes that already start with a Ryu envelope magic",
};

/** A row that does not open, as opposed to an infrastructure failure. */
export class ContentSealError extends Error {
	override readonly name = "ContentSealError";
	readonly code: ContentSealErrorCode;

	constructor(code: ContentSealErrorCode, detail?: string) {
		super(detail ? `${ERROR_MESSAGES[code]}: ${detail}` : ERROR_MESSAGES[code]);
		this.code = code;
	}
}

/** Whether `error` is a {@link ContentSealError} (count the row, skip it). */
export function isContentSealError(error: unknown): error is ContentSealError {
	return error instanceof ContentSealError;
}

/** A TEXT value opened from storage, plus whether it should be sealed again. */
export interface Opened {
	/** True for legacy plaintext or a retired key: write the value back sealed. */
	needsReseal: boolean;
	value: string;
}

/** A BLOB value opened from storage, plus whether it should be sealed again. */
export interface OpenedBytes {
	needsReseal: boolean;
	value: Uint8Array;
}

/** Encode a string as UTF-8. */
export function utf8(value: string): Uint8Array {
	return encoder.encode(value);
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
	let length = 0;
	for (const part of parts) {
		length += part.length;
	}
	const out = new Uint8Array(length);
	let offset = 0;
	for (const part of parts) {
		out.set(part, offset);
		offset += part.length;
	}
	return out;
}

/** Lower-case hex of `bytes`. */
export function toHex(bytes: Uint8Array): string {
	let out = "";
	for (const byte of bytes) {
		out += byte.toString(16).padStart(2, "0");
	}
	return out;
}

const BASE64_ALPHABET =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_LOOKUP = new Map<string, number>(
	Array.from(BASE64_ALPHABET, (char, index) => [char, index] as const)
);

/** Standard base64 with padding (no `btoa`, which some runtimes lack). */
export function toBase64(bytes: Uint8Array): string {
	let out = "";
	for (let index = 0; index < bytes.length; index += 3) {
		const a = bytes[index] ?? 0;
		const b = bytes[index + 1] ?? 0;
		const c = bytes[index + 2] ?? 0;
		const triple = (a << 16) | (b << 8) | c;
		const remaining = bytes.length - index;
		out += BASE64_ALPHABET[(triple >> 18) & 63];
		out += BASE64_ALPHABET[(triple >> 12) & 63];
		out += remaining > 1 ? BASE64_ALPHABET[(triple >> 6) & 63] : "=";
		out += remaining > 2 ? BASE64_ALPHABET[triple & 63] : "=";
	}
	return out;
}

/** Strict standard base64 with padding; `null` when malformed. */
export function fromBase64(encoded: string): Uint8Array | null {
	const text = encoded.trim();
	if (text.length % 4 !== 0) {
		return null;
	}
	const padding = text.endsWith("==") ? 2 : Number(text.endsWith("="));
	const out = new Uint8Array((text.length / 4) * 3 - padding);
	let written = 0;
	for (let index = 0; index < text.length; index += 4) {
		let triple = 0;
		for (let offset = 0; offset < 4; offset += 1) {
			const char = text[index + offset] ?? "";
			const isPad = char === "=" && index + 4 === text.length;
			const value = isPad ? 0 : BASE64_LOOKUP.get(char);
			if (value === undefined) {
				return null;
			}
			if (isPad && offset < 4 - padding) {
				return null;
			}
			triple = (triple << 6) | value;
		}
		for (let shift = 16; shift >= 0 && written < out.length; shift -= 8) {
			out[written] = (triple >> shift) & 255;
			written += 1;
		}
	}
	return out;
}

/** HKDF-SHA256 with a string salt and a prefix-plus-parts info, 32 bytes out. */
export function hkdf32(
	ikm: Uint8Array,
	salt: Uint8Array | string,
	...infoParts: (Uint8Array | string)[]
): Uint8Array {
	const info = concatBytes(
		...infoParts.map((part) => (typeof part === "string" ? utf8(part) : part))
	);
	return hkdf(
		sha256,
		ikm,
		typeof salt === "string" ? utf8(salt) : salt,
		info,
		KEY_LENGTH
	);
}

function assertKey(key: Uint8Array, what: string): void {
	if (key.length !== KEY_LENGTH) {
		throw new RangeError(`${what} must be exactly 32 bytes`);
	}
}

/**
 * The key check value of a root key: `hex(HMAC-SHA256(root, "ryu-kcv-v1")[..16])`.
 * Identifies a key without revealing it.
 */
export function kcv(root: Uint8Array): string {
	assertKey(root, "a root key");
	return toHex(hmac(sha256, root, utf8(KCV_LABEL)).subarray(0, 16));
}

function lengthPrefixed(part: Uint8Array): Uint8Array {
	const out = new Uint8Array(8 + part.length);
	new DataView(out.buffer).setBigUint64(0, BigInt(part.length), false);
	out.set(part, 8);
	return out;
}

/**
 * Where a sealed value lives: a purpose (`<table>.<column>`, `file`, `blob`,
 * `log`, a record kind) plus labelled stable ids, bound into the AEAD
 * associated data with the store. Immutable: {@link with} returns a copy.
 *
 * Use stable logical ids only (a TEXT/UUID id, an explicit INTEGER PRIMARY
 * KEY, a content address, a meeting id). Never an implicit rowid or a path.
 */
export class ContentContext {
	readonly purpose: string;
	readonly fields: readonly (readonly [string, string])[];

	constructor(
		purpose: string,
		fields: readonly (readonly [string, string])[] = []
	) {
		this.purpose = purpose;
		this.fields = fields;
	}

	/** `new ContentContext(purpose).with("id", id)`. */
	static forId(purpose: string, id: string | number | bigint): ContentContext {
		return new ContentContext(purpose).with("id", String(id));
	}

	/** Bind one more labelled id. Order is significant. */
	with(label: string, value: string | number | bigint): ContentContext {
		return new ContentContext(this.purpose, [
			...this.fields,
			[label, String(value)],
		]);
	}

	/** The canonical associated data: every part `u64 BE length || bytes`. */
	associatedData(store: string): Uint8Array {
		const parts: Uint8Array[] = [
			utf8(CONTENT_AAD_LABEL),
			utf8("store"),
			utf8(store),
			utf8("purpose"),
			utf8(this.purpose),
		];
		for (const [label, value] of this.fields) {
			parts.push(utf8(label), utf8(value));
		}
		return concatBytes(...parts.map(lengthPrefixed));
	}
}

/** How a recorded key check value relates to a {@link ContentCipher}. */
export type KcvMatch = "current" | "retired" | "unknown";

/** One key a cipher can open with (internal to this package). */
export interface ContentKeyCandidate {
	readonly key: Uint8Array;
	readonly retired: boolean;
	readonly rootKcv: string;
}

function storeNameOk(store: string): boolean {
	if (store.length === 0 || store.length > MAX_STORE_NAME) {
		return false;
	}
	for (let index = 0; index < store.length; index += 1) {
		const code = store.charCodeAt(index);
		if (code < 0x21 || code >= 0x7f) {
			return false;
		}
	}
	return true;
}

function deriveContentKey(root: Uint8Array, store: string): Uint8Array {
	return hkdf32(root, CONTENT_KDF_SALT, CONTENT_KDF_INFO_PREFIX, store);
}

function deriveSubKey(contentKey: Uint8Array, label: string): Uint8Array {
	return hkdf32(contentKey, SUB_KDF_SALT, SUB_KDF_INFO_PREFIX, label);
}

const MAGIC_BYTES = RYU_MAGICS.map((magic) => utf8(magic));
const CONTENT_MAGIC_BYTES = utf8(CONTENT_BYTES_MAGIC);

function startsWithBytes(value: Uint8Array, prefix: Uint8Array): boolean {
	if (value.length < prefix.length) {
		return false;
	}
	for (let index = 0; index < prefix.length; index += 1) {
		if (value[index] !== prefix[index]) {
			return false;
		}
	}
	return true;
}

function looksLikeRyuMagic(stored: Uint8Array): boolean {
	if (stored.length < 8) {
		return false;
	}
	return RYU_MAGIC_PATTERN.test(String.fromCharCode(...stored.subarray(0, 8)));
}

/**
 * The content cipher of one store. Carries no accessor for its key material
 * outside this package.
 */
export class ContentCipher {
	readonly store: string;
	readonly label: string | null;
	readonly #current: ContentKeyCandidate;
	readonly #retired: readonly ContentKeyCandidate[];
	/** Each label applied by {@link subcipher}, outermost first. */
	readonly #labelChain: string[] = [];

	private constructor(
		store: string,
		label: string | null,
		current: ContentKeyCandidate,
		retired: readonly ContentKeyCandidate[]
	) {
		this.store = store;
		this.label = label;
		this.#current = current;
		this.#retired = retired;
	}

	/**
	 * The cipher of `store` under an explicit root (a plugin subkey, a device
	 * key). Store names are registered constants and never renamed: the name is
	 * KDF input. Throws on an empty or non-printable-ASCII store name.
	 */
	static fromRoot(root: Uint8Array, store: string): ContentCipher {
		assertKey(root, "a root key");
		if (!storeNameOk(store)) {
			throw new RangeError(
				"content store names are non-empty printable ASCII without spaces"
			);
		}
		return new ContentCipher(
			store,
			null,
			{
				key: deriveContentKey(root, store),
				retired: false,
				rootKcv: kcv(root),
			},
			[]
		);
	}

	/** The same cipher, also able to open values sealed under retired roots. */
	withRetiredRoots(roots: readonly Uint8Array[]): ContentCipher {
		const retired: ContentKeyCandidate[] = [];
		for (const root of roots) {
			const rootKcv = kcv(root);
			if (
				rootKcv === this.#current.rootKcv ||
				retired.some((candidate) => candidate.rootKcv === rootKcv)
			) {
				continue;
			}
			let key = deriveContentKey(root, this.store);
			for (const part of this.#labelChain) {
				key = deriveSubKey(key, part);
			}
			retired.push({ key, retired: true, rootKcv });
		}
		const copy = new ContentCipher(
			this.store,
			this.label,
			this.#current,
			retired
		);
		copy.#labelChain.push(...this.#labelChain);
		return copy;
	}

	/**
	 * A child cipher under `K_sub = HKDF(K_s, "ryu-content-sub-v1", label)`,
	 * for very high-rate stores that bound nonce volume per segment. Same store
	 * name in the AAD; retired keys follow.
	 */
	subcipher(label: string): ContentCipher {
		const derive = (candidate: ContentKeyCandidate): ContentKeyCandidate => ({
			key: deriveSubKey(candidate.key, label),
			retired: candidate.retired,
			rootKcv: candidate.rootKcv,
		});
		const child = new ContentCipher(
			this.store,
			this.label === null ? label : `${this.label}/${label}`,
			derive(this.#current),
			this.#retired.map(derive)
		);
		child.#labelChain.push(...this.#labelChain, label);
		return child;
	}

	/** The key check value of the root this cipher seals under. */
	get kcv(): string {
		return this.#current.rootKcv;
	}

	/** The key check values of the retired roots this cipher can still open. */
	get retiredKcvs(): string[] {
		return this.#retired.map((candidate) => candidate.rootKcv);
	}

	/** Classify a recorded key check value. */
	matchKcv(recorded: string): KcvMatch {
		if (recorded === this.#current.rootKcv) {
			return "current";
		}
		if (this.#retired.some((candidate) => candidate.rootKcv === recorded)) {
			return "retired";
		}
		return "unknown";
	}

	/**
	 * Keys derived from this cipher's current and retired keys with
	 * `HKDF(key, salt, info)`. Internal to this package (sealed files and logs);
	 * never pass the result outside it.
	 */
	deriveCandidates(
		salt: Uint8Array,
		...info: (Uint8Array | string)[]
	): ContentKeyCandidate[] {
		return [this.#current, ...this.#retired].map((candidate) => ({
			key: hkdf32(candidate.key, salt, ...info),
			retired: candidate.retired,
			rootKcv: candidate.rootKcv,
		}));
	}

	#seal(plaintext: Uint8Array, context: ContentContext): Uint8Array {
		const nonce = randomBytes(NONCE_LENGTH);
		const sealed = chacha20poly1305(
			this.#current.key,
			nonce,
			context.associatedData(this.store)
		).encrypt(plaintext);
		return concatBytes(nonce, sealed);
	}

	#open(
		blob: Uint8Array,
		context: ContentContext
	): { plain: Uint8Array; retired: boolean } {
		if (blob.length < NONCE_LENGTH + TAG_LENGTH) {
			throw new ContentSealError("malformed");
		}
		const nonce = blob.subarray(0, NONCE_LENGTH);
		const ciphertext = blob.subarray(NONCE_LENGTH);
		const aad = context.associatedData(this.store);
		for (const candidate of [this.#current, ...this.#retired]) {
			try {
				const plain = chacha20poly1305(candidate.key, nonce, aad).decrypt(
					ciphertext
				);
				return { plain, retired: candidate.retired };
			} catch {
				// Try the next (retired) key.
			}
		}
		throw new ContentSealError("does_not_open");
	}

	/**
	 * Seal a TEXT value into `encb:v1:`. Any string can be sealed (user text may
	 * contain anything, including something that looks like an envelope).
	 */
	sealText(plaintext: string, context: ContentContext): string {
		return `${CONTENT_TEXT_PREFIX}${toBase64(this.#seal(utf8(plaintext), context))}`;
	}

	/**
	 * Open a TEXT value: `encb:v1:` is decrypted (current key, then retired keys,
	 * `needsReseal` on a retired success); `encb:v<n>:` of another version is
	 * refused; anything else (including other Ryu envelopes such as `encp:v1:`)
	 * is legacy plaintext returned verbatim with `needsReseal` (false for "").
	 */
	openText(stored: string, context: ContentContext): Opened {
		if (!stored.startsWith(CONTENT_TEXT_PREFIX)) {
			if (
				stored.startsWith(CONTENT_TEXT_FAMILY) &&
				VERSIONED_FAMILY_PATTERN.test(stored)
			) {
				throw new ContentSealError("unknown_version");
			}
			return { value: stored, needsReseal: stored !== "" };
		}
		const blob = fromBase64(stored.slice(CONTENT_TEXT_PREFIX.length));
		if (blob === null) {
			throw new ContentSealError("malformed");
		}
		const { plain, retired } = this.#open(blob, context);
		let value: string;
		try {
			value = strictDecoder.decode(plain);
		} catch {
			throw new ContentSealError("malformed");
		}
		return { value, needsReseal: retired };
	}

	/**
	 * Seal a BLOB value into `RYU-CB01 || nonce || ct || tag`. Refuses bytes that
	 * already start with a Ryu magic (no legitimate content does).
	 */
	sealBytes(plaintext: Uint8Array, context: ContentContext): Uint8Array {
		if (MAGIC_BYTES.some((magic) => startsWithBytes(plaintext, magic))) {
			throw new ContentSealError("already_a_ryu_envelope");
		}
		return concatBytes(CONTENT_MAGIC_BYTES, this.#seal(plaintext, context));
	}

	/**
	 * Open a BLOB value: `RYU-CB01` is decrypted; another `RYU-XX00` magic is
	 * refused; anything else is legacy plaintext (`needsReseal` unless empty).
	 */
	openBytes(stored: Uint8Array, context: ContentContext): OpenedBytes {
		if (startsWithBytes(stored, CONTENT_MAGIC_BYTES)) {
			const { plain, retired } = this.#open(
				stored.subarray(CONTENT_MAGIC_BYTES.length),
				context
			);
			return { value: plain, needsReseal: retired };
		}
		if (looksLikeRyuMagic(stored)) {
			throw new ContentSealError("unknown_version");
		}
		return { value: stored.slice(), needsReseal: stored.length > 0 };
	}

	/** Whether a TEXT value carries the current content envelope. */
	static isSealedText(stored: string): boolean {
		return stored.startsWith(CONTENT_TEXT_PREFIX);
	}

	/** Whether a BLOB value carries the content envelope. */
	static isSealedBytes(stored: Uint8Array): boolean {
		return startsWithBytes(stored, CONTENT_MAGIC_BYTES);
	}
}

/** Shared helper for the file and log formats: does `bytes` start with `magic`? */
export function hasMagic(bytes: Uint8Array, magic: string): boolean {
	return startsWithBytes(bytes, utf8(magic));
}
