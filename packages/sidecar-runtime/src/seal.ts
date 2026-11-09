/**
 * At-rest sealing for TypeScript/Bun app sidecars, compatible byte-for-byte
 * with the Rust `ryu_crypto::PluginCipher` (`encp:v1:` envelope,
 * ChaCha20-Poly1305, `base64(nonce || ciphertext || tag)`).
 *
 * Core derives this app's subkey from its master key and passes it in the
 * sidecar's environment (`RYU_SEAL_KEY` + `RYU_SEAL_SCOPE=plugin:<id>`); it is
 * never written to disk. A sidecar started by hand can instead derive the same
 * subkey from `RYU_MASTER_KEY`. Without either, sealing fails closed: the
 * caller must refuse to store the secret rather than store it in plaintext.
 *
 * Phase 2 adds {@link capturePluginKeys}: the same root also derives the app's
 * content ciphers (`./content`) and blind indexes (`./blind-index`), and the
 * satellite key states (delivered, compat under an older Core, standalone root
 * file) are resolved once at startup.
 *
 * Bun's `node:crypto` has no ChaCha20-Poly1305, so this uses the audited
 * `@noble/ciphers` and `@noble/hashes` implementations of the same primitives.
 */

import {
	chmodSync,
	closeSync,
	existsSync,
	fsyncSync,
	mkdirSync,
	openSync,
	readFileSync,
	renameSync,
	rmSync,
	writeSync,
} from "node:fs";
import { join } from "node:path";

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { BlindIndex } from "./blind-index.ts";
import { ContentCipher, kcv as keyCheckValue } from "./content.ts";
import { resolvePluginDataDir, type SidecarEnvironment } from "./index.ts";

/** Env var carrying the Core-derived subkey (base64, 32 bytes). */
export const SEAL_KEY_ENV = "RYU_SEAL_KEY";
/** Env var naming the subkey's scope (`plugin:<canonical id>`). */
export const SEAL_SCOPE_ENV = "RYU_SEAL_SCOPE";
/**
 * Env var carrying the same scope's subkeys under retired master keys (base64,
 * comma separated). Key-bearing: scrubbed like the others.
 */
export const SEAL_RETIRED_KEYS_ENV = "RYU_SEAL_RETIRED_KEYS";
/** Operator-supplied master key (base64, 32 bytes) for standalone runs. */
export const MASTER_KEY_ENV = "RYU_MASTER_KEY";
/** Every env var that carries key material; strip them before spawning. */
export const SEAL_ENV_VARS = [
	SEAL_KEY_ENV,
	SEAL_SCOPE_ENV,
	SEAL_RETIRED_KEYS_ENV,
	MASTER_KEY_ENV,
] as const;
/** Envelope prefix of values sealed with a plugin subkey. */
export const PLUGIN_ENVELOPE_PREFIX = "encp:v1:";
/** Placeholder an HTTP GET returns for a stored secret. */
export const REDACTED_SECRET = "••••••";

const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const PLUGIN_KDF_SALT = "ryu-plugin-crypto-v1";
const PLUGIN_KDF_INFO_PREFIX = "ryu-plugin-crypto-v1:";
const KNOWN_ENVELOPES = [
	"enc:v1:",
	"enc:v2:",
	"encp:v1:",
	"encc:v1:",
	"encb:v1:",
	"encm:v1:",
];
const PLACEHOLDER_PATTERN = /^[•*]+$/u;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: false });

/** Raised when a value cannot be sealed or opened. Never carries the value. */
export class SealError extends Error {
	override readonly name = "SealError";
}

/** A value opened from storage, plus whether it should be sealed again. */
export interface Opened {
	needsReseal: boolean;
	value: string;
}

function toBase64(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

function fromBase64(encoded: string): Uint8Array {
	let binary: string;
	try {
		binary = atob(encoded.trim());
	} catch {
		throw new SealError("sealed value is not valid base64");
	}
	const bytes = new Uint8Array(binary.length);
	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}
	return bytes;
}

function decodeKey(encoded: string, name: string): Uint8Array {
	const key = fromBase64(encoded);
	if (key.length !== KEY_LENGTH) {
		throw new SealError(`${name} must be base64 of exactly 32 bytes`);
	}
	return key;
}

/** Whether a stored value carries any Ryu envelope. */
export function looksSealed(stored: string): boolean {
	return KNOWN_ENVELOPES.some((prefix) => stored.startsWith(prefix));
}

/** Seals and opens one app's values with its plugin subkey. */
export class PluginSealer {
	readonly #key: Uint8Array;
	readonly #retired: readonly Uint8Array[];
	readonly pluginId: string;

	/**
	 * `retired` are this plugin's subkeys under retired master keys (a backup
	 * import or `keys adopt`). They only open values; sealing always uses the
	 * current subkey.
	 */
	constructor(
		subkey: Uint8Array,
		pluginId: string,
		retired: readonly Uint8Array[] = []
	) {
		if (subkey.length !== KEY_LENGTH) {
			throw new SealError("a plugin subkey must be 32 bytes");
		}
		for (const old of retired) {
			if (old.length !== KEY_LENGTH) {
				throw new SealError("a retired plugin subkey must be 32 bytes");
			}
		}
		const id = pluginId.trim();
		if (!id) {
			throw new SealError("a plugin subkey needs a non-empty plugin id");
		}
		this.#key = subkey;
		this.#retired = retired;
		this.pluginId = id;
	}

	/** Whether a stored value carries the plugin envelope. */
	static isSealed(stored: string): boolean {
		return stored.startsWith(PLUGIN_ENVELOPE_PREFIX);
	}

	/** Seal a plaintext into the `encp:v1:` envelope (fresh nonce each time). */
	seal(plaintext: string): string {
		const nonce = randomBytes(NONCE_LENGTH);
		const sealed = chacha20poly1305(this.#key, nonce).encrypt(
			encoder.encode(plaintext)
		);
		const blob = new Uint8Array(nonce.length + sealed.length);
		blob.set(nonce, 0);
		blob.set(sealed, nonce.length);
		return `${PLUGIN_ENVELOPE_PREFIX}${toBase64(blob)}`;
	}

	/**
	 * Decrypt an `encp:v1:` value with the current subkey, then each retired
	 * one. `retired` reports that an old subkey was needed.
	 */
	#decrypt(stored: string): { plaintext: string; retired: boolean } {
		const blob = fromBase64(stored.slice(PLUGIN_ENVELOPE_PREFIX.length));
		if (blob.length < NONCE_LENGTH) {
			throw new SealError("sealed value is shorter than a nonce");
		}
		const nonce = blob.subarray(0, NONCE_LENGTH);
		const ciphertext = blob.subarray(NONCE_LENGTH);
		const keys = [this.#key, ...this.#retired];
		for (const [index, key] of keys.entries()) {
			try {
				const plaintext = chacha20poly1305(key, nonce).decrypt(ciphertext);
				return { plaintext: decoder.decode(plaintext), retired: index > 0 };
			} catch {
				// Not this key; try the next retired one.
			}
		}
		throw new SealError(
			`value was sealed for a different key than plugin '${this.pluginId}'`
		);
	}

	/**
	 * Open a stored value. `encp:v1:` is decrypted (under the current subkey or
	 * a retired one); another scheme's envelope is refused; anything else is
	 * legacy plaintext, returned verbatim.
	 */
	open(stored: string): string {
		return this.openTracking(stored).value;
	}

	/**
	 * {@link open}, also reporting whether the stored form should be sealed
	 * again: legacy plaintext, or a value that only a retired subkey opened.
	 */
	openTracking(stored: string): Opened {
		if (!PluginSealer.isSealed(stored)) {
			if (looksSealed(stored)) {
				throw new SealError(
					`value is sealed under another key scheme, not plugin '${this.pluginId}''s subkey`
				);
			}
			return { value: stored, needsReseal: stored !== "" };
		}
		const { plaintext, retired } = this.#decrypt(stored);
		return { value: plaintext, needsReseal: retired };
	}

	/**
	 * The sealed form of a value that is legacy plaintext or was sealed under a
	 * retired subkey, or `null` if it is already sealed under the current one.
	 */
	resealIfStale(stored: string): string | null {
		if (stored === "") {
			return null;
		}
		const opened = this.openTracking(stored);
		return opened.needsReseal ? this.seal(opened.value) : null;
	}

	/** The sealed form of a legacy plaintext value, or `null` if already sealed. */
	resealIfPlaintext(stored: string): string | null {
		if (stored === "" || PluginSealer.isSealed(stored)) {
			return null;
		}
		return this.seal(this.open(stored));
	}
}

/** Derive a plugin subkey from the master key, as `ryu_crypto` does. */
function derivePluginKey(master: Uint8Array, pluginId: string): Uint8Array {
	return hkdf(
		sha256,
		master,
		encoder.encode(PLUGIN_KDF_SALT),
		encoder.encode(`${PLUGIN_KDF_INFO_PREFIX}${pluginId}`),
		KEY_LENGTH
	);
}

/** Build a sealer from an already-derived subkey (tests and fixtures). */
export function pluginSealerFromSubkey(
	pluginId: string,
	subkeyBase64: string
): PluginSealer {
	return new PluginSealer(decodeKey(subkeyBase64, "subkey"), pluginId);
}

/**
 * The sealer for this sidecar's own data. Resolution: the subkey Core
 * delivered (its scope must be `plugin:<pluginId>`) → `RYU_MASTER_KEY`. Throws
 * when neither is present: fail closed, never store the secret in plaintext.
 * `pluginId` is the app's canonical id (`@ryu/forms`).
 */
export function pluginSealerForProcess(
	pluginId: string,
	env: SidecarEnvironment
): PluginSealer {
	const id = pluginId.trim();
	const delivered = env[SEAL_KEY_ENV]?.trim();
	if (delivered) {
		const scope = env[SEAL_SCOPE_ENV]?.trim();
		if (scope !== `plugin:${id}`) {
			throw new SealError(
				`${SEAL_KEY_ENV} was delivered for '${scope ?? "no scope"}', not plugin:${id}`
			);
		}
		return new PluginSealer(
			decodeKey(delivered, SEAL_KEY_ENV),
			id,
			decodeRetiredRoots(env[SEAL_RETIRED_KEYS_ENV])
		);
	}
	const master = env[MASTER_KEY_ENV]?.trim();
	if (master) {
		return new PluginSealer(
			derivePluginKey(decodeKey(master, MASTER_KEY_ENV), id),
			id
		);
	}
	throw new SealError(
		`no sealing key for plugin:${id}: start this sidecar from Ryu (which sets ${SEAL_KEY_ENV}) or set ${MASTER_KEY_ENV}`
	);
}

/**
 * {@link pluginSealerForProcess}, then delete the delivered key from `env` so
 * children spawned later do not inherit it. Call once at startup with
 * `process.env` and keep the returned sealer.
 */
export function capturePluginSealer(
	pluginId: string,
	env: SidecarEnvironment
): PluginSealer {
	const sealer = pluginSealerForProcess(pluginId, env);
	delete env[SEAL_KEY_ENV];
	delete env[SEAL_SCOPE_ENV];
	delete env[SEAL_RETIRED_KEYS_ENV];
	return sealer;
}

/** Env var Core sets to the plugin's data dir; its presence means "run by Core". */
export const PLUGIN_DATA_DIR_ENV = "RYU_PLUGIN_DATA_DIR";
/** Standalone root key file, under `<plugin data dir>/secrets/`. */
export const STANDALONE_ROOT_FILE = "standalone-root.key";
/** Key check value of the root a standalone run sealed with. */
export const STANDALONE_KCV_FILE = "standalone-root.kcv.json";
/** Health text while a never-sealed store waits for a Core that delivers keys. */
export const COMPAT_HEALTH = "waiting for a Ryu update";

/** Where a satellite's root key came from. */
export type PluginKeySource = "delivered" | "master" | "standalone";

/**
 * The satellite key state (design section 11) at process level:
 * - `sealing`: a root is held (delivered by Core, `RYU_MASTER_KEY`, or the
 *   standalone root file);
 * - `compat`: run by Core (`RYU_PLUGIN_DATA_DIR` set) but no key delivered: an
 *   older Core, or the app lacks the `crypto:seal` grant. Stores that were
 *   never sealed keep their pre-phase-2 plaintext behaviour; stores that hold
 *   sealed data refuse writes ({@link PluginKeys.storeKeyState}).
 */
export type PluginKeyState =
	| { kind: "sealing"; kcv: string; source: PluginKeySource }
	| { health: typeof COMPAT_HEALTH; kind: "compat" };

/**
 * How one store relates to the process key (design section 11, states 1-4).
 * Persist `kcv` next to the store when `state` is `record`.
 */
export type StoreKeyStatus =
	/** Key held, store never recorded a key: seal/migrate, then record `kcv`. */
	| { kcv: string; sealing: true; state: "record"; writable: true }
	/** Key held and it is the key that sealed the store. */
	| { kcv: string; sealing: true; state: "current"; writable: true }
	/**
	 * Key held; the store was sealed under one of its retired keys (a backup
	 * import or `keys adopt` replaced the folder's key). Values open through
	 * the retired roots: reseal them under `kcv`, then record `kcv` once none
	 * is left unreadable.
	 */
	| {
			kcv: string;
			recorded: string;
			sealing: true;
			state: "retired";
			writable: true;
	  }
	/** Key held, but the store was sealed under another key: refuse writes. */
	| { recorded: string; sealing: false; state: "mismatch"; writable: false }
	/** No key, store never sealed, run by an older Core: plaintext as before. */
	| {
			health: typeof COMPAT_HEALTH;
			sealing: false;
			state: "compat";
			writable: true;
	  }
	/** No key, but the store holds sealed data: refuse writes, keep the data. */
	| { sealing: false; state: "no_key"; writable: false };

/** A satellite's keys, captured once at startup by {@link capturePluginKeys}. */
export interface PluginKeys {
	/** The blind index of `(store, field)`. Throws {@link SealError} in compat mode. */
	blindIndex(store: string, field: string): BlindIndex;
	/** Whether a root is held (false only in compat mode). */
	readonly canSeal: boolean;
	/** The content cipher of `store`. Throws {@link SealError} in compat mode. */
	contentCipher(store: string): ContentCipher;
	/** Key check value of the root (`null` in compat mode). */
	readonly kcv: string | null;
	readonly keyState: PluginKeyState;
	readonly pluginId: string;
	/** The `encp:v1:` secret sealer (`null` in compat mode). */
	readonly sealer: PluginSealer | null;
	/**
	 * Classify a store from its recorded key check value (`null` when none was
	 * recorded) and whether it holds any sealed value.
	 */
	storeKeyState(
		recordedKcv: string | null,
		holdsSealedData: boolean
	): StoreKeyStatus;
}

/** Options of {@link capturePluginKeys}. */
export interface CapturePluginKeysOptions {
	/** The plugin data dir (default: `resolvePluginDataDir(env, pluginId)`). */
	dataDir?: string;
}

const standaloneKcvSchemaVersion = 1;

function writePrivateFile(path: string, contents: string): void {
	const temp = `${path}.${Date.now()}.tmp`;
	const fd = openSync(temp, "wx", 0o600);
	try {
		writeSync(fd, contents);
		fsyncSync(fd);
	} finally {
		closeSync(fd);
	}
	try {
		renameSync(temp, path);
	} catch (error) {
		rmSync(temp, { force: true });
		throw error;
	}
}

function readStandaloneKcv(path: string): string | null {
	if (!existsSync(path)) {
		return null;
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(path, "utf8"));
	} catch {
		throw new SealError(
			`${path} is unreadable; refusing to guess which key sealed this data`
		);
	}
	const recorded =
		typeof parsed === "object" && parsed !== null && "kcv" in parsed
			? parsed.kcv
			: null;
	if (typeof recorded !== "string" || recorded.length === 0) {
		throw new SealError(
			`${path} is malformed; refusing to guess which key sealed this data`
		);
	}
	return recorded;
}

/** Record (or check) the standalone root's KCV; a different later key is refused. */
function pinStandaloneKcv(
	secretsDir: string,
	kcv: string,
	source: PluginKeySource
): void {
	const path = join(secretsDir, STANDALONE_KCV_FILE);
	const recorded = readStandaloneKcv(path);
	if (recorded === null) {
		mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
		writePrivateFile(
			path,
			`${JSON.stringify({ v: standaloneKcvSchemaVersion, kcv, source })}\n`
		);
		return;
	}
	if (recorded !== kcv) {
		throw new SealError(
			`this app's standalone data was sealed under a different key (kcv ${recorded}); restore that ${MASTER_KEY_ENV} or ${STANDALONE_ROOT_FILE} instead of starting with another key`
		);
	}
}

function loadOrCreateStandaloneRoot(secretsDir: string): Uint8Array {
	const path = join(secretsDir, STANDALONE_ROOT_FILE);
	if (existsSync(path)) {
		return decodeKey(readFileSync(path, "utf8"), STANDALONE_ROOT_FILE);
	}
	if (existsSync(join(secretsDir, STANDALONE_KCV_FILE))) {
		throw new SealError(
			`this app's standalone data was sealed under ${MASTER_KEY_ENV}; set it again instead of generating a new key`
		);
	}
	mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
	chmodSync(secretsDir, 0o700);
	const root = randomBytes(KEY_LENGTH);
	const fd = openSync(path, "wx", 0o600);
	try {
		writeSync(fd, `${toBase64(root)}\n`);
		fsyncSync(fd);
	} finally {
		closeSync(fd);
	}
	return root;
}

function compatKeys(pluginId: string): PluginKeys {
	const refuse = (): never => {
		throw new SealError(
			`no sealing key for plugin:${pluginId} (${COMPAT_HEALTH}); stores that were never sealed keep working unsealed`
		);
	};
	return {
		pluginId,
		canSeal: false,
		kcv: null,
		keyState: { kind: "compat", health: COMPAT_HEALTH },
		sealer: null,
		contentCipher: refuse,
		blindIndex: refuse,
		storeKeyState: (recordedKcv, holdsSealedData) =>
			recordedKcv !== null || holdsSealedData
				? { state: "no_key", writable: false, sealing: false }
				: {
						state: "compat",
						writable: true,
						sealing: false,
						health: COMPAT_HEALTH,
					},
	};
}

/** Decode `RYU_SEAL_RETIRED_KEYS` (comma-separated base64 32-byte roots). */
function decodeRetiredRoots(encoded: string | undefined): Uint8Array[] {
	const value = encoded?.trim();
	if (!value) {
		return [];
	}
	return value.split(",").map((item) => decodeKey(item, SEAL_RETIRED_KEYS_ENV));
}

function sealingKeys(
	pluginId: string,
	root: Uint8Array,
	source: PluginKeySource,
	retiredRoots: readonly Uint8Array[] = []
): PluginKeys {
	const kcv = keyCheckValue(root);
	const retiredKcvs = new Set(
		retiredRoots.map((retired) => keyCheckValue(retired))
	);
	retiredKcvs.delete(kcv);
	return {
		pluginId,
		canSeal: true,
		kcv,
		keyState: { kind: "sealing", kcv, source },
		sealer: new PluginSealer(root, pluginId, retiredRoots),
		contentCipher: (store) =>
			retiredRoots.length > 0
				? ContentCipher.fromRoot(root, store).withRetiredRoots(retiredRoots)
				: ContentCipher.fromRoot(root, store),
		blindIndex: (store, field) => BlindIndex.fromRoot(root, store, field),
		storeKeyState: (recordedKcv) => {
			if (recordedKcv === null) {
				return { state: "record", writable: true, sealing: true, kcv };
			}
			if (recordedKcv === kcv) {
				return { state: "current", writable: true, sealing: true, kcv };
			}
			if (retiredKcvs.has(recordedKcv)) {
				return {
					state: "retired",
					writable: true,
					sealing: true,
					kcv,
					recorded: recordedKcv,
				};
			}
			return {
				state: "mismatch",
				writable: false,
				sealing: false,
				recorded: recordedKcv,
			};
		},
	};
}

/**
 * Resolve this satellite's root key ONCE at startup and remove the delivered
 * key from `env` (`RYU_SEAL_KEY`, `RYU_SEAL_SCOPE`) so children do not inherit
 * it. Resolution (design section 11):
 *
 * 1. `RYU_SEAL_KEY` delivered by Core (scope must be `plugin:<pluginId>`), with
 *    `RYU_SEAL_RETIRED_KEYS` (that scope's subkeys under retired master keys);
 * 2. `RYU_MASTER_KEY` → this plugin's subkey (the same key Core would deliver);
 * 3. run by Core (`RYU_PLUGIN_DATA_DIR` set) with no key → compat mode;
 * 4. standalone → `<plugin data dir>/secrets/standalone-root.key` (0600),
 *    generated on first use.
 *
 * Standalone runs pin the root's key check value; a later different
 * `RYU_MASTER_KEY` (or a lost root file) is refused instead of silently
 * sealing new data under another key. `RYU_MASTER_KEY` is left in `env` (as
 * the Rust helper does): pass {@link scrubSealEnv} when spawning children.
 */
export function capturePluginKeys(
	pluginId: string,
	env: SidecarEnvironment,
	options: CapturePluginKeysOptions = {}
): PluginKeys {
	const id = pluginId.trim();
	if (!id) {
		throw new SealError("plugin keys need a non-empty plugin id");
	}
	const delivered = env[SEAL_KEY_ENV]?.trim();
	const scope = env[SEAL_SCOPE_ENV]?.trim();
	const retired = env[SEAL_RETIRED_KEYS_ENV];
	delete env[SEAL_KEY_ENV];
	delete env[SEAL_SCOPE_ENV];
	delete env[SEAL_RETIRED_KEYS_ENV];
	if (delivered) {
		if (scope !== `plugin:${id}`) {
			throw new SealError(
				`${SEAL_KEY_ENV} was delivered for '${scope ?? "no scope"}', not plugin:${id}`
			);
		}
		// The same scope's subkeys under retired master keys (a backup import
		// or `keys adopt`): stores sealed under them still open and are resealed.
		return sealingKeys(
			id,
			decodeKey(delivered, SEAL_KEY_ENV),
			"delivered",
			decodeRetiredRoots(retired)
		);
	}
	const underCore = Boolean(env[PLUGIN_DATA_DIR_ENV]?.trim());
	const secretsDir = join(
		options.dataDir ?? resolvePluginDataDir(env, id),
		"secrets"
	);
	const master = env[MASTER_KEY_ENV]?.trim();
	if (master) {
		const root = derivePluginKey(decodeKey(master, MASTER_KEY_ENV), id);
		if (!underCore) {
			if (existsSync(join(secretsDir, STANDALONE_ROOT_FILE))) {
				throw new SealError(
					`this app's standalone data was sealed under ${STANDALONE_ROOT_FILE}; unset ${MASTER_KEY_ENV} or move that data aside`
				);
			}
			pinStandaloneKcv(secretsDir, keyCheckValue(root), "master");
		}
		return sealingKeys(id, root, "master");
	}
	if (underCore) {
		return compatKeys(id);
	}
	const root = loadOrCreateStandaloneRoot(secretsDir);
	pinStandaloneKcv(secretsDir, keyCheckValue(root), "standalone");
	return sealingKeys(id, root, "standalone");
}

/** A copy of `env` without key-carrying variables, for spawning a child. */
export function scrubSealEnv(env: SidecarEnvironment): SidecarEnvironment {
	const copy: SidecarEnvironment = { ...env };
	for (const name of SEAL_ENV_VARS) {
		delete copy[name];
	}
	return copy;
}

/** Whether a client sent back a placeholder instead of a new secret. */
export function isRedactedPlaceholder(value: string): boolean {
	return PLACEHOLDER_PATTERN.test(value.trim());
}

/** The HTTP GET view of a secret: the placeholder when set, `""` when unset. */
export function redactSecret(value: string | null | undefined): string {
	return value ? REDACTED_SECRET : "";
}

/** Merge a PUT: a placeholder keeps the stored value; anything else replaces it. */
export function keepIfRedacted(
	incoming: string,
	current: string | null | undefined
): string | null {
	if (isRedactedPlaceholder(incoming)) {
		return current ?? null;
	}
	return incoming;
}
