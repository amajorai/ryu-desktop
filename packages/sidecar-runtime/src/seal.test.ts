import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
	existsSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ContentContext } from "./content.ts";

import {
	COMPAT_HEALTH,
	capturePluginKeys,
	capturePluginSealer,
	isRedactedPlaceholder,
	keepIfRedacted,
	looksSealed,
	PLUGIN_ENVELOPE_PREFIX,
	PluginSealer,
	pluginSealerForProcess,
	pluginSealerFromSubkey,
	REDACTED_SECRET,
	redactSecret,
	SEAL_KEY_ENV,
	SEAL_RETIRED_KEYS_ENV,
	SEAL_SCOPE_ENV,
	SealError,
	STANDALONE_KCV_FILE,
	STANDALONE_ROOT_FILE,
	scrubSealEnv,
} from "./seal.ts";

// Shared with `crates/core/crypto/src/process_keys.rs`: master key [7; 32],
// plugin `@ryu/forms`, value sealed by an independent implementation.
const MASTER_B64 = btoa(String.fromCharCode(...new Array(32).fill(7)));
const FORMS_SUBKEY_B64 = "9mkpBp6aF4R2Ik7g9laiJVWhDFYQUz6E5u9jB+Lak9w=";
const FORMS_SEALED =
	"encp:v1:AAECAwQFBgcICQoL1nNMTWwoK3z4Hm2Ay9qBARr3Zp4hKiyv/g==";

describe("plugin sealing", () => {
	test("opens the cross-language fixture and derives the same subkey", () => {
		const delivered = pluginSealerFromSubkey("@ryu/forms", FORMS_SUBKEY_B64);
		expect(delivered.open(FORMS_SEALED)).toBe("py-sealed");
		const derived = pluginSealerForProcess("@ryu/forms", {
			RYU_MASTER_KEY: MASTER_B64,
		});
		expect(derived.open(FORMS_SEALED)).toBe("py-sealed");
	});

	test("round-trips and keeps the plaintext out of the stored form", () => {
		const sealer = pluginSealerFromSubkey("@ryu/forms", FORMS_SUBKEY_B64);
		const sealed = sealer.seal("smtp-password");
		expect(sealed.startsWith(PLUGIN_ENVELOPE_PREFIX)).toBe(true);
		expect(sealed).not.toContain("smtp-password");
		expect(sealer.seal("smtp-password")).not.toBe(sealed);
		expect(sealer.open(sealed)).toBe("smtp-password");
		expect(looksSealed(sealed)).toBe(true);
	});

	test("reads legacy plaintext and reseals it once", () => {
		const sealer = pluginSealerFromSubkey("@ryu/forms", FORMS_SUBKEY_B64);
		expect(sealer.openTracking("legacy")).toEqual({
			needsReseal: true,
			value: "legacy",
		});
		const resealed = sealer.resealIfPlaintext("legacy");
		expect(resealed).not.toBeNull();
		expect(sealer.open(resealed ?? "")).toBe("legacy");
		expect(sealer.resealIfPlaintext(resealed ?? "")).toBeNull();
	});

	test("opens values sealed under a retired subkey and flags them for reseal", () => {
		const oldKey = new Uint8Array(32).fill(3);
		const newKey = new Uint8Array(32).fill(4);
		const oldSealed = new PluginSealer(oldKey, "@ryu/forms").seal("old-secret");
		const sealer = new PluginSealer(newKey, "@ryu/forms", [oldKey]);
		expect(sealer.open(oldSealed)).toBe("old-secret");
		expect(sealer.openTracking(oldSealed)).toEqual({
			needsReseal: true,
			value: "old-secret",
		});
		const resealed = sealer.resealIfStale(oldSealed);
		expect(resealed).not.toBeNull();
		expect(sealer.openTracking(resealed ?? "")).toEqual({
			needsReseal: false,
			value: "old-secret",
		});
		expect(sealer.resealIfStale(resealed ?? "")).toBeNull();
		// A sealer with no retired keys still refuses the old value.
		expect(() =>
			new PluginSealer(newKey, "@ryu/forms").open(oldSealed)
		).toThrow(SealError);
		expect(
			() => new PluginSealer(newKey, "@ryu/forms", [new Uint8Array(8)])
		).toThrow(SealError);
	});

	test("the delivered retired subkeys reach the process sealer", () => {
		const oldB64 = btoa(String.fromCharCode(...new Array(32).fill(3)));
		const oldSealed = pluginSealerFromSubkey("@ryu/forms", oldB64).seal("kept");
		const env: Record<string, string | undefined> = {
			[SEAL_KEY_ENV]: FORMS_SUBKEY_B64,
			[SEAL_SCOPE_ENV]: "plugin:@ryu/forms",
			[SEAL_RETIRED_KEYS_ENV]: oldB64,
		};
		expect(pluginSealerForProcess("@ryu/forms", env).open(oldSealed)).toBe(
			"kept"
		);
		const keys = capturePluginKeys("@ryu/forms", { ...env });
		expect(keys.sealer?.openTracking(oldSealed)).toEqual({
			needsReseal: true,
			value: "kept",
		});
	});

	test("refuses other plugins' values and other schemes", () => {
		const other = pluginSealerForProcess("@ryu/sites", {
			RYU_MASTER_KEY: MASTER_B64,
		});
		expect(() => other.open(FORMS_SEALED)).toThrow(SealError);
		expect(() => other.open("enc:v1:AAAA")).toThrow(SealError);
	});

	test("checks the delivered scope and fails closed without a key", () => {
		const env = {
			[SEAL_KEY_ENV]: FORMS_SUBKEY_B64,
			[SEAL_SCOPE_ENV]: "plugin:@ryu/forms",
		};
		expect(pluginSealerForProcess("@ryu/forms", env).open(FORMS_SEALED)).toBe(
			"py-sealed"
		);
		expect(() => pluginSealerForProcess("@ryu/sites", env)).toThrow(SealError);
		expect(() => pluginSealerForProcess("@ryu/forms", {})).toThrow(SealError);
		expect(() => new PluginSealer(new Uint8Array(8), "@ryu/forms")).toThrow(
			SealError
		);
	});

	test("capture removes the delivered key from the environment", () => {
		const env: Record<string, string | undefined> = {
			[SEAL_KEY_ENV]: FORMS_SUBKEY_B64,
			[SEAL_SCOPE_ENV]: "plugin:@ryu/forms",
		};
		const sealer = capturePluginSealer("@ryu/forms", env);
		expect(sealer.open(FORMS_SEALED)).toBe("py-sealed");
		expect(env).toEqual({});
	});

	test("scrubs key material from a child environment", () => {
		const child = scrubSealEnv({
			PATH: "/bin",
			RYU_MASTER_KEY: "m",
			[SEAL_KEY_ENV]: "k",
			[SEAL_SCOPE_ENV]: "s",
		});
		expect(child).toEqual({ PATH: "/bin" });
	});
});

describe("redaction", () => {
	test("masks GETs and keeps stored values on placeholder PUTs", () => {
		expect(redactSecret("sk-abc")).toBe(REDACTED_SECRET);
		expect(redactSecret("")).toBe("");
		expect(isRedactedPlaceholder("***")).toBe(true);
		expect(isRedactedPlaceholder(REDACTED_SECRET)).toBe(true);
		expect(isRedactedPlaceholder("sk-*")).toBe(false);
		expect(keepIfRedacted(REDACTED_SECRET, "stored")).toBe("stored");
		expect(keepIfRedacted("sk-new", "stored")).toBe("sk-new");
	});
});

describe("envelopes", () => {
	test("phase-2 content and cloud envelopes count as sealed", () => {
		expect(looksSealed("encb:v1:AAAA")).toBe(true);
		expect(looksSealed("encm:v1:AAAA")).toBe(true);
		expect(looksSealed("encb: notes")).toBe(false);
	});
});

describe("capturePluginKeys", () => {
	let dataDir = "";
	beforeEach(() => {
		dataDir = mkdtempSync(join(tmpdir(), "ryu-plugin-keys-"));
	});
	afterEach(() => {
		rmSync(dataDir, { recursive: true, force: true });
	});

	test("a delivered key seals, derives content ciphers and leaves the env", () => {
		const env: Record<string, string | undefined> = {
			[SEAL_KEY_ENV]: FORMS_SUBKEY_B64,
			[SEAL_SCOPE_ENV]: "plugin:@ryu/forms",
			RYU_PLUGIN_DATA_DIR: dataDir,
		};
		const keys = capturePluginKeys("@ryu/forms", env);
		expect(env[SEAL_KEY_ENV]).toBeUndefined();
		expect(env[SEAL_SCOPE_ENV]).toBeUndefined();
		expect(keys.keyState).toEqual({
			kind: "sealing",
			source: "delivered",
			kcv: keys.kcv ?? "",
		});
		expect(keys.sealer?.open(FORMS_SEALED)).toBe("py-sealed");
		const row = ContentContext.forId("responses.body", "r1");
		const sealed = keys.contentCipher("forms.db").sealText("answer", row);
		// The master key derives the same subkey, so the same store key.
		const viaMaster = capturePluginKeys("@ryu/forms", {
			RYU_MASTER_KEY: MASTER_B64,
			RYU_PLUGIN_DATA_DIR: dataDir,
		});
		expect(viaMaster.kcv).toBe(keys.kcv);
		expect(
			viaMaster.contentCipher("forms.db").openText(sealed, row).value
		).toBe("answer");
		expect(keys.blindIndex("forms.db", "email").token("a@b.c")).toBe(
			viaMaster.blindIndex("forms.db", "email").token("a@b.c")
		);
		expect(keys.storeKeyState(null, false)).toMatchObject({
			state: "record",
			writable: true,
		});
		expect(keys.storeKeyState(keys.kcv, true).state).toBe("current");
		expect(keys.storeKeyState("ffff", true)).toMatchObject({
			state: "mismatch",
			writable: false,
		});
	});

	test("delivered retired subkeys open old stores and mark them retired", () => {
		const oldRoot = new Uint8Array(32).fill(3);
		const oldB64 = btoa(String.fromCharCode(...oldRoot));
		const old = capturePluginKeys("@ryu/forms", {
			[SEAL_KEY_ENV]: oldB64,
			[SEAL_SCOPE_ENV]: "plugin:@ryu/forms",
		});
		const row = ContentContext.forId("responses.body", "r1");
		const sealed = old.contentCipher("forms.db").sealText("answer", row);
		const env: Record<string, string | undefined> = {
			[SEAL_KEY_ENV]: FORMS_SUBKEY_B64,
			[SEAL_SCOPE_ENV]: "plugin:@ryu/forms",
			[SEAL_RETIRED_KEYS_ENV]: oldB64,
		};
		const keys = capturePluginKeys("@ryu/forms", env);
		expect(env[SEAL_RETIRED_KEYS_ENV]).toBeUndefined();
		expect(keys.storeKeyState(old.kcv, true)).toMatchObject({
			state: "retired",
			writable: true,
			sealing: true,
			kcv: keys.kcv ?? "",
			recorded: old.kcv ?? "",
		});
		const opened = keys.contentCipher("forms.db").openText(sealed, row);
		expect(opened.value).toBe("answer");
		expect(opened.needsReseal).toBe(true);
		expect(() =>
			capturePluginKeys("@ryu/forms", {
				[SEAL_KEY_ENV]: FORMS_SUBKEY_B64,
				[SEAL_SCOPE_ENV]: "plugin:@ryu/forms",
				[SEAL_RETIRED_KEYS_ENV]: "not-a-key",
			})
		).toThrow(SealError);
	});

	test("a delivered key for another scope is refused", () => {
		expect(() =>
			capturePluginKeys("@ryu/sites", {
				[SEAL_KEY_ENV]: FORMS_SUBKEY_B64,
				[SEAL_SCOPE_ENV]: "plugin:@ryu/forms",
			})
		).toThrow(SealError);
	});

	test("compat mode under an older Core keeps never-sealed stores plaintext", () => {
		const keys = capturePluginKeys("@ryu/forms", {
			RYU_PLUGIN_DATA_DIR: dataDir,
		});
		expect(keys.canSeal).toBe(false);
		expect(keys.sealer).toBeNull();
		expect(keys.keyState).toEqual({ kind: "compat", health: COMPAT_HEALTH });
		expect(() => keys.contentCipher("forms.db")).toThrow(SealError);
		expect(keys.storeKeyState(null, false)).toMatchObject({
			state: "compat",
			writable: true,
			sealing: false,
		});
		expect(keys.storeKeyState(null, true)).toMatchObject({
			state: "no_key",
			writable: false,
		});
		expect(keys.storeKeyState("abcd", false).writable).toBe(false);
		expect(existsSync(join(dataDir, "secrets"))).toBe(false);
	});

	test("standalone runs generate a 0600 root once and reuse it", () => {
		const first = capturePluginKeys("@ryu/forms", {}, { dataDir });
		const rootPath = join(dataDir, "secrets", STANDALONE_ROOT_FILE);
		expect(first.keyState).toMatchObject({
			kind: "sealing",
			source: "standalone",
		});
		expect(existsSync(rootPath)).toBe(true);
		if (process.platform !== "win32") {
			expect(statSync(rootPath).mode & 0o777).toBe(0o600);
			expect(statSync(join(dataDir, "secrets")).mode & 0o777).toBe(0o700);
		}
		const row = ContentContext.forId("t.c", "1");
		const sealed = first.contentCipher("forms.db").sealText("kept", row);
		const second = capturePluginKeys("@ryu/forms", {}, { dataDir });
		expect(second.kcv).toBe(first.kcv);
		expect(second.contentCipher("forms.db").openText(sealed, row).value).toBe(
			"kept"
		);
		// A later RYU_MASTER_KEY would seal under another key: refused.
		expect(() =>
			capturePluginKeys(
				"@ryu/forms",
				{ RYU_MASTER_KEY: MASTER_B64 },
				{ dataDir }
			)
		).toThrow(SealError);
	});

	test("standalone master-key runs pin the key and refuse a different one", () => {
		const keys = capturePluginKeys(
			"@ryu/forms",
			{ RYU_MASTER_KEY: MASTER_B64 },
			{ dataDir }
		);
		expect(keys.keyState).toMatchObject({ kind: "sealing", source: "master" });
		const pinned = JSON.parse(
			readFileSync(join(dataDir, "secrets", STANDALONE_KCV_FILE), "utf8")
		);
		expect(pinned.kcv).toBe(keys.kcv);
		const otherMaster = btoa(String.fromCharCode(...new Array(32).fill(9)));
		expect(() =>
			capturePluginKeys(
				"@ryu/forms",
				{ RYU_MASTER_KEY: otherMaster },
				{ dataDir }
			)
		).toThrow(SealError);
		// Losing the master key never silently generates a fresh root.
		expect(() => capturePluginKeys("@ryu/forms", {}, { dataDir })).toThrow(
			SealError
		);
		expect(existsSync(join(dataDir, "secrets", STANDALONE_ROOT_FILE))).toBe(
			false
		);
	});

	test("a malformed pin file is refused rather than guessed", () => {
		capturePluginKeys(
			"@ryu/forms",
			{ RYU_MASTER_KEY: MASTER_B64 },
			{ dataDir }
		);
		writeFileSync(join(dataDir, "secrets", STANDALONE_KCV_FILE), "{");
		expect(() =>
			capturePluginKeys(
				"@ryu/forms",
				{ RYU_MASTER_KEY: MASTER_B64 },
				{ dataDir }
			)
		).toThrow(SealError);
	});
});
