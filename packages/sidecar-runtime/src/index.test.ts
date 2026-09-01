import { describe, expect, it } from "bun:test";
import {
	bearerOk,
	resolveSidecarDataDir,
	resolveSidecarPort,
	resolveSidecarToken,
} from "./index.ts";

describe("sidecar runtime", () => {
	it("resolves the Core token before the standalone override", () => {
		expect(
			resolveSidecarToken(
				{ RYU_EXT_TOKEN: " core ", RYU_BROWSER_TOKEN: "standalone" },
				"RYU_BROWSER_TOKEN"
			)
		).toBe("core");
		expect(
			resolveSidecarToken(
				{ RYU_BROWSER_TOKEN: " standalone " },
				"RYU_BROWSER_TOKEN"
			)
		).toBe("standalone");
		expect(resolveSidecarToken({})).toBeNull();
	});

	it("requires an exact, non-empty bearer", () => {
		expect(bearerOk("Bearer secret", "secret")).toBe(true);
		expect(bearerOk("Bearer secret-x", "secret")).toBe(false);
		expect(bearerOk("secret", "secret")).toBe(false);
		expect(bearerOk(undefined, null)).toBe(false);
	});

	it("keeps profile and data-root resolution in the runtime seam", () => {
		expect(resolveSidecarPort({ RYU_PROFILE: "dev" }, "PORT", 7993)).toBe(8993);
		expect(resolveSidecarPort({ PORT: "8123" }, "PORT", 7993)).toBe(8123);
		expect(resolveSidecarDataDir({ RYU_DIR: " /tmp/ryu " }, "/fallback")).toBe(
			"/tmp/ryu"
		);
		expect(resolveSidecarDataDir({}, "/fallback")).toBe("/fallback");
	});
});
