// Manifest contract test for the @ryu/desktop app. Loads the REAL manifest.json and
// asserts the surface the desktop panel depends on: a native dock panel, the loopback
// sidecar port, and the grant-gated control surface declared. This is what keeps the
// manifest and the desktop panel from silently drifting apart.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const manifest = JSON.parse(
	readFileSync(resolve(import.meta.dir, "../../manifest.json"), "utf8")
);

describe("@ryu/desktop manifest", () => {
	test("id + name identify the app", () => {
		expect(manifest.id).toBe("@ryu/desktop");
		expect(manifest.name).toBe("Virtual Desktop");
	});

	test("declares one local sidecar on a distinct loopback port", () => {
		expect(manifest.sidecars).toHaveLength(1);
		const [sidecar] = manifest.sidecars;
		expect(sidecar.name).toBe("desktop");
		expect(sidecar.process.kind).toBe("local");
		expect(sidecar.port).toBe(8015);
		expect(sidecar.health_path).toBe("/health");
	});

	test("declares the websockify + control routes the panel reaches", () => {
		const [sidecar] = manifest.sidecars;
		const paths = sidecar.http.routes.map((r: { path: string }) => r.path);
		for (const expected of ["/", "/health", "/capabilities", "/screen", "/ws", "/input"]) {
			expect(paths).toContain(expected);
		}
		// The `/ws` route is what Core's WebSocket ext-proxy allowlists, so the panel
		// can open `wss://<node>/api/ext/ws/@ryu/desktop/ws`.
		expect(paths).toContain("/ws");
	});

	test("contributes a native Virtual Desktop dock panel", () => {
		const panels = manifest.contributes?.dock_panels ?? [];
		expect(panels).toContainEqual(
			expect.objectContaining({ id: "desktop", panel: "native" })
		);
	});

	test("declares view + control permission levels with implies", () => {
		const levels = manifest.permission_levels ?? [];
		const byId = Object.fromEntries(
			levels.map((l: { id: string }) => [l.id, l])
		);
		expect(byId["desktop.view"]).toBeDefined();
		expect(byId["desktop.control"]).toBeDefined();
		expect(byId["desktop.control"].implies).toContain("desktop.view");
	});
});
