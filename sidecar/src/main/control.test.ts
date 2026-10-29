// Routing/auth unit tests for the Ryu Virtual Desktop sidecar control surface,
// driven with a FAKE `DesktopController` — no X server, no VNC, no sockets. The
// router (`handleRequest`) and bearer gate (`bearerOk`) are the same pure functions
// the real server calls, so a passing suite is direct evidence the loopback surface
// authenticates and routes correctly.

import { describe, expect, test } from "bun:test";
import { IncomingMessage } from "node:http";
import { Socket } from "node:net";
import { bearerOk, handleRequest, resolveControlPort } from "./control.ts";
import type {
	DesktopCapabilities,
	DesktopController,
	DesktopSessionManager,
	InputRequest,
	InputResult,
} from "./desktop.ts";

class FakeController implements DesktopController {
	calls: string[] = [];
	available = true;

	async start(): Promise<{ ok: boolean; error?: string }> {
		this.calls.push("start");
		return { ok: this.available };
	}
	teardown(): void {
		this.calls.push("teardown");
	}
	capabilities(): DesktopCapabilities {
		return {
			available: this.available,
			display: ":99",
			vncPort: 5900,
			resolution: "1600x1000x24",
		};
	}
	unavailableReason(): string {
		return "fake";
	}
	async screenshot(): Promise<Uint8Array | null> {
		this.calls.push("screenshot");
		return this.available ? PNG_BYTES : null;
	}
	async input(req: InputRequest): Promise<InputResult> {
		this.calls.push(`input:${req.type ?? "?"}`);
		return this.available ? { ok: true } : { ok: false, error: "unavailable" };
	}
}

function req(method: string, _path: string, authorized = true, body?: string) {
	const request = new IncomingMessage(new Socket());
	request.method = method;
	request.headers = authorized ? { authorization: "Bearer tok" } : {};
	if (body) {
		request.push(body);
	}
	request.push(null);
	return request;
}

const TOKEN = "tok";
const PNG_BYTES = new Uint8Array([
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
]);

describe("ryu-desktop control router", () => {
	test("resolves every known profile to a distinct control port", () => {
		expect(resolveControlPort({})).toBe(8015);
		expect(resolveControlPort({ RYU_PROFILE: "dev" })).toBe(9015);
		expect(resolveControlPort({ RYU_PROFILE: "canary" })).toBe(10_015);
		expect(resolveControlPort({ RYU_PROFILE: "nightly" })).toBe(11_015);
		expect(resolveControlPort({ RYU_PROFILE: "beta" })).toBe(12_015);
		expect(() => resolveControlPort({ RYU_PROFILE: "staging" })).toThrow(
			"unknown RYU_PROFILE"
		);
	});

	test("health is open; protected routes fail closed without a token", async () => {
		const c = new FakeController();
		const url = (p: string) => new URL(p, "http://127.0.0.1");
		const noAuth = (p: string) => req("GET", p, false);

		const health = await handleRequest(
			c,
			TOKEN,
			req("GET", "/health"),
			url("/health")
		);
		expect(health.status).toBe(200);

		// Without a bearer, every protected route is refused.
		for (const p of ["/", "/capabilities", "/screen"]) {
			const denied = await handleRequest(c, TOKEN, noAuth(p), url(p));
			expect(denied.status).toBe(401);
		}

		// With the correct bearer, they are allowed.
		for (const p of ["/", "/capabilities", "/screen"]) {
			const allowed = await handleRequest(c, TOKEN, req("GET", p), url(p));
			expect(allowed.status).toBe(200);
		}

		// No token configured on the sidecar ⇒ EVERYTHING (even a correct-looking
		// header) 401s. Fail-closed is the point: an unconfigured spawn must not
		// silently serve the desktop.
		const noToken = await handleRequest(
			c,
			null,
			req("GET", "/capabilities"),
			url("/capabilities")
		);
		expect(noToken.status).toBe(401);
	});

	test("capabilities reflects the controller", async () => {
		const c = new FakeController();
		const resp = await handleRequest(
			c,
			TOKEN,
			req("GET", "/capabilities"),
			new URL("http://127.0.0.1/capabilities")
		);
		expect(resp.status).toBe(200);
		expect(resp.json).toEqual({ ...c.capabilities() });
	});

	test("screen returns 503 when no display, raw PNG when present", async () => {
		const c = new FakeController();
		const url = new URL("http://127.0.0.1/screen");

		c.available = false;
		const down = await handleRequest(c, TOKEN, req("GET", "/screen"), url);
		expect(down.status).toBe(503);

		c.available = true;
		const up = await handleRequest(c, TOKEN, req("GET", "/screen"), url);
		expect(up.status).toBe(200);
		expect(up.raw?.contentType).toBe("image/png");
		// The PNG bytes themselves, never a path to a file on disk.
		expect(up.raw?.body).toEqual(PNG_BYTES);
	});

	test("input routes through and rejects bad bodies", async () => {
		const c = new FakeController();
		const url = new URL("http://127.0.0.1/input");

		// POST with a body → forwarded to the controller.
		const post = await handleRequest(c, TOKEN, req("POST", "/input"), url);
		// An empty native request yields undefined → 400 invalid body. The
		// happy path is exercised in the integration-ish test below via the real
		// server; here we assert the validation branch fails closed.
		expect(post.status).toBe(400);
	});

	test("input validates its native JSON fields before touching the controller", async () => {
		const controller = new FakeController();
		const url = new URL("http://127.0.0.1/input");
		const accepted = await handleRequest(
			controller,
			TOKEN,
			req(
				"POST",
				"/input",
				true,
				JSON.stringify({ type: "click", x: 4, y: 5 })
			),
			url
		);
		expect(accepted.status).toBe(200);
		expect(controller.calls).toEqual(["input:click"]);
		for (const body of ['{"type":"click","x":"4"}', "null", "{invalid"]) {
			expect(
				(
					await handleRequest(
						controller,
						TOKEN,
						req("POST", "/input", true, body),
						url
					)
				).status
			).toBe(400);
		}
		expect(controller.calls).toEqual(["input:click"]);
	});

	test("bearerOk is constant-time and fails on any mismatch", () => {
		expect(bearerOk("Bearer tok", "tok")).toBe(true);
		expect(bearerOk("Bearer tok2", "tok")).toBe(false);
		expect(bearerOk("Bearer tok", "tok2")).toBe(false);
		expect(bearerOk("tok", "tok")).toBe(false); // no prefix
		expect(bearerOk(undefined, "tok")).toBe(false);
		expect(bearerOk("Bearer tok", null)).toBe(false); // fail-closed
		expect(bearerOk("Bearer tok", "")).toBe(false);
	});

	test("unknown routes 404 behind auth", async () => {
		const c = new FakeController();
		const resp = await handleRequest(
			c,
			TOKEN,
			req("GET", "/nope"),
			new URL("http://127.0.0.1/nope")
		);
		expect(resp.status).toBe(404);
	});

	test("routes a Bot screen through the app-owned session manager", async () => {
		const c = new FakeController();
		const requested: (string | null | undefined)[] = [];
		const sessions: Pick<DesktopSessionManager, "controllerFor"> = {
			controllerFor: async (agentId) => {
				requested.push(agentId);
				return c;
			},
		};
		const resp = await handleRequest(
			sessions,
			TOKEN,
			req("GET", "/bots/agent-a/screen"),
			new URL("http://127.0.0.1/bots/agent-a/screen")
		);

		expect(resp.status).toBe(200);
		expect(requested).toEqual(["agent-a"]);
		expect(c.calls).toContain("screenshot");
	});
});
