// Loopback control server for the Ryu Virtual Desktop sidecar.
//
// Core spawns this as a `local` manifest sidecar (`apps-store/desktop/manifest.json`,
// `SidecarProcess::Local`). It exposes a small HTTP control surface bound to loopback
// so Core — and, through Core's generic WebSocket ext-proxy (`/api/ext/ws/...`), the
// desktop Virtual Desktop panel and Ghost — can reach the virtual display.
//
// What the sidecar owns:
//   - the VIRTUAL DISPLAY lifecycle (`desktop.ts`): Xvfb + a window manager + a VNC
//     server on loopback, so the node has a real desktop even with no physical
//     display. Core routes the selected Bot to its own display; Ghost receives that
//     same `DISPLAY` through the MCP env allowlist, so agents and the human
//     see/control one screen.
//   - the WEBSOCKET BRIDGE (`/ws`): a websockify-style pump between the panel's
//     RFB-over-WebSocket connection (arriving through Core) and the local VNC server
//     over TCP. This is what makes the stream interactive — noVNC sends mouse/keyboard
//     down the same socket the pixels come back on.
//   - `/screen`: a fallback single PNG screenshot (for surfaces without a WS client),
//     and `/input`: a JSON click/type fallback that injects into the display.
//
// SECURITY
// --------
// * Bound to 127.0.0.1 only.
// * Every route except `GET /health` requires `Authorization: Bearer <token>` — the
//   per-plugin secret Core injects at spawn (`RYU_EXT_TOKEN`); `RYU_DESKTOP_TOKEN`
//   overrides for standalone/dev. Neither set ⇒ FAIL-CLOSED (all protected routes 401).
//   The WebSocket bridge is also bearer-gated at upgrade time, so a remote caller can
//   only ever reach it through Core's authenticated `/api/ext/ws` tunnel.
// * Input control (typing on the desktop) is the whole point of the panel, but it is
//   gated on the same loopback bearer: nothing reaches the display except through
//   Core, and Core's per-route permission model decides who may (the `desktop.control`
//   level in the manifest).

import { createServer, type Server } from "node:http";
import {
	resolveSidecarPort,
	resolveSidecarToken,
	bearerOk as sharedBearerOk,
} from "@ryu/sidecar-runtime";
import type { DesktopController, DesktopSessionManager } from "./desktop.ts";

/** Default loopback port. Core (7980), browser (7993), simulator (7994), mail (7996). */
const DESKTOP_CONTROL_BASE_PORT = 8015;
const PACKAGE_VERSION = "1.0.0";

export function resolveControlPort(
	env: NodeJS.ProcessEnv = process.env
): number {
	return resolveSidecarPort(env, "RYU_DESKTOP_PORT", DESKTOP_CONTROL_BASE_PORT);
}

export function resolveControlToken(
	env: NodeJS.ProcessEnv = process.env
): string | null {
	return resolveSidecarToken(env, "RYU_DESKTOP_TOKEN");
}

/** Constant-time bearer check. `null`/empty `expected` ⇒ fail-closed (reject all). */
export function bearerOk(
	authHeader: string | undefined,
	expected: string | null
): boolean {
	return sharedBearerOk(authHeader, expected);
}

export interface ControlResponse {
	json?: unknown;
	raw?: { body: string; contentType: string };
	status: number;
}

export type DesktopControllerSource =
	| DesktopController
	| Pick<DesktopSessionManager, "controllerFor">;

function isSessionManager(
	source: DesktopControllerSource
): source is Pick<DesktopSessionManager, "controllerFor"> {
	return "controllerFor" in source;
}

function routeForSession(
	pathname: string
): { agentId?: string; path: string } | null {
	if (!pathname.startsWith("/bots/")) {
		return { path: pathname };
	}
	const match = pathname.match(/^\/bots\/([^/]+)(\/.*)?$/);
	if (!match) {
		return null;
	}
	try {
		const agentId = decodeURIComponent(match[1] ?? "").trim();
		return agentId ? { agentId, path: match[2] ?? "/" } : null;
	} catch {
		return null;
	}
}

const ok = (json?: unknown): ControlResponse => ({
	json: json ?? { ok: true },
	status: 200,
});
const notFound = (): ControlResponse => ({
	json: { error: "not found" },
	status: 404,
});

function readJsonBody(
	req: import("node:http").IncomingMessage
): Promise<unknown> {
	return new Promise((resolve) => {
		// Synthetic requests in tests (or a request with no body plumbing) resolve
		// immediately; the real server always supplies a full IncomingMessage.
		if (typeof req.on !== "function" || typeof req.setEncoding !== "function") {
			resolve(undefined);
			return;
		}
		let body = "";
		req.setEncoding("utf8");
		req.on("data", (chunk) => {
			body += chunk;
			if (body.length > 1_000_000) {
				req.destroy();
			}
		});
		req.on("end", () => {
			if (!body) {
				resolve(undefined);
				return;
			}
			try {
				resolve(JSON.parse(body));
			} catch {
				resolve(undefined);
			}
		});
	});
}

/**
 * Pure request router over an injected `DesktopController` — unit-tested with a fake
 * (no X server, no VNC, no sockets). Returns a `ControlResponse` describing what the
 * caller should receive; the server wrapper applies it.
 */
export async function handleRequest(
	source: DesktopControllerSource,
	token: string | null,
	req: import("node:http").IncomingMessage,
	url: URL
): Promise<ControlResponse> {
	const route = routeForSession(url.pathname);
	if (!route) {
		return { json: { error: "invalid bot session path" }, status: 400 };
	}
	const { agentId, path } = route;

	if (req.method === "GET" && path === "/health") {
		return ok({ status: "ok", version: PACKAGE_VERSION });
	}

	// Everything else is bearer-gated (fail-closed when no token is configured).
	const authed = bearerOk(req.headers.authorization, token);
	if (!authed) {
		return { json: { error: "unauthorized" }, status: 401 };
	}

	const controller = isSessionManager(source)
		? await source.controllerFor(agentId)
		: source;

	if (req.method === "GET" && path === "/") {
		return ok({
			name: "ryu-desktop",
			version: PACKAGE_VERSION,
			routes: ["/health", "/capabilities", "/screen", "/ws", "/input"],
		});
	}

	if (req.method === "GET" && path === "/capabilities") {
		return ok(controller.capabilities());
	}

	if (req.method === "GET" && path === "/screen") {
		const shot = await controller.screenshot();
		if (!shot) {
			return {
				json: { error: "no display", reason: controller.unavailableReason() },
				status: 503,
			};
		}
		return {
			raw: { body: shot, contentType: "image/png" },
			status: 200,
		};
	}

	if (req.method === "POST" && path === "/input") {
		const body = (await readJsonBody(req)) as
			| {
					type?: string;
					x?: number;
					y?: number;
					text?: string;
					key?: string;
					buttons?: number;
			  }
			| undefined;
		if (!body || typeof body !== "object") {
			return { json: { error: "invalid body" }, status: 400 };
		}
		const result = await controller.input(body);
		return result.ok
			? ok(result)
			: { json: { error: result.error ?? "input failed" }, status: 400 };
	}

	return notFound();
}

/** Whether a WS upgrade to `/ws` is allowed given the request headers + token. */
export function wsAllowed(
	headers: import("node:http").IncomingHttpHeaders,
	token: string | null
): boolean {
	return bearerOk(String(headers.authorization ?? ""), token);
}

/** Start the loopback HTTP control server. Returns the running `Server`. */
export function startControlServer(
	source: DesktopControllerSource,
	token: string | null,
	port: number,
	onUpgrade: (
		req: import("node:http").IncomingMessage,
		socket: import("node:net").Socket,
		head: Buffer
	) => void | Promise<void>
): Server {
	const server = createServer(async (req, res) => {
		const url = new URL(req.url ?? "/", "http://127.0.0.1");
		try {
			const resp = await handleRequest(source, token, req, url);
			res.statusCode = resp.status;
			if (resp.raw) {
				res.setHeader("Content-Type", resp.raw.contentType);
				res.end(resp.raw.body);
				return;
			}
			res.setHeader("Content-Type", "application/json");
			res.end(JSON.stringify(resp.json ?? {}));
		} catch (error) {
			res.statusCode = 500;
			res.setHeader("Content-Type", "application/json");
			res.end(JSON.stringify({ error: String(error) }));
		}
	});

	server.on("upgrade", (req, socket, head) => {
		const url = new URL(req.url ?? "/", "http://127.0.0.1");
		if (
			(url.pathname === "/ws" || url.pathname.startsWith("/bots/")) &&
			wsAllowed(req.headers, token)
		) {
			Promise.resolve(
				onUpgrade(req, socket as import("node:net").Socket, head)
			).catch(() => socket.end());
			return;
		}
		// Refuse the upgrade with a well-formed HTTP 401 so the WS client sees an
		// authentic failure (not a mystifying connection reset). Never forwards an
		// unauthenticated socket to the bridge.
		socket.write(
			"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n" +
				"Content-Length: 27\r\nConnection: close\r\n\r\n" +
				'{"error":"unauthorized"}'
		);
		socket.end();
	});

	server.listen(port, "127.0.0.1");
	return server;
}
