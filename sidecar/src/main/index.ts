// Ryu Virtual Desktop sidecar — entrypoint.
//
// A dependency-light Bun/Node process Core spawns as a `local` manifest sidecar
// (`apps-store/desktop/manifest.json`). It:
//   1. brings up the node's virtual desktop (`desktop.ts`): Xvfb + window manager +
//      loopback VNC server,
//   2. serves a loopback HTTP control surface (`control.ts`) — health, capabilities,
//      a screenshot fallback, and a JSON input fallback,
//   3. runs a websockify-style WebSocket bridge at `/ws` (`bridge.ts`): the desktop
//      panel's RFB-over-WebSocket connection (which arrived through Core's
//      `/api/ext/ws/...` tunnel) is pumped byte-for-byte onto the loopback VNC TCP
//      port, making the stream fully interactive (pixels down, mouse/keyboard up).
//
// The display is the one Ghost drives, so agent computer-use and the human panel are
// the same screen. No window, no Electron — the desktop is a headless X session.

import { createWsBridge } from "./bridge.ts";
import {
	resolveControlPort,
	resolveControlToken,
	startControlServer,
} from "./control.ts";
import { createDesktopController } from "./desktop.ts";

function main(): void {
	const port = resolveControlPort();
	const token = resolveControlToken();
	if (!token) {
		// Fail-closed is enforced per-request; warn once so a misconfigured spawn is
		// diagnosable rather than silently rejecting everything.
		console.warn(
			"[ryu-desktop] no RYU_EXT_TOKEN/RYU_DESKTOP_TOKEN set — all control routes will 401"
		);
	}

	const controller = createDesktopController();
	// Bring the desktop up eagerly so the first WS connect (or Ghost's first
	// computer-use call) finds the display already there. Best-effort: a missing
	// toolchain reports unavailable, never crashes the sidecar.
	void controller.start().then((r) => {
		if (!r.ok) {
			console.warn(`[ryu-desktop] display unavailable: ${r.error}`);
		} else {
			console.log(
				`[ryu-desktop] virtual desktop up on ${controller.capabilities().display} ` +
					`(vnc 127.0.0.1:${controller.capabilities().vncPort})`
			);
		}
	});

	const bridge = createWsBridge(controller);
	startControlServer(
		controller,
		token,
		port,
		(req, socket, head) => bridge.handleUpgrade(req, socket, head)
	);

	console.log(`[ryu-desktop] control server on 127.0.0.1:${port}`);
}

main();
