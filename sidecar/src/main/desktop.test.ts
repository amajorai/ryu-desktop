import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
	type DesktopCapabilities,
	type DesktopController,
	type DesktopOptions,
	DesktopSessionManager,
	type InputRequest,
	type InputResult,
	LinuxDesktopController,
} from "./desktop.ts";

const tempRoots: string[] = [];

afterEach(() => {
	for (const root of tempRoots.splice(0)) {
		rmSync(root, { force: true, recursive: true });
	}
});

class FakeController implements DesktopController {
	private readonly capabilitiesValue: DesktopCapabilities;

	constructor(options: DesktopOptions) {
		this.capabilitiesValue = {
			available: true,
			display: `:${options.display ?? 0}`,
			resolution: "1600x1000x24",
			vncPort: options.vncPort,
		};
	}

	capabilities(): DesktopCapabilities {
		return this.capabilitiesValue;
	}

	input(_request: InputRequest): Promise<InputResult> {
		return Promise.resolve({ ok: true });
	}

	screenshot(): Promise<string | null> {
		return Promise.resolve(null);
	}

	start(): Promise<{ ok: boolean; error?: string }> {
		return Promise.resolve({ ok: true });
	}

	teardown(): void {}

	unavailableReason(): string {
		return "fake";
	}
}

function managerFor(root: string): DesktopSessionManager {
	return new DesktopSessionManager(
		{ RYU_DIR: root },
		(options) => new FakeController(options)
	);
}

describe("DesktopSessionManager", () => {
	test("routes each allocated agent to its own persistent display", async () => {
		const root = join(
			process.env.TMPDIR ?? "/tmp",
			`ryu-desktop-session-${crypto.randomUUID()}`
		);
		tempRoots.push(root);
		mkdirSync(root, { recursive: true });
		writeFileSync(
			join(root, "computer-sessions.json"),
			JSON.stringify({
				sessions: {
					"agent-a": { agent_id: "agent-a", display: 99, vnc_port: 5900 },
					"agent-b": { agent_id: "agent-b", display: 100, vnc_port: 5901 },
				},
				version: 1,
			})
		);

		const manager = managerFor(root);
		const first = await manager.controllerFor("agent-a");
		const second = await manager.controllerFor("agent-b");
		const firstAgain = await manager.controllerFor(" agent-a ");

		expect(first.capabilities().display).toBe(":99");
		expect(first.capabilities().vncPort).toBe(5900);
		expect(second.capabilities().display).toBe(":100");
		expect(second.capabilities().vncPort).toBe(5901);
		expect(firstAgain).toBe(first);

		const allocated = await manager.controllerFor("agent-c");
		expect(allocated.capabilities().available).toBe(true);
		expect(allocated.capabilities().display).toBe(":101");
		expect(
			JSON.parse(readFileSync(join(root, "computer-sessions.json"), "utf8"))
				.sessions["agent-c"]
		).toEqual({ agent_id: "agent-c", display: 101, vnc_port: 5902 });
	});

	test("keeps the legacy ryu display when no allocation file exists", async () => {
		const root = join(
			process.env.TMPDIR ?? "/tmp",
			`ryu-desktop-session-${crypto.randomUUID()}`
		);
		tempRoots.push(root);
		const manager = managerFor(root);
		const controller = await manager.controllerFor();
		expect(controller.capabilities().display).toBe(":99");
		expect(controller.capabilities().vncPort).toBe(5900);
	});

	test("rejects malformed explicit Bot ids without reusing the legacy session", async () => {
		const root = join(
			process.env.TMPDIR ?? "/tmp",
			`ryu-desktop-session-${crypto.randomUUID()}`
		);
		tempRoots.push(root);
		const manager = managerFor(root);
		const legacy = await manager.controllerFor();
		expect(legacy.capabilities().available).toBe(true);

		for (const agentId of ["   ", "agent\0id", "a".repeat(129)]) {
			const rejected = await manager.controllerFor(agentId);
			expect(rejected).not.toBe(legacy);
			expect(rejected.capabilities().available).toBe(false);
			expect(rejected.unavailableReason()).toBe(
				"invalid computer session agent id"
			);
		}
		expect(await manager.controllerFor()).toBe(legacy);
	});

	test("allocates and persists a selected Bot without a Core warm-up route", async () => {
		const root = join(
			process.env.TMPDIR ?? "/tmp",
			`ryu-desktop-session-${crypto.randomUUID()}`
		);
		tempRoots.push(root);
		const firstManager = managerFor(root);
		const first = await firstManager.controllerFor("agent-a");
		expect(first.capabilities().display).toBe(":100");

		const secondManager = managerFor(root);
		const restored = await secondManager.controllerFor("agent-a");
		expect(restored.capabilities().display).toBe(":100");
		expect(restored.capabilities().vncPort).toBe(5901);
	});
});

describe("LinuxDesktopController", () => {
	test("reports a missing display server without an uncaught ENOENT", async () => {
		const controller = new LinuxDesktopController({
			starterApps: [],
			windowManager: [],
			xvncBin: "/definitely/missing/ryu-Xvnc",
		});
		const result = await controller.start();
		expect(result.ok).toBe(false);
		expect(result.error).toContain("ENOENT");
		expect(controller.capabilities().available).toBe(false);
		controller.teardown();
	});
});
