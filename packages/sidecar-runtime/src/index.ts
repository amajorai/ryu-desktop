/** Shared process-boundary helpers for Ryu TypeScript/Bun sidecars. */

import { z } from "zod";

const hostJsonSchema = z.json();
/** JSON values carried by Core's extension-host RPC and capability endpoints. */
export type SidecarHostValue = z.infer<typeof hostJsonSchema>;
const hostRpcResponseSchema = z.object({ result: hostJsonSchema });

export type SidecarEnvironment = Record<string, string | undefined>;

export class SidecarHostError extends Error {
	constructor(readonly status: number) {
		super(
			status === 401 || status === 403
				? "Ryu has not approved the required app permissions. Review this app's permissions in Ryu."
				: "The Ryu host service is unavailable. Retry when the node is ready."
		);
	}
}

/** Calls Core's existing extension-host API with only a minted app credential. */
export function createSidecarHostClient(options: {
	corePort: number;
	pluginId: string;
	token: string;
	fetchImpl?: typeof fetch;
}) {
	if (
		!Number.isInteger(options.corePort) ||
		options.corePort < 1 ||
		options.corePort > 65_535
	) {
		throw new Error("Invalid Core port");
	}
	if (!(options.token.trim() && options.pluginId.trim())) {
		throw new Error("Sidecar identity is required");
	}
	const doFetch = options.fetchImpl ?? fetch;
	const post = async (
		path: string,
		body: SidecarHostValue,
		userJwt?: string
	): Promise<SidecarHostValue> => {
		const headers = new Headers({
			"content-type": "application/json",
			authorization: `Bearer ${options.token}`,
			"x-ryu-plugin-id": options.pluginId,
		});
		if (userJwt) {
			headers.set("x-ryu-user-jwt", userJwt);
		}
		const response = await doFetch(
			`http://127.0.0.1:${options.corePort}${path}`,
			{
				method: "POST",
				redirect: "error",
				signal: AbortSignal.timeout(30_000),
				headers,
				body: JSON.stringify(body),
			}
		);
		if (!response.ok) {
			throw new SidecarHostError(response.status);
		}
		return hostJsonSchema.parse(await response.json());
	};
	return {
		async call(
			method: string,
			args: SidecarHostValue,
			userJwt?: string
		): Promise<SidecarHostValue> {
			const result = await post("/api/host/rpc", { method, args }, userJwt);
			const parsed = hostRpcResponseSchema.safeParse(result);
			if (!parsed.success) {
				throw new Error("Invalid Ryu host response");
			}
			return parsed.data.result;
		},
		capability(
			capability: string,
			body: SidecarHostValue,
			userJwt?: string
		): Promise<SidecarHostValue> {
			if (!/^[a-zA-Z][a-zA-Z0-9_.-]{0,100}$/.test(capability)) {
				throw new Error("Invalid capability name");
			}
			return post(`/api/host/capability/${capability}`, body, userJwt);
		},
	};
}

const PROFILE_PORT_OFFSETS = new Map<string, number>(
	Object.entries({
		beta: 4000,
		canary: 2000,
		dev: 1000,
		nightly: 3000,
		release: 0,
	})
);

/** Resolve an explicit or profile-shifted loopback port for a sidecar. */
export function resolveSidecarPort(
	env: SidecarEnvironment,
	explicitName: string,
	basePort: number
): number {
	const explicit = Number.parseInt(env[explicitName] ?? "", 10);
	if (Number.isInteger(explicit) && explicit > 0) {
		return explicit;
	}
	const profile = env.RYU_PROFILE?.trim().toLowerCase() || "release";
	const offset = PROFILE_PORT_OFFSETS.get(profile);
	if (offset === undefined) {
		throw new Error(`unknown RYU_PROFILE '${profile}'`);
	}
	return basePort + offset;
}

/** Join path segments with the separator the root already uses. */
function joinDataPath(root: string, ...segments: string[]): string {
	const separator = root.includes("\\") && !root.includes("/") ? "\\" : "/";
	const trimmed = root.replace(/[\\/]+$/, "");
	return [trimmed, ...segments].join(separator);
}

/** On-disk folder name of a plugin id: `@ryu/meetings` → `@ryu+meetings`. */
export function pluginDataDirName(pluginId: string): string {
	return pluginId.replaceAll("/", "+");
}

/**
 * Resolve the Ryu data dir: `RYU_DIR` (Core injects it into every sidecar), else
 * the profile's default `~/.ryu` / `~/.ryu-<profile>` for a standalone run.
 */
export function resolveRyuDir(env: SidecarEnvironment): string {
	const configured = env.RYU_DIR?.trim();
	if (configured) {
		return configured;
	}
	const home = env.HOME?.trim() || env.USERPROFILE?.trim();
	if (!home) {
		throw new Error("RYU_DIR is not set and no home directory is known");
	}
	const profile = env.RYU_PROFILE?.trim().toLowerCase() || "release";
	if (!PROFILE_PORT_OFFSETS.has(profile)) {
		throw new Error(`unknown RYU_PROFILE '${profile}'`);
	}
	const suffix = profile === "release" ? "" : `-${profile}`;
	return joinDataPath(home, `.ryu${suffix}`);
}

/**
 * Resolve this plugin's own data dir: `RYU_PLUGIN_DATA_DIR` (Core injects it
 * into every plugin sidecar), else `<data dir>/plugin-data/<id with / → +>`.
 */
export function resolvePluginDataDir(
	env: SidecarEnvironment,
	pluginId: string
): string {
	const injected = env.RYU_PLUGIN_DATA_DIR?.trim();
	if (injected) {
		return injected;
	}
	return joinDataPath(
		resolveRyuDir(env),
		"plugin-data",
		pluginDataDirName(pluginId)
	);
}

/** Resolve the Core-minted token, with a sidecar-only standalone override. */
export function resolveSidecarToken(
	env: SidecarEnvironment,
	overrideName?: string
): string | null {
	const raw =
		env.RYU_EXT_TOKEN ?? (overrideName ? env[overrideName] : undefined) ?? "";
	const token = raw.trim();
	return token.length > 0 ? token : null;
}

/**
 * Fail-closed constant-time bearer comparison.
 *
 * The length check is safe because a different byte length is already a
 * definitive mismatch; equal-length values are compared without an early exit.
 */
export function bearerOk(
	authHeader: string | undefined,
	expected: string | null
): boolean {
	if (!expected) {
		return false;
	}
	const presented = authHeader?.startsWith("Bearer ")
		? authHeader.slice("Bearer ".length)
		: null;
	if (!presented) {
		return false;
	}
	const providedBytes = new TextEncoder().encode(presented);
	const expectedBytes = new TextEncoder().encode(expected);
	if (providedBytes.length !== expectedBytes.length) {
		return false;
	}
	let difference = 0;
	for (let index = 0; index < providedBytes.length; index += 1) {
		difference |= (providedBytes[index] ?? 0) ^ (expectedBytes[index] ?? 0);
	}
	return difference === 0;
}
