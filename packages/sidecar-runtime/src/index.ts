/** Shared process-boundary helpers for Ryu TypeScript/Bun sidecars. */

export type SidecarEnvironment = Record<string, string | undefined>;

export class SidecarHostError extends Error {
	constructor(readonly status: number) {
		super(status === 401 || status === 403
			? "Ryu has not approved the required app permissions. Review this app's permissions in Ryu."
			: "The Ryu host service is unavailable. Retry when the node is ready.");
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
		body: unknown,
		userJwt?: string
	): Promise<unknown> => {
		const response = await doFetch(
			`http://127.0.0.1:${options.corePort}${path}`,
			{
				method: "POST",
				redirect: "error",
				signal: AbortSignal.timeout(30_000),
				headers: {
					"content-type": "application/json",
					authorization: `Bearer ${options.token}`,
					"x-ryu-plugin-id": options.pluginId,
					...(userJwt ? { "x-ryu-user-jwt": userJwt } : {}),
				},
				body: JSON.stringify(body),
			}
		);
		if (!response.ok) {
			throw new SidecarHostError(response.status);
		}
		return await response.json();
	};
	return {
		async call(
			method: string,
			args: unknown,
			userJwt?: string
		): Promise<unknown> {
			const result = await post("/api/host/rpc", { method, args }, userJwt);
			if (!result || typeof result !== "object" || !("result" in result)) {
				throw new Error("Invalid Ryu host response");
			}
			return result.result;
		},
		capability(
			capability: string,
			body: unknown,
			userJwt?: string
		): Promise<unknown> {
			if (!/^[a-zA-Z][a-zA-Z0-9_.-]{0,100}$/.test(capability)) {
				throw new Error("Invalid capability name");
			}
			return post(`/api/host/capability/${capability}`, body, userJwt);
		},
	};
}

const PROFILE_PORT_OFFSETS: Readonly<Record<string, number>> = {
	beta: 4000,
	canary: 2000,
	dev: 1000,
	nightly: 3000,
	release: 0,
};

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
	const offset = PROFILE_PORT_OFFSETS[profile];
	if (offset === undefined) {
		throw new Error(`unknown RYU_PROFILE '${profile}'`);
	}
	return basePort + offset;
}

/** Resolve the shared data root with an app-provided standalone fallback. */
export function resolveSidecarDataDir(
	env: SidecarEnvironment,
	fallback: string
): string {
	const configured = env.RYU_DIR?.trim();
	return configured || fallback;
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
