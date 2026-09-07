/** Shared process-boundary helpers for Ryu TypeScript/Bun sidecars. */

export type SidecarEnvironment = Record<string, string | undefined>;

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
