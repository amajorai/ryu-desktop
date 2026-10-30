import { expect, test } from "bun:test";
import { createSidecarHostClient } from "./index.ts";

test("sidecar calls use minted identity and cannot follow credential-bearing redirects", async () => {
	let seen: { url: string; init?: RequestInit } | undefined;
	const fetchImpl = Object.assign(
		async (
			input: Parameters<typeof fetch>[0],
			init?: Parameters<typeof fetch>[1]
		) => {
			seen = { url: String(input), init };
			return Response.json({ result: { matches: [] } });
		},
		{ preconnect: fetch.preconnect }
	);
	const client = createSidecarHostClient({
		corePort: 7980,
		pluginId: "@example/sites",
		token: "extension-only",
		fetchImpl,
	});
	expect(
		await client.call(
			"spaces.search",
			{ space_id: "one", query: "hello" },
			"verified-user-jwt"
		)
	).toEqual({ matches: [] });
	expect(seen?.url).toBe("http://127.0.0.1:7980/api/host/rpc");
	expect(seen?.init?.redirect).toBe("error");
	const headers = new Headers(seen?.init?.headers);
	expect(headers.get("authorization")).toBe("Bearer extension-only");
	expect(headers.get("x-ryu-plugin-id")).toBe("@example/sites");
	expect(headers.get("x-ryu-user-jwt")).toBe("verified-user-jwt");
	expect(() =>
		createSidecarHostClient({ corePort: 70_000, pluginId: "app", token: "x" })
	).toThrow();
	expect(() => client.capability("../admin", {})).toThrow();
});
