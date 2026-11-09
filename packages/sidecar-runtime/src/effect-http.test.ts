import { describe, expect, test } from "bun:test";
import { Effect, Fiber, Layer } from "effect";
import { HttpRouter, HttpServerResponse } from "effect/http";
import {
	BunListener,
	effectWebHandler,
	runServiceMain,
	scopedResource,
	serveBun,
	webRoute,
} from "./effect-http.ts";

describe("effectWebHandler", () => {
	test("routes Effect and bridged Web handlers through one router", async () => {
		const seen: Request[] = [];
		const routes = HttpRouter.addAll([
			HttpRouter.route("GET", "/health", HttpServerResponse.text("ok")),
			webRoute("POST", "/echo", async (request) => {
				seen.push(request);
				return Response.json({ body: await request.text() }, { status: 201 });
			}),
			webRoute("*", "*", () =>
				Response.json({ error: "not_found" }, { status: 404 })
			),
		]);
		const app = effectWebHandler(routes);
		try {
			const health = await app.fetch(new Request("http://x/health"));
			expect(health.status).toBe(200);
			expect(await health.text()).toBe("ok");

			const original = new Request("http://x/echo", {
				body: "hi",
				headers: { "x-test": "1" },
				method: "POST",
			});
			const echo = await app.fetch(original);
			expect(echo.status).toBe(201);
			expect(await echo.json()).toEqual({ body: "hi" });
			expect(seen[0]).toBe(original);

			const missing = await app.fetch(new Request("http://x/nope"));
			expect(missing.status).toBe(404);
			expect(await missing.json()).toEqual({ error: "not_found" });
		} finally {
			await app.dispose();
		}
	});
});

describe("serveBun and runServiceMain", () => {
	test("serves over Bun and runs finalizers when interrupted", async () => {
		const released: string[] = [];
		const app = effectWebHandler(
			HttpRouter.add("GET", "/ping", HttpServerResponse.text("pong"))
		);
		let url = "";
		const program = Layer.effectDiscard(
			Effect.gen(function* () {
				yield* scopedResource(
					() => "store",
					(name) => {
						released.push(name);
					}
				);
				const server = yield* BunListener;
				url = server.url.toString();
			})
		).pipe(
			Layer.provide(serveBun(app.fetch, { hostname: "127.0.0.1", port: 0 }))
		);
		const handlers = new Map<string, () => void>();
		const signals = {
			exitCode: undefined as number | string | undefined,
			once(event: string, handler: () => void) {
				handlers.set(event, handler);
				return signals;
			},
		};
		const fiber = runServiceMain(program, {
			name: "test",
			signals: signals as never,
		});
		for (let attempt = 0; attempt < 50 && !url; attempt += 1) {
			await Bun.sleep(10);
		}
		const response = await fetch(new URL("/ping", url));
		expect(await response.text()).toBe("pong");
		handlers.get("SIGTERM")?.();
		await Effect.runPromise(Fiber.await(fiber));
		for (let attempt = 0; attempt < 50 && released.length === 0; attempt += 1) {
			await Bun.sleep(10);
		}
		expect(released).toEqual(["store"]);
		expect(signals.exitCode).toBeUndefined();
		await app.dispose();
	});
});

describe("runServiceMain signal handling", () => {
	test("ignores a repeated signal while the finalizers run, then unregisters", async () => {
		const handlers = new Map<string, Set<() => void>>();
		let releaseCount = 0;
		const signals = {
			exitCode: undefined as number | string | undefined,
			on(event: string, handler: () => void) {
				const set = handlers.get(event) ?? new Set();
				set.add(handler);
				handlers.set(event, set);
				return signals;
			},
			once(event: string, handler: () => void) {
				return signals.on(event, handler);
			},
			removeListener(event: string, handler: () => void) {
				handlers.get(event)?.delete(handler);
				return signals;
			},
		};
		const program = Layer.effectDiscard(
			scopedResource(
				() => "store",
				async () => {
					await Bun.sleep(20);
					releaseCount += 1;
				}
			)
		);
		const fiber = runServiceMain(program, {
			name: "test",
			signals: signals as never,
		});
		await Bun.sleep(10);
		for (const handler of handlers.get("SIGINT") ?? []) {
			handler();
		}
		for (const handler of handlers.get("SIGTERM") ?? []) {
			handler();
		}
		await Effect.runPromise(Fiber.await(fiber));
		expect(releaseCount).toBe(1);
		expect(signals.exitCode).toBeUndefined();
		expect(handlers.get("SIGINT")?.size ?? 0).toBe(0);
		expect(handlers.get("SIGTERM")?.size ?? 0).toBe(0);
	});
});
