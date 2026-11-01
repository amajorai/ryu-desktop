/**
 * Effect v4 HTTP runtime shared by Ryu's standalone TypeScript services
 * (Box, the Box desktop daemon, Connect, Notify and the Sites sidecar).
 *
 * Every service routes requests through an `effect/http` `HttpRouter`, owns its
 * long-lived resources (stores, pollers, listeners) as scoped `Layer`s, and boots
 * through `runServiceMain`, which interrupts the program on SIGINT/SIGTERM so
 * every finalizer runs. Bun stays the socket listener: the router is turned into a
 * Web handler and handed to `Bun.serve`, so Bun-only features (client IP,
 * WebSocket upgrades, idle timeouts) keep working.
 */
import { Cause, Context, Effect, Exit, Fiber, Layer } from "effect";
import {
	HttpEffect,
	HttpRouter,
	HttpServer,
	type HttpServerError,
	type HttpServerResponse,
} from "effect/http";

/** A plain Web request handler, as the pre-Effect services exposed it. */
export type WebHandler = (request: Request) => Response | Promise<Response>;

/** HTTP methods a route can match; `*` matches every method. */
export type RouteMethod =
	| "*"
	| "GET"
	| "POST"
	| "PUT"
	| "PATCH"
	| "DELETE"
	| "OPTIONS"
	| "HEAD";

/** The Bun server that accepted a request, recorded before routing. */
const serverByRequest = new WeakMap<Request, Bun.Server<unknown>>();

/**
 * The Bun server that accepted `request`, or `undefined` when the request did
 * not arrive through `serveBun` (unit tests that call the handler directly).
 * Use it for `server.requestIP(request)` inside a route.
 */
export function bunServerOf(request: Request): Bun.Server<unknown> | undefined {
	return serverByRequest.get(request);
}

/**
 * Adapts an existing Web handler into an Effect route handler. The original
 * `Request` object reaches `handler` unchanged, so header, body and
 * `bunServerOf` lookups behave exactly as before.
 */
export function fromWeb(
	handler: WebHandler
): Effect.Effect<
	HttpServerResponse.HttpServerResponse,
	HttpServerError.HttpServerError,
	import("effect/http").HttpServerRequest.HttpServerRequest
> {
	return HttpEffect.fromWebHandler(async (request) => await handler(request));
}

/** A route served by an existing Web handler, for `HttpRouter.addAll`. */
export function webRoute(
	method: RouteMethod,
	path: HttpRouter.PathInput,
	handler: WebHandler
): HttpRouter.Route<HttpServerError.HttpServerError> {
	return HttpRouter.route(method, path, fromWeb(handler));
}

/** A Web `fetch` built from an Effect router layer, plus its disposer. */
export interface EffectWebHandler {
	readonly dispose: () => Promise<void>;
	readonly fetch: (request: Request) => Promise<Response>;
}

/**
 * Builds the router layer once and returns a Web `fetch` for it. The router
 * layer must provide every route (use `HttpRouter.addAll` / `HttpRouter.add`).
 * Request logging is left to each service so existing log formats stay stable.
 */
export function effectWebHandler<E>(
	routes: Layer.Layer<never, E, HttpRouter.HttpRouter>
): EffectWebHandler {
	const { handler, dispose } = HttpRouter.toWebHandler(
		routes.pipe(Layer.provide(HttpServer.layerServices)),
		{ disableLogger: true }
	);
	return {
		dispose,
		fetch: (request: Request) => handler(request),
	};
}

/** Options for the Bun listener; `fetch` comes from the Effect router. */
export interface BunListenOptions {
	readonly hostname: string;
	readonly idleTimeout?: number;
	readonly maxRequestBodySize?: number;
	readonly port: number;
	/**
	 * Runs before the router for requests that must stay on Bun's native path,
	 * such as WebSocket upgrades. Return a `Response` to answer directly,
	 * `undefined` after a successful `server.upgrade`, or `null` to route the
	 * request through Effect as usual.
	 */
	readonly preRoute?: (
		request: Request,
		server: Bun.Server<unknown>
	) => Response | undefined | null;
	readonly websocket?: Bun.WebSocketHandler<unknown>;
}

/** The running Bun listener, available to layers that need its URL or port. */
export class BunListener extends Context.Service<
	BunListener,
	Bun.Server<unknown>
>()("@ryu/sidecar-runtime/BunListener") {}

/**
 * A scoped layer that serves `fetch` with `Bun.serve` and stops the listener
 * (closing active connections) when the layer's scope closes.
 */
export function serveBun(
	fetch: (request: Request) => Promise<Response>,
	options: BunListenOptions
): Layer.Layer<BunListener> {
	return Layer.effect(BunListener)(
		Effect.acquireRelease(
			Effect.sync(() => {
				const serveOptions = {
					fetch(request: Request, server: Bun.Server<unknown>) {
						serverByRequest.set(request, server);
						const direct = options.preRoute?.(request, server);
						if (direct !== null && options.preRoute) {
							return direct;
						}
						return fetch(request);
					},
					hostname: options.hostname,
					port: options.port,
					...(options.idleTimeout === undefined
						? {}
						: { idleTimeout: options.idleTimeout }),
					...(options.maxRequestBodySize === undefined
						? {}
						: { maxRequestBodySize: options.maxRequestBodySize }),
					...(options.websocket ? { websocket: options.websocket } : {}),
				};
				return Bun.serve(
					serveOptions as unknown as Bun.Serve.Options<unknown>
				) as Bun.Server<unknown>;
			}),
			(server) => Effect.promise(() => server.stop(true))
		)
	);
}

/**
 * A scoped resource: `acquire` runs when the layer builds and `release` when
 * the program shuts down (signal, failure or interruption).
 */
export function scopedResource<A>(
	acquire: () => A,
	release: (value: A) => void | Promise<void>
): Effect.Effect<A, never, import("effect").Scope.Scope> {
	return Effect.acquireRelease(Effect.sync(acquire), (value) =>
		Effect.promise(async () => {
			await release(value);
		})
	);
}

export interface RunServiceMainOptions {
	/** Log prefix, for example `notify`. */
	readonly name: string;
	/**
	 * Defaults to `process`; injectable for tests. With `on`, the handlers stay
	 * registered for the whole shutdown so a repeated signal is ignored instead
	 * of killing the process before the finalizers finish; a source with only
	 * `once` must handle repeats itself.
	 */
	readonly signals?: Pick<NodeJS.Process, "once" | "exitCode"> &
		Partial<Pick<NodeJS.Process, "on" | "removeListener">>;
}

const SHUTDOWN_SIGNALS = ["SIGINT", "SIGTERM"] as const;

/**
 * Builds `program` and keeps it running until SIGINT or SIGTERM, then
 * interrupts it so every scoped finalizer (listener, stores, pollers) runs.
 * Repeated signals during shutdown are ignored. A build or runtime failure is
 * logged and sets a non-zero exit code.
 */
export function runServiceMain<E>(
	program: Layer.Layer<never, E>,
	options: RunServiceMainOptions
): Fiber.Fiber<never, E> {
	const processLike = options.signals ?? process;
	const fiber = Effect.runFork(Layer.launch(program));
	let shuttingDown = false;
	const shutdown = () => {
		if (shuttingDown) {
			return;
		}
		shuttingDown = true;
		Effect.runFork(Fiber.interrupt(fiber));
	};
	for (const signal of SHUTDOWN_SIGNALS) {
		if (processLike.on) {
			processLike.on(signal, shutdown);
		} else {
			processLike.once(signal, shutdown);
		}
	}
	fiber.addObserver(() => {
		for (const signal of SHUTDOWN_SIGNALS) {
			processLike.removeListener?.(signal, shutdown);
		}
	});
	fiber.addObserver((exit) => {
		if (Exit.isFailure(exit) && !Cause.hasInterruptsOnly(exit.cause)) {
			console.error(
				`[${options.name}] stopped with an error:\n${Cause.pretty(exit.cause)}`
			);
			processLike.exitCode = 1;
		}
	});
	return fiber;
}
