/**
 * "Powered by Ryu" — the badge Ryu stamps on public pages it serves for a member.
 *
 * Every published site, form and board a free member shares is shown to people who
 * have never heard of Ryu, so each visit doubles as an invitation (the same growth
 * loop as the "Sent from Ryu" mail footer). Paid plans drop it.
 *
 * Core decides who is paid, not the app: it injects `RYU_BRANDING_REMOVABLE` into
 * every sidecar from the plan the desktop last reported. The badge stays ON when
 * that is unset or unreadable — a headless node or a missed sync must never
 * unbrand a free member's pages.
 *
 * The markup is self-contained: inline styles only (published pages run under a
 * `style-src 'unsafe-inline'` CSP with no external stylesheets) and no script.
 */

import type { SidecarEnvironment } from "./index.ts";

/** Env var Core injects into every sidecar: `1` when the owner's plan drops the badge. */
export const ENV_BRANDING_REMOVABLE = "RYU_BRANDING_REMOVABLE";

export const POWERED_BY_RYU_URL = "https://ryuhq.com";

/** Whether this sidecar's owner is on a plan that drops the badge. Defaults to false. */
export function brandingRemovable(env: SidecarEnvironment): boolean {
	const raw = env[ENV_BRANDING_REMOVABLE]?.trim().toLowerCase();
	return raw === "1" || raw === "true" || raw === "on" || raw === "yes";
}

/**
 * The badge's link, tagged with the surface that showed it. Public pages are served
 * with `referrer-policy: no-referrer`, so the campaign parameters are the only way
 * a signup can be traced back to the badge that earned it.
 */
export function poweredByRyuHref(source: string): string {
	const url = new URL(POWERED_BY_RYU_URL);
	url.searchParams.set("utm_source", source);
	url.searchParams.set("utm_medium", "powered_by");
	url.searchParams.set("utm_campaign", "badge");
	return url.toString();
}

const SOURCE_PATTERN = /^[a-z0-9-]{1,40}$/;

/** The badge marker, so a page that already carries one is never stamped twice. */
const BADGE_MARKER = "data-ryu-powered-by";

/**
 * The fixed-corner badge as one HTML fragment. `source` names the surface
 * (`sites`, `forms`, …) and must be a short lowercase slug.
 */
export function poweredByRyuBadgeHtml(source: string): string {
	if (!SOURCE_PATTERN.test(source)) {
		throw new Error("Badge source must be a short lowercase slug");
	}
	const href = poweredByRyuHref(source).replaceAll("&", "&amp;");
	return (
		`<a ${BADGE_MARKER}="${source}" href="${href}" target="_blank" rel="noopener" ` +
		'aria-label="Powered by Ryu — make your own" ' +
		'style="position:fixed;right:12px;bottom:12px;z-index:2147483647;display:inline-flex;' +
		"align-items:center;gap:6px;padding:6px 10px 6px 8px;border-radius:999px;" +
		"background:rgba(17,17,20,.88);color:#fff;font:500 12px/1 -apple-system,BlinkMacSystemFont," +
		"'Segoe UI',Roboto,sans-serif;text-decoration:none;letter-spacing:0;" +
		'box-shadow:0 1px 2px rgba(0,0,0,.2),0 4px 14px rgba(0,0,0,.18);backdrop-filter:blur(8px)">' +
		'<svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none">' +
		'<path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z" fill="#facc15"/></svg>' +
		'<span>Powered by <strong style="font-weight:700">Ryu</strong></span></a>'
	);
}

/**
 * Stamp the badge into a full HTML document, just before `</body>` (or at the end
 * when the author left it out). A document that already carries a badge is
 * returned unchanged.
 */
export function injectPoweredByRyu(html: string, source: string): string {
	if (html.includes(BADGE_MARKER)) {
		return html;
	}
	const badge = poweredByRyuBadgeHtml(source);
	// Search the original string: lowercasing can change its length (`İ` becomes
	// two code units), which would shift an index taken from the copy.
	const closing = lastClosingBodyIndex(html);
	return closing === -1
		? `${html}${badge}`
		: `${html.slice(0, closing)}${badge}${html.slice(closing)}`;
}

const CLOSING_BODY = /<\/body\s*>/gi;

/** Index of the last `</body>` in `html`, matched case-insensitively, or -1. */
function lastClosingBodyIndex(html: string): number {
	let last = -1;
	for (const match of html.matchAll(CLOSING_BODY)) {
		last = match.index ?? last;
	}
	return last;
}
