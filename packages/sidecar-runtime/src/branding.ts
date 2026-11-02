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

/** The visible badge text: one ICU-style message whose `<b>` marks the name. */
export const POWERED_BY_RYU_LABEL = "Powered by <b>Ryu</b>";
/** The badge link's accessible name. */
export const POWERED_BY_RYU_ARIA_LABEL = "Powered by Ryu — make your own";

/**
 * The badge copy in the visitor's language. The serving app resolves the
 * locale (the badge has no localizer of its own) and passes the translated
 * `label` and `ariaLabel` plus the page direction; English is the default.
 */
export interface PoweredByRyuCopy {
	/** The translated accessible name ({@link POWERED_BY_RYU_ARIA_LABEL}). */
	readonly ariaLabel: string;
	/** Text direction of the visitor's language; places the badge at the inline end. */
	readonly dir: "ltr" | "rtl";
	/** The translated visible text ({@link POWERED_BY_RYU_LABEL}). */
	readonly label: string;
}

const ENGLISH_COPY: PoweredByRyuCopy = {
	ariaLabel: POWERED_BY_RYU_ARIA_LABEL,
	dir: "ltr",
	label: POWERED_BY_RYU_LABEL,
};

const HTML_ESCAPES: Readonly<Record<string, string>> = {
	"&": "&amp;",
	"<": "&lt;",
	">": "&gt;",
	'"': "&quot;",
	"'": "&#39;",
};

function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/gu, (char) => HTML_ESCAPES[char] ?? char);
}

/** The escaped visible label, with its one `<b>…</b>` span rendered bold. */
function labelHtml(label: string): string {
	return escapeHtml(label).replace(
		/&lt;b&gt;(.*?)&lt;\/b&gt;/u,
		'<strong style="font-weight:700">$1</strong>'
	);
}

/**
 * The fixed-corner badge as one HTML fragment. `source` names the surface
 * (`sites`, `forms`, …) and must be a short lowercase slug; `copy` is the
 * badge text in the visitor's language (English when omitted).
 */
export function poweredByRyuBadgeHtml(
	source: string,
	copy: PoweredByRyuCopy = ENGLISH_COPY
): string {
	if (!SOURCE_PATTERN.test(source)) {
		throw new Error("Badge source must be a short lowercase slug");
	}
	const href = poweredByRyuHref(source).replaceAll("&", "&amp;");
	const dir = copy.dir === "rtl" ? "rtl" : "ltr";
	return (
		`<a ${BADGE_MARKER}="${source}" href="${href}" target="_blank" rel="noopener" ` +
		`dir="${dir}" aria-label="${escapeHtml(copy.ariaLabel)}" ` +
		'style="position:fixed;inset-inline-end:12px;bottom:12px;z-index:2147483647;display:inline-flex;' +
		"align-items:center;gap:6px;padding-block:6px;padding-inline:8px 10px;border-radius:999px;" +
		"background:rgba(17,17,20,.88);color:#fff;font:500 12px/1 -apple-system,BlinkMacSystemFont," +
		"'Segoe UI',Roboto,sans-serif;text-decoration:none;letter-spacing:0;" +
		'box-shadow:0 1px 2px rgba(0,0,0,.2),0 4px 14px rgba(0,0,0,.18);backdrop-filter:blur(8px)">' +
		'<svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none">' +
		'<path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z" fill="#facc15"/></svg>' +
		`<span>${labelHtml(copy.label)}</span></a>`
	);
}

/**
 * Stamp the badge into a full HTML document, just before `</body>` (or at the end
 * when the author left it out). A document that already carries a badge is
 * returned unchanged.
 */
export function injectPoweredByRyu(
	html: string,
	source: string,
	copy?: PoweredByRyuCopy
): string {
	if (html.includes(BADGE_MARKER)) {
		return html;
	}
	const badge = poweredByRyuBadgeHtml(source, copy);
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
