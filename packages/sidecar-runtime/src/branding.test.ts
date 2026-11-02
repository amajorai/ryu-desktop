import { describe, expect, test } from "bun:test";
import {
	brandingRemovable,
	injectPoweredByRyu,
	poweredByRyuBadgeHtml,
	poweredByRyuHref,
} from "./branding.ts";

describe("brandingRemovable", () => {
	test("stays branded unless Core says the plan drops the badge", () => {
		expect(brandingRemovable({})).toBe(false);
		expect(brandingRemovable({ RYU_BRANDING_REMOVABLE: "" })).toBe(false);
		expect(brandingRemovable({ RYU_BRANDING_REMOVABLE: "0" })).toBe(false);
		expect(brandingRemovable({ RYU_BRANDING_REMOVABLE: "maybe" })).toBe(false);
		expect(brandingRemovable({ RYU_BRANDING_REMOVABLE: "1" })).toBe(true);
		expect(brandingRemovable({ RYU_BRANDING_REMOVABLE: " TRUE " })).toBe(true);
	});
});

describe("poweredByRyuHref", () => {
	test("tags the link with the surface that showed it", () => {
		const url = new URL(poweredByRyuHref("sites"));
		expect(url.origin).toBe("https://ryuhq.com");
		expect(url.searchParams.get("utm_source")).toBe("sites");
		expect(url.searchParams.get("utm_medium")).toBe("powered_by");
	});
});

describe("injectPoweredByRyu", () => {
	test("lands before </body> even when lowercasing would change the text's length", () => {
		const page = "<html><body><p>İİİ</p></BODY ></html>";
		const out = injectPoweredByRyu(page, "sites");
		expect(out.startsWith("<html><body><p>İİİ</p><a")).toBe(true);
		expect(out.endsWith("</BODY ></html>")).toBe(true);
	});

	test("inserts the badge before the closing body tag", () => {
		const html = injectPoweredByRyu(
			"<html><body><h1>Hi</h1></BODY></html>",
			"sites"
		);
		expect(html.indexOf("data-ryu-powered-by")).toBeLessThan(
			html.indexOf("</BODY>")
		);
		expect(html).toContain("Powered by");
	});

	test("appends to a document without a body tag", () => {
		expect(injectPoweredByRyu("<p>bare</p>", "forms")).toStartWith(
			"<p>bare</p><a data-ryu-powered-by"
		);
	});

	test("never stamps a page twice", () => {
		const once = injectPoweredByRyu("<body></body>", "sites");
		expect(injectPoweredByRyu(once, "sites")).toBe(once);
	});

	test("rejects a source that could break out of the attribute", () => {
		expect(() => poweredByRyuBadgeHtml('x" onclick="')).toThrow();
	});

	test("escapes query separators in the href attribute", () => {
		expect(poweredByRyuBadgeHtml("sites")).toContain("&amp;utm_medium");
	});
});

describe("poweredByRyuBadgeHtml copy", () => {
	test("renders English by default with the name in bold", () => {
		const badge = poweredByRyuBadgeHtml("sites");
		expect(badge).toContain(
			'<span>Powered by <strong style="font-weight:700">Ryu</strong></span>'
		);
		expect(badge).toContain('aria-label="Powered by Ryu — make your own"');
		expect(badge).toContain('dir="ltr"');
		expect(badge).toContain("inset-inline-end:12px");
		expect(badge).not.toContain("right:");
	});

	test("takes the visitor's translated label, aria-label and direction", () => {
		const badge = poweredByRyuBadgeHtml("sites", {
			ariaLabel: "مدعوم من Ryu — أنشئ الخاص بك",
			dir: "rtl",
			label: "مدعوم من <b>Ryu</b>",
		});
		expect(badge).toContain('dir="rtl"');
		expect(badge).toContain('aria-label="مدعوم من Ryu — أنشئ الخاص بك"');
		expect(badge).toContain(
			'<span>مدعوم من <strong style="font-weight:700">Ryu</strong></span>'
		);
	});

	test("escapes translated copy instead of trusting it as markup", () => {
		const badge = poweredByRyuBadgeHtml("sites", {
			ariaLabel: 'x" onclick="y',
			dir: "ltr",
			label: "<img src=x> <b>Ryu</b>",
		});
		expect(badge).not.toContain("<img");
		expect(badge).not.toContain('x" onclick');
		expect(badge).toContain("&lt;img src=x&gt;");
	});

	test("injectPoweredByRyu passes the copy through", () => {
		const html = injectPoweredByRyu("<body></body>", "sites", {
			ariaLabel: "Propulsé par Ryu — créez le vôtre",
			dir: "ltr",
			label: "Propulsé par <b>Ryu</b>",
		});
		expect(html).toContain("Propulsé par <strong");
	});
});
