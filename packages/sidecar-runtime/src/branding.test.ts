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
