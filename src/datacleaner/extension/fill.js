// Fills a broker's opt-out form. The popup injects this into the page with
// chrome.scripting.executeScript, which copies the function's source, so it must not
// use anything defined outside its own body.
//
// values:   {first_name, last_name, email, phone, street, city, state, state_name, zip, url, ...}
// patterns: [[key, regex source], ...] in priority order (from the Data Cleaner server)
// domains:  where this broker's form may be filled (its own domains)

export function fillPage(values, patterns, domains) {
  const host = location.hostname.toLowerCase();
  const allowed = domains.some((d) => host === d || host.endsWith("." + d));
  const local = host === "localhost" || host === "127.0.0.1";
  if (!allowed) return { ok: false, reason: "domain", host };
  if (location.protocol !== "https:" && !local) return { ok: false, reason: "insecure", host };

  const rules = patterns.map(([key, source]) => [key, new RegExp(source, "i")]);
  const SKIP = new Set(["hidden", "submit", "button", "reset", "checkbox", "radio", "file", "password", "image", "range", "color"]);
  const AUTOCOMPLETE = {
    "given-name": "first_name", "additional-name": "middle_name", "family-name": "last_name", name: "full_name",
    email: "email", tel: "phone", "tel-national": "phone", "street-address": "street", "address-line1": "street",
    "address-level2": "city", "address-level1": "state", "postal-code": "zip", bday: "dob", url: "url",
  };

  const labelText = (el) => {
    const parts = [];
    for (const label of el.labels || []) parts.push(label.textContent || "");
    for (const id of (el.getAttribute("aria-labelledby") || "").split(/\s+/).filter(Boolean)) {
      const node = document.getElementById(id);
      if (node) parts.push(node.textContent || "");
    }
    return parts.join(" ").replace(/[*:]/g, " ").replace(/\s+/g, " ").trim();
  };

  const classify = (el) => {
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (type === "email") return "email";
    if (type === "tel") return "phone";
    if (type === "date") return "dob";
    for (const token of (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/)) {
      if (AUTOCOMPLETE[token]) return AUTOCOMPLETE[token];
    }
    const parts = [labelText(el), el.name, el.id, el.getAttribute("placeholder"), el.getAttribute("aria-label")]
      .map((p) => (p || "").trim()).filter(Boolean);
    if (!parts.length) return null;
    const joined = parts.join(" ");
    for (const [key, re] of rules) {
      if (parts.some((p) => re.test(p)) || re.test(joined)) return key;
    }
    return null;
  };

  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && style.visibility !== "hidden" && style.display !== "none";
  };

  // Set the value the way typing would, so React/Vue forms notice it.
  const setValue = (el, value) => {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
      : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const optionFor = (select, candidates) => {
    const wanted = candidates.filter(Boolean).map((c) => String(c).trim().toLowerCase());
    for (const opt of select.options) {
      const text = (opt.textContent || "").trim().toLowerCase();
      if (wanted.includes((opt.value || "").toLowerCase()) || wanted.includes(text)) return opt.value;
    }
    return null;
  };

  const filled = [];
  for (const el of document.querySelectorAll("input, select, textarea")) {
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (el.disabled || el.readOnly || SKIP.has(type) || !visible(el)) continue;
    const key = classify(el);
    if (!key) continue;
    if (el instanceof HTMLSelectElement) {
      const value = key === "state" ? optionFor(el, [values.state, values.state_name]) : optionFor(el, [values[key]]);
      if (value === null || el.value === value) continue;
      setValue(el, value);
    } else {
      const value = values[key];
      if (!value || el.value) continue; // never overwrite what's already there
      setValue(el, value);
    }
    el.style.outline = "2px solid #1f6feb";
    el.style.outlineOffset = "1px";
    filled.push(key);
  }

  const old = document.getElementById("datacleaner-banner");
  if (old) old.remove();
  const banner = document.createElement("div");
  banner.id = "datacleaner-banner";
  banner.setAttribute("role", "status");
  banner.textContent = filled.length
    ? `Data Cleaner filled ${filled.length} field${filled.length === 1 ? "" : "s"} (outlined in blue). Check them, solve any CAPTCHA and press Submit. Then open the Data Cleaner extension and choose "I submitted it".`
    : "Data Cleaner couldn't recognise any fields on this page. You may need to search for your listing first, or fill the form yourself.";
  banner.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#1f6feb;color:#fff;"
    + "padding:10px 16px;font:14px/1.4 system-ui,sans-serif;text-align:center;box-shadow:0 2px 6px rgba(0,0,0,.3)";
  banner.addEventListener("click", () => banner.remove());
  document.documentElement.appendChild(banner);
  return { ok: true, filled: filled.length, keys: filled };
}
