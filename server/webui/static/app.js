// Atlantis web UI behaviour. Loaded as a module; no inline scripts so the
// page can run under a strict Content Security Policy.

// ---------- theme ----------
const root = document.documentElement;
const storage = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage blocked */ } },
};
const savedTheme = storage.get("atlantis-theme");
if (savedTheme === "dark" || savedTheme === "light") root.dataset.theme = savedTheme;

document.addEventListener("click", (e) => {
  const t = e.target.closest("[data-theme-toggle]");
  if (!t) return;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  storage.set("atlantis-theme", root.dataset.theme);
});

// Close an open confirm popover on Escape or an outside click.
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") document.querySelectorAll("details.confirm[open]").forEach((d) => d.removeAttribute("open"));
});
document.addEventListener("click", (e) => {
  document.querySelectorAll("details.confirm[open]").forEach((d) => { if (!d.contains(e.target)) d.removeAttribute("open"); });
});

// ---------- command palette ----------
function paletteItems() {
  const items = [];
  const seen = new Set();
  const add = (label, href, kind) => {
    if (!href || seen.has(href)) return;
    seen.add(href);
    items.push({ label, href, kind });
  };
  const tpl = document.getElementById("palette-items");
  if (tpl) tpl.content.querySelectorAll("a").forEach((a) => add(a.textContent.trim(), a.getAttribute("href"), a.dataset.kind || "Page"));
  document.querySelectorAll("a.rowlink").forEach((a) => add(a.textContent.trim(), a.getAttribute("href"), a.href.includes("/jobs/") ? "Job" : "Pull request"));
  return items;
}

function openPalette() {
  if (document.querySelector(".scrim")) return;
  const all = paletteItems();
  const scrim = document.createElement("div");
  scrim.className = "scrim";
  scrim.innerHTML = '<div class="palette" role="dialog" aria-modal="true" aria-label="Search or jump to">' +
    '<input type="text" aria-label="Search" placeholder="Search pages, pull requests and jobs on this page" autocomplete="off">' +
    '<ul role="listbox"></ul><footer><span><kbd>↑</kbd> <kbd>↓</kbd> move</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span></footer></div>';
  document.body.append(scrim);
  const input = scrim.querySelector("input");
  const list = scrim.querySelector("ul");
  const previousFocus = document.activeElement;
  let items = all;
  let sel = 0;
  const draw = () => {
    list.replaceChildren();
    if (!items.length) {
      const li = document.createElement("li");
      li.className = "muted";
      li.textContent = "Nothing matches. Try a repository, a pull request number, or a page name.";
      list.append(li);
      return;
    }
    items.forEach((it, i) => {
      const li = document.createElement("li");
      li.setAttribute("role", "option");
      li.setAttribute("aria-selected", String(i === sel));
      li.dataset.i = String(i);
      li.append(document.createTextNode(it.label));
      const small = document.createElement("small");
      small.textContent = it.kind;
      li.append(small);
      list.append(li);
    });
    list.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
  };
  const close = () => {
    scrim.remove();
    document.removeEventListener("keydown", onKey, true);
    previousFocus?.focus?.();
  };
  const go = (i) => { const it = items[i]; if (it) { close(); location.href = it.href; } };
  const onKey = (e) => {
    if (e.key === "Escape") { e.preventDefault(); close(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(sel + 1, items.length - 1); draw(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(sel - 1, 0); draw(); }
    else if (e.key === "Enter") { e.preventDefault(); go(sel); }
  };
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    items = all.filter((it) => it.label.toLowerCase().includes(q));
    sel = 0;
    draw();
  });
  list.addEventListener("click", (e) => { const li = e.target.closest("[data-i]"); if (li) go(Number(li.dataset.i)); });
  scrim.addEventListener("click", (e) => { if (e.target === scrim) close(); });
  document.addEventListener("keydown", onKey, true);
  draw();
  input.focus();
}

document.addEventListener("click", (e) => { if (e.target.closest("[data-palette]")) openPalette(); });
document.addEventListener("keydown", (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "");
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
  else if (e.key === "/" && !typing) { e.preventDefault(); openPalette(); }
});

// ---------- log viewer ----------
const SGR = /\x1b\[([0-9;]*)m/g;

// renderLine turns one output line into DOM nodes, honouring ANSI colour
// codes. Lines without codes get Terraform-aware colouring.
export function renderLine(text) {
  const frag = document.createDocumentFragment();
  if (!text.includes("\x1b[")) {
    const span = document.createElement("span");
    span.textContent = text;
    const cls = terraformClass(text);
    if (cls) span.className = cls;
    frag.append(span);
    return frag;
  }
  let classes = [];
  let last = 0;
  for (const m of text.matchAll(SGR)) {
    if (m.index > last) frag.append(styled(text.slice(last, m.index), classes));
    last = m.index + m[0].length;
    for (const code of (m[1] || "0").split(";").map(Number)) {
      if (code === 0) classes = [];
      else if (code === 1) classes.push("b1");
      else if (code === 2) classes.push("dim");
      else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97)) {
        classes = classes.filter((c) => !/^c\d+$/.test(c));
        classes.push("c" + code);
      } else if (code === 39) classes = classes.filter((c) => !/^c\d+$/.test(c));
      else if (code === 22) classes = classes.filter((c) => c !== "b1" && c !== "dim");
    }
  }
  if (last < text.length) frag.append(styled(text.slice(last), classes));
  return frag;
}

function styled(text, classes) {
  const span = document.createElement("span");
  span.textContent = text;
  if (classes.length) span.className = classes.join(" ");
  return span;
}

export function terraformClass(line) {
  const t = line.trimStart();
  if (/^(Plan:|Apply complete!|No changes\.)/.test(t) || /^\$ /.test(line)) return "tf-head";
  if (/^(\+ |# .* will be created)/.test(t)) return "tf-add";
  if (/^(- |# .* will be destroyed|Error:|│ Error:)/.test(t)) return "tf-del";
  if (/^(~ |-\/\+ |\+\/- |# .* will be updated|# .* must be replaced)/.test(t)) return "tf-chg";
  return "";
}

class LogView extends HTMLElement {
  connectedCallback() {
    this.lines = this.querySelector("[data-log-lines]");
    this.status = this.querySelector("[data-log-status]");
    this.count = this.querySelector("[data-log-count]");
    this.find = this.querySelector("[data-log-find]");
    this.follow = this.querySelector("[data-log-follow]");
    this.pending = [];
    this.total = 0;
    this.scheduled = false;

    this.find?.addEventListener("input", () => this.highlight());
    this.lines.addEventListener("scroll", () => {
      const atBottom = this.lines.scrollHeight - this.lines.scrollTop - this.lines.clientHeight < 24;
      if (this.follow && !atBottom && this.follow.checked && !this.autoScrolling) this.follow.checked = false;
    });

    this.source = new EventSource(this.dataset.src);
    this.source.onopen = () => this.setStatus("run", "Streaming");
    this.source.onmessage = (e) => this.push(Number(e.lastEventId) || this.total + this.pending.length + 1, e.data);
    this.source.addEventListener("done", () => {
      this.source.close();
      this.flush();
      this.setStatus("", "Finished");
    });
    this.source.onerror = () => {
      if (this.source.readyState === EventSource.CLOSED) {
        this.setStatus("bad", "Not available on this replica");
      } else {
        this.setStatus("warn", "Reconnecting");
      }
    };
  }

  disconnectedCallback() {
    this.source?.close();
  }

  setStatus(tone, label) {
    if (!this.status) return;
    this.status.className = "pill" + (tone ? " " + tone : "");
    this.status.replaceChildren();
    if (tone) {
      const dot = document.createElement("span");
      dot.className = "dot";
      this.status.append(dot);
    }
    this.status.append(document.createTextNode(label));
  }

  push(n, text) {
    this.pending.push([n, text]);
    if (!this.scheduled) {
      this.scheduled = true;
      requestAnimationFrame(() => this.flush());
    }
  }

  flush() {
    this.scheduled = false;
    if (!this.pending.length) return;
    const q = (this.find?.value || "").toLowerCase();
    const frag = document.createDocumentFragment();
    for (const [n, text] of this.pending) {
      const row = document.createElement("div");
      row.className = "ln";
      row.id = "L" + n;
      const no = document.createElement("a");
      no.className = "no";
      no.href = "#L" + n;
      no.textContent = String(n);
      no.setAttribute("aria-label", "Line " + n);
      const body = document.createElement("span");
      body.className = "txt";
      body.append(renderLine(text));
      if (q && text.toLowerCase().includes(q)) body.classList.add("hit");
      row.append(no, body);
      frag.append(row);
      this.total = Math.max(this.total, n);
    }
    this.pending = [];
    this.lines.append(frag);
    if (this.count) this.count.textContent = this.total + " lines";
    if (this.follow?.checked) {
      this.autoScrolling = true;
      this.lines.scrollTop = this.lines.scrollHeight;
      requestAnimationFrame(() => { this.autoScrolling = false; });
    } else if (location.hash && !this.jumped) {
      const target = document.getElementById(location.hash.slice(1));
      if (target) { target.scrollIntoView({ block: "center" }); this.jumped = true; }
    }
  }

  highlight() {
    const q = (this.find?.value || "").toLowerCase();
    let first = null;
    this.lines.querySelectorAll(".ln .txt").forEach((el) => {
      const hit = q !== "" && el.textContent.toLowerCase().includes(q);
      el.classList.toggle("hit", hit);
      if (hit && !first) first = el;
    });
    if (first) {
      if (this.follow) this.follow.checked = false;
      first.scrollIntoView({ block: "center" });
    }
  }
}

if (!customElements.get("log-view")) customElements.define("log-view", LogView);
