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
// Don't refresh a panel while one of its confirmations is open, or the
// refresh would close it under the pointer.
document.addEventListener("htmx:before:request", (e) => {
  if (e.target?.querySelector?.("details.confirm[open]")) e.preventDefault();
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

// Plan diff markers are always indented, which keeps init output such as
// "- Using previously-installed ..." from looking like a destroy.
export function terraformClass(line) {
  const t = line.trimStart();
  if (/^(Plan:|Apply complete!|No changes\.)/.test(t) || /^\$ /.test(line)) return "tf-head";
  if (/^\s+(-\/\+|\+\/-|~) /.test(line) || /^# .* (will be updated|must be replaced)/.test(t)) return "tf-chg";
  if (/^\s+\+ /.test(line) || /^# .* will be created/.test(t)) return "tf-add";
  if (/^\s+- /.test(line) || /^# .* will be destroyed/.test(t) || /^(│ )?Error:/.test(t)) return "tf-del";
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
    this.source.addEventListener("done", (e) => {
      this.source.close();
      this.flush();
      const status = (e.data || "").trim();
      if (status) this.setStatus("bad", status);
      else this.setStatus("", "Finished");
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

// ---------- plan view ----------
// Filter chips and the expand button work without a page load. Without
// JavaScript they stay hidden and every resource is listed.
function setupPlanView() {
  const filters = document.querySelector("[data-plan-filters]");
  if (!filters || filters.dataset.ready) return;
  filters.dataset.ready = "1";
  filters.hidden = false;
  const expand = document.querySelector("[data-plan-expand]");
  const visibleResources = () => [...document.querySelectorAll("[data-plan-group]:not([hidden]) details.res")];
  const syncExpand = () => {
    if (!expand) return;
    const shown = visibleResources();
    expand.textContent = shown.length && shown.every((d) => d.open) ? "Collapse all" : "Expand all";
  };
  filters.addEventListener("click", (e) => {
    const chip = e.target.closest("[data-plan-filter]");
    if (!chip) return;
    const key = chip.dataset.planFilter;
    filters.querySelectorAll("[data-plan-filter]").forEach((c) => c.setAttribute("aria-pressed", String(c === chip)));
    document.querySelectorAll("[data-plan-group]").forEach((g) => { g.hidden = key !== "all" && g.dataset.planGroup !== key; });
    syncExpand();
  });
  if (expand) {
    expand.hidden = false;
    expand.addEventListener("click", () => {
      const shown = visibleResources();
      const open = !shown.every((d) => d.open);
      shown.forEach((d) => { d.open = open; });
      syncExpand();
    });
    document.addEventListener("toggle", (e) => { if (e.target.matches?.("details.res")) syncExpand(); }, true);
    syncExpand();
  }
}
setupPlanView();

// ---------- timing waterfall ----------
// The server renders every row in tree order. This element collapses
// subtrees, sorts by duration, filters by name, shows a span's details, and
// reloads the waterfall while the job runs. Without JavaScript the full tree
// and every row stay visible.
class TraceView extends HTMLElement {
  connectedCallback() {
    this.body = this.querySelector("[data-wf-body]");
    this.state = { collapsed: new Set(), selected: null, filter: "", sort: false, critical: false };
    this.addEventListener("click", (e) => this.onClick(e));
    this.addEventListener("input", (e) => {
      if (!e.target.matches("[data-wf-filter]")) return;
      this.state.filter = e.target.value;
      this.apply();
    });
    this.addEventListener("keydown", (e) => this.onKey(e));
    this.setup();
    if (this.dataset.events) this.listen();
  }

  disconnectedCallback() {
    this.source?.close();
    clearTimeout(this.timer);
  }

  setup() {
    const tools = this.querySelector("[data-wf-tools]");
    if (tools) tools.hidden = false;
    const filter = this.querySelector("[data-wf-filter]");
    if (filter && filter.value !== this.state.filter) filter.value = this.state.filter;
    this.querySelector("[data-wf-sort]")?.setAttribute("aria-pressed", String(this.state.sort));
    this.querySelector("[data-wf-critical]")?.setAttribute("aria-pressed", String(this.state.critical));
    this.apply();
    if (this.state.selected) this.select(this.state.selected, false);
  }

  rows() {
    return [...this.querySelectorAll(".wf-row[data-id]")];
  }

  rowFor(id) {
    return this.querySelector('.wf-row[data-id="' + CSS.escape(id) + '"]');
  }

  onClick(e) {
    const t = e.target;
    const toggle = t.closest("[data-wf-toggle]");
    if (toggle) {
      const id = toggle.closest(".wf-row").dataset.id;
      if (this.state.collapsed.has(id)) this.state.collapsed.delete(id);
      else this.state.collapsed.add(id);
      this.apply();
      return;
    }
    const label = t.closest("[data-wf-select]");
    if (label) { this.select(label.closest(".wf-row").dataset.id, false); return; }
    const sort = t.closest("[data-wf-sort]");
    if (sort) { this.state.sort = !this.state.sort; sort.setAttribute("aria-pressed", String(this.state.sort)); this.apply(); return; }
    const crit = t.closest("[data-wf-critical]");
    if (crit) { this.state.critical = !this.state.critical; crit.setAttribute("aria-pressed", String(this.state.critical)); this.apply(); return; }
    const go = t.closest("[data-wf-goto]");
    if (go) this.select(go.dataset.wfGoto, true);
  }

  // apply orders and hides rows for the current state. Collapsing works on
  // the tree order, where a row's descendants follow it with greater depth.
  apply() {
    const list = this.querySelector("[data-wf-rows]");
    if (!list) return;
    const s = this.state;
    const q = s.filter.trim().toLowerCase();
    const flat = s.sort || q !== "" || s.critical;
    list.classList.toggle("flat", flat);
    const tree = this.rows().sort((a, b) => Number(a.dataset.i) - Number(b.dataset.i));
    const order = s.sort ? [...tree].sort((a, b) => Number(b.dataset.dur) - Number(a.dataset.dur)) : tree;
    // Moving rows drops keyboard focus, so only move them when the order
    // changes.
    const current = this.rows();
    if (order.some((r, i) => current[i] !== r)) {
      const active = document.activeElement;
      order.forEach((r) => list.append(r));
      if (active && this.contains(active)) active.focus({ preventScroll: true });
    }
    let hideBelow = Infinity;
    let shown = 0;
    for (const r of tree) {
      const depth = Number(r.dataset.depth);
      let hidden;
      if (flat) {
        hidden = (q !== "" && !r.dataset.name.includes(q)) || (s.critical && !r.dataset.crit);
      } else {
        if (depth <= hideBelow) hideBelow = Infinity;
        hidden = depth > hideBelow;
        if (!hidden && s.collapsed.has(r.dataset.id)) hideBelow = depth;
      }
      r.hidden = hidden;
      if (!hidden) shown++;
      const tw = r.querySelector("[data-wf-toggle]");
      if (tw) {
        const open = !s.collapsed.has(r.dataset.id);
        tw.setAttribute("aria-expanded", String(open));
        tw.setAttribute("aria-label", (open ? "Collapse " : "Expand ") + r.querySelector(".wf-label").textContent);
      }
    }
    let none = this.querySelector("[data-wf-none]");
    if (!shown) {
      if (!none) {
        none = document.createElement("p");
        none.className = "empty";
        none.dataset.wfNone = "";
        none.textContent = "No spans match. Clear the filter to see them all.";
        list.after(none);
      }
    } else none?.remove();
  }

  select(id, reveal) {
    const row = this.rowFor(id);
    if (!row) return;
    this.state.selected = id;
    if (reveal && row.hidden) {
      // Open the collapsed ancestors and drop filters that hide the row.
      this.state.collapsed.clear();
      this.state.filter = "";
      this.state.critical = false;
      this.setup();
    }
    this.querySelectorAll(".wf-row.sel").forEach((r) => r.classList.remove("sel"));
    row.classList.add("sel");
    this.querySelectorAll("[data-wf-detail]").forEach((d) => { d.hidden = d.dataset.wfDetail !== id; });
    const empty = this.querySelector("[data-wf-empty]");
    if (empty) empty.hidden = true;
    if (reveal) {
      row.scrollIntoView({ block: "center" });
      row.querySelector(".wf-label")?.focus();
    }
  }

  onKey(e) {
    const label = e.target.closest?.(".wf-label");
    if (!label) return;
    const row = label.closest(".wf-row");
    const visible = this.rows().filter((r) => !r.hidden);
    const i = visible.indexOf(row);
    const focus = (r) => { if (r) { r.querySelector(".wf-label").focus(); e.preventDefault(); } };
    const id = row.dataset.id;
    switch (e.key) {
      case "ArrowDown": focus(visible[i + 1]); break;
      case "ArrowUp": focus(visible[i - 1]); break;
      case "Home": focus(visible[0]); break;
      case "End": focus(visible[visible.length - 1]); break;
      case "ArrowRight":
        if (row.querySelector("[data-wf-toggle]") && this.state.collapsed.has(id)) { this.state.collapsed.delete(id); this.apply(); e.preventDefault(); }
        break;
      case "ArrowLeft":
        if (row.querySelector("[data-wf-toggle]") && !this.state.collapsed.has(id)) { this.state.collapsed.add(id); this.apply(); e.preventDefault(); }
        break;
    }
  }

  listen() {
    this.source = new EventSource(this.dataset.events);
    this.source.addEventListener("trace", () => this.schedule());
    this.source.addEventListener("done", () => { this.source.close(); this.schedule(); });
  }

  // schedule reloads the waterfall at most once a second.
  schedule() {
    if (this.timer) { this.again = true; return; }
    this.refresh();
    this.timer = setTimeout(() => {
      this.timer = null;
      if (this.again) { this.again = false; this.schedule(); }
    }, 1000);
  }

  async refresh() {
    let html;
    try {
      const resp = await fetch(this.dataset.src, { credentials: "same-origin", headers: { Accept: "text/html" } });
      if (!resp.ok) return;
      html = await resp.text();
    } catch { return; }
    const scroller = this.querySelector(".wf-scroll");
    const scroll = scroller ? [scroller.scrollLeft, scroller.scrollTop] : null;
    const focused = document.activeElement?.closest?.(".wf-row")?.dataset.id;
    this.body.innerHTML = html;
    this.setup();
    const next = this.querySelector(".wf-scroll");
    if (next && scroll) [next.scrollLeft, next.scrollTop] = scroll;
    if (focused) this.rowFor(focused)?.querySelector(".wf-label")?.focus({ preventScroll: true });
  }
}

if (!customElements.get("trace-view")) customElements.define("trace-view", TraceView);
