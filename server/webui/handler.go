// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/gorilla/mux"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webauth"
)

//go:generate go tool templ generate -path .

//go:embed static
var staticFiles embed.FS

// assetVersion busts browser caches when the embedded assets change.
var assetVersion = func() string {
	h := sha256.New()
	_ = fs.WalkDir(staticFiles, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := staticFiles.ReadFile(path)
		if err != nil {
			return err
		}
		h.Write([]byte(path))
		h.Write(b)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}()

// contentSecurityPolicy allows only same-origin scripts, styles and
// connections. The UI uses no inline scripts, inline styles, or eval.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Handler serves the web UI under {BasePath}/ui.
type Handler struct {
	Store   Store
	Actions Actions
	// BasePath is the path Atlantis is served at behind a proxy, without a
	// trailing slash. It is empty when Atlantis is served at the root.
	BasePath string
	Logger   logging.SimpleLogging
	// Now returns the current time. Tests replace it.
	Now func() time.Time
	// HeartbeatInterval is how often idle log streams send a keep-alive.
	HeartbeatInterval time.Duration
	// WriteTimeout bounds each write to a log stream. Defaults to 30s.
	WriteTimeout time.Duration
	// Auth signs users in and assigns roles. When nil, the UI relies on the
	// server's basic auth, or none, and everyone who reaches it is an admin,
	// as with the existing UI.
	Auth *webauth.Manager
}

// Register adds the UI routes to r. Mutating routes reject cross-origin
// requests.
func (h *Handler) Register(r *mux.Router) {
	ui := r.PathPrefix("/ui").Subrouter()
	ui.Use(securityHeaders)

	static, _ := fs.Sub(staticFiles, "static")
	ui.PathPrefix("/static/").Handler(http.StripPrefix("/ui/static/", cacheStatic(http.FileServer(http.FS(static)))))

	csrf := http.NewCrossOriginProtection()

	// Sign-in routes are reachable without a session.
	if h.signInPages() {
		ui.HandleFunc("/login", h.loginPage).Methods(http.MethodGet)
		ui.HandleFunc("/login/{provider}", h.startLogin).Methods(http.MethodGet)
		ui.HandleFunc("/auth/callback/{provider}", h.finishLogin).Methods(http.MethodGet)
		ui.Handle("/logout", csrf.Handler(http.HandlerFunc(h.logout))).Methods(http.MethodPost)
	}

	view := func(f http.HandlerFunc) http.Handler { return h.guard(webauth.RoleViewer, f) }
	ui.Handle("", view(h.overview)).Methods(http.MethodGet)
	ui.Handle("/", view(h.overview)).Methods(http.MethodGet)
	ui.Handle("/pulls", view(h.pulls)).Methods(http.MethodGet)
	ui.Handle("/repos/{repo:.+}/pulls/{num:[0-9]+}", view(h.pull)).Methods(http.MethodGet)
	ui.Handle("/locks", view(h.locks)).Methods(http.MethodGet)
	ui.Handle("/jobs", view(h.jobs)).Methods(http.MethodGet)
	ui.Handle("/jobs/{id}", view(h.job)).Methods(http.MethodGet)
	ui.Handle("/jobs/{id}/events", view(h.jobEvents)).Methods(http.MethodGet)
	ui.Handle("/replica", view(h.replica)).Methods(http.MethodGet)

	ui.Handle("/locks/discard", csrf.Handler(h.guard(webauth.RoleOperator, h.discardLocks))).Methods(http.MethodPost)
	ui.Handle("/applies/lock", csrf.Handler(h.guard(webauth.RoleAdmin, h.lockApplies))).Methods(http.MethodPost)
	ui.Handle("/applies/unlock", csrf.Handler(h.guard(webauth.RoleAdmin, h.unlockApplies))).Methods(http.MethodPost)
}

// signInPages reports whether users sign in on Atlantis's own pages, as
// opposed to through an authenticating proxy or not at all.
func (h *Handler) signInPages() bool {
	return h.Auth != nil && !h.Auth.UsesProxy()
}

// guard requires a signed-in principal with at least the given role.
func (h *Handler) guard(role webauth.Role, f http.HandlerFunc) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := webauth.FromContext(r.Context())
		if !p.Can(role) {
			h.forbidden(w, r, p, role)
			return
		}
		f(w, r)
	})
	if h.Auth != nil {
		return h.Auth.Middleware(inner)
	}
	return withoutSignIn(inner)
}

// withoutSignIn keeps the existing UI's access model when web sign-in is
// off: the basic-auth user, already checked by the server middleware, or an
// anonymous visitor when basic auth is off, has full access.
func withoutSignIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &webauth.Principal{Provider: "none", Role: webauth.RoleAdmin}
		if u, _, ok := r.BasicAuth(); ok {
			p.Subject, p.Name, p.Provider = u, u, "basic"
		}
		next.ServeHTTP(w, r.WithContext(webauth.WithPrincipal(r.Context(), p)))
	})
}

func (h *Handler) forbidden(w http.ResponseWriter, r *http.Request, p *webauth.Principal, need webauth.Role) {
	msg := fmt.Sprintf("This needs the %s role. You're signed in as %s with the %s role. Ask an administrator for access.", need, orUnknown(p.DisplayName()), p.Role)
	if p.Role == webauth.RoleNone {
		msg = fmt.Sprintf("You're signed in as %s, but your account has no Atlantis role. Ask an administrator to add you to a group that has access.", orUnknown(p.DisplayName()))
	}
	h.Logger.Info("web ui denied path=%q subject=%q provider=%q role=%q need=%q", r.URL.Path, p.Subject, p.Provider, p.Role, need)
	if r.Method != http.MethodGet || p.Role == webauth.RoleNone {
		http.Error(w, msg, http.StatusForbidden)
		return
	}
	m := h.meta(r, "Not allowed", "")
	h.render(w, r, http.StatusForbidden, errorPage(m, "You don't have access to this", msg))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", contentSecurityPolicy)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") == assetVersion {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// actor returns who is making the request, for PR comments and logs.
func actor(r *http.Request) string {
	return webauth.FromContext(r.Context()).DisplayName()
}

// auditFields describes the principal in a log line.
func auditFields(r *http.Request) string {
	p := webauth.FromContext(r.Context())
	if p == nil {
		return `actor=""`
	}
	return fmt.Sprintf("actor=%q subject=%q provider=%q role=%q", p.DisplayName(), p.Subject, p.Provider, p.Role)
}

// loaded carries lists a page already read, so meta doesn't read them again.
type loaded struct {
	pulls []PullRequest
	locks []Lock
	jobs  []Job
	have  struct{ pulls, locks, jobs bool }
}

func (h *Handler) meta(r *http.Request, title, nav string, crumbs ...crumb) meta {
	return h.metaWith(r, loaded{}, title, nav, crumbs...)
}

func (h *Handler) metaWith(r *http.Request, l loaded, title, nav string, crumbs ...crumb) meta {
	ctx := r.Context()
	m := meta{
		Title:     title,
		Nav:       nav,
		Base:      h.BasePath,
		Now:       h.now(),
		Instance:  h.Store.Instance(ctx),
		Caps:      h.Store.Capabilities(),
		Principal: webauth.FromContext(ctx),
		SignOut:   h.signInPages(),
		Flash:     flashMessage(r.URL.Query()),
	}
	m.Crumbs = append([]crumb{{Label: "Atlantis", Href: string(m.url(""))}}, crumbs...)
	if l.have.pulls {
		m.Counts.Pulls = len(l.pulls)
	} else if pulls, err := h.Store.ListPulls(ctx); err == nil {
		m.Counts.Pulls = len(pulls)
	}
	if l.have.locks {
		m.Counts.Locks = len(l.locks)
	} else if locks, err := h.Store.ListLocks(ctx); err == nil {
		m.Counts.Locks = len(locks)
	}
	if l.have.jobs {
		m.Counts.Jobs = len(l.jobs)
	} else {
		m.Counts.Jobs = len(h.Store.ListJobs(ctx, JobFilter{RunningOnly: true}))
	}
	return m
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := c.Render(r.Context(), w); err != nil {
		h.Logger.Err("rendering web ui page %q: %s", r.URL.Path, err)
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	h.Logger.Err("web ui %s: %s", what, err)
	m := h.meta(r, "Something went wrong", "")
	h.render(w, r, http.StatusServiceUnavailable, errorPage(m, "Atlantis couldn't load this page",
		fmt.Sprintf("Reading %s failed: %s. Check that the lock database is reachable, then reload.", what, err)))
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pulls, err := h.Store.ListPulls(ctx)
	if err != nil {
		h.fail(w, r, "pull requests", err)
		return
	}
	locks, err := h.Store.ListLocks(ctx)
	if err != nil {
		h.fail(w, r, "locks", err)
		return
	}
	al, err := h.Store.ApplyLock(ctx)
	if err != nil {
		h.fail(w, r, "the apply lock", err)
		return
	}
	running := h.Store.ListJobs(ctx, JobFilter{RunningOnly: true})
	l := loaded{pulls: pulls, locks: locks, jobs: running}
	l.have.pulls, l.have.locks, l.have.jobs = true, true, true
	m := h.metaWith(r, l, "Overview", "overview")
	m.Crumbs = []crumb{{Label: "Overview"}}
	h.render(w, r, http.StatusOK, overviewPage(m, overviewData{
		Pulls:     pulls,
		Locks:     locks,
		Running:   running,
		ApplyLock: al,
		Attention: needsAttention(m.Now, pulls, locks, h.BasePath),
	}))
}

func (h *Handler) pulls(w http.ResponseWriter, r *http.Request) {
	pulls, err := h.Store.ListPulls(r.Context())
	if err != nil {
		h.fail(w, r, "pull requests", err)
		return
	}
	filter := r.URL.Query().Get("state")
	known := false
	for _, f := range pullFilters {
		known = known || f.Key == filter
	}
	if !known {
		filter = ""
	}
	var shown []PullRequest
	for _, p := range pulls {
		if matchesFilter(p, filter) {
			shown = append(shown, p)
		}
	}
	l := loaded{pulls: pulls}
	l.have.pulls = true
	m := h.metaWith(r, l, "Pull requests", "pulls", crumb{Label: "Pull requests"})
	h.render(w, r, http.StatusOK, pullsPage(m, pullsData{Pulls: shown, Filter: filter, Total: len(pulls)}))
}

func (h *Handler) pull(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	num, _ := strconv.Atoi(vars["num"])
	repo := vars["repo"]
	p, err := h.Store.GetPull(r.Context(), Repository{VCSHost: r.URL.Query().Get("host"), FullName: repo}, num)
	if err != nil {
		h.fail(w, r, "the pull request", err)
		return
	}
	pullsCrumb := crumb{Label: "Pull requests", Href: h.BasePath + "/ui/pulls"}
	if p == nil {
		m := h.meta(r, "Pull request not found", "pulls", pullsCrumb, crumb{Label: fmt.Sprintf("%s #%d", repo, num)})
		h.render(w, r, http.StatusNotFound, errorPage(m, "Atlantis has nothing for this pull request",
			"It may not have been planned yet, or it was closed and cleaned up."))
		return
	}
	m := h.meta(r, fmt.Sprintf("%s #%d", p.Repo.FullName, p.Num), "pulls", pullsCrumb, crumb{Label: fmt.Sprintf("%s #%d", p.Repo.FullName, p.Num)})
	h.render(w, r, http.StatusOK, pullPage(m, *p))
}

func (h *Handler) locks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	locks, err := h.Store.ListLocks(ctx)
	if err != nil {
		h.fail(w, r, "locks", err)
		return
	}
	al, err := h.Store.ApplyLock(ctx)
	if err != nil {
		h.fail(w, r, "the apply lock", err)
		return
	}
	l := loaded{locks: locks}
	l.have.locks = true
	m := h.metaWith(r, l, "Locks", "locks", crumb{Label: "Locks"})
	h.render(w, r, http.StatusOK, locksPage(m, locksData{Locks: locks, ApplyLock: al}))
}

func (h *Handler) jobs(w http.ResponseWriter, r *http.Request) {
	m := h.meta(r, "Jobs", "jobs", crumb{Label: "Jobs"})
	h.render(w, r, http.StatusOK, jobsPage(m, jobsData{Jobs: h.Store.ListJobs(r.Context(), JobFilter{})}))
}

func (h *Handler) job(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	jobsCrumb := crumb{Label: "Jobs", Href: h.BasePath + "/ui/jobs"}
	j, ok := h.Store.GetJob(r.Context(), id)
	if !ok {
		m := h.meta(r, "Job not found", "jobs", jobsCrumb, crumb{Label: "Not found"})
		h.render(w, r, http.StatusNotFound, errorPage(m, "This replica has no output for that job",
			"Job output lives in memory on the replica that ran it and is cleared on restart. Try reloading; a load balancer may route you to another replica."))
		return
	}
	m := h.meta(r, jobLabel(j), "jobs", jobsCrumb, crumb{Label: jobLabel(j)})
	h.render(w, r, http.StatusOK, jobPage(m, j))
}

func (h *Handler) replica(w http.ResponseWriter, r *http.Request) {
	al, err := h.Store.ApplyLock(r.Context())
	if err != nil {
		h.fail(w, r, "the apply lock", err)
		return
	}
	m := h.meta(r, "This replica", "replica", crumb{Label: "This replica"})
	h.render(w, r, http.StatusOK, replicaPage(m, al))
}

// ---------- actions ----------

// flash messages are chosen by key so a link can't inject arbitrary text.
var flashes = map[string]string{
	"applies-locked":   "Applies locked. Every atlantis apply fails until applies are unlocked.",
	"applies-unlocked": "Applies unlocked.",
	"none-selected":    "Select at least one lock to unlock.",
}

func flashMessage(q url.Values) string {
	if q.Get("done") == "unlocked" {
		n, _ := strconv.Atoi(q.Get("n"))
		missing, _ := strconv.Atoi(q.Get("missing"))
		msg := fmt.Sprintf("Unlocked %d %s. Their plans were discarded and the pull requests got a comment.", n, plural(n, "project", "projects"))
		if missing > 0 {
			msg += fmt.Sprintf(" %d %s already unlocked.", missing, plural(missing, "was", "were"))
		}
		return msg
	}
	return flashes[q.Get("done")]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// redirectBack sends the browser to a same-site UI path after an action.
func (h *Handler) redirectBack(w http.ResponseWriter, r *http.Request, fallback string, q url.Values) {
	target := h.BasePath + "/ui" + fallback
	if ret, ok := h.uiPath(r.PostFormValue("return")); ok {
		target = ret
	}
	if len(q) > 0 {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target += sep + q.Encode()
	}
	// #nosec G710 -- target is the fallback or a cleaned path under BasePath/ui; uiPath rejects other hosts and paths.
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// uiPath accepts a return path only when it is a plain absolute path that
// stays under BasePath/ui after cleaning. Anything with a scheme, host,
// fragment, backslash, or protocol-relative prefix is rejected. Of the query,
// only the host parameter is kept.
func (h *Handler) uiPath(raw string) (string, bool) {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\#") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return "", false
	}
	cleaned := path.Clean(u.Path)
	prefix := h.BasePath + "/ui"
	if cleaned != prefix && !strings.HasPrefix(cleaned, prefix+"/") {
		return "", false
	}
	if host := u.Query().Get("host"); host != "" {
		cleaned += "?host=" + url.QueryEscape(host)
	}
	return cleaned, true
}

func (h *Handler) discardLocks(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "The form could not be read. Reload the page and try again.", http.StatusBadRequest)
		return
	}
	ids := r.PostForm["id"]
	if len(ids) == 0 {
		h.redirectBack(w, r, "/locks", url.Values{"done": {"none-selected"}})
		return
	}
	who := actor(r)
	unlocked, missing := 0, 0
	for _, id := range ids {
		ok, err := h.Actions.DiscardLock(id, who)
		if err != nil {
			h.Logger.Err("web ui discarding lock %q: %s", id, err)
			http.Error(w, fmt.Sprintf("Unlocking %q failed: %s. %d other locks were unlocked first. Check the lock database, then try again.", id, err, unlocked), http.StatusInternalServerError)
			return
		}
		if ok {
			unlocked++
			h.Logger.Info("web ui discarded lock %q %s", id, auditFields(r))
		} else {
			missing++
		}
	}
	h.redirectBack(w, r, "/locks", url.Values{"done": {"unlocked"}, "n": {strconv.Itoa(unlocked)}, "missing": {strconv.Itoa(missing)}})
}

func (h *Handler) lockApplies(w http.ResponseWriter, r *http.Request) {
	if err := h.Actions.LockApplies(); err != nil {
		h.Logger.Err("web ui locking applies: %s", err)
		http.Error(w, fmt.Sprintf("Locking applies failed: %s. Check the lock database, then try again.", err), http.StatusInternalServerError)
		return
	}
	h.Logger.Info("web ui locked applies %s", auditFields(r))
	h.redirectBack(w, r, "/locks", url.Values{"done": {"applies-locked"}})
}

func (h *Handler) unlockApplies(w http.ResponseWriter, r *http.Request) {
	if err := h.Actions.UnlockApplies(); err != nil {
		h.Logger.Err("web ui unlocking applies: %s", err)
		http.Error(w, fmt.Sprintf("Unlocking applies failed: %s. Check the lock database, then try again.", err), http.StatusInternalServerError)
		return
	}
	h.Logger.Info("web ui unlocked applies %s", auditFields(r))
	h.redirectBack(w, r, "/locks", url.Values{"done": {"applies-unlocked"}})
}

// ---------- log stream ----------

// jobEvents streams a job's output as server-sent events. Each line is one
// event whose id is its 1-based line number, so a reconnecting browser sends
// Last-Event-ID and receives only the lines after it. A "done" event marks
// the end of the job.
func (h *Handler) jobEvents(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, ok := h.Store.GetJob(r.Context(), id); !ok {
		http.Error(w, "This replica has no output for that job.", http.StatusNotFound)
		return
	}
	from, _ := strconv.Atoi(r.Header.Get("Last-Event-ID"))

	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream")
	hd.Set("Cache-Control", "no-cache")
	hd.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	s := &sseWriter{w: w, rc: http.NewResponseController(w), timeout: h.writeTimeout()}
	if s.write("retry: 3000\n\n") != nil || s.flush() != nil {
		return
	}
	streamLines(ctx, s, h.Store.JobLog(ctx, id, from), h.heartbeat())
}

func (h *Handler) heartbeat() time.Duration {
	if h.HeartbeatInterval > 0 {
		return h.HeartbeatInterval
	}
	return 15 * time.Second
}

func (h *Handler) writeTimeout() time.Duration {
	if h.WriteTimeout > 0 {
		return h.WriteTimeout
	}
	return 30 * time.Second
}

// sseWriter bounds every write with a deadline so a client that stops
// reading cannot hold the stream open forever. Writers that do not support
// deadlines are used without one.
type sseWriter struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
}

func (s *sseWriter) write(text string) error {
	_ = s.rc.SetWriteDeadline(time.Now().Add(s.timeout))
	_, err := fmt.Fprint(s.w, text)
	return err
}

func (s *sseWriter) flush() error {
	err := s.rc.Flush()
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

func streamLines(ctx context.Context, s *sseWriter, lines <-chan LogLine, beat time.Duration) {
	ticker := time.NewTicker(beat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.write(": keep-alive\n\n") != nil || s.flush() != nil {
				return
			}
		case line, ok := <-lines:
			if !ok {
				if ctx.Err() == nil {
					_ = s.write("event: done\ndata: \n\n")
					_ = s.flush()
				}
				return
			}
			if s.write(formatEvent(line)) != nil {
				return
			}
			// Flush once the backlog is drained so replays go out in batches.
			if len(lines) == 0 && s.flush() != nil {
				return
			}
		}
	}
}

func formatEvent(line LogLine) string {
	var b strings.Builder
	fmt.Fprintf(&b, "id: %d\n", line.N)
	for part := range strings.SplitSeq(strings.ReplaceAll(line.Text, "\r\n", "\n"), "\n") {
		b.WriteString("data: ")
		b.WriteString(strings.ReplaceAll(part, "\r", ""))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return b.String()
}

// ---------- sign-in ----------

// signInNotices are chosen by key so a link can't inject text.
var signInNotices = map[string]string{
	"signed-out": "You signed out.",
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	ret := r.URL.Query().Get("return")
	if p := h.Auth.Authenticate(r); p.Can(webauth.RoleViewer) {
		target, ok := h.Auth.SafeReturn(ret)
		if !ok {
			target = h.BasePath + "/ui"
		}
		http.Redirect(w, r, target, http.StatusSeeOther) // #nosec G710 -- target passed SafeReturn
		return
	}
	h.renderSignIn(w, r, http.StatusOK, ret, "", signInNotices[r.URL.Query().Get("notice")])
}

func (h *Handler) renderSignIn(w http.ResponseWriter, r *http.Request, status int, ret, errMsg, notice string) {
	if _, ok := h.Auth.SafeReturn(ret); !ok {
		ret = ""
	}
	h.render(w, r, status, signInPage(signInData{
		Base:      h.BasePath,
		Providers: h.Auth.Providers(),
		Return:    ret,
		Error:     errMsg,
		Notice:    notice,
	}))
}

func (h *Handler) startLogin(w http.ResponseWriter, r *http.Request) {
	ret := r.URL.Query().Get("return")
	if err := h.Auth.StartLogin(w, r, mux.Vars(r)["provider"], ret); err != nil {
		h.Logger.Warn("web sign-in could not start: %s", err)
		h.renderSignIn(w, r, http.StatusBadRequest, ret, "Sign-in couldn't start: "+err.Error(), "")
	}
}

func (h *Handler) finishLogin(w http.ResponseWriter, r *http.Request) {
	target, _, err := h.Auth.FinishLogin(w, r, mux.Vars(r)["provider"])
	if err != nil {
		h.Logger.Warn("web sign-in failed provider=%q: %s", mux.Vars(r)["provider"], err)
		h.renderSignIn(w, r, http.StatusForbidden, "", "Sign-in failed: "+err.Error(), "")
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther) // #nosec G710 -- FinishLogin returns a SafeReturn path
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if p := h.Auth.Authenticate(r); p != nil {
		h.Logger.Info("web sign-out subject=%q provider=%q", p.Subject, p.Provider)
	}
	h.Auth.Logout(w)
	http.Redirect(w, r, h.BasePath+"/ui/login?notice=signed-out", http.StatusSeeOther)
}
