// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
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
	// Policy is used when Auth is nil, so the Access page can still show the
	// configured rules. Auth carries its own policy.
	Policy *webauth.Policy
}

var emptyPolicy, _ = webauth.NewPolicy(webauth.PolicyConfig{})

func (h *Handler) policy() *webauth.Policy {
	switch {
	case h.Auth != nil:
		return h.Auth.Policy()
	case h.Policy != nil:
		return h.Policy
	}
	return emptyPolicy
}

// allows reports whether the request's principal may take an action in a
// repository, given as an ID such as github.com/acme/infra.
func (h *Handler) allows(r *http.Request, action webauth.Action, repoID string) bool {
	p := webauth.FromContext(r.Context())
	if p == nil {
		return false
	}
	return h.policy().Allows(p.AsSubject(), p.Base, action, repoID)
}

// canStopJob reports whether the request's principal may stop a job. When
// the job's VCS host is unknown, the repo rules can't be matched reliably, so
// only admins may stop it.
func (h *Handler) canStopJob(r *http.Request, j Job) bool {
	if j.Repo.VCSHost == "" {
		p := webauth.FromContext(r.Context())
		return p != nil && max(p.Base, h.policy().GlobalRole(p.AsSubject())) >= webauth.RoleAdmin
	}
	return h.allows(r, webauth.ActionStopJob, repoID(j.Repo))
}

// repoID is the server-side repo config ID of a repository.
func repoID(r Repository) string {
	if r.VCSHost == "" {
		return r.FullName
	}
	return r.VCSHost + "/" + r.FullName
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

	view := func(f http.HandlerFunc) http.Handler { return h.guard(webauth.ActionView, f) }
	ui.Handle("", view(h.overview)).Methods(http.MethodGet)
	ui.Handle("/", view(h.overview)).Methods(http.MethodGet)
	ui.Handle("/pulls", view(h.pulls)).Methods(http.MethodGet)
	ui.Handle("/repos/{repo:.+}/pulls/{num:[0-9]+}", view(h.pull)).Methods(http.MethodGet)
	ui.Handle("/repos/{repo:.+}/pulls/{num:[0-9]+}/plan", view(h.plan)).Methods(http.MethodGet)
	ui.Handle("/locks", view(h.locks)).Methods(http.MethodGet)
	ui.Handle("/jobs", view(h.jobs)).Methods(http.MethodGet)
	ui.Handle("/jobs/{id}", view(h.job)).Methods(http.MethodGet)
	ui.Handle("/jobs/{id}/events", view(h.jobEvents)).Methods(http.MethodGet)
	ui.Handle("/replica", view(h.replica)).Methods(http.MethodGet)
	ui.Handle("/access", view(h.access)).Methods(http.MethodGet)

	// Unlocking is checked per lock, against each lock's repository.
	ui.Handle("/locks/discard", csrf.Handler(h.guard(webauth.ActionView, h.discardLocks))).Methods(http.MethodPost)
	ui.Handle("/applies/lock", csrf.Handler(h.guard(webauth.ActionLockApplies, h.lockApplies))).Methods(http.MethodPost)
	ui.Handle("/applies/unlock", csrf.Handler(h.guard(webauth.ActionLockApplies, h.unlockApplies))).Methods(http.MethodPost)
	ui.Handle("/maintenance", csrf.Handler(h.guard(webauth.ActionMaintenance, h.startMaintenance))).Methods(http.MethodPost)
	ui.Handle("/maintenance/{id}/end", csrf.Handler(h.guard(webauth.ActionMaintenance, h.endMaintenance))).Methods(http.MethodPost)
	// Stopping is checked per job, against the job's repository. Keep this
	// route last: with gorilla/mux, a later route can turn a GET's 405 here
	// into a 404.
	ui.Handle("/jobs/{id}/stop", csrf.Handler(h.guard(webauth.ActionView, h.stopJob))).Methods(http.MethodPost)
}

// signInPages reports whether users sign in on Atlantis's own pages, as
// opposed to through an authenticating proxy or not at all.
func (h *Handler) signInPages() bool {
	return h.Auth != nil && !h.Auth.UsesProxy()
}

// guard requires a signed-in principal allowed to take the action. Global
// actions are checked here; unlocking is checked per repository.
func (h *Handler) guard(action webauth.Action, f http.HandlerFunc) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.allows(r, action, "") {
			h.forbidden(w, r, action, "")
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
		p := &webauth.Principal{Provider: "none", Role: webauth.RoleAdmin, Base: webauth.RoleAdmin}
		if u, _, ok := r.BasicAuth(); ok {
			p.Subject, p.Name, p.Provider = u, u, "basic"
		}
		next.ServeHTTP(w, r.WithContext(webauth.WithPrincipal(r.Context(), p)))
	})
}

// forbidden explains which role an action needs and where.
func (h *Handler) forbidden(w http.ResponseWriter, r *http.Request, action webauth.Action, repo string) {
	p := webauth.FromContext(r.Context())
	need := h.policy().Requires(action, repo)
	have := h.policy().RoleIn(p.AsSubject(), repo)
	where := ""
	if repo != "" {
		where = " on " + repo
	}
	msg := fmt.Sprintf("%s needs the %s role%s. You're signed in as %s with the %s role there. Ask an administrator for access.",
		action.Describe(), need, where, orUnknown(p.DisplayName()), have)
	if p.Role == webauth.RoleNone && have == webauth.RoleNone {
		msg = fmt.Sprintf("You're signed in as %s, but your account has no Atlantis role. Ask an administrator to add you to a group that has access.", orUnknown(p.DisplayName()))
	}
	h.Logger.Info("web ui denied path=%q action=%q repo=%q subject=%q provider=%q role=%q need=%q", r.URL.Path, action, repo, p.Subject, p.Provider, have, need)
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
		can:       func(a webauth.Action, repo string) bool { return h.allows(r, a, repo) },
		canStop:   func(j Job) bool { return h.canStopJob(r, j) },
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
		Pulls:       pulls,
		Locks:       locks,
		Running:     running,
		ApplyLock:   al,
		Attention:   needsAttention(m.Now, pulls, locks, h.BasePath),
		Maintenance: h.Store.ListMaintenance(ctx),
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
	locks, err := h.Store.ListLocks(r.Context())
	if err != nil {
		h.fail(w, r, "locks", err)
		return
	}
	d := pullData{Pull: *p}
	for _, l := range locks {
		if lockHeldBy(l, p.Repo, p.Num) {
			d.Locks = append(d.Locks, l)
		}
	}
	for _, mw := range h.Store.ListMaintenance(r.Context()) {
		if mw.CoversRepo(p.Repo) {
			d.Maintenance = append(d.Maintenance, mw)
		}
	}
	m := h.meta(r, fmt.Sprintf("%s #%d", p.Repo.FullName, p.Num), "pulls", pullsCrumb, crumb{Label: fmt.Sprintf("%s #%d", p.Repo.FullName, p.Num)})
	h.render(w, r, http.StatusOK, pullPage(m, d))
}

// plan shows the resource changes in one project's plan. The project is
// chosen by dir, workspace and project query parameters, and must be a
// project Atlantis tracks for the pull request.
func (h *Handler) plan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	num, _ := strconv.Atoi(vars["num"])
	repo := vars["repo"]
	q := r.URL.Query()
	ref := ProjectRef{Dir: q.Get("dir"), Workspace: q.Get("workspace"), Name: q.Get("project")}
	p, err := h.Store.GetPull(ctx, Repository{VCSHost: q.Get("host"), FullName: repo}, num)
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
	pullCrumb := crumb{Label: fmt.Sprintf("%s #%d", p.Repo.FullName, p.Num), Href: pullHref(h.BasePath, p.Repo, p.Num)}
	var proj *Project
	for i := range p.Projects {
		if p.Projects[i].Ref() == ref {
			proj = &p.Projects[i]
		}
	}
	var plan *ProjectPlan
	if proj != nil {
		plan, err = h.Store.GetPlan(ctx, p.Repo, p.Num, ref)
		if err != nil {
			h.fail(w, r, "the plan", err)
			return
		}
	}
	if plan == nil {
		m := h.meta(r, "Project not found", "pulls", pullsCrumb, pullCrumb, crumb{Label: "Plan"})
		h.render(w, r, http.StatusNotFound, errorPage(m, "Atlantis has no such project in this pull request",
			"The project may have been renamed or removed from the pull request. Open the pull request to see its projects."))
		return
	}
	label := projectLabel(*proj)
	m := h.meta(r, "Plan for "+label, "pulls", pullsCrumb, pullCrumb, crumb{Label: "Plan for " + label})
	h.render(w, r, http.StatusOK, planPage(m, planData{Pull: *p, Project: *proj, Plan: *plan, Groups: planGroups(plan.Plan)}))
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
	pulls, _ := h.Store.ListPulls(ctx)
	m := h.metaWith(r, l, "Locks", "locks", crumb{Label: "Locks"})
	h.render(w, r, http.StatusOK, locksPage(m, locksData{
		Locks:       locks,
		Groups:      groupLocks(locks),
		ApplyLock:   al,
		Maintenance: h.Store.ListMaintenance(ctx),
		KnownRepos:  knownRepoNames(pulls, locks),
	}))
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
			"Job output lives in memory on the replica that ran it and is cleared on restart, and only that replica can show or stop the job. Try reloading; a load balancer may route you to another replica."))
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
	"stop-requested":   "Stop requested. Terraform got an interrupt and stops once the operations in progress finish, then releases its state lock. The pull request shows the job as failed.",
	"already-stopping": "Someone already stopped this job. It ends once Terraform exits.",
	"stop-finished":    "That job had already finished, so there was nothing to stop.",
	"no-pull-locks":    "That pull request holds no locks now, so nothing was unlocked.",
	"maint-started":    "Maintenance window started. Atlantis on this replica rejects the frozen commands and comments with your reason.",
	"maint-ended":      "Maintenance window ended. Commands run again.",
	"maint-gone":       "That maintenance window had already ended.",
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

// discardLocks unlocks the selected locks, or, when the form names a pull
// request, every lock that pull request holds. The user must be allowed to
// unlock every lock before any is discarded. A failure doesn't stop the
// others; the result page lists what was and wasn't unlocked.
func (h *Handler) discardLocks(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "The form could not be read. Reload the page and try again.", http.StatusBadRequest)
		return
	}
	locks, err := h.Store.ListLocks(r.Context())
	if err != nil {
		h.fail(w, r, "locks", err)
		return
	}
	byID := map[string]Lock{}
	for _, l := range locks {
		byID[l.ID] = l
	}
	ids := r.PostForm["id"]
	if key := r.PostFormValue("pull"); key != "" {
		repo, num, ok := parsePullKey(key)
		if !ok {
			http.Error(w, "The pull request in the form is not valid. Reload the page and try again.", http.StatusBadRequest)
			return
		}
		ids = nil
		for _, l := range locks {
			if lockHeldBy(l, repo, num) {
				ids = append(ids, l.ID)
			}
		}
		if len(ids) == 0 {
			h.redirectBack(w, r, "/locks", url.Values{"done": {"no-pull-locks"}})
			return
		}
	}
	ids = slices.Compact(slices.Sorted(slices.Values(ids)))
	if len(ids) == 0 {
		h.redirectBack(w, r, "/locks", url.Values{"done": {"none-selected"}})
		return
	}
	// Check every lock before discarding any, so a request either unlocks
	// all the selected projects or none of them.
	for _, id := range ids {
		repo := ""
		if l, known := byID[id]; known {
			repo = repoID(l.Repo)
		}
		if !h.allows(r, webauth.ActionUnlock, repo) {
			h.forbidden(w, r, webauth.ActionUnlock, repo)
			return
		}
	}
	who := actor(r)
	res := discardResult{}
	for _, id := range ids {
		label := id
		if l, known := byID[id]; known {
			label = fmt.Sprintf("%s #%d %s", l.Repo.FullName, l.PullNum, lockLabel(l))
		}
		ok, err := h.Actions.DiscardLock(id, who)
		switch {
		case err != nil:
			h.Logger.Err("web ui discarding lock %q: %s", id, err)
			res.Failed = append(res.Failed, discardFailure{Label: label, Err: err.Error()})
		case ok:
			h.Logger.Info("web ui discarded lock %q %s", id, auditFields(r))
			res.Unlocked = append(res.Unlocked, label)
		default:
			res.Missing++
		}
	}
	if len(res.Failed) > 0 {
		res.Return = h.BasePath + "/ui/locks"
		if ret, ok := h.uiPath(r.PostFormValue("return")); ok {
			res.Return = ret
		}
		m := h.meta(r, "Some locks weren't unlocked", "locks", crumb{Label: "Locks", Href: h.BasePath + "/ui/locks"}, crumb{Label: "Unlock result"})
		h.render(w, r, http.StatusInternalServerError, discardResultPage(m, res))
		return
	}
	h.redirectBack(w, r, "/locks", url.Values{"done": {"unlocked"}, "n": {strconv.Itoa(len(res.Unlocked))}, "missing": {strconv.Itoa(res.Missing)}})
}

// discardResult is what a bulk unlock did, shown when part of it failed.
type discardResult struct {
	Unlocked []string
	Failed   []discardFailure
	Missing  int
	Return   string
}

type discardFailure struct {
	Label string
	Err   string
}

// pullKey identifies a pull request in a form value.
func pullKey(repo Repository, num int) string {
	return repo.VCSHost + "|" + repo.FullName + "|" + strconv.Itoa(num)
}

func parsePullKey(key string) (Repository, int, bool) {
	parts := strings.Split(key, "|")
	if len(parts) != 3 || parts[1] == "" {
		return Repository{}, 0, false
	}
	num, err := strconv.Atoi(parts[2])
	if err != nil || num <= 0 {
		return Repository{}, 0, false
	}
	return Repository{VCSHost: parts[0], FullName: parts[1]}, num, true
}

// lockHeldBy reports whether a pull request holds a lock.
func lockHeldBy(l Lock, repo Repository, num int) bool {
	return l.PullNum == num && l.Repo.FullName == repo.FullName && sameHost(l.Repo.VCSHost, repo.VCSHost)
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

// stopJob interrupts a job running on this replica. Only this replica knows
// the job's processes, so a job it has no record of can't be stopped here.
func (h *Handler) stopJob(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	j, ok := h.Store.GetJob(r.Context(), id)
	if !ok {
		http.Error(w, "This replica isn't running that job, so it can't stop it. Only the replica that runs a job can stop it, and a load balancer may have sent you to another one. Reload the job page and try again.", http.StatusNotFound)
		return
	}
	repo := repoID(j.Repo)
	if !h.canStopJob(r, j) {
		h.forbidden(w, r, webauth.ActionStopJob, repo)
		return
	}
	back := "/jobs/" + url.PathEscape(id)
	if j.Done {
		h.redirectBack(w, r, back, url.Values{"done": {"stop-finished"}})
		return
	}
	who := actor(r)
	if who == "" {
		// Without sign-in or basic auth there is no name to give.
		who = "an anonymous user"
	}
	stop, first, err := h.Actions.StopJob(id, who)
	if err != nil {
		h.Logger.Err("web ui stopping job %q: %s", id, err)
		http.Error(w, fmt.Sprintf("Stopping the job failed: %s. Restart the command from the pull request if it must not finish.", err), http.StatusInternalServerError)
		return
	}
	if !first {
		h.Logger.Info("web ui stop of job %q ignored, already stopped by %q %s", id, stop.By, auditFields(r))
		h.redirectBack(w, r, back, url.Values{"done": {"already-stopping"}})
		return
	}
	h.Logger.Info("web ui stopped job %q repo=%q pull=%d step=%q dir=%q workspace=%q %s", id, repo, j.PullNum, j.Step, j.Dir, j.Workspace, auditFields(r))
	h.redirectBack(w, r, back, url.Values{"done": {"stop-requested"}})
}

// maintenanceDurations are the end times a maintenance window can have,
// chosen by key so the form can't set arbitrary ones.
var maintenanceDurations = []struct {
	Key   string
	Label string
	D     time.Duration
}{
	{"", "No end time, until someone ends it", 0},
	{"1h", "1 hour", time.Hour},
	{"4h", "4 hours", 4 * time.Hour},
	{"12h", "12 hours", 12 * time.Hour},
	{"24h", "1 day", 24 * time.Hour},
	{"72h", "3 days", 72 * time.Hour},
	{"168h", "1 week", 168 * time.Hour},
}

// startMaintenance starts a maintenance window. Windows live in memory on
// this replica, so they only block commands this replica runs.
func (h *Handler) startMaintenance(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "The form could not be read. Reload the page and try again.", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	req := MaintenanceRequest{
		Repo:        Repository{FullName: strings.TrimSpace(f.Get("repo"))},
		Dir:         strings.TrimSpace(f.Get("dir")),
		Workspace:   strings.TrimSpace(f.Get("workspace")),
		ProjectName: strings.TrimSpace(f.Get("project")),
		Plans:       f.Get("plans") == "on",
		Reason:      f.Get("reason"),
	}
	found := false
	for _, d := range maintenanceDurations {
		if d.Key == f.Get("duration") {
			found = true
			if d.D > 0 {
				req.Until = h.now().Add(d.D)
			}
		}
	}
	if !found {
		http.Error(w, "Choose when the maintenance window ends from the list, then try again.", http.StatusBadRequest)
		return
	}
	// Pin the window to the repository's VCS host when Atlantis knows the
	// repository on exactly one host; otherwise it covers every host.
	pulls, _ := h.Store.ListPulls(r.Context())
	locks, _ := h.Store.ListLocks(r.Context())
	hosts := map[string]bool{}
	for _, repo := range knownRepos(pulls, locks) {
		if strings.EqualFold(repo.FullName, req.Repo.FullName) && repo.VCSHost != "" {
			hosts[repo.VCSHost] = true
		}
	}
	if len(hosts) == 1 {
		for host := range hosts {
			req.Repo.VCSHost = host
		}
	}
	who := actor(r)
	if who == "" {
		who = "an anonymous user"
	}
	mw, err := h.Actions.StartMaintenance(req, who)
	if err != nil {
		h.Logger.Info("web ui maintenance window rejected repo=%q: %s %s", req.Repo.FullName, err, auditFields(r))
		http.Error(w, fmt.Sprintf("The maintenance window wasn't started: %s. Go back, fix the form, and try again.", err), http.StatusBadRequest)
		return
	}
	h.Logger.Info("web ui started maintenance window %q repo=%q host=%q dir=%q workspace=%q project=%q plans=%t until=%q reason=%q %s",
		mw.ID, mw.Repo.FullName, mw.Repo.VCSHost, mw.Dir, mw.Workspace, mw.ProjectName, mw.Plans, untilText(mw.Until), mw.Reason, auditFields(r))
	h.redirectBack(w, r, "/locks", url.Values{"done": {"maint-started"}})
}

func untilText(t time.Time) string {
	if t.IsZero() {
		return "none"
	}
	return t.UTC().Format(time.RFC3339)
}

func (h *Handler) endMaintenance(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	mw, ok, err := h.Actions.EndMaintenance(id)
	if err != nil {
		h.Logger.Err("web ui ending maintenance window %q: %s", id, err)
		http.Error(w, fmt.Sprintf("Ending the maintenance window failed: %s.", err), http.StatusInternalServerError)
		return
	}
	if !ok {
		h.redirectBack(w, r, "/locks", url.Values{"done": {"maint-gone"}})
		return
	}
	h.Logger.Info("web ui ended maintenance window %q repo=%q set by %q %s", id, mw.Repo.FullName, mw.By, auditFields(r))
	h.redirectBack(w, r, "/locks", url.Values{"done": {"maint-ended"}})
}

// knownRepos lists the repositories Atlantis has pull requests or locks
// for, once each.
func knownRepos(pulls []PullRequest, locks []Lock) []Repository {
	seen := map[Repository]bool{}
	var out []Repository
	add := func(r Repository) {
		if r.FullName != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, p := range pulls {
		add(p.Repo)
	}
	for _, l := range locks {
		add(l.Repo)
	}
	return out
}

// knownRepoNames lists repository names for the maintenance form, sorted.
func knownRepoNames(pulls []PullRequest, locks []Lock) []string {
	var names []string
	for _, r := range knownRepos(pulls, locks) {
		names = append(names, r.FullName)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// lockGroup is the locks one pull request holds.
type lockGroup struct {
	Repo    Repository
	PullNum int
	Locks   []Lock
}

// groupLocks groups locks by pull request, keeping the order of each
// group's newest lock.
func groupLocks(locks []Lock) []lockGroup {
	var groups []lockGroup
	index := map[string]int{}
	for _, l := range locks {
		key := pullKey(l.Repo, l.PullNum)
		i, ok := index[key]
		if !ok {
			i = len(groups)
			index[key] = i
			groups = append(groups, lockGroup{Repo: l.Repo, PullNum: l.PullNum})
		}
		groups[i].Locks = append(groups[i].Locks, l)
	}
	return groups
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
	streamLines(ctx, s, h.Store.JobLog(ctx, id, from), h.heartbeat(), func() string {
		if j, ok := h.Store.GetJob(ctx, id); ok && j.Stop != nil {
			return "Stopped by " + j.Stop.By
		}
		return ""
	})
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

// streamLines sends lines as events, then a "done" event whose data is the
// job's final status, such as who stopped it, or empty.
func streamLines(ctx context.Context, s *sseWriter, lines <-chan LogLine, beat time.Duration, status func() string) {
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
					done := ""
					if status != nil {
						done = strings.NewReplacer("\r", " ", "\n", " ").Replace(status())
					}
					_ = s.write("event: done\ndata: " + done + "\n\n")
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

// signInMessage turns a sign-in error into text for the page. Messages
// meant for users are shown; anything else is logged with a reference the
// user can quote, so provider responses and internal hosts stay private.
func (h *Handler) signInMessage(provider string, err error) string {
	if ue, ok := errors.AsType[*webauth.UserError](err); ok {
		h.Logger.Info("web sign-in stopped provider=%q: %s", provider, err)
		msg := ue.Error()
		return strings.ToUpper(msg[:1]) + msg[1:] + "."
	}
	ref := make([]byte, 4)
	_, _ = rand.Read(ref)
	code := hex.EncodeToString(ref)
	h.Logger.Warn("web sign-in failed provider=%q ref=%q: %s", provider, code, err)
	return fmt.Sprintf("Sign-in didn't work. Try again, or give your Atlantis administrator this reference: %s.", code)
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
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
	noStore(w)
	ret := r.URL.Query().Get("return")
	provider := mux.Vars(r)["provider"]
	if err := h.Auth.StartLogin(w, r, provider, ret); err != nil {
		h.renderSignIn(w, r, http.StatusBadRequest, ret, h.signInMessage(provider, err), "")
	}
}

func (h *Handler) finishLogin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	provider := mux.Vars(r)["provider"]
	target, _, err := h.Auth.FinishLogin(w, r, provider)
	if err != nil {
		h.renderSignIn(w, r, http.StatusForbidden, "", h.signInMessage(provider, err), "")
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther) // #nosec G710 -- FinishLogin returns a SafeReturn path
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if p := h.Auth.Authenticate(r); p != nil {
		h.Logger.Info("web sign-out subject=%q provider=%q", p.Subject, p.Provider)
	}
	h.Auth.Logout(w)
	http.Redirect(w, r, h.BasePath+"/ui/login?notice=signed-out", http.StatusSeeOther)
}

func (h *Handler) access(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := webauth.FromContext(ctx)
	pol := h.policy()
	d := accessData{Summary: pol.Summarize(), SignIn: h.Auth != nil, Role: max(p.Base, pol.GlobalRole(p.AsSubject()))}
	seen := map[string]bool{}
	add := func(repo Repository) {
		id := repoID(repo)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		d.Repos = append(d.Repos, repoAccess{
			ID:         id,
			Role:       max(p.Base, pol.RoleIn(p.AsSubject(), id)),
			NeedUnlock: pol.Requires(webauth.ActionUnlock, id),
			CanUnlock:  h.allows(r, webauth.ActionUnlock, id),
			NeedStop:   pol.Requires(webauth.ActionStopJob, id),
			CanStop:    h.allows(r, webauth.ActionStopJob, id),
		})
	}
	if pulls, err := h.Store.ListPulls(ctx); err == nil {
		for _, pr := range pulls {
			add(pr.Repo)
		}
	}
	if locks, err := h.Store.ListLocks(ctx); err == nil {
		for _, l := range locks {
			add(l.Repo)
		}
	}
	slices.SortFunc(d.Repos, func(a, b repoAccess) int { return strings.Compare(a.ID, b.ID) })
	m := h.meta(r, "Access", "access", crumb{Label: "Access"})
	h.render(w, r, http.StatusOK, accessPage(m, d))
}

// ---------- existing UI routes ----------

// RedirectToUI sends a request for an existing-UI page to its new UI
// equivalent. Atlantis uses it for the existing UI's pages when web sign-in
// is on, so there is one way in, under one set of rules.
func (h *Handler) RedirectToUI(path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := h.BasePath + "/ui" + path
		if id := mux.Vars(r)["job-id"]; id != "" {
			target = jobHref(h.BasePath, id)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
}

// ProtectLockApplies guards the existing UI's apply lock endpoints with web
// sign-in and the lock_applies permission.
func (h *Handler) ProtectLockApplies(next http.HandlerFunc) http.Handler {
	return http.NewCrossOriginProtection().Handler(h.guard(webauth.ActionLockApplies, next))
}

// ProtectUnlock guards the existing UI's unlock endpoint, DELETE /locks?id=,
// with web sign-in and the unlock permission for the lock's repository.
func (h *Handler) ProtectUnlock(next http.HandlerFunc) http.Handler {
	return http.NewCrossOriginProtection().Handler(h.guard(webauth.ActionView, func(w http.ResponseWriter, r *http.Request) {
		id, _ := url.QueryUnescape(r.URL.Query().Get("id"))
		repo := ""
		if locks, err := h.Store.ListLocks(r.Context()); err == nil {
			for _, l := range locks {
				if l.ID == id {
					repo = repoID(l.Repo)
				}
			}
		}
		if !h.allows(r, webauth.ActionUnlock, repo) {
			h.forbidden(w, r, webauth.ActionUnlock, repo)
			return
		}
		next(w, r)
	}))
}
