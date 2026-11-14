// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/runatlantis/atlantis/server/webauth"
)

// apiPrefix is where the read-only JSON API is served, under /ui.
const apiPrefix = "/api/v1"

//go:embed openapi.json
var openAPIDoc []byte

// apiRoutes are the API's routes, relative to /ui/api/v1. openapi.json
// documents each of them; a test keeps the two in step.
func (h *Handler) apiRoutes() []struct {
	Path    string
	Handler http.HandlerFunc
} {
	return []struct {
		Path    string
		Handler http.HandlerFunc
	}{
		{"/instance", h.apiInstance},
		{"/pulls", h.apiPulls},
		{"/repos/{repo:.+}/pulls/{num:[0-9]+}", h.apiPull},
		{"/repos/{repo:.+}/pulls/{num:[0-9]+}/plan", h.apiPlan},
		{"/repos/{repo:.+}/pulls/{num:[0-9]+}/policies", h.apiPolicies},
		{"/locks", h.apiLocks},
		{"/apply-lock", h.apiApplyLock},
		{"/jobs", h.apiJobs},
		{"/jobs/{id}", h.apiJob},
		{"/maintenance", h.apiMaintenance},
		{"/drift", h.apiDrift},
	}
}

// registerAPI adds the read-only JSON API. It uses the same sign-in session
// and view permission as the pages, but answers 401 and 403 with JSON
// instead of redirecting to the sign-in page.
func (h *Handler) registerAPI(ui *mux.Router) {
	api := ui.PathPrefix(apiPrefix).Subrouter()
	api.Use(apiHeaders)
	api.Handle("/openapi.json", h.apiGuard(h.apiOpenAPI)).Methods(http.MethodGet, http.MethodHead)
	for _, rt := range h.apiRoutes() {
		api.Handle(rt.Path, h.apiGuard(rt.Handler)).Methods(http.MethodGet, http.MethodHead)
	}
	// Anything else under the prefix gets a JSON error rather than the
	// HTML pages' plain-text 404 or 405.
	api.PathPrefix("/").Handler(h.apiGuard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", http.MethodGet)
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "The web UI API is read-only. Use GET.")
			return
		}
		writeAPIError(w, http.StatusNotFound, "not_found", "There is no such API path. See openapi.json for the paths.")
	}))
}

func apiHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Content-Type", "application/json; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

// apiGuard requires a signed-in principal with the view permission, as the
// pages do. Without web sign-in, the server's basic auth, if any, already
// checked the request.
func (h *Handler) apiGuard(f http.HandlerFunc) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.allows(r, webauth.ActionView, "") {
			writeAPIError(w, http.StatusForbidden, "forbidden", h.denial(r, webauth.ActionView, ""))
			return
		}
		f(w, r)
	})
	if h.Auth == nil {
		return withoutSignIn(inner)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := h.Auth.Authenticate(r)
		if p == nil {
			msg := "Sign in to Atlantis in this browser, then try again. The API uses the web UI's sign-in session."
			if h.Auth.UsesProxy() {
				msg = "Atlantis did not receive a signed-in user from the authenticating proxy. Check the proxy configuration."
			}
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", msg)
			return
		}
		inner.ServeHTTP(w, r.WithContext(webauth.WithPrincipal(r.Context(), p)))
	})
}

func writeAPIError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: apiErrorBody{Code: code, Message: msg}})
}

// writeJSON writes v. encoding/json escapes <, >, and & so the response is
// safe even if a client renders it as HTML by mistake.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"internal","message":"The response could not be encoded."}}`))
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// apiFail logs a store error and answers 503 without the error text, which
// can name internal hosts or paths.
func (h *Handler) apiFail(w http.ResponseWriter, what string, err error) {
	h.Logger.Err("web ui api reading %s: %s", what, err)
	writeAPIError(w, http.StatusServiceUnavailable, "unavailable",
		fmt.Sprintf("Atlantis couldn't read %s. Check that the lock database is reachable, then try again.", what))
}

func (h *Handler) caps() apiCapabilities {
	return toAPICapabilities(h.Store.Capabilities())
}

func (h *Handler) apiOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openAPIDoc)
}

func (h *Handler) globalPermissions(r *http.Request) apiGlobalPermissions {
	return apiGlobalPermissions{
		LockApplies: h.allows(r, webauth.ActionLockApplies, ""),
		Maintenance: h.allows(r, webauth.ActionMaintenance, ""),
	}
}

func (h *Handler) apiInstance(w http.ResponseWriter, r *http.Request) {
	in := h.Store.Instance(r.Context())
	p := webauth.FromContext(r.Context())
	out := apiInstance{
		Version: in.Version, ShuttingDown: in.ShuttingDown, InProgressOperations: in.InProgressOps,
		DatabaseOK: in.DatabaseOK, DatabaseError: in.DatabaseError, LockingBackend: in.LockingBackend,
		StartedAt: apiTime(in.StartedAt), Experiments: nonNil(in.Experiments),
		Viewer: apiViewer{
			Name:     p.DisplayName(),
			Provider: p.Provider,
			Role:     max(p.Base, h.policy().GlobalRole(p.AsSubject())).String(),
		},
		Permissions: h.globalPermissions(r),
	}
	writeJSON(w, http.StatusOK, apiItem[apiInstance]{Item: out, Capabilities: h.caps()})
}

func (h *Handler) toAPIPull(r *http.Request, p PullRequest) apiPull {
	repo := repoID(p.Repo)
	out := apiPull{
		Repo: toAPIRepo(p.Repo), Number: p.Num, URL: p.URL, Author: p.Author,
		HeadBranch: p.HeadBranch, BaseBranch: p.BaseBranch, HeadCommit: p.HeadCommit,
		State: string(pullState(p)), Changes: toAPIChanges(p.Changes()), PolicyFailing: p.PolicyFailing(),
		LastActivityAt: apiTime(p.LastActivity), Projects: []apiProject{},
		Permissions: apiPullPermissions{
			Unlock:          h.allows(r, webauth.ActionUnlock, repo),
			ApprovePolicies: h.allows(r, webauth.ActionApprovePolicies, repo),
		},
	}
	for _, proj := range p.Projects {
		out.Projects = append(out.Projects, toAPIProject(proj))
	}
	return out
}

func (h *Handler) toAPILock(r *http.Request, l Lock) apiLock {
	return apiLock{
		ID: l.ID, Repo: toAPIRepo(l.Repo), Dir: l.Dir, Workspace: l.Workspace, Project: l.ProjectName,
		Pull: apiLockPull{Number: l.PullNum, URL: l.PullURL, Author: l.PullAuthor, Tracked: l.PullTracked},
		User: l.User, Since: apiTime(l.Since), Stale: lockStale(h.now(), l),
		Permissions: apiLockPermissions{Unlock: h.allows(r, webauth.ActionUnlock, repoID(l.Repo))},
	}
}

func (h *Handler) toAPIJob(r *http.Request, j Job) apiJob {
	out := apiJob{
		ID: j.ID, Repo: toAPIRepo(j.Repo), PullNumber: j.PullNum, Dir: j.Dir, Workspace: j.Workspace,
		Project: j.ProjectName, Step: j.Step, Description: j.Description, Status: apiJobStatus(j),
		LastOutputAt: apiTime(j.LastOutput), Lines: j.Lines,
		Permissions: apiJobPermissions{Stop: j.Stoppable() && h.canStopJob(r, j)},
	}
	if j.Stop != nil {
		out.Stop = &apiJobStop{By: j.Stop.By, At: apiTime(j.Stop.At), Killed: j.Stop.Killed}
	}
	return out
}

func (h *Handler) apiPulls(w http.ResponseWriter, r *http.Request) {
	pulls, err := h.Store.ListPulls(r.Context())
	if err != nil {
		h.apiFail(w, "pull requests", err)
		return
	}
	out := apiList[apiPull]{Items: []apiPull{}, Capabilities: h.caps()}
	for _, p := range pulls {
		out.Items = append(out.Items, h.toAPIPull(r, p))
	}
	writeJSON(w, http.StatusOK, out)
}

// apiPullFromPath reads the pull request the path and host parameter name.
// It writes the error response and returns nil when there is none.
func (h *Handler) apiPullFromPath(w http.ResponseWriter, r *http.Request) *PullRequest {
	vars := mux.Vars(r)
	num, err := strconv.Atoi(vars["num"])
	if err != nil || num <= 0 {
		writeAPIError(w, http.StatusNotFound, "not_found", "Atlantis has nothing for this pull request.")
		return nil
	}
	p, err := h.Store.GetPull(r.Context(), Repository{VCSHost: r.URL.Query().Get("host"), FullName: vars["repo"]}, num)
	if err != nil {
		h.apiFail(w, "the pull request", err)
		return nil
	}
	if p == nil {
		writeAPIError(w, http.StatusNotFound, "not_found",
			"Atlantis has nothing for this pull request. It may not have been planned yet, or it was closed and cleaned up.")
	}
	return p
}

func (h *Handler) apiPull(w http.ResponseWriter, r *http.Request) {
	p := h.apiPullFromPath(w, r)
	if p == nil {
		return
	}
	locks, err := h.Store.ListLocks(r.Context())
	if err != nil {
		h.apiFail(w, "locks", err)
		return
	}
	out := apiPullDetail{apiPull: h.toAPIPull(r, *p), Locks: []apiLock{}, Maintenance: []apiMaintenance{}}
	for _, l := range locks {
		if lockHeldBy(l, p.Repo, p.Num) {
			out.Locks = append(out.Locks, h.toAPILock(r, l))
		}
	}
	for _, mw := range h.Store.ListMaintenance(r.Context()) {
		if mw.CoversRepo(p.Repo) {
			out.Maintenance = append(out.Maintenance, toAPIMaintenance(mw))
		}
	}
	writeJSON(w, http.StatusOK, apiItem[apiPullDetail]{Item: out, Capabilities: h.caps()})
}

// apiProjectFromQuery finds the project the dir, workspace and project
// parameters name in the pull request. It writes a 404 and returns false
// when there is none.
func apiProjectFromQuery(w http.ResponseWriter, r *http.Request, p *PullRequest) (ProjectRef, bool) {
	q := r.URL.Query()
	ref := ProjectRef{Dir: q.Get("dir"), Workspace: q.Get("workspace"), Name: q.Get("project")}
	if findRef(p, ref) == nil {
		writeAPIError(w, http.StatusNotFound, "not_found",
			"Atlantis has no such project in this pull request. Get the pull request to see its projects' dir, workspace and name.")
		return ref, false
	}
	return ref, true
}

func (h *Handler) apiPlan(w http.ResponseWriter, r *http.Request) {
	p := h.apiPullFromPath(w, r)
	if p == nil {
		return
	}
	ref, ok := apiProjectFromQuery(w, r, p)
	if !ok {
		return
	}
	plan, err := h.Store.GetPlan(r.Context(), p.Repo, p.Num, ref)
	if err != nil {
		h.apiFail(w, "the plan", err)
		return
	}
	if plan == nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "Atlantis has no such project in this pull request.")
		return
	}
	writeJSON(w, http.StatusOK, apiItem[apiPlan]{Item: toAPIPlan(*p, ref, *plan), Capabilities: h.caps()})
}

func (h *Handler) apiPolicies(w http.ResponseWriter, r *http.Request) {
	p := h.apiPullFromPath(w, r)
	if p == nil {
		return
	}
	ref, ok := apiProjectFromQuery(w, r, p)
	if !ok {
		return
	}
	pp, err := h.Store.GetPolicies(r.Context(), p.Repo, p.Num, ref)
	if err != nil {
		h.apiFail(w, "the policy check", err)
		return
	}
	if pp == nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "Atlantis has no such project in this pull request.")
		return
	}
	approval := h.approvalFor(r, *p, *pp)
	out := apiPolicies{
		Repo: toAPIRepo(p.Repo), PullNumber: p.Num, Project: apiProjectRef(ref),
		OutputStatus: string(pp.Output), CheckedAt: apiTime(pp.CheckedAt), Admins: toAPIOwners(pp.Admins),
		Sets: []apiPolicySetDetail{},
	}
	for _, s := range pp.Sets {
		d := apiPolicySetDetail{apiPolicySet: toAPIPolicySet(s)}
		if pp.Output == PolicyOutputReady {
			o := s.Output
			d.Output = &o
		}
		if !s.Cleared() {
			d.CanApprove = approval.CanApprove(s.Name)
			if !d.CanApprove {
				d.Reason = approval.Reason(s.Name)
			}
		}
		out.Sets = append(out.Sets, d)
	}
	writeJSON(w, http.StatusOK, apiItem[apiPolicies]{Item: out, Capabilities: h.caps()})
}

func (h *Handler) apiLocks(w http.ResponseWriter, r *http.Request) {
	locks, err := h.Store.ListLocks(r.Context())
	if err != nil {
		h.apiFail(w, "locks", err)
		return
	}
	out := apiList[apiLock]{Items: []apiLock{}, Capabilities: h.caps()}
	for _, l := range locks {
		out.Items = append(out.Items, h.toAPILock(r, l))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) apiApplyLock(w http.ResponseWriter, r *http.Request) {
	al, err := h.Store.ApplyLock(r.Context())
	if err != nil {
		h.apiFail(w, "the apply lock", err)
		return
	}
	out := apiApplyLock{Enabled: al.Enabled, Locked: al.Locked, Since: apiTime(al.Since), Permissions: h.globalPermissions(r)}
	writeJSON(w, http.StatusOK, apiItem[apiApplyLock]{Item: out, Capabilities: h.caps()})
}

func (h *Handler) apiJobs(w http.ResponseWriter, r *http.Request) {
	out := apiList[apiJob]{Items: []apiJob{}, Capabilities: h.caps()}
	for _, j := range h.Store.ListJobs(r.Context(), JobFilter{}) {
		out.Items = append(out.Items, h.toAPIJob(r, j))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) apiJob(w http.ResponseWriter, r *http.Request) {
	j, ok := h.Store.GetJob(r.Context(), mux.Vars(r)["id"])
	if !ok {
		writeAPIError(w, http.StatusNotFound, "not_found",
			"This replica has no record of that job. Job output lives in memory on the replica that ran it and is cleared on restart.")
		return
	}
	writeJSON(w, http.StatusOK, apiItem[apiJob]{Item: h.toAPIJob(r, j), Capabilities: h.caps()})
}

func (h *Handler) apiMaintenance(w http.ResponseWriter, r *http.Request) {
	out := apiList[apiMaintenance]{Items: []apiMaintenance{}, Capabilities: h.caps()}
	for _, mw := range h.Store.ListMaintenance(r.Context()) {
		out.Items = append(out.Items, toAPIMaintenance(mw))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) apiDrift(w http.ResponseWriter, r *http.Request) {
	report, err := h.Store.ListDrift(r.Context())
	if err != nil {
		h.apiFail(w, "drift results", err)
		return
	}
	now := h.now()
	c := countDrift(now, report.Checks)
	out := apiDriftList{
		apiList: apiList[apiDriftCheck]{Items: []apiDriftCheck{}, Capabilities: h.caps()},
		Enabled: report.Enabled,
		Counts:  apiDriftCounts(c),
	}
	for _, d := range report.Checks {
		ch := toAPIChanges(d.Changes)
		out.Items = append(out.Items, apiDriftCheck{
			Repo: toAPIRepo(d.Repo), Project: d.ProjectName, Dir: d.Dir, Workspace: d.Workspace, Ref: d.Ref,
			BaseBranch: d.BaseBranch, Commit: d.Commit, DetectionID: d.DetectionID, Status: string(d.Status()),
			ChangesOutside: d.ChangesOutside, Changes: ch, Summary: d.Summary, Error: d.Error,
			CheckedAt: apiTime(d.CheckedAt), Stale: driftStale(now, d),
		})
	}
	writeJSON(w, http.StatusOK, out)
}
