// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/webauth"
)

// policyApprover is who a request approves policies as on the VCS.
type policyApprover struct {
	Login string
	// Teams are the slugs of the GitHub teams, in the repository's
	// organization, that the person is a direct member of. Like
	// "atlantis approve_policies", membership in a child team doesn't count
	// for its parent team.
	Teams []string
}

// approverFor maps the signed-in person to a GitHub login on the
// repository's host, which is what policy owners are matched against. It
// returns why not when it can't. Without web sign-in nobody has a login
// Atlantis can trust, so approving from the UI is off.
func (h *Handler) approverFor(r *http.Request, repo Repository) (policyApprover, string) {
	const instead = " Comment atlantis approve_policies on the pull request instead."
	if h.Auth == nil {
		return policyApprover{}, "Approving policies from the web UI needs GitHub sign-in, so Atlantis can check that you're a policy owner. Web sign-in is off." + instead
	}
	p := webauth.FromContext(r.Context())
	ghHost := h.Auth.GitHubHostname()
	if p == nil || p.GitHubLogin() == "" {
		if ghHost == "" {
			return policyApprover{}, "Approving policies from the web UI needs GitHub sign-in, so Atlantis can check that you're a policy owner. This Atlantis doesn't offer GitHub sign-in." + instead
		}
		return policyApprover{}, "You signed in without GitHub, so Atlantis doesn't know your GitHub login and can't check that you're a policy owner. Sign out and sign in with GitHub, or comment atlantis approve_policies on the pull request."
	}
	if repo.VCSHost == "" || !strings.EqualFold(repo.VCSHost, ghHost) {
		host := repo.VCSHost
		if host == "" {
			host = "an unknown host"
		}
		return policyApprover{}, fmt.Sprintf("You signed in with GitHub at %s, but this repository is on %s, so Atlantis doesn't know your login there.%s", ghHost, host, instead)
	}
	org, _, _ := strings.Cut(repo.FullName, "/")
	a := policyApprover{Login: p.GitHubLogin()}
	for _, t := range p.GitHubTeams {
		if o, team, ok := strings.Cut(t, "/"); ok && strings.EqualFold(o, org) {
			a.Teams = append(a.Teams, team)
		}
	}
	return a, ""
}

// includes reports whether the approver is one of the owners. It uses the
// check "atlantis approve_policies" uses, so the UI offers approving exactly
// when the command accepts it.
func (o PolicyOwners) includes(a policyApprover) bool {
	if a.Login == "" {
		return false
	}
	owners := valid.PolicyOwners{Users: o.Users, Teams: o.Teams}
	return owners.IsOwner(a.Login, a.Teams)
}

// ownersText lists owners in plain words.
func ownersText(o PolicyOwners) string {
	parts := slices.Clone(o.Users)
	for _, t := range o.Teams {
		parts = append(parts, "team "+t)
	}
	if len(parts) == 0 {
		return "nobody"
	}
	return strings.Join(parts, ", ")
}

// setDecision says whether someone may approve one failing policy set.
type setDecision struct {
	Name       string
	CanApprove bool
	Reason     string
}

// decideSets applies the rules "atlantis approve_policies" applies to the
// sets that still need approvals: only owners of the set or top-level owners
// approve it, authors can't approve sets that prevent self-approval, and an
// owner's approval counts once.
func decideSets(pp ProjectPolicies, author string, a policyApprover) []setDecision {
	var out []setDecision
	for _, s := range pp.Sets {
		if s.Cleared() {
			continue
		}
		d := setDecision{Name: s.Name}
		switch {
		case !s.Configured:
			d.Reason = fmt.Sprintf("%s is no longer in the server-side repo config, so it can't be approved. Plan again.", s.Name)
		case !s.Owners.includes(a) && !pp.Admins.includes(a):
			d.Reason = fmt.Sprintf("Only policy owners can approve %s: %s.", s.Name, ownersText(mergeOwners(s.Owners, pp.Admins)))
		case s.PreventSelfApprove && a.Login == author:
			d.Reason = fmt.Sprintf("You opened this pull request, and %s doesn't let authors approve it. Ask another policy owner.", s.Name)
		case approvedBy(s, a.Login):
			d.Reason = fmt.Sprintf("You already approved %s. It needs %d more %s from a different policy owner.", s.Name, s.Required-s.CurrentApprovals(), plural(s.Required-s.CurrentApprovals(), "approval", "approvals"))
		default:
			d.CanApprove = true
		}
		out = append(out, d)
	}
	return out
}

func approvedBy(s PolicySet, login string) bool {
	return slices.ContainsFunc(s.Approvals, func(a PolicyApproval) bool { return a.Current && a.By == login })
}

func mergeOwners(a, b PolicyOwners) PolicyOwners {
	return PolicyOwners{
		Users: slices.Compact(slices.Sorted(slices.Values(slices.Concat(a.Users, b.Users)))),
		Teams: slices.Compact(slices.Sorted(slices.Values(slices.Concat(a.Teams, b.Teams)))),
	}
}

// approvalView is what a page needs to offer approving policies.
type approvalView struct {
	// Allowed is false when the person's role doesn't allow approving here.
	Allowed bool
	// NeedRole is the role approving needs in the repository.
	NeedRole webauth.Role
	// Login is the GitHub login approvals are recorded for.
	Login string
	// Blocked explains why the person can't approve as anyone; empty when
	// Login is set.
	Blocked string
	// Sets are the decisions for the sets that still need approvals.
	Sets []setDecision
}

// Approvable lists the sets the person can approve.
func (v approvalView) Approvable() []string {
	var out []string
	for _, d := range v.Sets {
		if d.CanApprove {
			out = append(out, d.Name)
		}
	}
	return out
}

// CanApprove reports whether the person can approve the named set.
func (v approvalView) CanApprove(name string) bool {
	return v.Allowed && v.Blocked == "" && slices.Contains(v.Approvable(), name)
}

// Reason explains why the person can't approve the named set, if they can't.
func (v approvalView) Reason(name string) string {
	switch {
	case !v.Allowed:
		return fmt.Sprintf("Approving policies here needs the %s role.", v.NeedRole)
	case v.Blocked != "":
		return v.Blocked
	}
	for _, d := range v.Sets {
		if d.Name == name {
			return d.Reason
		}
	}
	return ""
}

func (h *Handler) approvalFor(r *http.Request, p PullRequest, pp ProjectPolicies) approvalView {
	repo := repoID(p.Repo)
	v := approvalView{Allowed: h.allows(r, webauth.ActionApprovePolicies, repo), NeedRole: h.policy().Requires(webauth.ActionApprovePolicies, repo)}
	a, blocked := h.approverFor(r, p.Repo)
	v.Login, v.Blocked = a.Login, blocked
	v.Sets = decideSets(pp, p.Author, a)
	return v
}

// policiesHref links to a project's policy check.
func policiesHref(base string, repo Repository, num int, ref ProjectRef) string {
	href, query, _ := strings.Cut(planHref(base, repo, num, ref), "?")
	return strings.TrimSuffix(href, "/plan") + "/policies?" + query
}

func (h *Handler) policies(w http.ResponseWriter, r *http.Request) {
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
	proj := findRef(p, ref)
	var pp *ProjectPolicies
	if proj != nil {
		pp, err = h.Store.GetPolicies(ctx, p.Repo, p.Num, ref)
		if err != nil {
			h.fail(w, r, "the policy check", err)
			return
		}
	}
	if pp == nil {
		m := h.meta(r, "Project not found", "pulls", pullsCrumb, pullCrumb, crumb{Label: "Policies"})
		h.render(w, r, http.StatusNotFound, errorPage(m, "Atlantis has no such project in this pull request",
			"The project may have been renamed or removed from the pull request. Open the pull request to see its projects."))
		return
	}
	label := projectLabel(*proj)
	m := h.meta(r, "Policies for "+label, "pulls", pullsCrumb, pullCrumb, crumb{Label: "Policies for " + label})
	h.render(w, r, http.StatusOK, policiesPage(m, policiesData{
		Pull:     *p,
		Project:  *proj,
		Policies: *pp,
		Approval: h.approvalFor(r, *p, *pp),
	}))
}

func findRef(p *PullRequest, ref ProjectRef) *Project {
	for i := range p.Projects {
		if p.Projects[i].Ref() == ref {
			return &p.Projects[i]
		}
	}
	return nil
}

// pullApproval is what the pull request page needs to offer approving
// policies in every project.
func (h *Handler) pullApproval(r *http.Request, p PullRequest) approvalView {
	repo := repoID(p.Repo)
	v := approvalView{Allowed: h.allows(r, webauth.ActionApprovePolicies, repo), NeedRole: h.policy().Requires(webauth.ActionApprovePolicies, repo)}
	if !p.PolicyFailing() {
		return v
	}
	a, blocked := h.approverFor(r, p.Repo)
	v.Login, v.Blocked = a.Login, blocked
	// The page refreshes often, so read the top-level owners once and take
	// the sets from the pull request instead of reading each project's
	// policy output.
	var admins PolicyOwners
	for _, proj := range p.Projects {
		if !proj.PolicyFailing() {
			continue
		}
		pp, err := h.Store.GetPolicies(r.Context(), p.Repo, p.Num, proj.Ref())
		if err != nil {
			h.Logger.Warn("web ui reading policy owners for %q #%d: %s", p.Repo.FullName, p.Num, err)
		} else if pp != nil {
			admins = pp.Admins
		}
		break
	}
	for _, proj := range p.Projects {
		if !proj.PolicyFailing() {
			continue
		}
		for _, d := range decideSets(ProjectPolicies{Sets: proj.Policies, Admins: admins}, p.Author, a) {
			d.Name = projectLabel(proj) + ": " + d.Name
			v.Sets = append(v.Sets, d)
		}
	}
	return v
}

// approvePolicies runs "atlantis approve_policies" for a pull request, one
// project, or one policy set, on behalf of the signed-in policy owner. The
// person needs the approve_policies permission in the repository and must
// be a policy owner as the server-side repo config defines it; the command
// checks ownership again with the VCS.
func (h *Handler) approvePolicies(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "The form could not be read. Reload the page and try again.", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	vars := mux.Vars(r)
	num, _ := strconv.Atoi(vars["num"])
	f := r.PostForm
	p, err := h.Store.GetPull(ctx, Repository{VCSHost: f.Get("host"), FullName: vars["repo"]}, num)
	if err != nil {
		h.fail(w, r, "the pull request", err)
		return
	}
	if p == nil {
		http.Error(w, "Atlantis has nothing for this pull request. It may have been closed. Reload the page.", http.StatusNotFound)
		return
	}
	repo := repoID(p.Repo)
	if !h.allows(r, webauth.ActionApprovePolicies, repo) {
		h.forbidden(w, r, webauth.ActionApprovePolicies, repo)
		return
	}
	approver, blocked := h.approverFor(r, p.Repo)
	if blocked != "" {
		h.Logger.Info("web ui policy approval denied repo=%q pull=%d reason=%q %s", repo, p.Num, "no github login", auditFields(r))
		http.Error(w, blocked, http.StatusForbidden)
		return
	}

	var targets []Project
	var ref *ProjectRef
	back := pullHref(h.BasePath, p.Repo, p.Num)
	if f.Get("scope") == "project" {
		want := ProjectRef{Dir: f.Get("dir"), Workspace: f.Get("workspace"), Name: f.Get("project")}
		proj := findRef(p, want)
		if proj == nil {
			http.Error(w, "Atlantis has no such project in this pull request. Reload the page and try again.", http.StatusNotFound)
			return
		}
		targets, ref = []Project{*proj}, &want
		back = policiesHref(h.BasePath, p.Repo, p.Num, want)
	} else {
		targets = p.Projects
	}
	set := f.Get("policy_set")

	var approvable, reasons []string
	failing := 0
	for _, proj := range targets {
		pp, err := h.Store.GetPolicies(ctx, p.Repo, p.Num, proj.Ref())
		if err != nil {
			h.fail(w, r, "the policy check", err)
			return
		}
		if pp == nil {
			continue
		}
		for _, d := range decideSets(*pp, p.Author, approver) {
			if set != "" && d.Name != set {
				continue
			}
			failing++
			if d.CanApprove {
				approvable = append(approvable, projectLabel(proj)+": "+d.Name)
			} else {
				reasons = append(reasons, d.Reason)
			}
		}
	}
	if failing == 0 {
		h.redirectTo(w, r, back, "policies-clear")
		return
	}
	if len(approvable) == 0 {
		h.Logger.Info("web ui policy approval denied repo=%q pull=%d policy_set=%q login=%q reason=%q %s", repo, p.Num, set, approver.Login, "not an owner", auditFields(r))
		http.Error(w, "You can't approve these policies. "+strings.Join(slices.Compact(reasons), " "), http.StatusForbidden)
		return
	}
	req := PolicyApprovalRequest{Repo: p.Repo, Num: p.Num, Project: ref, PolicySet: set, Login: approver.Login}
	if err := h.Actions.ApprovePolicies(req); err != nil {
		h.Logger.Err("web ui approving policies repo=%q pull=%d: %s", repo, p.Num, err)
		status := http.StatusInternalServerError
		msg := fmt.Sprintf("Approving policies failed: %s. Comment atlantis approve_policies on the pull request instead.", err)
		switch {
		case errors.Is(err, ErrPolicyApprovalNotGitHub):
			status = http.StatusBadRequest
			msg = "Approving policies from the web UI works only for GitHub repositories. Comment atlantis approve_policies on the pull request instead."
		case errors.Is(err, ErrPullNotTracked):
			status = http.StatusNotFound
			msg = "Atlantis has nothing for this pull request. It may have been closed. Reload the page."
		}
		http.Error(w, msg, status)
		return
	}
	projectText := "all"
	if ref != nil {
		projectText = projectLabel(targets[0])
	}
	h.Logger.Info("web ui approved policies repo=%q pull=%d project=%q policy_set=%q login=%q sets=%q %s",
		repo, p.Num, projectText, set, approver.Login, strings.Join(approvable, ", "), auditFields(r))
	h.redirectTo(w, r, back, "policies-approving")
}

// redirectTo sends the browser to a UI link built by the server, with a
// flash message.
func (h *Handler) redirectTo(w http.ResponseWriter, r *http.Request, href, done string) {
	sep := "?"
	if strings.Contains(href, "?") {
		sep = "&"
	}
	// #nosec G710 -- href is built from BasePath and escaped path segments, not from user input.
	http.Redirect(w, r, href+sep+url.Values{"done": {done}}.Encode(), http.StatusSeeOther)
}
