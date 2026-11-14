// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	pego "github.com/petergtz/pegomock/v4"
	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/events"
	"github.com/runatlantis/atlantis/server/events/command"
	eventmocks "github.com/runatlantis/atlantis/server/events/mocks"
	"github.com/runatlantis/atlantis/server/events/models"
	vcsmocks "github.com/runatlantis/atlantis/server/events/vcs/mocks"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webauth"
	"github.com/runatlantis/atlantis/server/webauth/webauthtest"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

var netRef = webui.ProjectRef{Dir: "network", Workspace: "default"}

func securitySet() webui.PolicySet {
	return webui.PolicySet{
		Name: "security", Configured: true, Required: 2, PreventSelfApprove: true,
		Owners:    webui.PolicyOwners{Users: []string{"carol", "dave"}, Teams: []string{"sec"}},
		Approvals: []webui.PolicyApproval{{By: "carol", Current: true}, {By: "dave", Current: false}},
	}
}

// policyStore has pull requests with failing policies in a normal repo, a
// prod repo, a sandbox repo, and a repo on another GitHub host.
func policyStore() *fakeStore {
	s := sampleStore()
	failing := func(name string, num int, host string) webui.PullRequest {
		return webui.PullRequest{
			Repo: webui.Repository{VCSHost: host, FullName: name}, Num: num, Author: "mrivera",
			Projects: []webui.Project{{Dir: "network", Workspace: "default", State: webui.StatePolicyFailed, Policies: []webui.PolicySet{securitySet()}}},
		}
	}
	s.pulls = []webui.PullRequest{
		{
			Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Num: 1482, Author: "mrivera",
			Projects: []webui.Project{
				{Dir: "network", Workspace: "default", State: webui.StatePolicyFailed, Policies: []webui.PolicySet{
					securitySet(),
					{Name: "tagging", Passed: true, Configured: true, Required: 1},
				}},
				{Dir: "dns", Workspace: "default", State: webui.StatePlanned},
				{Dir: "edge", Workspace: "prod", State: webui.StatePolicyFailed, Policies: []webui.PolicySet{
					{Name: "cost", Configured: true, Required: 1, Owners: webui.PolicyOwners{Users: []string{"frank"}}},
				}},
			},
		},
		failing("acme/prod-network", 9, "github.com"),
		failing("acme/sandbox", 3, "github.com"),
		failing("acme/infra", 5, "github.acme.internal"),
	}
	net := webui.ProjectPolicies{
		Sets:      []webui.PolicySet{securitySet(), {Name: "tagging", Passed: true, Configured: true, Required: 1, Output: "1 test, 1 passed"}},
		Admins:    webui.PolicyOwners{Users: []string{"root"}},
		Output:    webui.PolicyOutputReady,
		CheckedAt: now.Add(-3 * time.Minute),
	}
	net.Sets[0].Output = "FAIL - main.tf - <script>alert(\"x\")</script> aws_s3_bucket.logs is public\n2 tests, 1 passed, 0 warnings, 1 failure, 0 exceptions"
	s.policies = map[webui.ProjectRef]*webui.ProjectPolicies{netRef: &net}
	return s
}

func approveForm(extra url.Values) url.Values {
	f := url.Values{"host": {"github.com"}}
	maps.Copy(f, extra)
	return f
}

func TestPolicies_PagesShowResults(t *testing.T) {
	srv := newServer(t, policyStore(), &fakeActions{}, "")

	resp, body := get(t, srv, "/ui/repos/acme/infra/pulls/1482/policies?dir=network&workspace=default&host=github.com")
	Equals(t, http.StatusOK, resp.StatusCode)
	assertContains(t, body, "Policies for network", "1 of 2 policy sets need approval", "security", "1 of 2 approvals",
		"carol", "dave", "for an earlier failure, no longer counts", "carol, dave, team sec", "root", "can approve every set",
		"mrivera can't approve this set", "aws_s3_bucket.logs is public", "1 test, 1 passed", "Checked 3m ago")
	// Policy output is escaped.
	assertContains(t, body, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;")
	Assert(t, !strings.Contains(body, `<script>alert`), "policy output was not escaped")
	// Without web sign-in there is no GitHub login to approve as.
	assertContains(t, body, "Approving policies from the web UI needs GitHub sign-in")
	Assert(t, !strings.Contains(body, "/policies/approve"), "approve control shown without sign-in")

	// A project whose output isn't on this replica says so.
	_, body = get(t, srv, "/ui/repos/acme/infra/pulls/1482/policies?dir=edge&workspace=prod&host=github.com")
	assertContains(t, body, "cost", "0 of 1 approval", "frank", "This replica has no policy output")

	// Unknown projects and pull requests are 404s.
	resp, _ = get(t, srv, "/ui/repos/acme/infra/pulls/1482/policies?dir=nope&workspace=default")
	Equals(t, http.StatusNotFound, resp.StatusCode)
	resp, _ = get(t, srv, "/ui/repos/acme/infra/pulls/1/policies?dir=network&workspace=default")
	Equals(t, http.StatusNotFound, resp.StatusCode)

	// The pull request page summarizes and links each project.
	_, body = get(t, srv, "/ui/repos/acme/infra/pulls/1482?host=github.com")
	assertContains(t, body, "Policy checks", "2 of 2 projects need approval", "Failing: security", "Failing: cost",
		"1 of 2 policy sets need approval", ">Policies<",
		"/ui/repos/acme/infra/pulls/1482/policies?dir=network&amp;host=github.com&amp;workspace=default")

	// The overview links straight to the policies.
	_, body = get(t, srv, "/ui")
	assertContains(t, body, "acme/infra #1482 is waiting for a policy approval in network", "Failing policy set: security",
		"/ui/repos/acme/infra/pulls/1482/policies?dir=edge&amp;host=github.com&amp;workspace=prod")
	_, body = get(t, srv, "/ui/pulls?state=policy")
	assertContains(t, body, "4 of 4 pull requests")
}

func TestPolicies_ApproveNeedsGitHubSignIn(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, policyStore(), actions, "")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ui/repos/acme/infra/pulls/1482/policies/approve", strings.NewReader(approveForm(nil).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.SetBasicAuth("alice", "pw")
	resp, err := noRedirectClient().Do(req)
	Ok(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	Equals(t, http.StatusForbidden, resp.StatusCode)
	assertContains(t, string(b), "needs GitHub sign-in", "Comment atlantis approve_policies on the pull request instead")
	Equals(t, 0, len(actions.approvals))
}

// newApprovalServer serves the UI with GitHub and OIDC sign-in. GitHub team
// acme/sre and OIDC group sre are operators, acme/platform admins, and
// every acme member a viewer. Prod repos need admin to approve policies;
// the sandbox lets viewers approve.
func newApprovalServer(t *testing.T, store *fakeStore, actions *fakeActions) (*httptest.Server, *webauthtest.GitHub, *webauthtest.OIDC) {
	t.Helper()
	gh := webauthtest.NewGitHub()
	t.Cleanup(gh.Server.Close)
	idp := webauthtest.NewOIDC()
	t.Cleanup(idp.Server.Close)
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	public, _ := url.Parse(srv.URL)
	policy, err := webauth.NewPolicy(webauth.PolicyConfig{
		Flags: webauth.RoleMapper{Admins: []string{"github:acme/platform"}, Operators: []string{"github:acme/sre", "sre"}, Viewers: []string{"github:acme"}},
		Repos: []valid.Repo{
			{IDRegex: regexp.MustCompile(".*")},
			{IDRegex: regexp.MustCompile(`^github\.com/acme/prod-`), Access: &valid.RepoAccess{Permissions: valid.AccessPermissions{ApprovePolicies: "admin"}}},
			{ID: "github.com/acme/sandbox", Access: &valid.RepoAccess{Permissions: valid.AccessPermissions{ApprovePolicies: "viewer"}}},
		},
		PolicyOwnerTeams: []string{"sec"},
	})
	Ok(t, err)
	ghp, err := webauth.NewGitHubProvider(webauth.GitHubConfig{ClientID: gh.ClientID, ClientSecret: gh.ClientSecret, BaseURLOverride: gh.Server.URL, AllowedOrgs: []string{"acme"}})
	Ok(t, err)
	oidc, err := webauth.NewOIDCProvider(webauth.OIDCConfig{IssuerURL: idp.Server.URL, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, Scopes: []string{"email"}})
	Ok(t, err)
	auth, err := webauth.NewManager(webauth.Config{PublicURL: public, SessionSecrets: []string{sessionSecret}, Providers: []webauth.LoginProvider{ghp, oidc}, Policy: policy, Logger: logging.NewNoopLogger(t)})
	Ok(t, err)
	h := &webui.Handler{Store: store, Actions: actions, Logger: logging.NewNoopLogger(t), Now: func() time.Time { return now }, Auth: auth}
	r := mux.NewRouter()
	h.Register(r)
	handler = r
	return srv, gh, idp
}

func signInGitHub(t *testing.T, b browserClient, gh *webauthtest.GitHub, login string, teams ...string) {
	t.Helper()
	var ts []map[string]any
	for _, team := range teams {
		ts = append(ts, map[string]any{"slug": team, "organization": map[string]any{"login": "acme"}})
	}
	gh.SetUser(map[string]any{"id": len(login), "login": login}, nil, []map[string]any{{"login": "acme"}}, ts)
	status, _ := b.get(t, "/ui/login/github")
	Equals(t, http.StatusOK, status)
}

func TestPolicies_ApproveByRoleOwnerAndRepo(t *testing.T) {
	cases := []struct {
		name   string
		login  string
		teams  []string
		pull   string
		form   url.Values
		allow  bool
		reason string
	}{
		{"owner by login with operator role", "dave", []string{"sre"}, "acme/infra/pulls/1482", nil, true, ""},
		{"owner by team", "erin", []string{"sre", "sec"}, "acme/infra/pulls/1482", nil, true, ""},
		{"top-level owner", "root", []string{"sre"}, "acme/infra/pulls/1482", nil, true, ""},
		{"viewer role isn't enough", "dave", nil, "acme/infra/pulls/1482", nil, false, "needs the operator role"},
		{"operator who isn't an owner", "olga", []string{"sre"}, "acme/infra/pulls/1482", nil, false, "Only policy owners can approve security: carol, dave, root, team sec."},
		{"author can't approve their own pull request", "mrivera", []string{"sre", "sec"}, "acme/infra/pulls/1482", nil, false, "You opened this pull request"},
		{"an owner's approval counts once", "carol", []string{"sre"}, "acme/infra/pulls/1482", nil, false, "You already approved security. It needs 1 more approval"},
		{"prod repos need admin", "dave", []string{"sre"}, "acme/prod-network/pulls/9", nil, false, "needs the admin role"},
		{"admins approve prod", "dave", []string{"platform"}, "acme/prod-network/pulls/9", nil, true, ""},
		{"the sandbox lets viewers approve", "dave", nil, "acme/sandbox/pulls/3", nil, true, ""},
		{"another GitHub host", "dave", []string{"sre"}, "acme/infra/pulls/5", url.Values{"host": {"github.acme.internal"}}, false, "this repository is on github.acme.internal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actions := &fakeActions{}
			srv, gh, _ := newApprovalServer(t, policyStore(), actions)
			b := newBrowser(t, srv.URL)
			signInGitHub(t, b, gh, tc.login, tc.teams...)

			host := "github.com"
			if tc.form != nil {
				host = tc.form.Get("host")
			}
			form := approveForm(url.Values{"host": {host}, "scope": {"project"}, "dir": {"network"}, "workspace": {"default"}, "policy_set": {"security"}})
			_, page := b.get(t, "/ui/repos/"+tc.pull+"/policies?dir=network&workspace=default&host="+host)
			Equals(t, tc.allow, strings.Contains(page, `action="/ui/repos/`+tc.pull+`/policies/approve"`))
			if !tc.allow {
				assertContains(t, page, strings.ReplaceAll(tc.reason, "'", "&#39;"))
			}

			resp := b.post(t, "/ui/repos/"+tc.pull+"/policies/approve", form)
			if !tc.allow {
				Equals(t, http.StatusForbidden, resp.StatusCode)
				Equals(t, 0, len(actions.approvals))
				return
			}
			Equals(t, http.StatusSeeOther, resp.StatusCode)
			assertContains(t, resp.Header.Get("Location"), "/policies?", "done=policies-approving")
			Equals(t, 1, len(actions.approvals))
			got := actions.approvals[0]
			Equals(t, tc.login, got.Login)
			Equals(t, "security", got.PolicySet)
			Equals(t, &netRef, got.Project)
		})
	}
}

func TestPolicies_ApproveEveryProject(t *testing.T) {
	actions := &fakeActions{}
	srv, gh, _ := newApprovalServer(t, policyStore(), actions)
	b := newBrowser(t, srv.URL)
	signInGitHub(t, b, gh, "frank", "sre", "sec")

	_, page := b.get(t, "/ui/repos/acme/infra/pulls/1482?host=github.com")
	assertContains(t, page, "Approve policies…", "Atlantis runs atlantis approve_policies as GitHub user frank", "network: security", "edge (prod): cost")

	resp := b.post(t, "/ui/repos/acme/infra/pulls/1482/policies/approve", approveForm(nil))
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/repos/acme/infra/pulls/1482?host=github.com&done=policies-approving", resp.Header.Get("Location"))
	Equals(t, []webui.PolicyApprovalRequest{{Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Num: 1482, Login: "frank"}}, actions.approvals)

	_, page = b.get(t, "/ui/repos/acme/infra/pulls/1482?host=github.com&done=policies-approving")
	assertContains(t, page, "Approval started.")
}

func TestPolicies_NothingToApprove(t *testing.T) {
	actions := &fakeActions{}
	srv, gh, _ := newApprovalServer(t, policyStore(), actions)
	b := newBrowser(t, srv.URL)
	signInGitHub(t, b, gh, "dave", "sre")
	resp := b.post(t, "/ui/repos/acme/infra/pulls/1482/policies/approve", approveForm(url.Values{"scope": {"project"}, "dir": {"network"}, "workspace": {"default"}, "policy_set": {"tagging"}}))
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	assertContains(t, resp.Header.Get("Location"), "done=policies-clear")
	Equals(t, 0, len(actions.approvals))

	resp = b.post(t, "/ui/repos/acme/infra/pulls/1482/policies/approve", approveForm(url.Values{"scope": {"project"}, "dir": {"nope"}, "workspace": {"default"}}))
	Equals(t, http.StatusNotFound, resp.StatusCode)
	resp = b.post(t, "/ui/repos/acme/infra/pulls/404/policies/approve", approveForm(nil))
	Equals(t, http.StatusNotFound, resp.StatusCode)
}

func TestPolicies_SignInWithoutGitHubCantApprove(t *testing.T) {
	actions := &fakeActions{}
	srv, _, idp := newApprovalServer(t, policyStore(), actions)
	b := newBrowser(t, srv.URL)
	signIn(t, b, idp, map[string]any{"sub": "o", "name": "Omar", "groups": []string{"sre"}})

	_, page := b.get(t, "/ui/repos/acme/infra/pulls/1482/policies?dir=network&workspace=default&host=github.com")
	assertContains(t, page, "You signed in without GitHub", "Not mapped to a GitHub user")
	Assert(t, !strings.Contains(page, "/policies/approve"), "approve control shown to an OIDC user")

	resp := b.post(t, "/ui/repos/acme/infra/pulls/1482/policies/approve", approveForm(nil))
	Equals(t, http.StatusForbidden, resp.StatusCode)
	Equals(t, 0, len(actions.approvals))
}

func TestPolicies_ApproveRejectsCrossOriginAndGet(t *testing.T) {
	actions := &fakeActions{}
	srv, gh, _ := newApprovalServer(t, policyStore(), actions)
	b := newBrowser(t, srv.URL)
	signInGitHub(t, b, gh, "dave", "sre")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ui/repos/acme/infra/pulls/1482/policies/approve", strings.NewReader(approveForm(nil).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := b.noFollow().Do(req)
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusForbidden, resp.StatusCode)
	// GET approves nothing. Like the other actions except the last route,
	// gorilla/mux answers it with 404.
	status, _ := b.get(t, "/ui/repos/acme/infra/pulls/1482/policies/approve")
	Assert(t, status == http.StatusNotFound || status == http.StatusMethodNotAllowed, "GET status %d", status)
	Equals(t, 0, len(actions.approvals))
}

func TestPolicies_ApproveErrors(t *testing.T) {
	cases := map[error]int{
		webui.ErrPolicyApprovalNotGitHub: http.StatusBadRequest,
		webui.ErrPullNotTracked:          http.StatusNotFound,
		errors.New("vcs down"):           http.StatusInternalServerError,
	}
	for err, want := range cases {
		t.Run(err.Error(), func(t *testing.T) {
			srv, gh, _ := newApprovalServer(t, policyStore(), &fakeActions{approveErr: err})
			b := newBrowser(t, srv.URL)
			signInGitHub(t, b, gh, "dave", "sre")
			Equals(t, want, b.post(t, "/ui/repos/acme/infra/pulls/1482/policies/approve", approveForm(nil)).StatusCode)
		})
	}
}

func TestPolicies_AccessPageShowsTheRule(t *testing.T) {
	srv, gh, _ := newApprovalServer(t, policyStore(), &fakeActions{})
	b := newBrowser(t, srv.URL)
	signInGitHub(t, b, gh, "dave", "sre")
	_, body := b.get(t, "/ui/access")
	assertContains(t, body, "Approve failing policy checks, for policy owners", "Approving policies needs", "Your role allows approving",
		"Approving policies also needs you to be a policy owner")
}

// ownerParityCases sign in with GitHub teams, where a team written
// "child>parent" is a child team of parent. Policy set security is owned by
// carol, dave, and team sec; root owns every set.
var ownerParityCases = []struct {
	name  string
	login string
	teams []string
	owner bool
}{
	{"direct user owner", "dave", []string{"sre"}, true},
	{"top-level user owner", "root", []string{"sre"}, true},
	{"direct member of the owner team", "erin", []string{"sre", "sec"}, true},
	{"owner team is a child team of another", "gina", []string{"sre", "sec>security-org"}, true},
	{"member of a child team of the owner team", "olga", []string{"sre", "sec-oncall>sec"}, false},
	{"not an owner", "pat", []string{"sre"}, false},
}

// signInGitHubTeams is signInGitHub for teams written "child>parent".
func signInGitHubTeams(t *testing.T, b browserClient, gh *webauthtest.GitHub, login string, teams []string) (direct []string) {
	t.Helper()
	var ts []map[string]any
	for _, team := range teams {
		slug, parent, nested := strings.Cut(team, ">")
		entry := map[string]any{"slug": slug, "organization": map[string]any{"login": "acme"}}
		if nested {
			entry["parent"] = map[string]any{"slug": parent}
		}
		ts = append(ts, entry)
		direct = append(direct, slug)
	}
	gh.SetUser(map[string]any{"id": len(login), "login": login}, nil, []map[string]any{{"login": "acme"}}, ts)
	status, _ := b.get(t, "/ui/login/github")
	Equals(t, http.StatusOK, status)
	return direct
}

type lockURLs struct{}

func (lockURLs) GenerateLockURL(string) string { return "" }

// commandAccepts runs the real "atlantis approve_policies" project command
// for login against the same policy sets, with GitHub reporting the user's
// direct teams as GetTeamNamesForUser does, and reports whether it accepted
// the approval.
func commandAccepts(t *testing.T, login string, directTeams []string) bool {
	t.Helper()
	pego.RegisterMockTestingT(t)
	vcsClient := vcsmocks.NewMockClient()
	locker := eventmocks.NewMockProjectLocker()
	workingDir := eventmocks.NewMockWorkingDir()
	runner := events.DefaultProjectCommandRunner{
		Locker:           locker,
		VcsClient:        vcsClient,
		WorkingDir:       workingDir,
		WorkingDirLocker: events.NewDefaultWorkingDirLocker(),
		LockURLGenerator: lockURLs{},
	}
	pego.When(workingDir.GetWorkingDir(pego.Any[models.Repo](), pego.Any[models.PullRequest](), pego.Any[string]())).ThenReturn(t.TempDir(), nil)
	pego.When(locker.TryLock(pego.Any[logging.SimpleLogging](), pego.Any[models.PullRequest](), pego.Any[models.User](), pego.Any[string](), pego.Any[models.Project](), pego.Any[bool]())).
		ThenReturn(&events.TryLockResponse{LockAcquired: true, LockKey: "lock-key"}, nil)
	repo := models.Repo{FullName: "acme/infra", Owner: "acme", Name: "infra", VCSHost: models.VCSHost{Hostname: "github.com", Type: models.Github}}
	user := models.User{Username: login}
	pego.When(vcsClient.GetTeamNamesForUser(pego.Any[logging.SimpleLogging](), pego.Eq(repo), pego.Eq(user))).ThenReturn(directTeams, nil)
	res := runner.ApprovePolicies(command.ProjectContext{
		User: user, Log: logging.NewNoopLogger(t), Workspace: "default", RepoRelDir: "network",
		Pull: models.PullRequest{BaseRepo: repo, Num: 1482, Author: "mrivera", State: models.OpenPullState},
		PolicySets: valid.PolicySets{
			Owners: valid.PolicyOwners{Users: []string{"root"}},
			PolicySets: []valid.PolicySet{{
				Name: "security", ApproveCount: 2, PreventSelfApprove: true,
				Owners: valid.PolicyOwners{Users: []string{"carol", "dave"}, Teams: []string{"sec"}},
			}},
		},
		ProjectPolicyStatus: []models.PolicySetStatus{{PolicySetName: "security"}},
	})
	if res.Error != nil {
		Assert(t, strings.Contains(res.Error.Error(), "is not a policy owner"), "unexpected command error: %s", res.Error)
		return false
	}
	return true
}

// The UI offers approving exactly when "atlantis approve_policies" accepts
// it: owner teams match by direct membership, so a child team's members
// aren't owners through the parent team, even though they count as its
// members for the access policy.
func TestPolicies_OwnerDecisionMatchesTheCommand(t *testing.T) {
	for _, tc := range ownerParityCases {
		t.Run(tc.name, func(t *testing.T) {
			actions := &fakeActions{}
			srv, gh, _ := newApprovalServer(t, policyStore(), actions)
			b := newBrowser(t, srv.URL)
			direct := signInGitHubTeams(t, b, gh, tc.login, tc.teams)

			_, page := b.get(t, "/ui/repos/acme/infra/pulls/1482/policies?dir=network&workspace=default&host=github.com")
			offered := strings.Contains(page, `action="/ui/repos/acme/infra/pulls/1482/policies/approve"`)
			Equals(t, tc.owner, offered)
			if !tc.owner {
				assertContains(t, page, "Only policy owners can approve security: carol, dave, root, team sec.")
			}
			resp := b.post(t, "/ui/repos/acme/infra/pulls/1482/policies/approve",
				approveForm(url.Values{"scope": {"project"}, "dir": {"network"}, "workspace": {"default"}, "policy_set": {"security"}}))
			resp.Body.Close()
			if tc.owner {
				Equals(t, http.StatusSeeOther, resp.StatusCode)
				Equals(t, 1, len(actions.approvals))
			} else {
				Equals(t, http.StatusForbidden, resp.StatusCode)
				Equals(t, 0, len(actions.approvals))
			}

			Equals(t, tc.owner, commandAccepts(t, tc.login, direct))
		})
	}
}
