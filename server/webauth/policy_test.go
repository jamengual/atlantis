// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth_test

import (
	"regexp"
	"testing"

	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/webauth"
	. "github.com/runatlantis/atlantis/testing"
)

func testPolicy(t *testing.T) *webauth.Policy {
	t.Helper()
	p, err := webauth.NewPolicy(webauth.PolicyConfig{
		Rules: webauth.RoleMapper{Viewers: []string{"domain:acme.com"}},
		Access: &valid.Access{
			Roles: valid.AccessRoles{
				Admin:    []valid.AccessRule{{Group: "platform-admins"}, {Email: "lead@acme.com"}},
				Operator: []valid.AccessRule{{GitHub: "acme/sre"}, {GitHubUser: "octocat"}},
			},
			Permissions: valid.AccessPermissions{Unlock: "operator"},
		},
		Repos: []valid.Repo{
			{IDRegex: regexp.MustCompile(".*")},
			{ID: "github.com/acme/data-lake", Access: &valid.RepoAccess{Roles: valid.AccessRoles{Operator: []valid.AccessRule{{Group: "data-eng"}}}}},
			{IDRegex: regexp.MustCompile(`^github\.com/acme/prod-`), Access: &valid.RepoAccess{Permissions: valid.AccessPermissions{Unlock: "admin"}}},
		},
	})
	Ok(t, err)
	return p
}

func TestPolicy_RolesAndPermissions(t *testing.T) {
	p := testPolicy(t)
	viewer := webauth.Subject{Email: "v@acme.com"}
	dataEng := webauth.Subject{Email: "d@acme.com", Groups: []string{"data-eng"}}
	sre := webauth.Subject{Groups: []string{"github:acme/sre"}}
	admin := webauth.Subject{Groups: []string{"platform-admins"}}
	stranger := webauth.Subject{Email: "x@elsewhere.com"}

	cases := []struct {
		name   string
		s      webauth.Subject
		action webauth.Action
		repo   string
		want   bool
	}{
		{"viewer can view", viewer, webauth.ActionView, "", true},
		{"stranger can't view", stranger, webauth.ActionView, "", false},
		{"viewer can't unlock", viewer, webauth.ActionUnlock, "github.com/acme/infra", false},
		{"repo grant lets data-eng unlock its repo", dataEng, webauth.ActionUnlock, "github.com/acme/data-lake", true},
		{"repo grant doesn't reach other repos", dataEng, webauth.ActionUnlock, "github.com/acme/infra", false},
		{"operator can unlock", sre, webauth.ActionUnlock, "github.com/acme/infra", true},
		{"prod repos need admin to unlock", sre, webauth.ActionUnlock, "github.com/acme/prod-network", false},
		{"admin unlocks prod", admin, webauth.ActionUnlock, "github.com/acme/prod-network", true},
		{"operator can't lock applies", sre, webauth.ActionLockApplies, "", false},
		{"admin locks applies", admin, webauth.ActionLockApplies, "", true},
		{"github user rule", webauth.Subject{Login: "OctoCat", LoginKind: "github"}, webauth.ActionUnlock, "github.com/acme/infra", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			Equals(t, c.want, p.Allows(c.s, webauth.RoleNone, c.action, c.repo))
		})
	}
	// A base role, such as the basic-auth user's, counts too.
	Assert(t, p.Allows(stranger, webauth.RoleAdmin, webauth.ActionLockApplies, ""), "base admin denied")
	Equals(t, webauth.RoleAdmin, p.Requires(webauth.ActionUnlock, "github.com/acme/prod-x"))
	Equals(t, webauth.RoleOperator, p.Requires(webauth.ActionUnlock, "github.com/acme/infra"))
	Equals(t, webauth.RoleOperator, p.RoleIn(dataEng, "github.com/acme/data-lake"))
	Equals(t, webauth.RoleViewer, p.GlobalRole(dataEng))
}

func TestPolicy_HelpersAndSummary(t *testing.T) {
	p := testPolicy(t)
	Equals(t, []string{"platform-admins", "data-eng"}, p.RelevantGroups([]string{"platform-admins", "unrelated", "data-eng"}))
	Equals(t, []string{"sre"}, p.GitHubTeamRules("acme"))
	Equals(t, 0, len(p.GitHubTeamRules("other")))
	Assert(t, p.HasRules(), "policy has rules")

	s := p.Summarize()
	Equals(t, webauth.RoleOperator, s.Requirements[1].Role)
	Equals(t, 2, len(s.Repos))
	Equals(t, "github.com/acme/data-lake", s.Repos[0].Match)
	Equals(t, []string{"group platform-admins", "lead@acme.com"}, s.Roles[0].Rules)

	empty, err := webauth.NewPolicy(webauth.PolicyConfig{})
	Ok(t, err)
	Assert(t, !empty.HasRules(), "empty policy has no rules")
}

func TestPolicy_StopJob(t *testing.T) {
	p, err := webauth.NewPolicy(webauth.PolicyConfig{
		Access: &valid.Access{
			Roles: valid.AccessRoles{
				Admin:    []valid.AccessRule{{Group: "platform-admins"}},
				Operator: []valid.AccessRule{{Group: "sre"}},
				Viewer:   []valid.AccessRule{{Domain: "acme.com"}},
			},
		},
		Repos: []valid.Repo{
			{IDRegex: regexp.MustCompile(".*")},
			{ID: "github.com/acme/data-lake", Access: &valid.RepoAccess{Roles: valid.AccessRoles{Operator: []valid.AccessRule{{Group: "data-eng"}}}}},
			{IDRegex: regexp.MustCompile(`^github\.com/acme/prod-`), Access: &valid.RepoAccess{Permissions: valid.AccessPermissions{StopJob: "admin"}}},
			{ID: "github.com/acme/sandbox", Access: &valid.RepoAccess{Permissions: valid.AccessPermissions{StopJob: "viewer"}}},
		},
	})
	Ok(t, err)
	viewer := webauth.Subject{Email: "v@acme.com"}
	dataEng := webauth.Subject{Email: "d@acme.com", Groups: []string{"data-eng"}}
	sre := webauth.Subject{Groups: []string{"sre"}}
	admin := webauth.Subject{Groups: []string{"platform-admins"}}
	cases := []struct {
		name string
		s    webauth.Subject
		repo string
		want bool
	}{
		{"operators stop jobs by default", sre, "github.com/acme/infra", true},
		{"viewers don't", viewer, "github.com/acme/infra", false},
		{"a repo grant reaches stopping", dataEng, "github.com/acme/data-lake", true},
		{"but not other repos", dataEng, "github.com/acme/infra", false},
		{"a repo can require admin", sre, "github.com/acme/prod-network", false},
		{"which admins have", admin, "github.com/acme/prod-network", true},
		{"a repo can relax it", viewer, "github.com/acme/sandbox", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			Equals(t, c.want, p.Allows(c.s, webauth.RoleNone, webauth.ActionStopJob, c.repo))
		})
	}
	Equals(t, webauth.RoleOperator, p.Requires(webauth.ActionStopJob, ""))
	Equals(t, webauth.RoleAdmin, p.Requires(webauth.ActionStopJob, "github.com/acme/prod-x"))
	// The stop requirement doesn't change unlocking, and vice versa.
	Equals(t, webauth.RoleOperator, p.Requires(webauth.ActionUnlock, "github.com/acme/prod-x"))
	Assert(t, webauth.ActionStopJob.PerRepo() && webauth.ActionUnlock.PerRepo(), "stop and unlock are per repo")
	Assert(t, !webauth.ActionLockApplies.PerRepo() && !webauth.ActionView.PerRepo(), "view and lock applies are global")

	s := p.Summarize()
	Equals(t, webauth.ActionStopJob, s.Requirements[2].Action)
	Equals(t, webauth.RoleOperator, s.Requirements[2].Role)
	Equals(t, webauth.RoleAdmin, s.Repos[1].StopJob)
	Equals(t, webauth.RoleNone, s.Repos[1].Unlock)
}

func TestPolicy_Maintenance(t *testing.T) {
	p, err := webauth.NewPolicy(webauth.PolicyConfig{
		Access: &valid.Access{
			Roles: valid.AccessRoles{
				Admin:    []valid.AccessRule{{Group: "platform-admins"}},
				Operator: []valid.AccessRule{{Group: "sre"}},
			},
		},
		Repos: []valid.Repo{
			{ID: "github.com/acme/data-lake", Access: &valid.RepoAccess{Roles: valid.AccessRoles{Admin: []valid.AccessRule{{Group: "data-eng"}}}}},
		},
	})
	Ok(t, err)
	admin := webauth.Subject{Groups: []string{"platform-admins"}}
	sre := webauth.Subject{Groups: []string{"sre"}}
	dataEng := webauth.Subject{Groups: []string{"data-eng"}}
	Equals(t, webauth.RoleAdmin, p.Requires(webauth.ActionMaintenance, ""))
	Assert(t, p.Allows(admin, webauth.RoleNone, webauth.ActionMaintenance, ""), "admins manage maintenance")
	Assert(t, !p.Allows(sre, webauth.RoleNone, webauth.ActionMaintenance, ""), "operators don't by default")
	// Maintenance is global, so a per-repo admin grant doesn't reach it,
	// even when asked about that repo.
	Assert(t, !webauth.ActionMaintenance.PerRepo(), "maintenance is global")
	Assert(t, !p.Allows(dataEng, webauth.RoleNone, webauth.ActionMaintenance, "github.com/acme/data-lake"), "a repo grant doesn't reach maintenance")
	Equals(t, "Start and end maintenance windows that freeze applies", webauth.ActionMaintenance.Describe())

	relaxed, err := webauth.NewPolicy(webauth.PolicyConfig{Access: &valid.Access{
		Roles:       valid.AccessRoles{Operator: []valid.AccessRule{{Group: "sre"}}},
		Permissions: valid.AccessPermissions{Maintenance: "operator"},
	}})
	Ok(t, err)
	Assert(t, relaxed.Allows(sre, webauth.RoleNone, webauth.ActionMaintenance, ""), "the requirement can be changed")
	Equals(t, webauth.ActionMaintenance, relaxed.Summarize().Requirements[3].Action)
	Equals(t, webauth.RoleOperator, relaxed.Summarize().Requirements[3].Role)
}

func TestPolicy_ApprovePolicies(t *testing.T) {
	p, err := webauth.NewPolicy(webauth.PolicyConfig{
		Access: &valid.Access{
			Roles: valid.AccessRoles{
				Admin:    []valid.AccessRule{{Group: "platform-admins"}},
				Operator: []valid.AccessRule{{GitHub: "acme/sre"}},
				Viewer:   []valid.AccessRule{{Domain: "acme.com"}},
			},
		},
		Repos: []valid.Repo{
			{IDRegex: regexp.MustCompile(`^github\.com/acme/prod-`), Access: &valid.RepoAccess{Permissions: valid.AccessPermissions{ApprovePolicies: "admin"}}},
			{ID: "github.com/acme/sandbox", Access: &valid.RepoAccess{Permissions: valid.AccessPermissions{ApprovePolicies: "viewer"}}},
		},
		PolicyOwnerTeams: []string{"Sec"},
	})
	Ok(t, err)
	viewer := webauth.Subject{Email: "v@acme.com"}
	sre := webauth.Subject{Groups: []string{"github:acme/sre"}}
	admin := webauth.Subject{Groups: []string{"platform-admins"}}
	Assert(t, webauth.ActionApprovePolicies.PerRepo(), "approving is per repo")
	Equals(t, webauth.RoleOperator, p.Requires(webauth.ActionApprovePolicies, ""))
	Assert(t, p.Allows(sre, webauth.RoleNone, webauth.ActionApprovePolicies, "github.com/acme/infra"), "operators approve by default")
	Assert(t, !p.Allows(viewer, webauth.RoleNone, webauth.ActionApprovePolicies, "github.com/acme/infra"), "viewers don't")
	Assert(t, !p.Allows(sre, webauth.RoleNone, webauth.ActionApprovePolicies, "github.com/acme/prod-db"), "prod needs admin")
	Assert(t, p.Allows(admin, webauth.RoleNone, webauth.ActionApprovePolicies, "github.com/acme/prod-db"), "admins approve prod")
	Assert(t, p.Allows(viewer, webauth.RoleNone, webauth.ActionApprovePolicies, "github.com/acme/sandbox"), "the sandbox relaxes it")
	// The approve requirement doesn't change unlocking.
	Equals(t, webauth.RoleOperator, p.Requires(webauth.ActionUnlock, "github.com/acme/prod-db"))
	Equals(t, "Approve failing policy checks, for policy owners", webauth.ActionApprovePolicies.Describe())

	s := p.Summarize()
	Equals(t, webauth.ActionApprovePolicies, s.Requirements[4].Action)
	Equals(t, webauth.RoleAdmin, s.Repos[0].ApprovePolicies)
	Equals(t, webauth.RoleViewer, s.Repos[1].ApprovePolicies)

	// Groups keep only what rules mention; owner teams are kept separately,
	// from direct memberships, in any org, so the UI can match them the way
	// approve_policies does.
	Equals(t, []string{"github:acme/sre"},
		p.RelevantGroups([]string{"github:acme/sre", "github:acme/sec", "github:other/SEC", "github:acme/web", "github:sec", "sec"}))
	Equals(t, []string{"acme/sec", "other/SEC"},
		p.PolicyOwnerTeams([]string{"acme/sre", "acme/sec", "other/SEC", "acme/web", "sec", "acme/sec-oncall"}))
}
