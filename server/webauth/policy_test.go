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
		Flags: webauth.RoleMapper{Viewers: []string{"domain:acme.com"}},
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
		{"github user rule", webauth.Subject{GitHubLogin: "OctoCat"}, webauth.ActionUnlock, "github.com/acme/infra", true},
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
