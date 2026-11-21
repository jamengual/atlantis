// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/webauth"
	"github.com/runatlantis/atlantis/server/webauth/webauthtest"
	. "github.com/runatlantis/atlantis/testing"
)

func vcsSignIn(p webauth.LoginProvider, roles webauth.RoleMapper) func(*url.URL) webauth.Config {
	return func(*url.URL) webauth.Config {
		return webauth.Config{SessionSecrets: []string{secretA}, Providers: []webauth.LoginProvider{p}, Roles: roles}
	}
}

func TestGitLab_SignInWithGroups(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	// GitLab's ID token only has groups_direct; userinfo lists every group.
	idp.SetUser(map[string]any{"sub": "17", "name": "Ana Lab", "nickname": "ana", "email": "ana@acme.com", "email_verified": true,
		"groups_direct": []string{"acme/platform"}})
	idp.SetUserInfo(map[string]any{"groups": []string{"acme", "acme/platform", "acme/platform/oncall"}})
	p, err := webauth.NewGitLabProvider(webauth.GitLabConfig{ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, Hostname: idp.Server.URL, AllowedGroups: []string{"acme"}})
	Ok(t, err)
	Equals(t, "gitlab", p.ID())
	a := newApp(t, "", vcsSignIn(p, webauth.RoleMapper{Operators: []string{"gitlab:acme/platform"}}))
	_, body := fetch(t, browser(t), a.srv.URL+"/ui/login/gitlab")
	Equals(t, "hello Ana Lab role=operator provider=gitlab email=ana@acme.com path=/ui/", body)
}

func TestGitea_SignInWithTeams(t *testing.T) {
	idp := webauthtest.NewOIDC()
	idp.IssuerSlash = true
	defer idp.Server.Close()
	// Gitea writes teams as "org:team".
	idp.SetUser(map[string]any{"sub": "5", "name": "Tea", "preferred_username": "tea", "groups": []string{"acme", "acme:ops"}})
	p, err := webauth.NewGiteaProvider(webauth.GiteaConfig{ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, BaseURL: idp.Server.URL, AllowedOrgs: []string{"acme"}})
	Ok(t, err)
	a := newApp(t, "", vcsSignIn(p, webauth.RoleMapper{Admins: []string{"gitea:acme/ops"}}))
	_, body := fetch(t, browser(t), a.srv.URL+"/ui/login/gitea")
	Equals(t, "hello Tea role=admin provider=gitea email= path=/ui/", body)
}

func TestVCSSignIn_AllowedGroups(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		groups  []string
		ok      bool
	}{
		{"member of the group", []string{"acme"}, []string{"acme"}, true},
		{"member of a subgroup", []string{"acme"}, []string{"acme/platform"}, true},
		{"allowed subgroup, case and slashes ignored", []string{"/ACME/Platform/"}, []string{"acme/platform/oncall"}, true},
		{"sibling with a shared prefix", []string{"acme"}, []string{"acme-evil"}, false},
		{"parent of the allowed subgroup", []string{"acme/platform"}, []string{"acme"}, false},
		{"no groups", []string{"acme"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := webauthtest.NewOIDC()
			defer idp.Server.Close()
			idp.SetUser(map[string]any{"sub": "1", "nickname": "u", "groups": tc.groups})
			p, err := webauth.NewGitLabProvider(webauth.GitLabConfig{ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, Hostname: idp.Server.URL, AllowedGroups: tc.allowed})
			Ok(t, err)
			a := newApp(t, "", vcsSignIn(p, webauth.RoleMapper{Default: webauth.RoleViewer}))
			status, body := fetch(t, browser(t), a.srv.URL+"/ui/login/gitlab")
			if tc.ok {
				Equals(t, http.StatusOK, status)
				return
			}
			Equals(t, http.StatusForbidden, status)
			Assert(t, strings.Contains(body, "can sign in to Atlantis with GitLab"), body)
		})
	}
}

func TestVCSProviders_RequireAllowList(t *testing.T) {
	_, err := webauth.NewGitLabProvider(webauth.GitLabConfig{ClientID: "id", ClientSecret: "s"})
	ErrContains(t, "allowed groups", err)
	_, err = webauth.NewGitLabProvider(webauth.GitLabConfig{AllowedGroups: []string{"acme"}})
	ErrContains(t, "application ID and secret", err)
	_, err = webauth.NewGiteaProvider(webauth.GiteaConfig{ClientID: "id", ClientSecret: "s"})
	ErrContains(t, "allowed organizations", err)
	_, err = webauth.NewGiteaProvider(webauth.GiteaConfig{AllowedOrgs: []string{"acme"}})
	ErrContains(t, "client ID and client secret", err)
}

func TestPolicy_VCSRules(t *testing.T) {
	p, err := webauth.NewPolicy(webauth.PolicyConfig{Access: &valid.Access{Roles: valid.AccessRoles{
		Admin:    []valid.AccessRule{{GitLab: "acme/platform"}, {Gitea: "acme/ops"}},
		Operator: []valid.AccessRule{{GitHubUser: "octo"}, {GitLabUser: "ana"}, {GiteaUser: "tea"}},
	}}})
	Ok(t, err)
	cases := []struct {
		name string
		s    webauth.Subject
		want webauth.Role
	}{
		{"gitlab group", webauth.Subject{Groups: []string{"gitlab:Acme/Platform"}}, webauth.RoleAdmin},
		{"gitea team", webauth.Subject{Groups: []string{"gitea:acme/ops"}}, webauth.RoleAdmin},
		{"gitlab user", webauth.Subject{Login: "ana", LoginKind: "gitlab"}, webauth.RoleOperator},
		{"gitea user", webauth.Subject{Login: "tea", LoginKind: "gitea"}, webauth.RoleOperator},
		// The same username on another VCS is another person.
		{"github user rule doesn't match a gitlab login", webauth.Subject{Login: "octo", LoginKind: "gitlab"}, webauth.RoleNone},
		{"gitlab user rule doesn't match a github login", webauth.Subject{Login: "ana", LoginKind: "github"}, webauth.RoleNone},
		{"group without the gitlab prefix", webauth.Subject{Groups: []string{"acme/platform"}}, webauth.RoleNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			Equals(t, c.want, p.GlobalRole(c.s))
		})
	}

	// Comments are matched on the commenter's own VCS only.
	ok, _ := p.AllowsCommenterUnlock("gitlab.com/acme/infra", "gitlab", "ana", nil)
	Assert(t, ok, "gitlab commenter denied")
	ok, _ = p.AllowsCommenterUnlock("bitbucket.org/acme/infra", "", "octo", nil)
	Assert(t, !ok, "a bitbucket commenter matched a github_user rule")
	ok, _ = p.AllowsCommenterUnlock("gitlab.com/acme/infra", "gitlab", "x", []string{"github:acme/platform", "gitea:acme/ops"})
	Assert(t, !ok, "groups of another VCS matched a gitlab commenter")
	ok, _ = p.AllowsCommenterUnlock("gitlab.com/acme/infra", "gitlab", "x", []string{"gitlab:acme/platform"})
	Assert(t, ok, "gitlab group commenter denied")
}

func TestManager_DropsOtherVCSGroups(t *testing.T) {
	// A generic identity provider can't report groups in a VCS's namespace.
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	idp.SetUser(map[string]any{"sub": "u", "name": "Mallory", "groups": []string{"gitlab:acme/platform", "github:acme/sre", "gitea:acme/ops"}})
	a := newApp(t, "", func(public *url.URL) webauth.Config {
		cfg := oidcConfig(idp, nil)(public)
		cfg.Roles = webauth.RoleMapper{Admins: []string{"gitlab:acme/platform", "github:acme/sre", "gitea:acme/ops"}}
		return cfg
	})
	status, body := fetch(t, browser(t), a.srv.URL+"/ui/login/oidc")
	Equals(t, http.StatusForbidden, status)
	Assert(t, strings.Contains(body, "no Atlantis role"), body)
}
