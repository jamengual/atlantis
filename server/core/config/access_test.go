// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/core/config"
	"github.com/runatlantis/atlantis/server/core/config/valid"
	. "github.com/runatlantis/atlantis/testing"
)

func parseRepoConfig(t *testing.T, yaml string) (valid.GlobalCfg, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "repos.yaml")
	Ok(t, os.WriteFile(path, []byte(yaml), 0o600))
	return (&config.ParserValidator{}).ParseGlobalCfg(path, valid.NewGlobalCfgFromArgs(valid.GlobalCfgArgs{}))
}

func TestParseGlobalCfg_Access(t *testing.T) {
	cfg, err := parseRepoConfig(t, `
access:
  roles:
    admin:
      - group: platform-admins
      - email: lead@acme.com
    operator:
      - github: acme/sre
      - github_user: octocat
      - gitlab: /acme/platform/
      - gitlab_user: ana
      - gitea: acme/ops
      - gitea_user: tea
    viewer:
      - domain: acme.com
      - everyone: true
  default: none
  permissions:
    unlock: Admin
    stop_job: Admin
    maintenance: Operator
    approve_policies: Admin
    lock_applies: admin
  enforce_in_pr_comments: true
repos:
  - id: /.*/
  - id: github.com/acme/data-lake
    access:
      roles:
        operator:
          - group: data-eng
      permissions:
        unlock: operator
        stop_job: operator
        approve_policies: viewer
`)
	Ok(t, err)
	Assert(t, cfg.Access != nil, "access section was not parsed")
	Equals(t, valid.AccessRoles{
		Admin:    []valid.AccessRule{{Group: "platform-admins"}, {Email: "lead@acme.com"}},
		Operator: []valid.AccessRule{{GitHub: "acme/sre"}, {GitHubUser: "octocat"}, {GitLab: "acme/platform"}, {GitLabUser: "ana"}, {Gitea: "acme/ops"}, {GiteaUser: "tea"}},
		Viewer:   []valid.AccessRule{{Domain: "acme.com"}, {Everyone: true}},
	}, cfg.Access.Roles)
	Equals(t, "none", cfg.Access.Default)
	Equals(t, valid.AccessPermissions{Unlock: "admin", LockApplies: "admin", StopJob: "admin", Maintenance: "operator", ApprovePolicies: "admin"}, cfg.Access.Permissions)
	Equals(t, true, cfg.Access.EnforceInPRComments)

	repo := cfg.MatchingRepo("github.com/acme/data-lake")
	Assert(t, repo.Access != nil, "per-repo access was not parsed")
	Equals(t, []valid.AccessRule{{Group: "data-eng"}}, repo.Access.Roles.Operator)
	Equals(t, "operator", repo.Access.Permissions.Unlock)
	Equals(t, "operator", repo.Access.Permissions.StopJob)
	Equals(t, "viewer", repo.Access.Permissions.ApprovePolicies)
}

func TestParseGlobalCfg_NoAccess(t *testing.T) {
	cfg, err := parseRepoConfig(t, "repos:\n  - id: /.*/\n")
	Ok(t, err)
	Assert(t, cfg.Access == nil, "access should be nil when not configured")
}

func TestParseGlobalCfg_AccessErrors(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want string
	}{
		"two attributes in one rule":   {"access:\n  roles:\n    admin:\n      - group: a\n        email: b@acme.com\n", "exactly one of"},
		"gitlab and gitea in one rule": {"access:\n  roles:\n    admin:\n      - gitlab: a\n        gitea: b\n", "exactly one of group, github, github_user, gitlab, gitlab_user, gitea, gitea_user"},
		"empty rule":                   {"access:\n  roles:\n    admin:\n      - {}\n", "exactly one of"},
		"bad email":                    {"access:\n  roles:\n    admin:\n      - email: not-an-email\n", "not an email address"},
		"unknown role in permissions":  {"access:\n  permissions:\n    unlock: root\n", "unknown role"},
		"action needs none":            {"access:\n  permissions:\n    view: none\n", "can't require the none role"},
		"unknown default":              {"access:\n  default: superuser\n", "unknown role"},
		"per-repo view":                {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        view: viewer\n", "viewing is set for the whole server"},
		"per-repo apply lock":          {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        lock_applies: operator\n", "the apply lock covers every repo"},
		"stop job needs none":          {"access:\n  permissions:\n    stop_job: none\n", "access.permissions.stop_job: an action can't require the none role"},
		"unknown stop job role":        {"access:\n  permissions:\n    stop_job: root\n", "access.permissions.stop_job: unknown role"},
		"per-repo stop job none":       {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        stop_job: none\n", "permissions.stop_job: an action can't require the none role"},
		"per-repo stop job unknown":    {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        stop_job: boss\n", "permissions.stop_job: unknown role"},
		"maintenance needs none":       {"access:\n  permissions:\n    maintenance: none\n", "access.permissions.maintenance: an action can't require the none role"},
		"unknown maintenance role":     {"access:\n  permissions:\n    maintenance: root\n", "access.permissions.maintenance: unknown role"},
		"per-repo maintenance":         {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        maintenance: operator\n", "maintenance windows are managed for every repo"},
		"approve policies needs none":  {"access:\n  permissions:\n    approve_policies: none\n", "access.permissions.approve_policies: an action can't require the none role"},
		"unknown approve role":         {"access:\n  permissions:\n    approve_policies: root\n", "access.permissions.approve_policies: unknown role"},
		"per-repo approve none":        {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        approve_policies: none\n", "permissions.approve_policies: an action can't require the none role"},
		"per-repo approve unknown":     {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        approve_policies: boss\n", "permissions.approve_policies: unknown role"},
		"unknown key":                  {"access:\n  roles:\n    admin:\n      - team: x\n", "team"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseRepoConfig(t, tc.yaml)
			ErrContains(t, tc.want, err)
		})
	}
}

func TestParseGlobalCfg_SignIn(t *testing.T) {
	cfg, err := parseRepoConfig(t, `
access:
  sign_in:
    session_secrets_env: ATLANTIS_SESSION_SECRETS
    session_lifetime: 8h
    providers:
      - type: GitLab
        client_id: " gl-app "
        client_secret_env: GITLAB_SIGN_IN_SECRET
        allowed_groups: [acme, " acme/platform "]
      - type: oidc
        name: Microsoft Entra ID
        issuer_url: https://login.microsoftonline.com/t/v2.0
        client_id: app
        client_secret_env: ENTRA_SECRET
        groups_claims: [roles]
  roles:
    viewer:
      - gitlab: acme
`)
	Ok(t, err)
	Equals(t, &valid.SignIn{
		SessionSecretsEnv: "ATLANTIS_SESSION_SECRETS",
		SessionLifetime:   8 * time.Hour,
		Providers: []valid.SignInProvider{
			{Type: "gitlab", ClientID: "gl-app", ClientSecretEnv: "GITLAB_SIGN_IN_SECRET", AllowedGroups: []string{"acme", "acme/platform"}},
			{Type: "oidc", Name: "Microsoft Entra ID", IssuerURL: "https://login.microsoftonline.com/t/v2.0", ClientID: "app", ClientSecretEnv: "ENTRA_SECRET", GroupsClaims: []string{"roles"}},
		},
	}, cfg.Access.SignIn)

	cfg, err = parseRepoConfig(t, "access:\n  sign_in:\n    session_secrets_env: SS\n    proxy:\n      type: ALB\n      alb_arn: arn:x\n  default: viewer\n")
	Ok(t, err)
	Equals(t, &valid.SignInProxy{Type: "alb", ALBArn: "arn:x"}, cfg.Access.SignIn.Proxy)
}

func TestParseGlobalCfg_SignInErrors(t *testing.T) {
	const p = "access:\n  sign_in:\n    session_secrets_env: SS\n    providers:\n      - "
	cases := map[string]struct {
		yaml string
		want string
	}{
		"empty":               {"access:\n  sign_in: {session_secrets_env: SS}\n", "access.sign_in: add providers or a proxy"},
		"no session secrets":  {"access:\n  sign_in:\n    proxy: {type: iap}\n", "access.sign_in: needs session_secrets_env"},
		"both modes":          {"access:\n  sign_in:\n    session_secrets_env: SS\n    proxy: {type: iap}\n    providers:\n      - {type: google, client_id: x, client_secret_env: S, allowed_domains: [a.com]}\n", "providers and proxy can't be used together"},
		"unknown provider":    {p + "{type: saml, client_id: x, client_secret_env: S}\n", `access.sign_in.providers[0].type: unknown provider "saml"; use github, gitlab, gitea, oidc, google`},
		"no client id":        {p + "{type: github, client_secret_env: S, allowed_orgs: [acme]}\n", "github sign-in needs client_id"},
		"no secret env":       {p + "{type: github, client_id: x, allowed_orgs: [acme]}\n", "needs client_secret_env"},
		"secret env not name": {p + "{type: github, client_id: x, client_secret_env: 'hunter2!', allowed_orgs: [acme]}\n", "needs client_secret_env"},
		"inline secret":       {p + "{type: github, client_id: x, client_secret: hunter2, allowed_orgs: [acme]}\n", "client_secret"},
		"github no orgs":      {p + "{type: github, client_id: x, client_secret_env: S}\n", "github sign-in needs allowed_orgs"},
		"gitea no orgs":       {p + "{type: gitea, client_id: x, client_secret_env: S}\n", "gitea sign-in needs allowed_orgs"},
		"gitlab no groups":    {p + "{type: gitlab, client_id: x, client_secret_env: S}\n", "gitlab sign-in needs allowed_groups"},
		"google no domains":   {p + "{type: google, client_id: x, client_secret_env: S}\n", "google sign-in needs allowed_domains"},
		"oidc no issuer":      {p + "{type: oidc, client_id: x, client_secret_env: S}\n", "oidc sign-in needs issuer_url"},
		"field for another":   {p + "{type: gitlab, client_id: x, client_secret_env: S, allowed_groups: [a], allowed_orgs: [a]}\n", "access.sign_in.providers[0].allowed_orgs: doesn't apply to gitlab sign-in"},
		"issuer on github":    {p + "{type: github, client_id: x, client_secret_env: S, allowed_orgs: [a], issuer_url: https://x}\n", "issuer_url: doesn't apply to github sign-in"},
		"duplicate type":      {p + "{type: google, client_id: x, client_secret_env: S, allowed_domains: [a.com]}\n      - {type: Google, client_id: y, client_secret_env: T, allowed_domains: [b.com]}\n", "providers[1]: there is already a google provider"},
		"unknown proxy":       {"access:\n  sign_in:\n    session_secrets_env: SS\n    proxy: {type: saml}\n", `access.sign_in.proxy.type: unknown proxy type "saml"`},
		"bad lifetime":        {"access:\n  sign_in:\n    session_secrets_env: SS\n    session_lifetime: forever\n    proxy: {type: iap}\n", "session_lifetime: \"forever\" is not a positive duration"},
		"negative lifetime":   {"access:\n  sign_in:\n    session_secrets_env: SS\n    session_lifetime: -1h\n    proxy: {type: iap}\n", "not a positive duration"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseRepoConfig(t, tc.yaml)
			ErrContains(t, tc.want, err)
		})
	}
}
