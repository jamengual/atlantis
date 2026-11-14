// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
	"path/filepath"
	"testing"

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
    viewer:
      - domain: acme.com
      - everyone: true
  default: none
  permissions:
    unlock: Admin
    stop_job: Admin
    maintenance: Operator
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
`)
	Ok(t, err)
	Assert(t, cfg.Access != nil, "access section was not parsed")
	Equals(t, valid.AccessRoles{
		Admin:    []valid.AccessRule{{Group: "platform-admins"}, {Email: "lead@acme.com"}},
		Operator: []valid.AccessRule{{GitHub: "acme/sre"}, {GitHubUser: "octocat"}},
		Viewer:   []valid.AccessRule{{Domain: "acme.com"}, {Everyone: true}},
	}, cfg.Access.Roles)
	Equals(t, "none", cfg.Access.Default)
	Equals(t, valid.AccessPermissions{Unlock: "admin", LockApplies: "admin", StopJob: "admin", Maintenance: "operator"}, cfg.Access.Permissions)
	Equals(t, true, cfg.Access.EnforceInPRComments)

	repo := cfg.MatchingRepo("github.com/acme/data-lake")
	Assert(t, repo.Access != nil, "per-repo access was not parsed")
	Equals(t, []valid.AccessRule{{Group: "data-eng"}}, repo.Access.Roles.Operator)
	Equals(t, "operator", repo.Access.Permissions.Unlock)
	Equals(t, "operator", repo.Access.Permissions.StopJob)
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
		"two attributes in one rule":  {"access:\n  roles:\n    admin:\n      - group: a\n        email: b@acme.com\n", "exactly one of"},
		"empty rule":                  {"access:\n  roles:\n    admin:\n      - {}\n", "exactly one of"},
		"bad email":                   {"access:\n  roles:\n    admin:\n      - email: not-an-email\n", "not an email address"},
		"unknown role in permissions": {"access:\n  permissions:\n    unlock: root\n", "unknown role"},
		"action needs none":           {"access:\n  permissions:\n    view: none\n", "can't require the none role"},
		"unknown default":             {"access:\n  default: superuser\n", "unknown role"},
		"per-repo view":               {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        view: viewer\n", "viewing is set for the whole server"},
		"per-repo apply lock":         {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        lock_applies: operator\n", "the apply lock covers every repo"},
		"stop job needs none":         {"access:\n  permissions:\n    stop_job: none\n", "access.permissions.stop_job: an action can't require the none role"},
		"unknown stop job role":       {"access:\n  permissions:\n    stop_job: root\n", "access.permissions.stop_job: unknown role"},
		"per-repo stop job none":      {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        stop_job: none\n", "permissions.stop_job: an action can't require the none role"},
		"per-repo stop job unknown":   {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        stop_job: boss\n", "permissions.stop_job: unknown role"},
		"maintenance needs none":      {"access:\n  permissions:\n    maintenance: none\n", "access.permissions.maintenance: an action can't require the none role"},
		"unknown maintenance role":    {"access:\n  permissions:\n    maintenance: root\n", "access.permissions.maintenance: unknown role"},
		"per-repo maintenance":        {"repos:\n  - id: /.*/\n    access:\n      permissions:\n        maintenance: operator\n", "maintenance windows are managed for every repo"},
		"unknown key":                 {"access:\n  roles:\n    admin:\n      - team: x\n", "team"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseRepoConfig(t, tc.yaml)
			ErrContains(t, tc.want, err)
		})
	}
}
