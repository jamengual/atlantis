// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth

import (
	"testing"

	. "github.com/runatlantis/atlantis/testing"
)

func TestVCSIssuerURLs(t *testing.T) {
	for host, want := range map[string]string{
		"":                                 "https://gitlab.com",
		"gitlab.acme.internal":             "https://gitlab.acme.internal",
		"https://gitlab.acme.internal/":    "https://gitlab.acme.internal",
		"http://gitlab.acme.internal:8080": "http://gitlab.acme.internal:8080",
	} {
		p, err := NewGitLabProvider(GitLabConfig{ClientID: "id", ClientSecret: "s", Hostname: host, AllowedGroups: []string{"acme"}})
		Ok(t, err)
		Equals(t, want, p.cfg.IssuerURL)
	}
	// Gitea's issuer is its root URL with a trailing slash.
	for base, want := range map[string]string{
		"":                             "https://gitea.com/",
		"https://gitea.acme.internal":  "https://gitea.acme.internal/",
		"https://gitea.acme.internal/": "https://gitea.acme.internal/",
	} {
		p, err := NewGiteaProvider(GiteaConfig{ClientID: "id", ClientSecret: "s", BaseURL: base, AllowedOrgs: []string{"acme"}})
		Ok(t, err)
		Equals(t, want, p.cfg.IssuerURL)
	}
}

func TestWithoutForeignVCSGroups(t *testing.T) {
	in := []string{"sre", "github:acme/sre", "GitLab:acme/platform", "gitea:acme", "okta:admins"}
	Equals(t, []string{"sre", "github:acme/sre", "okta:admins"}, withoutForeignVCSGroups(in, VCSGitHub))
	Equals(t, []string{"sre", "GitLab:acme/platform", "okta:admins"}, withoutForeignVCSGroups(in, VCSGitLab))
	Equals(t, []string{"sre", "okta:admins"}, withoutForeignVCSGroups(in, "oidc"))
}
