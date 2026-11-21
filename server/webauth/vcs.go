// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth

import (
	"errors"
	"slices"
	"strings"
)

// People usually sign in with the VCS account they already use, so roles can
// follow the organizations, groups, and teams the VCS already has. GitHub has
// its own OAuth sign-in (github.go). GitLab and Gitea are OpenID Connect
// providers, so they reuse the OIDC sign-in with their own group names.

// The VCS kinds people can sign in with. Each is also the provider ID, the
// prefix of the groups it reports, and the "<kind>_user" rule it satisfies.
const (
	VCSGitHub = "github"
	VCSGitLab = "gitlab"
	VCSGitea  = "gitea"
)

// vcsKinds are the providers whose group names are reserved. Only the
// provider of that kind may report groups starting with "<kind>:", so an
// identity provider group named "github:acme/admins" can't pose as a team.
var vcsKinds = []string{VCSGitHub, VCSGitLab, VCSGitea}

const (
	// GitLabGroupPrefix starts every group name that comes from GitLab,
	// such as "gitlab:acme/platform".
	GitLabGroupPrefix = VCSGitLab + ":"
	// GiteaGroupPrefix starts every group name that comes from Gitea, such
	// as "gitea:acme" for an organization or "gitea:acme/ops" for a team.
	GiteaGroupPrefix = VCSGitea + ":"
)

// vcsName is the product name shown to people.
func vcsName(kind string) string {
	switch kind {
	case VCSGitHub:
		return "GitHub"
	case VCSGitLab:
		return "GitLab"
	case VCSGitea:
		return "Gitea"
	}
	return kind
}

// withoutForeignVCSGroups drops groups in another VCS's namespace.
func withoutForeignVCSGroups(groups []string, provider string) []string {
	return slices.DeleteFunc(slices.Clone(groups), func(g string) bool {
		kind, _, ok := strings.Cut(strings.ToLower(g), ":")
		return ok && kind != provider && slices.Contains(vcsKinds, kind)
	})
}

// GitLabConfig configures sign-in with a GitLab application.
type GitLabConfig struct {
	ClientID     string
	ClientSecret string
	// Hostname is "gitlab.com" or a self-managed GitLab host, optionally
	// with a scheme, as for --gitlab-hostname.
	Hostname string
	// AllowedGroups admits only members of these groups or their subgroups,
	// such as "acme" or "acme/platform".
	AllowedGroups []string
}

// NewGitLabProvider signs users in with GitLab. GitLab lists every group a
// user can access, including subgroups of groups they belong to, as
// "gitlab:full/path". The GitLab username can be matched by gitlab_user.
func NewGitLabProvider(cfg GitLabConfig) (*OIDCProvider, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("GitLab sign-in needs an application ID and secret")
	}
	if len(cfg.AllowedGroups) == 0 {
		return nil, errors.New("GitLab sign-in needs the allowed groups, because anyone can create a GitLab account")
	}
	return NewOIDCProvider(OIDCConfig{
		ID:           VCSGitLab,
		Name:         "GitLab",
		IssuerURL:    vcsBaseURL(cfg.Hostname, "gitlab.com", false),
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       []string{"profile", "email"},
		// The ID token only has groups_direct; userinfo has every group.
		GroupsClaims:  []string{"groups"},
		GroupPrefix:   GitLabGroupPrefix,
		LoginClaims:   []string{"nickname", "preferred_username"},
		AllowedGroups: cfg.AllowedGroups,
	})
}

// GiteaConfig configures sign-in with a Gitea or Forgejo OAuth2 application.
type GiteaConfig struct {
	ClientID     string
	ClientSecret string
	// BaseURL is the Gitea address, as for --gitea-base-url.
	BaseURL string
	// AllowedOrgs admits only members of these organizations.
	AllowedOrgs []string
}

// NewGiteaProvider signs users in with Gitea or Forgejo. Organizations become
// "gitea:org" and teams "gitea:org/team". The Gitea username can be matched
// by gitea_user.
func NewGiteaProvider(cfg GiteaConfig) (*OIDCProvider, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("Gitea sign-in needs a client ID and client secret")
	}
	if len(cfg.AllowedOrgs) == 0 {
		return nil, errors.New("Gitea sign-in needs the allowed organizations, because people can usually register their own Gitea accounts")
	}
	return NewOIDCProvider(OIDCConfig{
		ID:   VCSGitea,
		Name: "Gitea",
		// Gitea's issuer is its root URL, which always ends with a slash.
		IssuerURL:    vcsBaseURL(cfg.BaseURL, "gitea.com", true),
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       []string{"profile", "email", "groups"},
		GroupsClaims: []string{"groups"},
		GroupPrefix:  GiteaGroupPrefix,
		// Gitea writes teams as "org:team".
		GroupMap:      func(g string) string { return strings.Replace(g, ":", "/", 1) },
		LoginClaims:   []string{"preferred_username", "nickname"},
		AllowedGroups: cfg.AllowedOrgs,
	})
}

// vcsBaseURL turns a VCS hostname or URL setting into an https base URL.
func vcsBaseURL(host, fallback string, trailingSlash bool) string {
	u := strings.TrimSpace(host)
	if u == "" {
		u = fallback
	}
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	u = strings.TrimRight(u, "/")
	if trailingSlash {
		u += "/"
	}
	return u
}

// inAllowedGroups reports whether any group is one of the allowed groups or
// below one, such as "acme/platform" for "acme". Groups and allowed values
// are compared without the provider prefix.
func inAllowedGroups(groups []string, prefix string, allowed []string) bool {
	for _, g := range groups {
		name, ok := strings.CutPrefix(strings.ToLower(g), prefix)
		if !ok {
			continue
		}
		for _, a := range allowed {
			a = strings.ToLower(strings.Trim(strings.TrimSpace(a), "/"))
			if a != "" && (name == a || strings.HasPrefix(name, a+"/")) {
				return true
			}
		}
	}
	return false
}
