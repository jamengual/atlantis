// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

// Package webauth signs people in to the Atlantis web UI and decides what
// they may do there.
//
// Identity comes from the VCS people already use (GitHub, GitLab, or Gitea),
// from an OpenID Connect provider (Entra ID, Google, Okta, Keycloak, and
// others), or from an authenticating proxy in front of Atlantis (AWS ALB,
// Google IAP, or trusted headers). Sessions are encrypted cookies, so any
// replica can serve any request. Roles come from the user's VCS teams and
// groups, identity provider groups, VCS username, email, or email domain.
package webauth

import (
	"context"
	"fmt"
	"strings"
)

// Role is what a signed-in user may do. Higher roles include lower ones.
type Role int

const (
	// RoleNone means the user is signed in but may not use the UI.
	RoleNone Role = iota
	// RoleViewer may read pull requests, locks, and logs.
	RoleViewer
	// RoleOperator may also discard plans and unlock projects.
	RoleOperator
	// RoleAdmin may also lock or unlock applies for every repository.
	RoleAdmin
)

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	}
	return "none"
}

// ParseRole reads a role name as used in configuration.
func ParseRole(s string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return RoleNone, nil
	case "viewer":
		return RoleViewer, nil
	case "operator":
		return RoleOperator, nil
	case "admin":
		return RoleAdmin, nil
	}
	return RoleNone, fmt.Errorf("unknown role %q; use none, viewer, operator, or admin", s)
}

// Identity is what a provider says about a user before roles are applied.
type Identity struct {
	Subject string
	Name    string
	Email   string
	// EmailVerified is false when the provider does not vouch for Email.
	// Unverified emails are not used for role matching.
	EmailVerified bool
	Groups        []string
	// Login is the VCS username, set by the GitHub, GitLab, and Gitea
	// providers, and LoginKind which of them it belongs to.
	Login     string
	LoginKind string
	// GitHubTeams are the "org/team" slugs of the GitHub teams the user is
	// a direct member of, set by the GitHub provider. Unlike Groups, parent
	// teams aren't added, because policy owners are matched the way
	// "atlantis approve_policies" matches them: by direct membership only.
	GitHubTeams []string
}

// Principal is the signed-in user of one request.
type Principal struct {
	Subject  string `json:"sub"`
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Provider string `json:"prv"`
	// Role is the global role, recomputed from the policy on every request.
	Role Role `json:"role"`
	// Groups are the user's groups that the access policy mentions.
	Groups []string `json:"g,omitempty"`
	// Login is the VCS username when the user signed in with a VCS, and
	// LoginKind the VCS: github, gitlab, or gitea.
	Login     string `json:"lg,omitempty"`
	LoginKind string `json:"lk,omitempty"`
	// GitHubTeams are the "org/team" slugs of the GitHub teams the user is
	// a direct member of that own policy sets. Approving policies from the
	// web UI matches owners against these, as the comment command does.
	GitHubTeams []string `json:"ght,omitempty"`
	// Base is a role held regardless of policy rules, such as the
	// basic-auth user's when web sign-in is off. It is never stored.
	Base Role `json:"-"`
}

// Subject is what policy rules are matched against.
func (p *Principal) AsSubject() Subject {
	if p == nil {
		return Subject{}
	}
	return Subject{Groups: p.Groups, Email: p.Email, Login: p.Login, LoginKind: p.LoginKind}
}

// GitHubLogin is the GitHub username, or "" when the user didn't sign in
// with GitHub.
func (p *Principal) GitHubLogin() string {
	if p == nil || p.LoginKind != VCSGitHub {
		return ""
	}
	return p.Login
}

// Can reports whether the principal has at least the given role.
func (p *Principal) Can(r Role) bool {
	return p != nil && p.Role >= r
}

// DisplayName is the best human-readable name for the principal.
func (p *Principal) DisplayName() string {
	switch {
	case p == nil:
		return ""
	case p.Name != "":
		return p.Name
	case p.Email != "":
		return p.Email
	}
	return p.Subject
}

type principalKey struct{}

// WithPrincipal stores the principal in the request context.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the request's principal, or nil.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}
