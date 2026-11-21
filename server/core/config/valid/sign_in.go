// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package valid

import "time"

// SignIn is how people sign in to the web UI: providers with sign-in pages,
// or an authenticating proxy, never both.
type SignIn struct {
	// SessionLifetime is zero for the default.
	SessionLifetime time.Duration
	Providers       []SignInProvider
	Proxy           *SignInProxy
}

// SignInProvider is one sign-in button. Type is github, gitlab, gitea,
// oidc, or google.
type SignInProvider struct {
	Type      string
	Name      string
	IssuerURL string
	ClientID  string
	// ClientSecretEnv names the environment variable with the client secret.
	ClientSecretEnv string
	Scopes          []string
	GroupsClaims    []string
	AllowedDomains  []string
	AllowedOrgs     []string
	AllowedGroups   []string
}

// SignInProxy is an authenticating proxy. Type is alb, iap, or header.
type SignInProxy struct {
	Type         string
	ALBArn       string
	IAPAudience  string
	UserHeader   string
	EmailHeader  string
	GroupsHeader string
	TrustedCIDRs []string
}
