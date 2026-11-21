// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/runatlantis/atlantis/server/core/config/valid"
)

// SignIn is the raw schema of web UI sign-in, under access:
//
//	access:
//	  sign_in:
//	    session_lifetime: 4h
//	    providers:
//	      - type: github
//	        client_id: Iv1.0123456789abcdef
//	        client_secret_env: GITHUB_OAUTH_SECRET
//	        allowed_orgs: [acme]
//	      - type: oidc
//	        name: Microsoft Entra ID
//	        issuer_url: https://login.microsoftonline.com/TENANT/v2.0
//	        client_id: APPLICATION_ID
//	        client_secret_env: ENTRA_CLIENT_SECRET
//	        groups_claims: [roles]
//
// or, behind an authenticating proxy:
//
//	access:
//	  sign_in:
//	    proxy:
//	      type: alb
//	      alb_arn: arn:aws:elasticloadbalancing:...
//
// Secrets are never written here: client_secret_env names the environment
// variable that holds them.
type SignIn struct {
	SessionLifetime string           `yaml:"session_lifetime,omitempty" json:"session_lifetime,omitempty"`
	Providers       []SignInProvider `yaml:"providers,omitempty" json:"providers,omitempty"`
	Proxy           *SignInProxy     `yaml:"proxy,omitempty" json:"proxy,omitempty"`
}

// SignInProvider is one sign-in button. Which fields apply depends on Type.
type SignInProvider struct {
	Type            string   `yaml:"type" json:"type"`
	Name            string   `yaml:"name,omitempty" json:"name,omitempty"`
	IssuerURL       string   `yaml:"issuer_url,omitempty" json:"issuer_url,omitempty"`
	ClientID        string   `yaml:"client_id" json:"client_id"`
	ClientSecretEnv string   `yaml:"client_secret_env" json:"client_secret_env"`
	Scopes          []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	GroupsClaims    []string `yaml:"groups_claims,omitempty" json:"groups_claims,omitempty"`
	AllowedDomains  []string `yaml:"allowed_domains,omitempty" json:"allowed_domains,omitempty"`
	AllowedOrgs     []string `yaml:"allowed_orgs,omitempty" json:"allowed_orgs,omitempty"`
	AllowedGroups   []string `yaml:"allowed_groups,omitempty" json:"allowed_groups,omitempty"`
}

// SignInProxy takes the identity from a proxy in front of Atlantis.
type SignInProxy struct {
	Type         string   `yaml:"type" json:"type"`
	ALBArn       string   `yaml:"alb_arn,omitempty" json:"alb_arn,omitempty"`
	IAPAudience  string   `yaml:"iap_audience,omitempty" json:"iap_audience,omitempty"`
	UserHeader   string   `yaml:"user_header,omitempty" json:"user_header,omitempty"`
	EmailHeader  string   `yaml:"email_header,omitempty" json:"email_header,omitempty"`
	GroupsHeader string   `yaml:"groups_header,omitempty" json:"groups_header,omitempty"`
	TrustedCIDRs []string `yaml:"trusted_cidrs,omitempty" json:"trusted_cidrs,omitempty"`
}

var signInProviderTypes = []string{"github", "gitlab", "gitea", "oidc", "google"}

// envVarName is a portable environment variable name.
var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// providerFields lists, per type, the optional fields that apply; every
// provider also has client_id and client_secret_env.
var providerFields = map[string][]string{
	"github": {"allowed_orgs"},
	"gitlab": {"allowed_groups"},
	"gitea":  {"allowed_orgs"},
	"oidc":   {"name", "issuer_url", "scopes", "groups_claims", "allowed_domains"},
	"google": {"allowed_domains"},
}

// setFields names the optional fields that have a value.
func (p SignInProvider) setFields() []string {
	var out []string
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"name", p.Name != ""},
		{"issuer_url", p.IssuerURL != ""},
		{"scopes", len(p.Scopes) > 0},
		{"groups_claims", len(p.GroupsClaims) > 0},
		{"allowed_domains", len(p.AllowedDomains) > 0},
		{"allowed_orgs", len(p.AllowedOrgs) > 0},
		{"allowed_groups", len(p.AllowedGroups) > 0},
	} {
		if f.set {
			out = append(out, f.name)
		}
	}
	return out
}

func (p SignInProvider) validate(where string) error {
	t := strings.ToLower(strings.TrimSpace(p.Type))
	if !slices.Contains(signInProviderTypes, t) {
		return fmt.Errorf("%s.type: unknown provider %q; use %s", where, p.Type, strings.Join(signInProviderTypes, ", "))
	}
	if strings.TrimSpace(p.ClientID) == "" {
		return fmt.Errorf("%s: %s sign-in needs client_id", where, t)
	}
	if !envVarName.MatchString(p.ClientSecretEnv) {
		return fmt.Errorf("%s: %s sign-in needs client_secret_env, the name of the environment variable that holds the client secret, such as %s_CLIENT_SECRET", where, t, strings.ToUpper(t))
	}
	for _, f := range p.setFields() {
		if !slices.Contains(providerFields[t], f) {
			return fmt.Errorf("%s.%s: doesn't apply to %s sign-in", where, f, t)
		}
	}
	// Anyone can create an account on these providers, so each needs a list
	// of who may sign in.
	switch {
	case (t == "github" || t == "gitea") && len(p.AllowedOrgs) == 0:
		return fmt.Errorf("%s: %s sign-in needs allowed_orgs, because people can create their own accounts", where, t)
	case t == "gitlab" && len(p.AllowedGroups) == 0:
		return fmt.Errorf("%s: gitlab sign-in needs allowed_groups, because people can create their own accounts", where)
	case t == "google" && len(p.AllowedDomains) == 0:
		return fmt.Errorf("%s: google sign-in needs allowed_domains, because anyone can create a Google account", where)
	case t == "oidc" && strings.TrimSpace(p.IssuerURL) == "":
		return fmt.Errorf("%s: oidc sign-in needs issuer_url", where)
	}
	return nil
}

var signInProxyTypes = []string{"alb", "iap", "header"}

func (p SignInProxy) validate(where string) error {
	t := strings.ToLower(strings.TrimSpace(p.Type))
	if !slices.Contains(signInProxyTypes, t) {
		return fmt.Errorf("%s.type: unknown proxy type %q; use %s", where, p.Type, strings.Join(signInProxyTypes, ", "))
	}
	// Type-specific requirements, such as the ALB ARN, are checked when the
	// proxy authenticator is built at startup.
	return nil
}

// Validate checks the sign-in section.
func (s SignIn) Validate() error {
	const where = "access.sign_in"
	if s.SessionLifetime != "" {
		if d, err := time.ParseDuration(s.SessionLifetime); err != nil || d <= 0 {
			return fmt.Errorf("%s.session_lifetime: %q is not a positive duration such as 8h", where, s.SessionLifetime)
		}
	}
	if len(s.Providers) > 0 && s.Proxy != nil {
		return fmt.Errorf("%s: providers and proxy can't be used together; choose sign-in pages or an authenticating proxy", where)
	}
	if len(s.Providers) == 0 && s.Proxy == nil {
		return fmt.Errorf("%s: add providers or a proxy", where)
	}
	seen := map[string]bool{}
	for i, p := range s.Providers {
		w := fmt.Sprintf("%s.providers[%d]", where, i)
		if err := p.validate(w); err != nil {
			return err
		}
		t := strings.ToLower(strings.TrimSpace(p.Type))
		if seen[t] {
			return fmt.Errorf("%s: there is already a %s provider; each type can be used once", w, t)
		}
		seen[t] = true
	}
	if s.Proxy != nil {
		return s.Proxy.validate(where + ".proxy")
	}
	return nil
}

func trimAll(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ToValid converts a validated section; nil stays nil.
func (s *SignIn) ToValid() *valid.SignIn {
	if s == nil {
		return nil
	}
	out := &valid.SignIn{}
	if s.SessionLifetime != "" {
		out.SessionLifetime, _ = time.ParseDuration(s.SessionLifetime)
	}
	for _, p := range s.Providers {
		out.Providers = append(out.Providers, valid.SignInProvider{
			Type:            strings.ToLower(strings.TrimSpace(p.Type)),
			Name:            strings.TrimSpace(p.Name),
			IssuerURL:       strings.TrimSpace(p.IssuerURL),
			ClientID:        strings.TrimSpace(p.ClientID),
			ClientSecretEnv: p.ClientSecretEnv,
			Scopes:          trimAll(p.Scopes),
			GroupsClaims:    trimAll(p.GroupsClaims),
			AllowedDomains:  trimAll(p.AllowedDomains),
			AllowedOrgs:     trimAll(p.AllowedOrgs),
			AllowedGroups:   trimAll(p.AllowedGroups),
		})
	}
	if s.Proxy != nil {
		out.Proxy = &valid.SignInProxy{
			Type:         strings.ToLower(strings.TrimSpace(s.Proxy.Type)),
			ALBArn:       strings.TrimSpace(s.Proxy.ALBArn),
			IAPAudience:  strings.TrimSpace(s.Proxy.IAPAudience),
			UserHeader:   strings.TrimSpace(s.Proxy.UserHeader),
			EmailHeader:  strings.TrimSpace(s.Proxy.EmailHeader),
			GroupsHeader: strings.TrimSpace(s.Proxy.GroupsHeader),
			TrustedCIDRs: trimAll(s.Proxy.TrustedCIDRs),
		}
	}
	return out
}
