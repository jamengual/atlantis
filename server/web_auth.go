// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webauth"
)

// webSignInConfigured reports whether any web UI sign-in setting is set.
func (c UserConfig) webSignInConfigured() bool {
	return len(c.WebSSOProviders) > 0 || c.WebProxyAuth != ""
}

// newWebAuth builds web UI sign-in from the server configuration. It returns
// nil when no sign-in is configured, in which case the UI keeps using basic
// auth, or no auth, like the rest of Atlantis.
func newWebAuth(c UserConfig, publicURL *url.URL, logger logging.SimpleLogging) (*webauth.Manager, error) {
	if !c.webSignInConfigured() {
		return nil, nil
	}
	if len(c.WebSSOProviders) > 0 && c.WebProxyAuth != "" {
		return nil, errors.New("web-sso-providers and web-proxy-auth can't be used together; choose sign-in pages or an authenticating proxy")
	}

	defaultRole, err := webauth.ParseRole(c.WebRoleDefault)
	if err != nil {
		return nil, fmt.Errorf("web-role-default: %w", err)
	}
	roles := webauth.RoleMapper{Admins: c.WebRoleAdmins, Operators: c.WebRoleOperators, Viewers: c.WebRoleViewers, Default: defaultRole}
	if len(roles.Admins)+len(roles.Operators)+len(roles.Viewers) == 0 && defaultRole == webauth.RoleNone {
		return nil, errors.New("web sign-in has no role rules, so nobody could use the UI; set web-role-admins, web-role-operators, web-role-viewers, or web-role-default")
	}

	lifetime := webauth.DefaultSessionLifetime
	if c.WebSessionLifetime != "" {
		lifetime, err = time.ParseDuration(c.WebSessionLifetime)
		if err != nil || lifetime <= 0 {
			return nil, fmt.Errorf("web-session-lifetime %q is not a positive duration such as 8h", c.WebSessionLifetime)
		}
	}

	cfg := webauth.Config{
		PublicURL:       publicURL,
		SessionSecrets:  c.WebSessionSecrets,
		SessionLifetime: lifetime,
		Roles:           roles,
		Logger:          logger,
	}

	if c.WebProxyAuth != "" {
		var cidrs []*net.IPNet
		for _, s := range c.WebProxyTrustedCIDRs {
			_, n, err := net.ParseCIDR(strings.TrimSpace(s))
			if err != nil {
				return nil, fmt.Errorf("web-proxy-trusted-cidrs: %q is not a network such as 10.0.0.0/8", s)
			}
			cidrs = append(cidrs, n)
		}
		proxy, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{
			Type:         strings.ToLower(strings.TrimSpace(c.WebProxyAuth)),
			ALBArn:       c.WebProxyALBArn,
			IAPAudience:  c.WebProxyIAPAudience,
			UserHeader:   c.WebProxyUserHeader,
			EmailHeader:  c.WebProxyEmailHeader,
			GroupsHeader: c.WebProxyGroupsHeader,
			TrustedCIDRs: cidrs,
		})
		if err != nil {
			return nil, fmt.Errorf("web-proxy-auth: %w", err)
		}
		cfg.Proxy = proxy
		m, err := webauth.NewManager(cfg)
		if err != nil {
			return nil, fmt.Errorf("web sign-in: %w", err)
		}
		return m, nil
	}

	for _, name := range c.WebSSOProviders {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "oidc":
			p, err := webauth.NewOIDCProvider(webauth.OIDCConfig{
				Name:           c.WebOIDCName,
				IssuerURL:      c.WebOIDCIssuerURL,
				ClientID:       c.WebOIDCClientID,
				ClientSecret:   c.WebOIDCClientSecret,
				Scopes:         c.WebOIDCScopes,
				GroupsClaims:   c.WebOIDCGroupsClaims,
				AllowedDomains: c.WebOIDCAllowedDomains,
			})
			if err != nil {
				return nil, fmt.Errorf("web-sso-providers oidc: %w; set web-oidc-issuer-url, web-oidc-client-id, and web-oidc-client-secret", err)
			}
			cfg.Providers = append(cfg.Providers, p)
		case "google":
			p, err := webauth.NewGoogleProvider(c.WebGoogleClientID, c.WebGoogleClientSecret, c.WebGoogleAllowedDomains)
			if err != nil {
				return nil, fmt.Errorf("web-sso-providers google: %w; set web-google-client-id, web-google-client-secret, and web-google-allowed-domains", err)
			}
			cfg.Providers = append(cfg.Providers, p)
		case "github":
			p, err := webauth.NewGitHubProvider(webauth.GitHubConfig{
				ClientID:     c.WebGitHubClientID,
				ClientSecret: c.WebGitHubClientSecret,
				Hostname:     c.GithubHostname,
				AllowedOrgs:  c.WebGitHubAllowedOrgs,
			})
			if err != nil {
				return nil, fmt.Errorf("web-sso-providers github: %w; set web-github-client-id and web-github-client-secret", err)
			}
			cfg.Providers = append(cfg.Providers, p)
		default:
			return nil, fmt.Errorf("web-sso-providers: unknown provider %q; use oidc, google, or github", name)
		}
	}
	m, err := webauth.NewManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("web sign-in: %w", err)
	}
	return m, nil
}
