// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webauth"
)

// signInConfig returns the sign_in section of the access policy, or nil.
func signInConfig(globalCfg valid.GlobalCfg) *valid.SignIn {
	if globalCfg.Access == nil {
		return nil
	}
	return globalCfg.Access.SignIn
}

// validateSignInExperiment rejects sign-in settings without the web-ui
// experiment, so they are never silently ignored.
func validateSignInExperiment(c UserConfig, globalCfg valid.GlobalCfg) error {
	if signInConfig(globalCfg) != nil && !slices.Contains(c.Experiments, webUIExperiment) {
		return fmt.Errorf("web UI sign-in (access.sign_in in the server-side repo config) requires the %q experiment; add it to experiments or remove the sign-in settings; see %s", webUIExperiment, ExperimentsDocumentationURL)
	}
	return nil
}

// newWebAuth builds web UI sign-in from the server configuration. It returns
// nil when no sign-in is configured, in which case the UI keeps using basic
// auth, or no auth, like the rest of Atlantis.
func newWebAuth(c UserConfig, publicURL *url.URL, logger logging.SimpleLogging, globalCfg valid.GlobalCfg) (*webauth.Manager, *webauth.Policy, error) {
	policy, err := newAccessPolicy(globalCfg)
	if err != nil {
		return nil, nil, err
	}
	m, err := newWebAuthManager(c, publicURL, logger, policy, signInConfig(globalCfg), os.Getenv)
	return m, policy, err
}

// newAccessPolicy builds the access policy from the server-side repo config.
func newAccessPolicy(globalCfg valid.GlobalCfg) (*webauth.Policy, error) {
	policy, err := webauth.NewPolicy(webauth.PolicyConfig{
		Access:           globalCfg.Access,
		Repos:            globalCfg.Repos,
		PolicyOwnerTeams: slices.Clone(globalCfg.PolicySets.AllTeams()),
	})
	if err != nil {
		return nil, fmt.Errorf("web access policy: %w", err)
	}
	return policy, nil
}

// newWebAuthManager builds sign-in from access.sign_in. getenv reads the
// client secrets named by client_secret_env.
func newWebAuthManager(c UserConfig, publicURL *url.URL, logger logging.SimpleLogging, policy *webauth.Policy, signIn *valid.SignIn, getenv func(string) string) (*webauth.Manager, error) {
	if signIn == nil {
		return nil, nil
	}
	if !policy.HasRules() {
		return nil, errors.New("web sign-in has no role rules, so nobody could use the UI; add roles, or a default role, to the access section of the server-side repo config")
	}

	lifetime := webauth.DefaultSessionLifetime
	if signIn.SessionLifetime > 0 {
		lifetime = signIn.SessionLifetime
	}
	cfg := webauth.Config{
		PublicURL:       publicURL,
		SessionSecrets:  c.WebSessionSecrets,
		SessionLifetime: lifetime,
		Policy:          policy,
		Logger:          logger,
	}

	if px := signIn.Proxy; px != nil {
		var cidrs []*net.IPNet
		for _, s := range px.TrustedCIDRs {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("access.sign_in.proxy.trusted_cidrs: %q is not a network such as 10.0.0.0/8", s)
			}
			cidrs = append(cidrs, n)
		}
		proxy, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{
			Type:         px.Type,
			ALBArn:       px.ALBArn,
			IAPAudience:  px.IAPAudience,
			UserHeader:   px.UserHeader,
			EmailHeader:  px.EmailHeader,
			GroupsHeader: px.GroupsHeader,
			TrustedCIDRs: cidrs,
		})
		if err != nil {
			return nil, fmt.Errorf("access.sign_in.proxy: %w", err)
		}
		cfg.Proxy = proxy
	}

	for i, sp := range signIn.Providers {
		where := fmt.Sprintf("access.sign_in.providers[%d] (%s)", i, sp.Type)
		secret := strings.TrimSpace(getenv(sp.ClientSecretEnv))
		if secret == "" {
			return nil, fmt.Errorf("%s: the environment variable %s named by client_secret_env is not set", where, sp.ClientSecretEnv)
		}
		p, err := newLoginProvider(c, sp, secret)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		cfg.Providers = append(cfg.Providers, p)
	}
	m, err := webauth.NewManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("web sign-in: %w", err)
	}
	return m, nil
}

// newLoginProvider builds one provider. VCS providers sign in on the host
// Atlantis already uses for that VCS.
func newLoginProvider(c UserConfig, sp valid.SignInProvider, secret string) (webauth.LoginProvider, error) {
	switch sp.Type {
	case "github":
		return webauth.NewGitHubProvider(webauth.GitHubConfig{ClientID: sp.ClientID, ClientSecret: secret, Hostname: c.GithubHostname, AllowedOrgs: sp.AllowedOrgs})
	case "gitlab":
		return webauth.NewGitLabProvider(webauth.GitLabConfig{ClientID: sp.ClientID, ClientSecret: secret, Hostname: c.GitlabHostname, AllowedGroups: sp.AllowedGroups})
	case "gitea":
		return webauth.NewGiteaProvider(webauth.GiteaConfig{ClientID: sp.ClientID, ClientSecret: secret, BaseURL: c.GiteaBaseURL, AllowedOrgs: sp.AllowedOrgs})
	case "google":
		return webauth.NewGoogleProvider(sp.ClientID, secret, sp.AllowedDomains)
	case "oidc":
		scopes := sp.Scopes
		if len(scopes) == 0 {
			scopes = []string{"email", "profile"}
		}
		return webauth.NewOIDCProvider(webauth.OIDCConfig{
			Name:           sp.Name,
			IssuerURL:      sp.IssuerURL,
			ClientID:       sp.ClientID,
			ClientSecret:   secret,
			Scopes:         scopes,
			GroupsClaims:   sp.GroupsClaims,
			AllowedDomains: sp.AllowedDomains,
		})
	}
	return nil, fmt.Errorf("unknown provider %q", sp.Type)
}
