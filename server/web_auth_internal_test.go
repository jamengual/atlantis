// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/runatlantis/atlantis/server/core/config/valid"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webauth"
	. "github.com/runatlantis/atlantis/testing"
	"github.com/urfave/negroni/v3"
)

const testSessionSecret = "0123456789abcdef0123456789abcdef"

func TestNewWebAuth(t *testing.T) {
	public, _ := url.Parse("https://atlantis.example.com")
	logger := logging.NewNoopLogger(t)
	oidc := UserConfig{
		WebSSOProviders:     []string{"oidc"},
		WebSessionSecrets:   []string{testSessionSecret},
		WebOIDCIssuerURL:    "https://login.example.com",
		WebOIDCClientID:     "id",
		WebOIDCClientSecret: "secret",
		WebRoleViewers:      []string{"*"},
	}

	m, err := webAuthFor(UserConfig{}, public, logger)
	Ok(t, err)
	Assert(t, m == nil, "no sign-in configured should return nil")

	m, err = webAuthFor(oidc, public, logger)
	Ok(t, err)
	Equals(t, "oidc", m.Providers()[0].ID)

	gh := UserConfig{WebSSOProviders: []string{"oidc", "github"}, WebSessionSecrets: []string{testSessionSecret},
		WebOIDCIssuerURL: "https://login.example.com", WebOIDCClientID: "id", WebOIDCClientSecret: "secret",
		WebGitHubClientID: "gh", WebGitHubClientSecret: "s", WebGitHubAllowedOrgs: []string{"acme"}, WebRoleDefault: "viewer"}
	m, err = webAuthFor(gh, public, logger)
	Ok(t, err)
	Equals(t, 2, len(m.Providers()))

	both := UserConfig{WebSSOProviders: []string{"oidc", "google"}, WebSessionSecrets: []string{testSessionSecret},
		WebOIDCIssuerURL: "https://login.microsoftonline.com/t/v2.0", WebOIDCClientID: "id", WebOIDCClientSecret: "secret",
		WebGoogleClientID: "g", WebGoogleClientSecret: "gs", WebGoogleAllowedDomains: []string{"acme.com"}, WebRoleViewers: []string{"*"}}
	m, err = webAuthFor(both, public, logger)
	Ok(t, err)
	Equals(t, "oidc", m.Providers()[0].ID)
	Equals(t, "google", m.Providers()[1].ID)
	Equals(t, "Google", m.Providers()[1].Name)
	both.WebGoogleAllowedDomains = nil
	_, err = webAuthFor(both, public, logger)
	ErrContains(t, "web-google-allowed-domains", err)

	vcs := UserConfig{WebSSOProviders: []string{"github", "gitlab", "gitea"}, WebSessionSecrets: []string{testSessionSecret},
		WebGitHubClientID: "gh", WebGitHubClientSecret: "s", WebGitHubAllowedOrgs: []string{"acme"},
		WebGitLabClientID: "gl", WebGitLabClientSecret: "s", WebGitLabAllowedGroups: []string{"acme"}, GitlabHostname: "gitlab.acme.internal",
		WebGiteaClientID: "gt", WebGiteaClientSecret: "s", WebGiteaAllowedOrgs: []string{"acme"}, GiteaBaseURL: "https://gitea.acme.internal",
		WebRoleViewers: []string{"gitlab:acme", "gitea:acme", "github:acme"}}
	m, err = webAuthFor(vcs, public, logger)
	Ok(t, err)
	Equals(t, 3, len(m.Providers()))
	Equals(t, "GitLab", m.Providers()[1].Name)
	Equals(t, "gitea", m.Providers()[2].ID)
	vcs.WebGitLabAllowedGroups = nil
	_, err = webAuthFor(vcs, public, logger)
	ErrContains(t, "web-gitlab-allowed-groups", err)
	vcs.WebGitLabAllowedGroups = []string{"acme"}
	vcs.WebGiteaClientSecret = ""
	_, err = webAuthFor(vcs, public, logger)
	ErrContains(t, "web-gitea-client-secret", err)

	proxy := UserConfig{WebProxyAuth: "header", WebProxyUserHeader: "X-User", WebProxyTrustedCIDRs: []string{"10.0.0.0/8"}, WebRoleViewers: []string{"*"}}
	m, err = webAuthFor(proxy, public, logger)
	Ok(t, err)
	Assert(t, m.UsesProxy(), "proxy mode expected")

	bad := []struct {
		name   string
		mutate func(*UserConfig)
		want   string
	}{
		{"both modes", func(c *UserConfig) { c.WebProxyAuth = "alb" }, "can't be used together"},
		{"no roles", func(c *UserConfig) { c.WebRoleViewers = nil }, "no role rules"},
		{"bad default role", func(c *UserConfig) { c.WebRoleDefault = "root" }, "unknown role"},
		{"bad role rule", func(c *UserConfig) { c.WebRoleAdmins = []string{"team:x"} }, "unknown kind"},
		{"bad lifetime", func(c *UserConfig) { c.WebSessionLifetime = "forever" }, "positive duration"},
		{"negative lifetime", func(c *UserConfig) { c.WebSessionLifetime = "-1h" }, "positive duration"},
		{"no secrets", func(c *UserConfig) { c.WebSessionSecrets = nil }, "session secret"},
		{"short secret", func(c *UserConfig) { c.WebSessionSecrets = []string{"short"} }, "at least 32"},
		{"oidc incomplete", func(c *UserConfig) { c.WebOIDCClientSecret = "" }, "web-oidc-client-secret"},
		{"unknown provider", func(c *UserConfig) { c.WebSSOProviders = []string{"saml"} }, "unknown provider"},
		{"github incomplete", func(c *UserConfig) { c.WebSSOProviders = []string{"github"} }, "web-github-client-id"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			c := oidc
			tc.mutate(&c)
			_, err := webAuthFor(c, public, logger)
			ErrContains(t, tc.want, err)
			Assert(t, !strings.Contains(err.Error(), testSessionSecret), "error leaked a secret")
		})
	}

	badProxy := []struct {
		name string
		c    UserConfig
		want string
	}{
		{"alb without arn", UserConfig{WebProxyAuth: "alb", WebRoleViewers: []string{"*"}}, "load balancer ARN"},
		{"iap without audience", UserConfig{WebProxyAuth: "iap", WebRoleViewers: []string{"*"}}, "audience"},
		{"header without cidrs", UserConfig{WebProxyAuth: "header", WebProxyUserHeader: "X-User", WebRoleViewers: []string{"*"}}, "trusted proxy networks"},
		{"bad cidr", UserConfig{WebProxyAuth: "header", WebProxyUserHeader: "X-User", WebProxyTrustedCIDRs: []string{"10.0.0.1"}, WebRoleViewers: []string{"*"}}, "not a network"},
		{"unknown type", UserConfig{WebProxyAuth: "saml", WebRoleViewers: []string{"*"}}, "unknown proxy type"},
	}
	for _, tc := range badProxy {
		t.Run(tc.name, func(t *testing.T) {
			_, err := webAuthFor(tc.c, public, logger)
			ErrContains(t, tc.want, err)
		})
	}
}

func TestValidateExperiments_SignInNeedsWebUI(t *testing.T) {
	c := UserConfig{WebSSOProviders: []string{"oidc"}}
	ErrContains(t, `requires the "web-ui" experiment`, c.ValidateExperiments())
	c = UserConfig{WebProxyAuth: "alb"}
	ErrContains(t, `requires the "web-ui" experiment`, c.ValidateExperiments())
	c.Experiments = []string{"web-ui"}
	Ok(t, c.ValidateExperiments())
}

func TestRequestLogger_WebUISignInSkipsBasicAuthOnlyForUI(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	serve := func(l *RequestLogger, path string) int {
		n := negroni.New(l)
		n.UseHandler(ok)
		rec := httptest.NewRecorder()
		n.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}
	withSignIn := &RequestLogger{logger: logging.NewNoopLogger(t), WebAuthentication: true, WebUsername: "u", WebPassword: "p", webUISignIn: true}
	without := &RequestLogger{logger: logging.NewNoopLogger(t), WebAuthentication: true, WebUsername: "u", WebPassword: "p"}

	// With web sign-in, /ui authenticates its own users.
	Equals(t, http.StatusOK, serve(withSignIn, "/ui"))
	Equals(t, http.StatusOK, serve(withSignIn, "/ui/locks"))
	// The existing UI's pages and actions move to web sign-in too: pages
	// redirect to the new UI and actions check the access policy.
	Equals(t, http.StatusOK, serve(withSignIn, "/"))
	Equals(t, http.StatusOK, serve(withSignIn, "/locks"))
	Equals(t, http.StatusOK, serve(withSignIn, "/apply/lock"))
	Equals(t, http.StatusOK, serve(withSignIn, "/jobs/abc"))
	// Everything else keeps basic auth.
	Equals(t, http.StatusUnauthorized, serve(withSignIn, "/uix"))
	Equals(t, http.StatusUnauthorized, serve(withSignIn, "/jobs/abc/ws"))
	Equals(t, http.StatusUnauthorized, serve(withSignIn, "/debug/pprof/"))
	Equals(t, http.StatusUnauthorized, serve(withSignIn, "/metrics"))
	Equals(t, http.StatusUnauthorized, serve(withSignIn, "/github-app/setup"))
	// Without web sign-in, /ui stays behind basic auth.
	Equals(t, http.StatusUnauthorized, serve(without, "/ui"))
}

func webAuthFor(c UserConfig, public *url.URL, logger logging.SimpleLogging) (*webauth.Manager, error) {
	m, _, err := newWebAuth(c, public, logger, valid.GlobalCfg{})
	return m, err
}
