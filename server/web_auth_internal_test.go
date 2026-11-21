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

// signInCfg is a server-side repo config with sign-in and one role rule.
func signInCfg(signIn *valid.SignIn) valid.GlobalCfg {
	if signIn.SessionSecretsEnv == "" {
		signIn.SessionSecretsEnv = "SESSION_SECRETS"
	}
	return valid.GlobalCfg{Access: &valid.Access{
		SignIn: signIn,
		Roles:  valid.AccessRoles{Viewer: []valid.AccessRule{{Everyone: true}}},
	}}
}

var testEnv = map[string]string{"SESSION_SECRETS": " " + testSessionSecret + ", " + testSessionSecret + "x", "SHORT_SECRETS": "short", "OIDC_SECRET": "oidc-secret", "GH_SECRET": "gh-secret", "GL_SECRET": "gl-secret", "GT_SECRET": "gt-secret", "G_SECRET": "g-secret"}

func oidcProvider() valid.SignInProvider {
	return valid.SignInProvider{Type: "oidc", IssuerURL: "https://login.example.com", ClientID: "id", ClientSecretEnv: "OIDC_SECRET"}
}

func TestNewWebAuth(t *testing.T) {
	public, _ := url.Parse("https://atlantis.example.com")
	server := UserConfig{GitlabHostname: "gitlab.acme.internal", GiteaBaseURL: "https://gitea.acme.internal"}

	m, err := webAuthFor(server, valid.GlobalCfg{}, public, t)
	Ok(t, err)
	Assert(t, m == nil, "no sign-in configured should return nil")

	m, err = webAuthFor(server, signInCfg(&valid.SignIn{Providers: []valid.SignInProvider{oidcProvider()}}), public, t)
	Ok(t, err)
	Equals(t, "oidc", m.Providers()[0].ID)
	Equals(t, "Single sign-on", m.Providers()[0].Name)

	all := &valid.SignIn{Providers: []valid.SignInProvider{
		{Type: "github", ClientID: "gh", ClientSecretEnv: "GH_SECRET", AllowedOrgs: []string{"acme"}},
		{Type: "gitlab", ClientID: "gl", ClientSecretEnv: "GL_SECRET", AllowedGroups: []string{"acme"}},
		{Type: "gitea", ClientID: "gt", ClientSecretEnv: "GT_SECRET", AllowedOrgs: []string{"acme"}},
		{Type: "oidc", Name: "Microsoft Entra ID", IssuerURL: "https://login.microsoftonline.com/t/v2.0", ClientID: "id", ClientSecretEnv: "OIDC_SECRET", GroupsClaims: []string{"roles"}},
		{Type: "google", ClientID: "g", ClientSecretEnv: "G_SECRET", AllowedDomains: []string{"acme.com"}},
	}}
	m, err = webAuthFor(server, signInCfg(all), public, t)
	Ok(t, err)
	var names []string
	for _, p := range m.Providers() {
		names = append(names, p.ID+"="+p.Name)
	}
	Equals(t, []string{"github=GitHub", "gitlab=GitLab", "gitea=Gitea", "oidc=Microsoft Entra ID", "google=Google"}, names)

	proxy := &valid.SignIn{Proxy: &valid.SignInProxy{Type: "header", UserHeader: "X-User", TrustedCIDRs: []string{"10.0.0.0/8"}}}
	m, err = webAuthFor(server, signInCfg(proxy), public, t)
	Ok(t, err)
	Assert(t, m.UsesProxy(), "proxy mode expected")

	bad := []struct {
		name   string
		server func(*UserConfig)
		cfg    valid.GlobalCfg
		want   string
	}{
		{"no roles", nil, valid.GlobalCfg{Access: &valid.Access{SignIn: &valid.SignIn{Providers: []valid.SignInProvider{oidcProvider()}}}}, "no role rules"},
		{"secret env unset", nil, signInCfg(&valid.SignIn{Providers: []valid.SignInProvider{{Type: "github", ClientID: "gh", ClientSecretEnv: "UNSET_SECRET", AllowedOrgs: []string{"acme"}}}}),
			"access.sign_in.providers[0] (github): the environment variable UNSET_SECRET named by client_secret_env is not set"},
		{"no session secrets", nil, signInCfg(&valid.SignIn{SessionSecretsEnv: "UNSET_SECRETS", Providers: []valid.SignInProvider{oidcProvider()}}), "the environment variable UNSET_SECRETS named by session_secrets_env is not set"},
		{"short session secret", nil, signInCfg(&valid.SignIn{SessionSecretsEnv: "SHORT_SECRETS", Providers: []valid.SignInProvider{oidcProvider()}}), "at least 32"},
		{"alb without arn", nil, signInCfg(&valid.SignIn{Proxy: &valid.SignInProxy{Type: "alb"}}), "load balancer ARN"},
		{"iap without audience", nil, signInCfg(&valid.SignIn{Proxy: &valid.SignInProxy{Type: "iap"}}), "audience"},
		{"header without cidrs", nil, signInCfg(&valid.SignIn{Proxy: &valid.SignInProxy{Type: "header", UserHeader: "X-User"}}), "trusted proxy networks"},
		{"bad cidr", nil, signInCfg(&valid.SignIn{Proxy: &valid.SignInProxy{Type: "header", UserHeader: "X-User", TrustedCIDRs: []string{"10.0.0.1"}}}), "not a network"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			c := server
			if tc.server != nil {
				tc.server(&c)
			}
			_, err := webAuthFor(c, tc.cfg, public, t)
			ErrContains(t, tc.want, err)
			for _, secret := range append([]string{testSessionSecret}, "oidc-secret", "gh-secret") {
				Assert(t, !strings.Contains(err.Error(), secret), "error leaked a secret")
			}
		})
	}
}

func TestValidateSignInExperiment(t *testing.T) {
	cfg := signInCfg(&valid.SignIn{Providers: []valid.SignInProvider{oidcProvider()}})
	ErrContains(t, `access.sign_in in the server-side repo config) requires the "web-ui" experiment`, validateSignInExperiment(UserConfig{}, cfg))
	Ok(t, validateSignInExperiment(UserConfig{Experiments: []string{"web-ui"}}, cfg))
	Ok(t, validateSignInExperiment(UserConfig{}, valid.GlobalCfg{Access: &valid.Access{}}))
	Ok(t, validateSignInExperiment(UserConfig{}, valid.GlobalCfg{}))
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

func webAuthFor(c UserConfig, globalCfg valid.GlobalCfg, public *url.URL, t *testing.T) (*webauth.Manager, error) {
	t.Helper()
	policy, err := newAccessPolicy(globalCfg)
	if err != nil {
		return nil, err
	}
	return newWebAuthManager(c, public, logging.NewNoopLogger(t), policy, signInConfig(globalCfg), func(k string) string { return testEnv[k] })
}
