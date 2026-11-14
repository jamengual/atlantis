// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webauth"
	"github.com/runatlantis/atlantis/server/webauth/webauthtest"
	. "github.com/runatlantis/atlantis/testing"
)

// app is a minimal web UI wired the way the real one is: sign-in routes
// outside the middleware and everything else behind it.
type app struct {
	srv *httptest.Server
	m   *webauth.Manager
}

func newApp(t *testing.T, base string, build func(public *url.URL) webauth.Config) *app {
	t.Helper()
	a := &app{}
	mux := http.NewServeMux()
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	public, _ := url.Parse(a.srv.URL + base)
	cfg := build(public)
	cfg.PublicURL = public
	cfg.Logger = logging.NewNoopLogger(t)
	m, err := webauth.NewManager(cfg)
	Ok(t, err)
	a.m = m

	mux.HandleFunc(base+"/ui/login/{provider}", func(w http.ResponseWriter, r *http.Request) {
		if err := m.StartLogin(w, r, r.PathValue("provider"), r.URL.Query().Get("return")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})
	mux.HandleFunc(base+"/ui/auth/callback/{provider}", func(w http.ResponseWriter, r *http.Request) {
		ret, _, err := m.FinishLogin(w, r, r.PathValue("provider"))
		if err != nil {
			http.Error(w, "sign-in failed: "+err.Error(), http.StatusForbidden)
			return
		}
		http.Redirect(w, r, ret, http.StatusSeeOther) //nolint:gosec // test app; ret comes from SafeReturn
	})
	mux.HandleFunc(base+"/ui/logout", func(w http.ResponseWriter, _ *http.Request) {
		m.Logout(w)
		fmt.Fprint(w, "signed out")
	})
	mux.HandleFunc(base+"/ui/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "login page return=%s", r.URL.Query().Get("return")) //nolint:gosec // test app plain-text echo
	})
	mux.Handle(base+"/ui/", m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := webauth.FromContext(r.Context())
		fmt.Fprintf(w, "hello %s role=%s provider=%s email=%s path=%s", p.DisplayName(), p.Role, p.Provider, p.Email, r.URL.RequestURI()) //nolint:gosec // test app plain-text echo
	})))
	return a
}

func browser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	Ok(t, err)
	return &http.Client{Jar: jar}
}

func fetch(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := c.Get(u)
	Ok(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func oidcConfig(f *webauthtest.OIDC, mutate func(*webauth.OIDCConfig)) func(*url.URL) webauth.Config {
	return func(*url.URL) webauth.Config {
		oc := webauth.OIDCConfig{Name: "Microsoft Entra ID", IssuerURL: f.Server.URL, ClientID: f.ClientID, ClientSecret: f.ClientSecret, Scopes: []string{"email", "profile"}}
		if mutate != nil {
			mutate(&oc)
		}
		p, err := webauth.NewOIDCProvider(oc)
		if err != nil {
			panic(err)
		}
		return webauth.Config{
			SessionSecrets: []string{secretA},
			Providers:      []webauth.LoginProvider{p},
			Roles:          webauth.RoleMapper{Admins: []string{"platform-admins"}, Operators: []string{"sre"}, Viewers: []string{"domain:acme.com"}},
		}
	}
}

func TestOIDC_SignInFlow(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	idp.SetUser(map[string]any{"sub": "u-1", "name": "Maya Rivera", "email": "maya@acme.com", "email_verified": true, "groups": []string{"sre"}})
	a := newApp(t, "", oidcConfig(idp, nil))
	c := browser(t)

	// Not signed in: a page load goes to the sign-in page and keeps the target.
	noRedirect := &http.Client{Jar: c.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(a.srv.URL + "/ui/locks?state=x")
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/login?return=%2Fui%2Flocks%3Fstate%3Dx", resp.Header.Get("Location"))

	status, body := fetch(t, c, a.srv.URL+"/ui/login/oidc?return="+url.QueryEscape("/ui/locks?state=x"))
	Equals(t, http.StatusOK, status)
	Equals(t, "hello Maya Rivera role=operator provider=oidc email=maya@acme.com path=/ui/locks?state=x", body)

	// The session works for later requests.
	_, body = fetch(t, c, a.srv.URL+"/ui")
	Assert(t, strings.HasPrefix(body, "hello Maya Rivera role=operator"), "session not kept: %s", body)

	// Signing out clears it.
	fetch(t, c, a.srv.URL+"/ui/logout")
	_, body = fetch(t, c, a.srv.URL+"/ui")
	Assert(t, strings.HasPrefix(body, "login page"), "still signed in after logout: %s", body)
}

func TestOIDC_SessionCookieAttributes(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	idp.SetUser(map[string]any{"sub": "u-1", "groups": []string{"sre"}})
	a := newApp(t, "/atlantis", oidcConfig(idp, nil))
	c := browser(t)
	fetch(t, c, a.srv.URL+"/atlantis/ui/login/oidc")
	u, _ := url.Parse(a.srv.URL + "/atlantis/ui")
	cookies := c.Jar.Cookies(u)
	Equals(t, 1, len(cookies))
	Equals(t, "atlantis_session", cookies[0].Name)
	// The cookie jar only returns name and value; check the header directly.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(a.srv.URL + "/atlantis/ui/login/oidc")
	Ok(t, err)
	resp.Body.Close()
	flow := resp.Header.Get("Set-Cookie")
	assertHas(t, flow, "atlantis_signin=", "Path=/atlantis/ui/auth/", "HttpOnly", "SameSite=Lax")
}

func assertHas(t *testing.T, s string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		Assert(t, strings.Contains(s, p), "%q does not contain %q", s, p)
	}
}

func TestOIDC_RoleFromUserInfoGroups(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	// No groups claim in the ID token; the provider lists them in userinfo.
	idp.SetUser(map[string]any{"sub": "u-2", "name": "Ana"})
	idp.SetUserInfo(map[string]any{"groups": []string{"platform-admins"}})
	a := newApp(t, "", oidcConfig(idp, nil))
	_, body := fetch(t, browser(t), a.srv.URL+"/ui/login/oidc")
	Equals(t, "hello Ana role=admin provider=oidc email= path=/ui/", body)
}

func TestOIDC_EntraAppRoles(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	idp.SetUser(map[string]any{"sub": "u-3", "name": "Kai", "roles": []string{"platform-admins"}})
	a := newApp(t, "", oidcConfig(idp, func(c *webauth.OIDCConfig) { c.GroupsClaims = []string{"groups", "roles"} }))
	_, body := fetch(t, browser(t), a.srv.URL+"/ui/login/oidc")
	Assert(t, strings.Contains(body, "role=admin"), "app role not used: %s", body)
}

func TestOIDC_Denials(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		mutate func(*webauth.OIDCConfig)
		tamper bool
		want   string
	}{
		{"no matching role", map[string]any{"sub": "u", "email": "x@other.com", "email_verified": true}, nil, false, "no Atlantis role"},
		{"unverified email does not match the domain rule", map[string]any{"sub": "u", "email": "x@acme.com"}, nil, false, "no Atlantis role"},
		{"entra group overage", map[string]any{"sub": "u", "_claim_names": map[string]any{"groups": "src1"},
			"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://graph.windows.net/tenant/users/u/getMemberObjects"}}}, nil, false, "too many groups"},
		{"wrong nonce", map[string]any{"sub": "u", "groups": []string{"sre"}}, nil, true, "nonce"},
		{"domain not allowed", map[string]any{"sub": "u", "email": "x@evil.com", "email_verified": true, "groups": []string{"sre"}},
			func(c *webauth.OIDCConfig) { c.AllowedDomains = []string{"acme.com"} }, false, "allowed domains are acme.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := webauthtest.NewOIDC()
			defer idp.Server.Close()
			idp.SetUser(tc.claims)
			idp.TamperNonce(tc.tamper)
			a := newApp(t, "", oidcConfig(idp, tc.mutate))
			c := browser(t)
			status, body := fetch(t, c, a.srv.URL+"/ui/login/oidc")
			Equals(t, http.StatusForbidden, status)
			Assert(t, strings.Contains(body, tc.want), "got %q, want %q", body, tc.want)
			_, body = fetch(t, c, a.srv.URL+"/ui")
			Assert(t, strings.HasPrefix(body, "login page"), "denied user got a session: %s", body)
		})
	}
}

func TestOIDC_HostedDomainAllowed(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	idp.SetUser(map[string]any{"sub": "u", "email": "x@acme.com", "email_verified": true, "hd": "acme.com"})
	a := newApp(t, "", oidcConfig(idp, func(c *webauth.OIDCConfig) { c.AllowedDomains = []string{"acme.com"} }))
	_, body := fetch(t, browser(t), a.srv.URL+"/ui/login/oidc")
	Assert(t, strings.Contains(body, "role=viewer"), "google workspace user denied: %s", body)
}

func TestCallback_RejectsForgedOrReplayedState(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	idp.SetUser(map[string]any{"sub": "u", "groups": []string{"sre"}})
	a := newApp(t, "", oidcConfig(idp, nil))

	// A callback with no sign-in cookie, as from a forged link.
	status, body := fetch(t, browser(t), a.srv.URL+"/ui/auth/callback/oidc?code=x&state=y")
	Equals(t, http.StatusForbidden, status)
	Assert(t, strings.Contains(body, "no saved state"), body)

	// A real flow whose state is swapped.
	c := browser(t)
	noRedirect := &http.Client{Jar: c.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(a.srv.URL + "/ui/login/oidc")
	Ok(t, err)
	resp.Body.Close()
	status, body = fetch(t, noRedirect, a.srv.URL+"/ui/auth/callback/oidc?code=x&state=forged")
	Equals(t, http.StatusForbidden, status)
	Assert(t, strings.Contains(body, "does not match"), body)

	// Provider errors are shown, not swallowed.
	resp, err = noRedirect.Get(a.srv.URL + "/ui/login/oidc")
	Ok(t, err)
	resp.Body.Close()
	_, body = fetch(t, noRedirect, a.srv.URL+"/ui/auth/callback/oidc?error=access_denied&error_description=User+cancelled")
	Assert(t, strings.Contains(body, "User cancelled"), body)
}

func TestSafeReturn(t *testing.T) {
	m, err := webauth.NewManager(webauth.Config{
		PublicURL:      &url.URL{Scheme: "https", Host: "atlantis.example", Path: "/atlantis"},
		SessionSecrets: []string{secretA},
		Providers:      []webauth.LoginProvider{mustGitHub(t, webauth.GitHubConfig{ClientID: "a", ClientSecret: "b"})},
		Logger:         logging.NewNoopLogger(t),
	})
	Ok(t, err)
	ok := map[string]string{
		"/atlantis/ui":                    "/atlantis/ui",
		"/atlantis/ui/locks?state=x":      "/atlantis/ui/locks?state=x",
		"/atlantis/ui/../ui/pulls":        "/atlantis/ui/pulls",
		"/atlantis/ui/login?return=/evil": "/atlantis/ui",
		"/atlantis/ui/auth/callback/oidc": "/atlantis/ui",
	}
	for in, want := range ok {
		got, accepted := m.SafeReturn(in)
		Assert(t, accepted, "%q rejected", in)
		Equals(t, want, got)
	}
	for _, bad := range []string{"", "https://evil.example/atlantis/ui", "//evil.example/atlantis/ui", "/\\evil", "/atlantis/uix", "/atlantis/ui/../../etc", "/other", "/atlantis/ui#x"} {
		_, accepted := m.SafeReturn(bad)
		Assert(t, !accepted, "%q accepted", bad)
	}
}

func mustGitHub(t *testing.T, cfg webauth.GitHubConfig) *webauth.GitHubProvider {
	t.Helper()
	p, err := webauth.NewGitHubProvider(cfg)
	Ok(t, err)
	return p
}

func githubConfig(f *webauthtest.GitHub, allowed []string) func(*url.URL) webauth.Config {
	return func(*url.URL) webauth.Config {
		p, err := webauth.NewGitHubProvider(webauth.GitHubConfig{ClientID: f.ClientID, ClientSecret: f.ClientSecret, BaseURLOverride: f.Server.URL, AllowedOrgs: allowed})
		if err != nil {
			panic(err)
		}
		return webauth.Config{
			SessionSecrets: []string{secretA},
			Providers:      []webauth.LoginProvider{p},
			Roles:          webauth.RoleMapper{Admins: []string{"acme/platform"}, Operators: []string{"acme/sre"}, Viewers: []string{"acme"}},
		}
	}
}

func TestGitHub_SignInWithTeams(t *testing.T) {
	gh := webauthtest.NewGitHub()
	defer gh.Server.Close()
	gh.SetUser(
		map[string]any{"id": 42, "login": "octo", "name": "Octo Cat"},
		[]map[string]any{{"email": "octo@acme.com", "primary": true, "verified": true}},
		[]map[string]any{{"login": "acme"}},
		// Membership in a child team counts for its parent team.
		[]map[string]any{{"slug": "sre-oncall", "organization": map[string]any{"login": "acme"}, "parent": map[string]any{"slug": "sre"}}},
	)
	a := newApp(t, "", githubConfig(gh, []string{"acme"}))
	_, body := fetch(t, browser(t), a.srv.URL+"/ui/login/github")
	Equals(t, "hello Octo Cat role=operator provider=github email=octo@acme.com path=/ui/", body)
}

func TestGitHub_OrgRestriction(t *testing.T) {
	gh := webauthtest.NewGitHub()
	defer gh.Server.Close()
	gh.SetUser(map[string]any{"id": 7, "login": "outsider"}, nil, []map[string]any{{"login": "other"}}, nil)
	a := newApp(t, "", githubConfig(gh, []string{"acme"}))
	status, body := fetch(t, browser(t), a.srv.URL+"/ui/login/github")
	Equals(t, http.StatusForbidden, status)
	Assert(t, strings.Contains(body, "only members of acme"), body)
}

func TestGitHubHosts(t *testing.T) {
	for host, want := range map[string]string{
		"":                     "https://github.com/login/oauth/authorize",
		"github.com":           "https://github.com/login/oauth/authorize",
		"github.acme.internal": "https://github.acme.internal/login/oauth/authorize",
		"acme.ghe.com":         "https://acme.ghe.com/login/oauth/authorize",
	} {
		p := mustGitHub(t, webauth.GitHubConfig{ClientID: "id", ClientSecret: "s", Hostname: host})
		u, err := p.AuthCodeURL(t.Context(), "state", "", "verifier-verifier-verifier-verifier-verifier", "https://atlantis/cb")
		Ok(t, err)
		Assert(t, strings.HasPrefix(u, want+"?"), "%s: %s", host, u)
		assertHas(t, u, "code_challenge_method=S256", "scope=read%3Aorg+user%3Aemail")
	}
}

func TestSessionExpires(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	idp.SetUser(map[string]any{"sub": "u", "groups": []string{"sre"}})
	clock := time.Now()
	a := newApp(t, "", func(p *url.URL) webauth.Config {
		cfg := oidcConfig(idp, nil)(p)
		cfg.SessionLifetime = time.Hour
		cfg.Now = func() time.Time { return clock }
		return cfg
	})
	c := browser(t)
	_, body := fetch(t, c, a.srv.URL+"/ui/login/oidc")
	Assert(t, strings.HasPrefix(body, "hello"), body)
	clock = clock.Add(2 * time.Hour)
	_, body = fetch(t, c, a.srv.URL+"/ui")
	Assert(t, strings.HasPrefix(body, "login page"), "expired session still accepted: %s", body)
}

func TestMiddleware_NonPageRequestsGet401(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	a := newApp(t, "", oidcConfig(idp, nil))
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, a.srv.URL+"/ui/locks/discard", nil),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, a.srv.URL+"/ui/jobs/x/events", nil)
			r.Header.Set("Accept", "text/event-stream")
			return r
		}(),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, a.srv.URL+"/ui/pulls", nil)
			r.Header.Set("HX-Request", "true")
			return r
		}(),
	} {
		req.RequestURI = ""
		resp, err := http.DefaultClient.Do(req)
		Ok(t, err)
		resp.Body.Close()
		Equals(t, http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestNewManagerValidation(t *testing.T) {
	_, err := webauth.NewManager(webauth.Config{PublicURL: &url.URL{Scheme: "https", Host: "a"}, Logger: logging.NewNoopLogger(t)})
	ErrContains(t, "at least one provider", err)
	gh := mustGitHub(t, webauth.GitHubConfig{ClientID: "a", ClientSecret: "b"})
	_, err = webauth.NewManager(webauth.Config{PublicURL: &url.URL{Scheme: "https", Host: "a"}, Providers: []webauth.LoginProvider{gh}, Logger: logging.NewNoopLogger(t)})
	ErrContains(t, "session secret", err)
	_, err = webauth.NewManager(webauth.Config{PublicURL: &url.URL{Scheme: "https", Host: "a"}, Providers: []webauth.LoginProvider{gh}, SessionSecrets: []string{secretA}, Roles: webauth.RoleMapper{Admins: []string{"team:x"}}, Logger: logging.NewNoopLogger(t)})
	ErrContains(t, "unknown kind", err)
	_, err = webauth.NewOIDCProvider(webauth.OIDCConfig{IssuerURL: "https://x"})
	ErrContains(t, "client ID", err)
}
