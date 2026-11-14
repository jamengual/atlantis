// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webauth"
	"github.com/runatlantis/atlantis/server/webauth/webauthtest"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

const sessionSecret = "0123456789abcdef0123456789abcdef"

var signInRoles = webauth.RoleMapper{
	Admins:    []string{"platform-admins"},
	Operators: []string{"sre"},
	Viewers:   []string{"domain:acme.com"},
}

// newSignInServer serves the UI with OIDC sign-in against a fake provider.
func newSignInServer(t *testing.T, store *fakeStore, actions *fakeActions) (*httptest.Server, *webauthtest.OIDC) {
	t.Helper()
	idp := webauthtest.NewOIDC()
	t.Cleanup(idp.Server.Close)

	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	public, _ := url.Parse(srv.URL)

	provider, err := webauth.NewOIDCProvider(webauth.OIDCConfig{Name: "Microsoft Entra ID", IssuerURL: idp.Server.URL, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret, Scopes: []string{"email"}})
	Ok(t, err)
	auth, err := webauth.NewManager(webauth.Config{
		PublicURL: public, SessionSecrets: []string{sessionSecret}, Providers: []webauth.LoginProvider{provider},
		Roles: signInRoles, Logger: logging.NewNoopLogger(t),
	})
	Ok(t, err)
	h := &webui.Handler{Store: store, Actions: actions, Logger: logging.NewNoopLogger(t), Now: func() time.Time { return now }, Auth: auth}
	r := mux.NewRouter()
	h.Register(r)
	handler = r
	return srv, idp
}

type browserClient struct {
	*http.Client
	base string
}

func newBrowser(t *testing.T, base string) browserClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	Ok(t, err)
	return browserClient{&http.Client{Jar: jar}, base}
}

func (b browserClient) noFollow() *http.Client {
	return &http.Client{Jar: b.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (b browserClient) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := b.Get(b.base + path)
	Ok(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (b browserClient) post(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.base+path, strings.NewReader(form.Encode()))
	Ok(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := b.noFollow().Do(req)
	Ok(t, err)
	resp.Body.Close()
	return resp
}

func signIn(t *testing.T, b browserClient, idp *webauthtest.OIDC, claims map[string]any) string {
	t.Helper()
	idp.SetUser(claims)
	status, body := b.get(t, "/ui/login/oidc")
	Equals(t, http.StatusOK, status)
	return body
}

func TestSignIn_SignedOutVisitorsSeeOnlyTheSignInPage(t *testing.T) {
	srv, _ := newSignInServer(t, sampleStore(), &fakeActions{})
	b := newBrowser(t, srv.URL)

	resp, err := b.noFollow().Get(srv.URL + "/ui/locks")
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/login?return=%2Fui%2Flocks", resp.Header.Get("Location"))

	status, body := b.get(t, "/ui/login?return=%2Fui%2Flocks")
	Equals(t, http.StatusOK, status)
	assertContains(t, body, "Sign in to Atlantis", "Continue with Microsoft Entra ID", `href="/ui/login/oidc?return=%2Fui%2Flocks"`)
	// Nothing about the server leaks to signed-out visitors.
	for _, secret := range []string{"9.9.9", "acme/infra", "redis", "mrivera"} {
		Assert(t, !strings.Contains(body, secret), "sign-in page leaked %q", secret)
	}

	// Actions and log streams get 401 instead of a redirect.
	Equals(t, http.StatusUnauthorized, b.post(t, "/ui/locks/discard", url.Values{"id": {"a"}}).StatusCode)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/ui/jobs/job-1/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err = http.DefaultClient.Do(req)
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSignIn_RolesControlActions(t *testing.T) {
	cases := []struct {
		name          string
		claims        map[string]any
		role          string
		canUnlock     bool
		canLockApply  bool
		wantDiscarded []string
	}{
		{"viewer", map[string]any{"sub": "v", "name": "Vera Viewer", "email": "vera@acme.com", "email_verified": true}, "viewer", false, false, nil},
		{"operator", map[string]any{"sub": "o", "name": "Omar Operator", "groups": []string{"sre"}}, "operator", true, false, []string{"lock-1"}},
		{"admin", map[string]any{"sub": "a", "name": "Ada Admin", "groups": []string{"platform-admins"}}, "admin", true, true, []string{"lock-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actions := &fakeActions{}
			srv, idp := newSignInServer(t, sampleStore(), actions)
			b := newBrowser(t, srv.URL)
			body := signIn(t, b, idp, tc.claims)
			assertContains(t, body, tc.claims["name"].(string), "Single sign-on · "+tc.role, "Sign out")

			_, locks := b.get(t, "/ui/locks")
			Equals(t, tc.canUnlock, strings.Contains(locks, "Unlock selected"))
			Equals(t, tc.canLockApply, strings.Contains(locks, "Lock applies"))

			discard := b.post(t, "/ui/locks/discard", url.Values{"id": {"lock-1"}})
			lock := b.post(t, "/ui/applies/lock", nil)
			if tc.canUnlock {
				Equals(t, http.StatusSeeOther, discard.StatusCode)
			} else {
				Equals(t, http.StatusForbidden, discard.StatusCode)
			}
			if tc.canLockApply {
				Equals(t, http.StatusSeeOther, lock.StatusCode)
				Equals(t, 1, actions.locked)
			} else {
				Equals(t, http.StatusForbidden, lock.StatusCode)
				Equals(t, 0, actions.locked)
			}
			Equals(t, tc.wantDiscarded, actions.discarded)
			if tc.canUnlock {
				// The PR comment names the person who signed in.
				Equals(t, []string{tc.claims["name"].(string)}, actions.actors)
			}
		})
	}
}

func TestSignIn_SignOut(t *testing.T) {
	srv, idp := newSignInServer(t, sampleStore(), &fakeActions{})
	b := newBrowser(t, srv.URL)
	signIn(t, b, idp, map[string]any{"sub": "o", "name": "Omar", "groups": []string{"sre"}})

	resp := b.post(t, "/ui/logout", nil)
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Equals(t, "/ui/login?notice=signed-out", resp.Header.Get("Location"))
	_, body := b.get(t, "/ui/login?notice=signed-out")
	assertContains(t, body, "You signed out.")

	resp2, err := b.noFollow().Get(srv.URL + "/ui")
	Ok(t, err)
	resp2.Body.Close()
	Equals(t, http.StatusSeeOther, resp2.StatusCode)

	// Signing out from another site is refused.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ui/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp3, err := b.noFollow().Do(req)
	Ok(t, err)
	resp3.Body.Close()
	Equals(t, http.StatusForbidden, resp3.StatusCode)
}

func TestSignIn_AccountWithoutRoleIsTurnedAway(t *testing.T) {
	srv, idp := newSignInServer(t, sampleStore(), &fakeActions{})
	b := newBrowser(t, srv.URL)
	idp.SetUser(map[string]any{"sub": "x", "email": "x@elsewhere.com", "email_verified": true})
	status, body := b.get(t, "/ui/login/oidc")
	Equals(t, http.StatusForbidden, status)
	assertContains(t, body, "Sign in to Atlantis", "no Atlantis role")
	resp, err := b.noFollow().Get(srv.URL + "/ui")
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusSeeOther, resp.StatusCode)
}

func TestSignIn_SignedInUserSkipsTheSignInPage(t *testing.T) {
	srv, idp := newSignInServer(t, sampleStore(), &fakeActions{})
	b := newBrowser(t, srv.URL)
	signIn(t, b, idp, map[string]any{"sub": "o", "groups": []string{"sre"}})
	resp, err := b.noFollow().Get(srv.URL + "/ui/login?return=%2Fui%2Fpulls")
	Ok(t, err)
	resp.Body.Close()
	Equals(t, "/ui/pulls", resp.Header.Get("Location"))
	resp, err = b.noFollow().Get(srv.URL + "/ui/login?return=https%3A%2F%2Fevil.example")
	Ok(t, err)
	resp.Body.Close()
	Equals(t, "/ui", resp.Header.Get("Location"))
}

func TestProxySignIn(t *testing.T) {
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	proxy, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyHeader, UserHeader: "X-Forwarded-User", GroupsHeader: "X-Forwarded-Groups", TrustedCIDRs: []*net.IPNet{loopback}})
	Ok(t, err)
	actions := &fakeActions{}
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer srv.Close()
	public, _ := url.Parse(srv.URL)
	auth, err := webauth.NewManager(webauth.Config{PublicURL: public, Proxy: proxy, Roles: signInRoles, Logger: logging.NewNoopLogger(t)})
	Ok(t, err)
	h := &webui.Handler{Store: sampleStore(), Actions: actions, Logger: logging.NewNoopLogger(t), Now: func() time.Time { return now }, Auth: auth}
	r := mux.NewRouter()
	h.Register(r)
	handler = r

	resp, err := http.Get(srv.URL + "/ui")
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusUnauthorized, resp.StatusCode)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/ui/locks", nil)
	req.Header.Set("X-Forwarded-User", "omar")
	req.Header.Set("X-Forwarded-Groups", "sre")
	resp, err = http.DefaultClient.Do(req)
	Ok(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	Equals(t, http.StatusOK, resp.StatusCode)
	assertContains(t, string(body), "omar", "Proxy sign-in · operator", "Unlock selected")
	// Proxy users sign out at the proxy, so there's no sign-out button.
	Assert(t, !strings.Contains(string(body), ">Sign out<"), "proxy mode should not show sign out")

	// There are no sign-in pages in proxy mode.
	resp, err = http.Get(srv.URL + "/ui/login")
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusNotFound, resp.StatusCode)
}

// Internal sign-in failures show a reference, not provider responses or
// internal hosts, and sign-in pages are never cached.
func TestSignIn_InternalErrorsAreNotShown(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	idp.SetUser(map[string]any{"sub": "u", "groups": []string{"sre"}})
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer srv.Close()
	public, _ := url.Parse(srv.URL)
	// A wrong client secret makes the token exchange fail inside Atlantis.
	provider, err := webauth.NewOIDCProvider(webauth.OIDCConfig{IssuerURL: idp.Server.URL, ClientID: idp.ClientID, ClientSecret: "wrong"})
	Ok(t, err)
	auth, err := webauth.NewManager(webauth.Config{PublicURL: public, SessionSecrets: []string{sessionSecret}, Providers: []webauth.LoginProvider{provider}, Roles: signInRoles, Logger: logging.NewNoopLogger(t)})
	Ok(t, err)
	h := &webui.Handler{Store: sampleStore(), Actions: &fakeActions{}, Logger: logging.NewNoopLogger(t), Auth: auth}
	r := mux.NewRouter()
	h.Register(r)
	handler = r

	b := newBrowser(t, srv.URL)
	resp, err := b.Get(srv.URL + "/ui/login/oidc")
	Ok(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	Equals(t, http.StatusForbidden, resp.StatusCode)
	Equals(t, "no-store", resp.Header.Get("Cache-Control"))
	assertContains(t, string(body), "give your Atlantis administrator this reference")
	for _, leak := range []string{"invalid_client", idp.Server.URL, "oauth2"} {
		Assert(t, !strings.Contains(string(body), leak), "sign-in page leaked %q", leak)
	}
}
