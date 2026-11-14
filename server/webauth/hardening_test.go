// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth_test

import (
	"crypto/ecdsa"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webauth"
	"github.com/runatlantis/atlantis/server/webauth/webauthtest"
	. "github.com/runatlantis/atlantis/testing"
)

// Finding: an identity provider that lets users edit their email and omits
// email_verified must not let them match email: or domain: rules.
func TestProxyALB_EmailNeedsExplicitVerification(t *testing.T) {
	key := ecKey(t)
	srv := albKeyServer(t, map[string]*ecdsa.PrivateKey{"k": key})
	p, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyALB, ALBArn: albARN, KeyURLOverride: srv.URL})
	Ok(t, err)
	exp := time.Now().Add(time.Minute).Unix()
	for verified, want := range map[any]bool{true: true, "true": true, false: false, "false": false, nil: false} {
		claims := jwt.MapClaims{"sub": "s", "email": "admin@acme.com", "exp": exp}
		if verified != nil {
			claims["email_verified"] = verified
		}
		req := httptest.NewRequest(http.MethodGet, "/ui", nil)
		req.Header.Set("x-amzn-oidc-data", albToken(t, key, "k", albARN, claims))
		id, err := p.Authenticate(req)
		Ok(t, err)
		Equals(t, want, id.EmailVerified)
	}
}

// Finding: a burst of requests with made-up key IDs must not turn into a
// burst of outbound requests.
func TestProxyALB_UnknownKeyIDsAreFetchedOnce(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	p, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyALB, ALBArn: albARN, KeyURLOverride: srv.URL})
	Ok(t, err)
	token := albToken(t, ecKey(t), "missing-key", albARN, jwt.MapClaims{"sub": "s", "exp": time.Now().Add(time.Minute).Unix()})
	for range 20 {
		req := httptest.NewRequest(http.MethodGet, "/ui", nil)
		req.Header.Set("x-amzn-oidc-data", token)
		_, err := p.Authenticate(req)
		Assert(t, err != nil, "unknown key accepted")
	}
	Equals(t, int32(1), hits.Load())
}

// Finding: header mode with a network like 0.0.0.0/0 trusts everyone.
func TestProxyHeader_RejectsBroadNetworks(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "10.0.0.0/7", "::/0", "fd00::/8"} {
		_, n, err := net.ParseCIDR(cidr)
		Ok(t, err)
		_, err = webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyHeader, UserHeader: "X-User", TrustedCIDRs: []*net.IPNet{n}})
		ErrContains(t, "too broad", err)
	}
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	_, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyHeader, UserHeader: "X-User", TrustedCIDRs: []*net.IPNet{n}})
	Ok(t, err)
}

// Finding: anyone can register a GitHub organization, so GitHub groups live
// in their own namespace and GitHub sign-in needs an organization allowlist.
func TestGitHubGroupsAreNamespaced(t *testing.T) {
	_, err := webauth.NewGitHubProvider(webauth.GitHubConfig{ClientID: "a", ClientSecret: "b"})
	ErrContains(t, "allowed organizations", err)

	m := webauth.RoleMapper{Admins: []string{"platform-admins"}, Operators: []string{"github:acme/sre"}}
	Ok(t, m.Validate())
	// A GitHub org named like an identity provider group does not match.
	Equals(t, webauth.RoleNone, m.Resolve(webauth.Identity{Groups: []string{"github:platform-admins"}}))
	Equals(t, webauth.RoleOperator, m.Resolve(webauth.Identity{Groups: []string{"github:acme/sre"}}))
}

func TestOIDCCannotClaimGitHubGroups(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	idp.SetUser(map[string]any{"sub": "u", "groups": []string{"github:acme/platform"}})
	a := newApp(t, "", func(p *url.URL) webauth.Config {
		cfg := oidcConfig(idp, nil)(p)
		cfg.Roles = webauth.RoleMapper{Admins: []string{"github:acme/platform"}}
		return cfg
	})
	status, body := fetch(t, browser(t), a.srv.URL+"/ui/login/oidc")
	Equals(t, http.StatusForbidden, status)
	Assert(t, strings.Contains(body, "no Atlantis role"), body)
}

// Finding: userinfo from another subject, or an hd claim from a provider
// other than Google, must not change the identity.
func TestOIDC_IgnoresMismatchedUserInfoAndForeignHD(t *testing.T) {
	idp := webauthtest.NewOIDC()
	defer idp.Server.Close()
	idp.SetUser(map[string]any{"sub": "u-1", "name": "Ana"})
	idp.SetUserInfo(map[string]any{"sub": "someone-else", "groups": []string{"platform-admins"}})
	a := newApp(t, "", oidcConfig(idp, nil))
	status, body := fetch(t, browser(t), a.srv.URL+"/ui/login/oidc")
	Equals(t, http.StatusForbidden, status)
	Assert(t, strings.Contains(body, "no Atlantis role"), "userinfo for another subject was used: %s", body)

	idp2 := webauthtest.NewOIDC()
	defer idp2.Server.Close()
	idp2.SetUser(map[string]any{"sub": "u", "hd": "acme.com", "groups": []string{"sre"}})
	b := newApp(t, "", oidcConfig(idp2, func(c *webauth.OIDCConfig) { c.AllowedDomains = []string{"acme.com"} }))
	status, body = fetch(t, browser(t), b.srv.URL+"/ui/login/oidc")
	Equals(t, http.StatusForbidden, status)
	Assert(t, strings.Contains(body, "Allowed domains"), "hd from a non-Google issuer was trusted: %s", body)
}

// Finding: session cookies must be Secure unless Atlantis runs on loopback
// over plain http.
func TestSecureCookies(t *testing.T) {
	gh, err := webauth.NewGitHubProvider(webauth.GitHubConfig{ClientID: "a", ClientSecret: "b", AllowedOrgs: []string{"acme"}})
	Ok(t, err)
	for raw, want := range map[string]bool{
		"https://atlantis.example.com": true,
		"http://atlantis.example.com":  true,
		"http://10.0.0.5:4141":         true,
		"http://localhost:4141":        false,
		"http://127.0.0.1:4141":        false,
		"http://[::1]:4141":            false,
	} {
		u, _ := url.Parse(raw)
		m, err := webauth.NewManager(webauth.Config{PublicURL: u, SessionSecrets: []string{secretA}, Providers: []webauth.LoginProvider{gh}, Logger: logging.NewNoopLogger(t)})
		Ok(t, err)
		Equals(t, want, m.SecureCookies())
	}
}

func TestDefaultSessionLifetimeIsShort(t *testing.T) {
	Assert(t, webauth.DefaultSessionLifetime <= 4*time.Hour, "default session lifetime is %s", webauth.DefaultSessionLifetime)
}
