// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/runatlantis/atlantis/server/webauth"
	. "github.com/runatlantis/atlantis/testing"
)

const albARN = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/atlantis/50dc6c495c0c9188"

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Ok(t, err)
	return k
}

// albKeyServer serves PEM public keys by key ID, like
// public-keys.auth.elb.<region>.amazonaws.com.
func albKeyServer(t *testing.T, keys map[string]*ecdsa.PrivateKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k, ok := keys[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		_ = pem.Encode(w, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func albToken(t *testing.T, key *ecdsa.PrivateKey, kid, signer string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	tok.Header["signer"] = signer
	s, err := tok.SignedString(key)
	Ok(t, err)
	return s
}

func TestProxyALB(t *testing.T) {
	good, other := ecKey(t), ecKey(t)
	srv := albKeyServer(t, map[string]*ecdsa.PrivateKey{"key-1": good})
	p, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyALB, ALBArn: albARN, KeyURLOverride: srv.URL})
	Ok(t, err)
	exp := time.Now().Add(time.Minute).Unix()
	userClaims := jwt.MapClaims{"sub": "abc", "email": "maya@acme.com", "name": "Maya", "groups": []string{"sre"}, "exp": exp}

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.Header.Set("x-amzn-oidc-data", albToken(t, good, "key-1", albARN, userClaims))
	id, err := p.Authenticate(req)
	Ok(t, err)
	Equals(t, webauth.Identity{Subject: "alb:abc", Name: "Maya", Email: "maya@acme.com", EmailVerified: true, Groups: []string{"sre"}}, id)

	cases := map[string]string{
		"signed by another load balancer": albToken(t, good, "key-1", strings.Replace(albARN, "atlantis", "other", 1), userClaims),
		"signed with an unknown key":      albToken(t, other, "key-1", albARN, userClaims),
		"unknown key id":                  albToken(t, good, "key-9", albARN, userClaims),
		"path traversal in key id":        albToken(t, good, "../key-1", albARN, userClaims),
		"expired":                         albToken(t, good, "key-1", albARN, jwt.MapClaims{"sub": "abc", "exp": time.Now().Add(-time.Minute).Unix()}),
		"no expiry":                       albToken(t, good, "key-1", albARN, jwt.MapClaims{"sub": "abc"}),
		"not a token":                     "garbage",
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ui", nil)
			req.Header.Set("x-amzn-oidc-data", header)
			_, err := p.Authenticate(req)
			Assert(t, err != nil, "accepted a bad ALB header")
		})
	}

	_, err = p.Authenticate(httptest.NewRequest(http.MethodGet, "/ui", nil))
	Equals(t, webauth.ErrNoProxyIdentity, err)
}

func TestProxyALB_RegionFromARN(t *testing.T) {
	_, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyALB, ALBArn: "not-an-arn"})
	ErrContains(t, "load balancer ARN", err)
	_, err = webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyALB, ALBArn: "arn:aws-us-gov:elasticloadbalancing:us-gov-west-1:1:loadbalancer/app/a/b"})
	Ok(t, err)
}

func iapServer(t *testing.T, key *ecdsa.PrivateKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "iap-1", Algorithm: "ES256", Use: "sig"}}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func iapToken(t *testing.T, key *ecdsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = "iap-1"
	s, err := tok.SignedString(key)
	Ok(t, err)
	return s
}

func TestProxyIAP(t *testing.T) {
	key := ecKey(t)
	srv := iapServer(t, key)
	const aud = "/projects/123/global/backendServices/456"
	p, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyIAP, IAPAudience: aud, KeyURLOverride: srv.URL})
	Ok(t, err)
	now := time.Now()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"sub": "accounts.google.com:1", "email": "accounts.google.com:maya@acme.com", "iss": "https://cloud.google.com/iap", "aud": aud, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	}

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.Header.Set("x-goog-iap-jwt-assertion", iapToken(t, key, base()))
	id, err := p.Authenticate(req)
	Ok(t, err)
	Equals(t, "maya@acme.com", id.Email)
	Equals(t, true, id.EmailVerified)

	bad := map[string]func(jwt.MapClaims){
		"wrong audience": func(c jwt.MapClaims) { c["aud"] = "/projects/999/global/backendServices/1" },
		"wrong issuer":   func(c jwt.MapClaims) { c["iss"] = "https://evil.example" },
		"expired":        func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Minute).Unix() },
		"from the future": func(c jwt.MapClaims) {
			c["iat"] = now.Add(time.Hour).Unix()
			c["exp"] = now.Add(2 * time.Hour).Unix()
		},
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(c)
			req := httptest.NewRequest(http.MethodGet, "/ui", nil)
			req.Header.Set("x-goog-iap-jwt-assertion", iapToken(t, key, c))
			_, err := p.Authenticate(req)
			Assert(t, err != nil, "accepted a bad IAP assertion")
		})
	}
	t.Run("signed by another key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ui", nil)
		req.Header.Set("x-goog-iap-jwt-assertion", iapToken(t, ecKey(t), base()))
		_, err := p.Authenticate(req)
		Assert(t, err != nil, "accepted an assertion signed by another key")
	})
}

func TestProxyHeader(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	p, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{
		Type: webauth.ProxyHeader, UserHeader: "X-Forwarded-User", EmailHeader: "X-Forwarded-Email", GroupsHeader: "X-Forwarded-Groups",
		TrustedCIDRs: []*net.IPNet{trusted},
	})
	Ok(t, err)

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("X-Forwarded-User", "maya")
	req.Header.Set("X-Forwarded-Email", "maya@acme.com")
	req.Header.Set("X-Forwarded-Groups", "sre, platform-admins")
	id, err := p.Authenticate(req)
	Ok(t, err)
	Equals(t, webauth.Identity{Subject: "header:maya", Name: "maya", Email: "maya@acme.com", EmailVerified: true, Groups: []string{"sre", "platform-admins"}}, id)

	// The same headers from outside the trusted network are refused, even with
	// a forged X-Forwarded-For.
	spoof := httptest.NewRequest(http.MethodGet, "/ui", nil)
	spoof.RemoteAddr = "203.0.113.9:4444"
	spoof.Header.Set("X-Forwarded-For", "10.1.2.3")
	spoof.Header.Set("X-Forwarded-User", "admin")
	_, err = p.Authenticate(spoof)
	ErrContains(t, "not a trusted proxy network", err)

	empty := httptest.NewRequest(http.MethodGet, "/ui", nil)
	empty.RemoteAddr = "10.1.2.3:5555"
	_, err = p.Authenticate(empty)
	Equals(t, webauth.ErrNoProxyIdentity, err)

	_, err = webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyHeader, UserHeader: "X-User"})
	ErrContains(t, "trusted proxy networks", err)
}
