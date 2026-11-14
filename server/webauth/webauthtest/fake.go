// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

// Package webauthtest provides fake identity providers for tests and local
// demos. They follow the protocols closely enough for the real OIDC and
// OAuth2 client code to run against them: discovery, JWKS, PKCE, nonces,
// and signed ID tokens.
package webauthtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type grant struct {
	nonce     string
	challenge string
	redirect  string
	claims    map[string]any
}

// OIDC is a fake OpenID Connect provider. Every authorization request signs
// in the user described by the claims set with SetUser, without a page.
type OIDC struct {
	Server       *httptest.Server
	ClientID     string
	ClientSecret string

	mu       sync.Mutex
	claims   map[string]any
	userInfo map[string]any
	tamper   bool
	key      *rsa.PrivateKey
	grants   map[string]grant
	tokens   map[string]map[string]any
}

// NewOIDC starts a fake provider. Close it with Server.Close.
func NewOIDC() *OIDC {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	f := &OIDC{ClientID: "atlantis", ClientSecret: "client-secret", key: key, grants: map[string]grant{}, tokens: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/authorize", f.authorize)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/userinfo", f.userinfo)
	f.Server = httptest.NewServer(mux)
	return f
}

// SetUser sets the ID token claims of the next sign-in. "sub" is required.
func (f *OIDC) SetUser(claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = claims
}

// SetUserInfo sets the claims served from the userinfo endpoint.
func (f *OIDC) SetUserInfo(claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userInfo = claims
}

// TamperNonce makes the next ID tokens carry a different nonce.
func (f *OIDC) TamperNonce(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tamper = on
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *OIDC) discovery(w http.ResponseWriter, _ *http.Request) {
	u := f.Server.URL
	writeJSON(w, map[string]any{
		"issuer":                                u,
		"authorization_endpoint":                u + "/authorize",
		"token_endpoint":                        u + "/token",
		"jwks_uri":                              u + "/jwks",
		"userinfo_endpoint":                     u + "/userinfo",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func randomString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func redirectWithCode(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	v := target.Query()
	v.Set("code", code)
	v.Set("state", state)
	target.RawQuery = v.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound) //nolint:gosec // fake provider redirects to the client's redirect_uri by design
}

func (f *OIDC) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != f.ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := randomString()
	f.mu.Lock()
	f.grants[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), claims: f.claims}
	f.mu.Unlock()
	redirectWithCode(w, r, q.Get("redirect_uri"), code, q.Get("state"))
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *OIDC) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != f.ClientID || secret != f.ClientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"error": "invalid_client"})
		return
	}
	code := r.PostForm.Get("code")
	f.mu.Lock()
	g, ok := f.grants[code]
	delete(f.grants, code)
	tamper := f.tamper
	info := f.userInfo
	f.mu.Unlock()
	if !ok || g.redirect != r.PostForm.Get("redirect_uri") || s256(r.PostForm.Get("code_verifier")) != g.challenge {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	claims := jwt.MapClaims{"iss": f.Server.URL, "aud": f.ClientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": g.nonce}
	if tamper {
		claims["nonce"] = "tampered"
	}
	maps.Copy(claims, g.claims)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key"
	idToken, err := tok.SignedString(f.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	access := randomString()
	userinfo := map[string]any{"sub": g.claims["sub"]}
	maps.Copy(userinfo, info)
	f.mu.Lock()
	f.tokens[access] = userinfo
	f.mu.Unlock()
	writeJSON(w, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

func (f *OIDC) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
}

func (f *OIDC) userinfo(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	info, ok := f.tokens[h[len(prefix):]]
	f.mu.Unlock()
	if !ok {
		http.Error(w, "unknown token", http.StatusUnauthorized)
		return
	}
	writeJSON(w, info)
}

// GitHub is a fake GitHub OAuth app and API, served under /api.
type GitHub struct {
	Server       *httptest.Server
	ClientID     string
	ClientSecret string

	mu     sync.Mutex
	user   map[string]any
	emails []map[string]any
	orgs   []map[string]any
	teams  []map[string]any
	grants map[string]string // code -> PKCE challenge
}

// NewGitHub starts a fake GitHub. Close it with Server.Close.
func NewGitHub() *GitHub {
	f := &GitHub{ClientID: "gh-client", ClientSecret: "gh-secret", grants: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != f.ClientID || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "bad authorization request", http.StatusBadRequest)
			return
		}
		code := randomString()
		f.mu.Lock()
		f.grants[code] = q.Get("code_challenge")
		f.mu.Unlock()
		redirectWithCode(w, r, q.Get("redirect_uri"), code, q.Get("state"))
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.PostForm.Get("code")
		f.mu.Lock()
		challenge, ok := f.grants[code]
		delete(f.grants, code)
		f.mu.Unlock()
		if !ok || r.PostForm.Get("client_secret") != f.ClientSecret || s256(r.PostForm.Get("code_verifier")) != challenge {
			writeJSON(w, map[string]string{"error": "bad_verification_code"})
			return
		}
		writeJSON(w, map[string]any{"access_token": "gh-token", "token_type": "bearer", "scope": "read:org,user:email"})
	})
	api := func(path string, get func() any) {
		mux.HandleFunc("/api"+path, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer gh-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if p := r.URL.Query().Get("page"); p != "" && p != "1" {
				writeJSON(w, []any{})
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			writeJSON(w, get())
		})
	}
	api("/user", func() any { return f.user })
	api("/user/emails", func() any { return f.emails })
	api("/user/orgs", func() any { return f.orgs })
	api("/user/teams", func() any { return f.teams })
	f.Server = httptest.NewServer(mux)
	return f
}

// SetUser sets what the API reports about the signed-in user.
func (f *GitHub) SetUser(user map[string]any, emails, orgs, teams []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user, f.emails, f.orgs, f.teams = user, emails, orgs, teams
}
