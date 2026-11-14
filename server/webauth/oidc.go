// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// LoginProvider signs users in with an authorization-code redirect.
type LoginProvider interface {
	// ID is the provider's URL segment, such as "oidc" or "github".
	ID() string
	// Name is shown on the sign-in button.
	Name() string
	// AuthCodeURL is where the browser goes to sign in.
	AuthCodeURL(ctx context.Context, state, nonce, verifier, redirectURL string) (string, error)
	// Exchange turns the callback's code into a verified identity.
	Exchange(ctx context.Context, code, verifier, nonce, redirectURL string) (Identity, error)
}

// OIDCConfig configures an OpenID Connect provider such as Microsoft Entra
// ID, Google, Okta, Keycloak, Auth0, Amazon Cognito, GitLab, or Dex.
type OIDCConfig struct {
	// ID is the provider's URL segment. Defaults to "oidc".
	ID string
	// Name is shown on the sign-in button, for example "Microsoft Entra ID".
	Name         string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	// Scopes are requested in addition to "openid".
	Scopes []string
	// GroupsClaims are the claims read as groups, such as "groups" or, for
	// Entra ID app roles, "roles".
	GroupsClaims []string
	// AllowedDomains, when set, admits only users whose verified email, or
	// Google Workspace "hd" claim, is in one of these domains.
	AllowedDomains []string
}

// OIDCProvider signs users in with OpenID Connect. Discovery runs on the
// first sign-in rather than at startup, so an unreachable identity provider
// does not stop Atlantis from starting.
type OIDCProvider struct {
	cfg OIDCConfig

	client *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// googleIssuer is the only issuer whose "hd" claim is trusted.
const googleIssuer = "https://accounts.google.com"

var _ LoginProvider = (*OIDCProvider)(nil)

// NewOIDCProvider validates the configuration. It does not contact the
// issuer.
func NewOIDCProvider(cfg OIDCConfig) (*OIDCProvider, error) {
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("OIDC sign-in needs an issuer URL, client ID, and client secret")
	}
	if cfg.Name == "" {
		cfg.Name = "Single sign-on"
	}
	if cfg.ID == "" {
		cfg.ID = "oidc"
	}
	if len(cfg.GroupsClaims) == 0 {
		cfg.GroupsClaims = []string{"groups"}
	}
	return &OIDCProvider{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}}, nil
}

// withClient bounds every call to the identity provider.
func (p *OIDCProvider) withClient(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, p.client)
}

func (p *OIDCProvider) ID() string   { return p.cfg.ID }
func (p *OIDCProvider) Name() string { return p.cfg.Name }

func (p *OIDCProvider) discover(ctx context.Context) (*oidc.Provider, *oidc.IDTokenVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil {
		return p.provider, p.verifier, nil
	}
	ctx, cancel := context.WithTimeout(p.withClient(context.WithoutCancel(ctx)), 15*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, p.cfg.IssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("reading OIDC discovery document from %q: %w", p.cfg.IssuerURL, err)
	}
	p.provider = provider
	p.verifier = provider.Verifier(&oidc.Config{ClientID: p.cfg.ClientID})
	return p.provider, p.verifier, nil
}

func (p *OIDCProvider) oauth2Config(provider *oidc.Provider, redirectURL string) *oauth2.Config {
	scopes := []string{oidc.ScopeOpenID}
	for _, s := range p.cfg.Scopes {
		if s != oidc.ScopeOpenID && !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}
}

func (p *OIDCProvider) AuthCodeURL(ctx context.Context, state, nonce, verifier, redirectURL string) (string, error) {
	provider, _, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	return p.oauth2Config(provider, redirectURL).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// errGroupOverage explains Entra ID's behaviour for users in many groups.
var errGroupOverage error = &UserError{msg: "your account belongs to too many groups for the identity provider to list them in the sign-in token. " +
	"Ask your administrator to assign Atlantis app roles and read them from the \"roles\" claim"}

func (p *OIDCProvider) Exchange(ctx context.Context, code, verifier, nonce, redirectURL string) (Identity, error) {
	provider, idVerifier, err := p.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	ctx = p.withClient(ctx)
	conf := p.oauth2Config(provider, redirectURL)
	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchanging the authorization code: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Identity{}, errors.New("the identity provider returned no ID token")
	}
	idt, err := idVerifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("verifying the ID token: %w", err)
	}
	if idt.Nonce != nonce {
		return Identity{}, userError("the sign-in response does not match this browser's sign-in. Start again")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("reading ID token claims: %w", err)
	}

	id := identityFromClaims(idt.Subject, claims, p.cfg.GroupsClaims)
	if !hasAnyClaim(claims, p.cfg.GroupsClaims) {
		if overage(claims) {
			return Identity{}, errGroupOverage
		}
		// Some providers (GitLab, Okta by default) only return groups from
		// the userinfo endpoint.
		if info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil && info.Subject == idt.Subject {
			var extra map[string]any
			if info.Claims(&extra) == nil {
				id.Groups = groupsFromClaims(extra, p.cfg.GroupsClaims)
				if id.Email == "" {
					id.Email = info.Email
					id.EmailVerified = info.EmailVerified
				}
			}
		}
	}
	if idt.Issuer != googleIssuer {
		delete(claims, "hd")
	}
	if err := checkDomain(id, claims, p.cfg.AllowedDomains); err != nil {
		return Identity{}, err
	}
	return id, nil
}

func identityFromClaims(subject string, claims map[string]any, groupsClaims []string) Identity {
	id := Identity{Subject: subject, Groups: groupsFromClaims(claims, groupsClaims)}
	id.Email, _ = claims["email"].(string)
	id.EmailVerified, _ = claims["email_verified"].(bool)
	for _, key := range []string{"name", "preferred_username", "email"} {
		if v, _ := claims[key].(string); v != "" {
			id.Name = v
			break
		}
	}
	return id
}

func hasAnyClaim(claims map[string]any, keys []string) bool {
	for _, k := range keys {
		if _, ok := claims[k]; ok {
			return true
		}
	}
	return false
}

// groupsFromClaims reads string or string-array claims.
func groupsFromClaims(claims map[string]any, keys []string) []string {
	var out []string
	for _, k := range keys {
		switch v := claims[k].(type) {
		case string:
			for g := range strings.SplitSeq(v, ",") {
				if g = strings.TrimSpace(g); g != "" {
					out = append(out, g)
				}
			}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// overage reports Entra ID's group overage marker, which replaces the groups
// claim with a pointer to Microsoft Graph.
func overage(claims map[string]any) bool {
	names, ok := claims["_claim_names"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = names["groups"]
	return ok
}

func checkDomain(id Identity, claims map[string]any, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	hd, _ := claims["hd"].(string)
	_, emailDomain, _ := strings.Cut(id.Email, "@")
	for _, d := range allowed {
		d = strings.TrimPrefix(strings.TrimSpace(d), "@")
		if hd != "" && strings.EqualFold(hd, d) {
			return nil
		}
		if id.EmailVerified && strings.EqualFold(emailDomain, d) {
			return nil
		}
	}
	return userError("accounts from this domain can't sign in to Atlantis. Allowed domains are %s", strings.Join(allowed, ", "))
}

// NewGoogleProvider signs users in with Google accounts. Anyone can create a
// Google account, so it requires the Google Workspace domains to admit, which
// are checked against the verified hd claim or email.
func NewGoogleProvider(clientID, clientSecret string, allowedDomains []string) (*OIDCProvider, error) {
	if len(allowedDomains) == 0 {
		return nil, errors.New("sign-in with Google needs the allowed domains, because anyone can create a Google account")
	}
	return NewOIDCProvider(OIDCConfig{
		ID:             "google",
		Name:           "Google",
		IssuerURL:      googleIssuer,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		Scopes:         []string{"email", "profile"},
		AllowedDomains: allowedDomains,
	})
}
