// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

// Proxy types.
const (
	ProxyALB    = "alb"
	ProxyIAP    = "iap"
	ProxyHeader = "header"
)

// ProxyConfig configures sign-in through an authenticating proxy in front
// of Atlantis.
type ProxyConfig struct {
	// Type is "alb", "iap", or "header".
	Type string

	// ALBArn is the load balancer ARN that must have signed the
	// x-amzn-oidc-data header. Its region selects the public key endpoint.
	ALBArn string
	// IAPAudience is the expected "aud" of the IAP assertion, for example
	// "/projects/123/global/backendServices/456".
	IAPAudience string

	// UserHeader, EmailHeader, and GroupsHeader name the headers read in
	// header mode. Groups are comma-separated.
	UserHeader   string
	EmailHeader  string
	GroupsHeader string
	// TrustedCIDRs are the networks header mode accepts requests from. The
	// connection's address is checked, not X-Forwarded-For.
	TrustedCIDRs []*net.IPNet

	// HTTPClient fetches public keys. Tests replace it.
	HTTPClient *http.Client
	// KeyURLOverride replaces the ALB key endpoint or IAP JWKS URL. Tests
	// use it.
	KeyURLOverride string
	// Now returns the current time. Tests replace it.
	Now func() time.Time
}

const (
	albHeader = "x-amzn-oidc-data"
	iapHeader = "x-goog-iap-jwt-assertion"
	iapIssuer = "https://cloud.google.com/iap"
	iapJWKS   = "https://www.gstatic.com/iap/verify/public_key-jwk"
)

var albArnRegion = regexp.MustCompile(`^arn:aws[a-z-]*:elasticloadbalancing:([a-z0-9-]+):`)

// ProxyAuthenticator reads the identity an authenticating proxy attached to
// a request.
type ProxyAuthenticator struct {
	cfg      ProxyConfig
	albKeys  string // base URL for ALB public keys
	iapKeys  *oidc.RemoteKeySet
	keyMu    sync.Mutex
	keyCache map[string]*ecdsa.PublicKey
	// fetchMu serializes key downloads so a burst of requests with unknown
	// key IDs makes at most one outbound request at a time.
	fetchMu sync.Mutex
	// misses remembers key IDs that failed recently.
	misses map[string]time.Time
}

// keyMissTTL is how long a key ID that failed to load is not retried.
const keyMissTTL = 5 * time.Minute

// ErrNoProxyIdentity means the request carried no proxy identity.
var ErrNoProxyIdentity = errors.New("the request has no identity from the authenticating proxy")

func NewProxyAuthenticator(cfg ProxyConfig) (*ProxyAuthenticator, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	p := &ProxyAuthenticator{cfg: cfg, keyCache: map[string]*ecdsa.PublicKey{}, misses: map[string]time.Time{}}
	switch cfg.Type {
	case ProxyALB:
		m := albArnRegion.FindStringSubmatch(cfg.ALBArn)
		if m == nil {
			return nil, fmt.Errorf("ALB sign-in needs the load balancer ARN, such as arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/atlantis/abc; got %q", cfg.ALBArn)
		}
		p.albKeys = "https://public-keys.auth.elb." + m[1] + ".amazonaws.com/"
		if cfg.KeyURLOverride != "" {
			p.albKeys = strings.TrimRight(cfg.KeyURLOverride, "/") + "/"
		}
	case ProxyIAP:
		if cfg.IAPAudience == "" {
			return nil, errors.New("IAP sign-in needs the expected audience, such as /projects/123/global/backendServices/456")
		}
		jwks := iapJWKS
		if cfg.KeyURLOverride != "" {
			jwks = cfg.KeyURLOverride
		}
		ctx := oidc.ClientContext(context.Background(), cfg.HTTPClient)
		p.iapKeys = oidc.NewRemoteKeySet(ctx, jwks)
	case ProxyHeader:
		if cfg.UserHeader == "" {
			return nil, errors.New("header sign-in needs the name of the header that carries the user")
		}
		if len(cfg.TrustedCIDRs) == 0 {
			return nil, errors.New("header sign-in needs the trusted proxy networks, so other clients can't set the headers")
		}
		for _, n := range cfg.TrustedCIDRs {
			ones, bits := n.Mask.Size()
			if (bits == 32 && ones < 8) || (bits == 128 && ones < 16) {
				return nil, fmt.Errorf("trusted proxy network %s is too broad; list only the networks your proxy connects from", n)
			}
		}
	default:
		return nil, fmt.Errorf("unknown proxy type %q; use alb, iap, or header", cfg.Type)
	}
	return p, nil
}

// Authenticate returns the identity on the request. It returns
// ErrNoProxyIdentity when the proxy attached none.
func (p *ProxyAuthenticator) Authenticate(r *http.Request) (Identity, error) {
	switch p.cfg.Type {
	case ProxyALB:
		return p.alb(r)
	case ProxyIAP:
		return p.iap(r)
	default:
		return p.header(r)
	}
}

type albClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
	Name          string `json:"name"`
	Groups        any    `json:"groups"`
}

func (p *ProxyAuthenticator) alb(r *http.Request) (Identity, error) {
	raw := r.Header.Get(albHeader)
	if raw == "" {
		return Identity{}, ErrNoProxyIdentity
	}
	var claims albClaims
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"}), jwt.WithPaddingAllowed(), jwt.WithTimeFunc(p.cfg.Now), jwt.WithExpirationRequired())
	_, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		if signer, _ := t.Header["signer"].(string); signer != p.cfg.ALBArn {
			return nil, fmt.Errorf("the header was signed by %q, not this load balancer", signer)
		}
		kid, _ := t.Header["kid"].(string)
		return p.albKey(r.Context(), kid)
	})
	if err != nil {
		return Identity{}, fmt.Errorf("verifying the ALB identity header: %w", err)
	}
	id := Identity{Subject: "alb:" + claims.Subject, Email: claims.Email, Name: claims.Name}
	// Some identity providers let users edit their email and omit
	// email_verified, so only an explicit true is trusted for role rules.
	id.EmailVerified = claims.Email != "" && (claims.EmailVerified == true || claims.EmailVerified == "true")
	id.Groups = groupsFromClaims(map[string]any{"groups": claims.Groups}, []string{"groups"})
	if id.Name == "" {
		id.Name = id.Email
	}
	return id, nil
}

var kidPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

func (p *ProxyAuthenticator) albKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	if !kidPattern.MatchString(kid) {
		return nil, fmt.Errorf("invalid key id %q", kid)
	}
	if k, ok := p.cachedKey(kid); ok {
		return k, nil
	}
	p.fetchMu.Lock()
	defer p.fetchMu.Unlock()
	// Another request may have loaded or failed this key while we waited.
	if k, ok := p.cachedKey(kid); ok {
		return k, nil
	}
	p.keyMu.Lock()
	missed, recent := p.misses[kid]
	p.keyMu.Unlock()
	if recent && p.cfg.Now().Sub(missed) < keyMissTTL {
		return nil, fmt.Errorf("ALB public key %q failed to load recently", kid)
	}
	key, err := p.fetchALBKey(ctx, kid)
	p.keyMu.Lock()
	defer p.keyMu.Unlock()
	if err != nil {
		if len(p.misses) > 1000 {
			p.misses = map[string]time.Time{}
		}
		p.misses[kid] = p.cfg.Now()
		return nil, err
	}
	p.keyCache[kid] = key
	return key, nil
}

func (p *ProxyAuthenticator) cachedKey(kid string) (*ecdsa.PublicKey, bool) {
	p.keyMu.Lock()
	defer p.keyMu.Unlock()
	k, ok := p.keyCache[kid]
	return k, ok
}

func (p *ProxyAuthenticator) fetchALBKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.albKeys+url.PathEscape(kid), nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching ALB public key %q: %w", kid, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching ALB public key %q: status %d", kid, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return nil, fmt.Errorf("reading ALB public key %q: %w", kid, err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("ALB public key %q is not PEM", kid)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing ALB public key %q: %w", kid, err)
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ALB public key %q is not an ECDSA key", kid)
	}
	return key, nil
}

type iapClaims struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Issuer   string `json:"iss"`
	Audience any    `json:"aud"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
}

func (p *ProxyAuthenticator) iap(r *http.Request) (Identity, error) {
	raw := r.Header.Get(iapHeader)
	if raw == "" {
		return Identity{}, ErrNoProxyIdentity
	}
	payload, err := p.iapKeys.VerifySignature(r.Context(), raw)
	if err != nil {
		return Identity{}, fmt.Errorf("verifying the IAP assertion: %w", err)
	}
	var c iapClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Identity{}, fmt.Errorf("reading the IAP assertion: %w", err)
	}
	now := p.cfg.Now().Unix()
	switch {
	case c.Issuer != iapIssuer:
		return Identity{}, fmt.Errorf("the IAP assertion was issued by %q", c.Issuer)
	case !audienceMatches(c.Audience, p.cfg.IAPAudience):
		return Identity{}, errors.New("the IAP assertion is for a different backend service")
	case c.Expiry == 0 || now >= c.Expiry:
		return Identity{}, errors.New("the IAP assertion has expired")
	case c.IssuedAt > now+60:
		return Identity{}, errors.New("the IAP assertion is issued in the future")
	}
	email := strings.TrimPrefix(c.Email, "accounts.google.com:")
	return Identity{Subject: "iap:" + c.Subject, Email: email, EmailVerified: email != "", Name: email}, nil
}

func audienceMatches(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, _ := a.(string); s == want {
				return true
			}
		}
	}
	return false
}

func (p *ProxyAuthenticator) header(r *http.Request) (Identity, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	trusted := false
	for _, n := range p.cfg.TrustedCIDRs {
		if ip != nil && n.Contains(ip) {
			trusted = true
			break
		}
	}
	user := strings.TrimSpace(r.Header.Get(p.cfg.UserHeader))
	if !trusted {
		if user != "" {
			return Identity{}, fmt.Errorf("identity headers came from %s, which is not a trusted proxy network", host)
		}
		return Identity{}, ErrNoProxyIdentity
	}
	if user == "" {
		return Identity{}, ErrNoProxyIdentity
	}
	id := Identity{Subject: "header:" + user, Name: user}
	if p.cfg.EmailHeader != "" {
		id.Email = strings.TrimSpace(r.Header.Get(p.cfg.EmailHeader))
		id.EmailVerified = id.Email != ""
	}
	if p.cfg.GroupsHeader != "" {
		id.Groups = groupsFromClaims(map[string]any{"g": r.Header.Get(p.cfg.GroupsHeader)}, []string{"g"})
	}
	return id, nil
}
