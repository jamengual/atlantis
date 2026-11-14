// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/runatlantis/atlantis/server/logging"
	"golang.org/x/oauth2"
)

const (
	sessionCookie  = "atlantis_session"
	flowCookie     = "atlantis_signin"
	sessionPurpose = "session"
	flowPurpose    = "signin"
	flowLifetime   = 10 * time.Minute
)

// Config configures a Manager.
type Config struct {
	// PublicURL is Atlantis's external URL, including any base path. It is
	// used to build callback URLs and decides whether cookies are Secure.
	PublicURL *url.URL
	// SessionSecrets encrypt cookies. The first one encrypts; all decrypt.
	SessionSecrets []string
	// SessionLifetime is how long a sign-in lasts. Defaults to 4 hours.
	SessionLifetime time.Duration
	// Roles are the role rules from server flags. They are combined with
	// Policy when both are set; Policy alone carries the repo config rules.
	Roles     RoleMapper
	Policy    *Policy
	Providers []LoginProvider
	// Proxy, when set, takes the identity from an authenticating proxy
	// instead of a sign-in page.
	Proxy  *ProxyAuthenticator
	Logger logging.SimpleLogging
	// Now returns the current time. Tests replace it.
	Now func() time.Time
}

// Manager authenticates web UI requests and runs the sign-in flow.
type Manager struct {
	cfg  Config
	keys *Keyring
	base string // external base path, without a trailing slash
}

// DefaultSessionLifetime is how long a sign-in lasts by default. Roles are
// fixed for the life of a session, and a session can only be ended early by
// rotating the session secrets, so the default is kept short.
const DefaultSessionLifetime = 4 * time.Hour

// UserError is an error whose message is safe to show to the person signing
// in. Other errors are logged and replaced with a generic message, so
// internal hostnames and provider responses never reach the browser.
type UserError struct{ msg string }

func (e *UserError) Error() string { return e.msg }

func userError(format string, args ...any) error {
	return &UserError{msg: fmt.Sprintf(format, args...)}
}

// SecureCookies reports whether cookies get the Secure attribute: always,
// except when Atlantis is served over plain http on a loopback host for
// local development.
func (m *Manager) SecureCookies() bool {
	if m.cfg.PublicURL.Scheme == "https" {
		return true
	}
	host := m.cfg.PublicURL.Hostname()
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

// ProviderInfo describes a sign-in button.
type ProviderInfo struct {
	ID   string
	Name string
}

// NewManager validates the configuration.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.PublicURL == nil {
		return nil, errors.New("web sign-in needs the Atlantis URL")
	}
	if cfg.Proxy == nil && len(cfg.Providers) == 0 {
		return nil, errors.New("web sign-in needs at least one provider or an authenticating proxy")
	}
	if cfg.Policy == nil {
		policy, err := NewPolicy(PolicyConfig{Flags: cfg.Roles})
		if err != nil {
			return nil, err
		}
		cfg.Policy = policy
	}
	if cfg.SessionLifetime <= 0 {
		cfg.SessionLifetime = DefaultSessionLifetime
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	m := &Manager{cfg: cfg, base: strings.TrimRight(cfg.PublicURL.Path, "/")}
	if cfg.Proxy == nil {
		keys, err := NewKeyring(cfg.SessionSecrets)
		if err != nil {
			return nil, err
		}
		m.keys = keys
	}
	return m, nil
}

// Policy is the access policy roles and permissions come from.
func (m *Manager) Policy() *Policy { return m.cfg.Policy }

// UsesProxy reports whether identities come from an authenticating proxy.
func (m *Manager) UsesProxy() bool { return m.cfg.Proxy != nil }

// GitHubHostname is the host of the GitHub sign-in provider, or empty when
// people can't sign in with GitHub. Logins of people who signed in with
// GitHub are logins on this host.
func (m *Manager) GitHubHostname() string {
	for _, p := range m.cfg.Providers {
		if gh, ok := p.(*GitHubProvider); ok {
			return gh.Hostname()
		}
	}
	return ""
}

// Providers lists the sign-in buttons.
func (m *Manager) Providers() []ProviderInfo {
	out := make([]ProviderInfo, 0, len(m.cfg.Providers))
	for _, p := range m.cfg.Providers {
		out = append(out, ProviderInfo{ID: p.ID(), Name: p.Name()})
	}
	return out
}

// Authenticate returns the request's principal, or nil when nobody is
// signed in. A principal with RoleNone signed in but may not use the UI.
func (m *Manager) Authenticate(r *http.Request) *Principal {
	if m.cfg.Proxy != nil {
		id, err := m.cfg.Proxy.Authenticate(r)
		if err != nil {
			if !errors.Is(err, ErrNoProxyIdentity) {
				m.cfg.Logger.Warn("web sign-in rejected proxy identity: %s", err)
			}
			return nil
		}
		return m.principal(id, "proxy")
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	var p Principal
	if err := m.keys.Open(sessionPurpose, c.Value, m.cfg.Now(), &p); err != nil {
		return nil
	}
	// Recompute the role so policy changes apply without signing in again.
	p.Role = m.cfg.Policy.GlobalRole(p.AsSubject())
	return &p
}

func (m *Manager) principal(id Identity, provider string) *Principal {
	if provider != "github" {
		// Only the GitHub provider may report github: groups.
		id.Groups = slices.DeleteFunc(slices.Clone(id.Groups), func(g string) bool {
			return strings.HasPrefix(strings.ToLower(g), GitHubGroupPrefix)
		})
	}
	p := &Principal{Subject: id.Subject, Name: id.Name, Provider: provider, GitHubLogin: id.Login}
	if id.EmailVerified {
		p.Email = id.Email
	}
	p.Groups = m.cfg.Policy.RelevantGroups(id.Groups)
	p.Role = m.cfg.Policy.GlobalRole(p.AsSubject())
	return p
}

// Middleware puts the principal in the request context. Requests without a
// principal are sent to the sign-in page when they are page loads and get
// 401 otherwise. Principals without a role get 403.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := m.Authenticate(r)
		if p == nil {
			if m.UsesProxy() {
				http.Error(w, "Atlantis did not receive a signed-in user from the authenticating proxy. Check the proxy configuration.", http.StatusUnauthorized)
				return
			}
			if r.Method == http.MethodGet && !strings.Contains(r.Header.Get("Accept"), "text/event-stream") && r.Header.Get("HX-Request") == "" {
				// #nosec G710 -- LoginPath only embeds a return path accepted by SafeReturn.
				http.Redirect(w, r, m.LoginPath(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			http.Error(w, "Sign in to Atlantis to continue.", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// LoginPath is the sign-in page, returning to returnTo afterwards.
func (m *Manager) LoginPath(returnTo string) string {
	login := m.base + "/ui/login"
	if ret, ok := m.SafeReturn(returnTo); ok {
		login += "?return=" + url.QueryEscape(ret)
	}
	return login
}

// SafeReturn accepts only plain absolute paths that stay under the UI after
// cleaning, keeping their query. Anything with a scheme, host, fragment,
// backslash, or protocol-relative prefix is rejected.
func (m *Manager) SafeReturn(raw string) (string, bool) {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\#") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return "", false
	}
	cleaned := path.Clean(u.Path)
	prefix := m.base + "/ui"
	if cleaned != prefix && !strings.HasPrefix(cleaned, prefix+"/") {
		return "", false
	}
	if strings.HasPrefix(cleaned, prefix+"/login") || strings.HasPrefix(cleaned, prefix+"/auth/") {
		return prefix, true
	}
	if u.RawQuery != "" {
		cleaned += "?" + u.Query().Encode()
	}
	return cleaned, true
}

type flowState struct {
	Provider string `json:"p"`
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
}

func (m *Manager) provider(id string) LoginProvider {
	for _, p := range m.cfg.Providers {
		if p.ID() == id {
			return p
		}
	}
	return nil
}

func (m *Manager) callbackURL(providerID string) string {
	u := *m.cfg.PublicURL
	u.Path = m.base + "/ui/auth/callback/" + providerID
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// StartLogin redirects the browser to the provider. The state, nonce, and
// PKCE verifier travel in a short-lived encrypted cookie, so the callback
// can reach any replica.
func (m *Manager) StartLogin(w http.ResponseWriter, r *http.Request, providerID, returnTo string) error {
	p := m.provider(providerID)
	if p == nil {
		return fmt.Errorf("unknown sign-in provider %q", providerID)
	}
	ret, ok := m.SafeReturn(returnTo)
	if !ok {
		ret = m.base + "/ui"
	}
	state, err := randomToken()
	if err != nil {
		return err
	}
	nonce, err := randomToken()
	if err != nil {
		return err
	}
	verifier := oauth2.GenerateVerifier()
	target, err := p.AuthCodeURL(r.Context(), state, nonce, verifier, m.callbackURL(providerID))
	if err != nil {
		return err
	}
	exp := m.cfg.Now().Add(flowLifetime)
	sealed, err := m.keys.Seal(flowPurpose, flowState{Provider: providerID, State: state, Nonce: nonce, Verifier: verifier, Return: ret}, exp)
	if err != nil {
		return err
	}
	http.SetCookie(w, m.cookie(flowCookie, sealed, m.base+"/ui/auth/", exp))
	http.Redirect(w, r, target, http.StatusFound)
	return nil
}

// FinishLogin handles the provider's callback. On success it sets the
// session cookie and returns where to send the browser and who signed in.
func (m *Manager) FinishLogin(w http.ResponseWriter, r *http.Request, providerID string) (string, *Principal, error) {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		return "", nil, userError("this sign-in has no saved state; it may have expired or been opened in another browser. Start again")
	}
	// The sign-in state is single use.
	http.SetCookie(w, m.cookie(flowCookie, "", m.base+"/ui/auth/", time.Unix(0, 0)))
	var fs flowState
	if err := m.keys.Open(flowPurpose, c.Value, m.cfg.Now(), &fs); err != nil {
		return "", nil, userError("this sign-in expired. Start again")
	}
	q := r.URL.Query()
	if fs.Provider != providerID || subtle.ConstantTimeCompare([]byte(fs.State), []byte(q.Get("state"))) != 1 {
		return "", nil, userError("the sign-in response does not match this browser's sign-in. Start again")
	}
	if e := q.Get("error"); e != "" {
		// The description comes from the provider; log it, don't show it.
		m.cfg.Logger.Info("web sign-in refused by provider=%q error=%q description=%q", providerID, e, q.Get("error_description"))
		return "", nil, userError("the identity provider didn't complete the sign-in")
	}
	p := m.provider(providerID)
	if p == nil {
		return "", nil, fmt.Errorf("unknown sign-in provider %q", providerID)
	}
	id, err := p.Exchange(r.Context(), q.Get("code"), fs.Verifier, fs.Nonce, m.callbackURL(providerID))
	if err != nil {
		return "", nil, err
	}
	principal := m.principal(id, providerID)
	if !m.cfg.Policy.Allows(principal.AsSubject(), RoleNone, ActionView, "") {
		m.cfg.Logger.Info("web sign-in denied subject=%q provider=%q reason=%q", principal.Subject, providerID, "no matching role")
		return "", principal, ErrNoRole
	}
	exp := m.cfg.Now().Add(m.cfg.SessionLifetime)
	sealed, err := m.keys.Seal(sessionPurpose, principal, exp)
	if err != nil {
		return "", nil, err
	}
	http.SetCookie(w, m.cookie(sessionCookie, sealed, m.sessionPath(), exp))
	m.cfg.Logger.Info("web sign-in subject=%q name=%q provider=%q role=%q", principal.Subject, principal.DisplayName(), providerID, principal.Role)
	return fs.Return, principal, nil
}

// ErrNoRole means the user signed in but matches no role.
var ErrNoRole error = &UserError{msg: "your account signed in, but it has no Atlantis role. Ask an administrator to add you to a group that has access"}

// sessionPath scopes the session cookie to Atlantis's base path, so the
// existing UI's actions, which follow the same policy, receive it too.
func (m *Manager) sessionPath() string {
	return m.base + "/"
}

// Logout clears the session cookie. It also clears a cookie under the UI
// path, where earlier versions kept the session, so an old cookie can't keep
// the user signed in.
func (m *Manager) Logout(w http.ResponseWriter) {
	http.SetCookie(w, m.cookie(sessionCookie, "", m.sessionPath(), time.Unix(0, 0)))
	http.SetCookie(w, m.cookie(sessionCookie, "", m.base+"/ui", time.Unix(0, 0)))
}

func (m *Manager) cookie(name, value, cookiePath string, exp time.Time) *http.Cookie {
	// Secure is off only when the Atlantis URL is plain http, as in local
	// development; browsers drop Secure cookies on http origins.
	c := &http.Cookie{ // #nosec G124 -- HttpOnly and SameSite are always set; Secure follows the URL scheme.
		Name:     name,
		Value:    value,
		Path:     cookiePath,
		HttpOnly: true,
		Secure:   m.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	}
	if value == "" {
		c.MaxAge = -1
	}
	return c
}
