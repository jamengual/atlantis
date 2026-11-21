// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// GitHubConfig configures sign-in with a GitHub OAuth app or the user
// authorization of a GitHub App.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	// Hostname is "github.com", a GitHub Enterprise Server host, or a GitHub
	// Enterprise Cloud host ending in ".ghe.com".
	Hostname string
	// AllowedOrgs, when set, admits only members of these organizations.
	AllowedOrgs []string
	// HTTPClient is used for API calls. Tests replace it.
	HTTPClient *http.Client
	// BaseURLOverride replaces the web and API base URLs. Tests use it.
	BaseURLOverride string
}

// GitHubProvider signs users in with GitHub. Organizations become groups
// named "github:org", and teams "github:org/team"; membership in a child team
// also counts as membership in its parent team. Direct team memberships are
// also reported on their own, for matching policy owners. The prefix keeps anyone who
// registers a GitHub organization from matching another provider's group.
type GitHubProvider struct {
	cfg     GitHubConfig
	host    string
	webBase string
	apiBase string
}

var _ LoginProvider = (*GitHubProvider)(nil)

// maxPages bounds paging through organizations and teams.
const maxPages = 10

// GitHubGroupPrefix starts every group name that comes from GitHub.
const GitHubGroupPrefix = "github:"

func NewGitHubProvider(cfg GitHubConfig) (*GitHubProvider, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("GitHub sign-in needs a client ID and client secret")
	}
	if len(cfg.AllowedOrgs) == 0 {
		return nil, errors.New("GitHub sign-in needs the allowed organizations, because anyone can create a GitHub account")
	}
	host := strings.TrimSpace(cfg.Hostname)
	if host == "" {
		host = "github.com"
	}
	p := &GitHubProvider{cfg: cfg, host: strings.ToLower(host)}
	switch {
	case cfg.BaseURLOverride != "":
		p.webBase = strings.TrimRight(cfg.BaseURLOverride, "/")
		p.apiBase = p.webBase + "/api"
	case host == "github.com":
		p.webBase, p.apiBase = "https://github.com", "https://api.github.com"
	case strings.HasSuffix(host, ".ghe.com"):
		p.webBase, p.apiBase = "https://"+host, "https://api."+host
	default:
		p.webBase, p.apiBase = "https://"+host, "https://"+host+"/api/v3"
	}
	if p.cfg.HTTPClient == nil {
		p.cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return p, nil
}

// Hostname is the GitHub host people sign in to, such as github.com.
func (p *GitHubProvider) Hostname() string { return p.host }

func (p *GitHubProvider) ID() string   { return VCSGitHub }
func (p *GitHubProvider) Name() string { return "GitHub" }

func (p *GitHubProvider) oauth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   p.webBase + "/login/oauth/authorize",
			TokenURL:  p.webBase + "/login/oauth/access_token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: redirectURL,
		Scopes:      []string{"read:org", "user:email"},
	}
}

func (p *GitHubProvider) AuthCodeURL(_ context.Context, state, _, verifier, redirectURL string) (string, error) {
	return p.oauth2Config(redirectURL).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

type ghUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

type ghEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type ghOrg struct {
	Login string `json:"login"`
}

type ghTeam struct {
	Slug         string  `json:"slug"`
	Organization ghOrg   `json:"organization"`
	Parent       *ghTeam `json:"parent"`
}

func (p *GitHubProvider) Exchange(ctx context.Context, code, verifier, _, redirectURL string) (Identity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.cfg.HTTPClient)
	tok, err := p.oauth2Config(redirectURL).Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchanging the GitHub authorization code: %w", err)
	}
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(tok))

	var user ghUser
	if err := p.get(ctx, client, "/user", &user); err != nil {
		return Identity{}, err
	}
	id := Identity{Subject: "github:" + strconv.FormatInt(user.ID, 10), Name: user.Login, Login: user.Login, LoginKind: VCSGitHub}
	if user.Name != "" {
		id.Name = user.Name
	}

	var emails []ghEmail
	if err := p.get(ctx, client, "/user/emails", &emails); err == nil {
		for _, e := range emails {
			if e.Primary && e.Verified {
				id.Email, id.EmailVerified = e.Email, true
			}
		}
	}

	orgs, err := pages[ghOrg](ctx, p, client, "/user/orgs")
	if err != nil {
		return Identity{}, err
	}
	teams, err := pages[ghTeam](ctx, p, client, "/user/teams")
	if err != nil {
		return Identity{}, err
	}
	seen := map[string]bool{}
	add := func(g string) {
		if g != "" && !seen[strings.ToLower(g)] {
			seen[strings.ToLower(g)] = true
			id.Groups = append(id.Groups, g)
		}
	}
	for _, o := range orgs {
		add(GitHubGroupPrefix + o.Login)
	}
	for _, t := range teams {
		add(GitHubGroupPrefix + t.Organization.Login)
		if t.Organization.Login != "" && t.Slug != "" {
			id.GitHubTeams = append(id.GitHubTeams, t.Organization.Login+"/"+t.Slug)
		}
		for team := &t; team != nil; team = team.Parent {
			add(GitHubGroupPrefix + t.Organization.Login + "/" + team.Slug)
		}
	}

	if len(p.cfg.AllowedOrgs) > 0 && !memberOfAny(orgs, p.cfg.AllowedOrgs) {
		return Identity{}, userError("only members of %s can sign in to Atlantis with GitHub", strings.Join(p.cfg.AllowedOrgs, ", "))
	}
	return id, nil
}

func memberOfAny(orgs []ghOrg, allowed []string) bool {
	for _, o := range orgs {
		for _, a := range allowed {
			if strings.EqualFold(o.Login, strings.TrimSpace(a)) {
				return true
			}
		}
	}
	return false
}

func (p *GitHubProvider) get(ctx context.Context, client *http.Client, path string, out any) error {
	// #nosec G704 -- apiBase comes from server configuration and path is a fixed API route.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req) // #nosec G704 -- see above
	if err != nil {
		return fmt.Errorf("calling GitHub %s: %w", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("calling GitHub %s: status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("reading GitHub %s: %w", path, err)
	}
	return nil
}

func pages[T any](ctx context.Context, p *GitHubProvider, client *http.Client, path string) ([]T, error) {
	var all []T
	for page := 1; page <= maxPages; page++ {
		var batch []T
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		if err := p.get(ctx, client, path+"?"+q.Encode(), &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			break
		}
	}
	return all, nil
}
