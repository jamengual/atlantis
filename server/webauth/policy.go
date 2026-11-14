// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/runatlantis/atlantis/server/core/config/valid"
)

// Action is something a signed-in user can do.
type Action string

const (
	// ActionView is reading pull requests, locks, and logs.
	ActionView Action = "view"
	// ActionUnlock is unlocking a project, which discards its plan.
	ActionUnlock Action = "unlock"
	// ActionLockApplies is locking or unlocking applies for every repo.
	ActionLockApplies Action = "lock_applies"
)

// Actions lists every action, in the order the UI explains them.
var Actions = []Action{ActionView, ActionUnlock, ActionLockApplies}

var defaultRequirements = map[Action]Role{
	ActionView:        RoleViewer,
	ActionUnlock:      RoleOperator,
	ActionLockApplies: RoleAdmin,
}

// Describe says what an action lets someone do.
func (a Action) Describe() string {
	switch a {
	case ActionView:
		return "See pull requests, plans, locks, and job logs"
	case ActionUnlock:
		return "Unlock projects and discard their plans"
	case ActionLockApplies:
		return "Lock and unlock applies for every repository"
	}
	return string(a)
}

// rule is one parsed role rule.
type rule struct {
	kind  string // group, github_user, email, domain, everyone
	value string
}

// String renders the rule in plain words.
func (r rule) String() string {
	switch r.kind {
	case "everyone":
		return "everyone who signs in"
	case "group":
		if v, ok := strings.CutPrefix(r.value, GitHubGroupPrefix); ok {
			return "GitHub " + v
		}
		return "group " + r.value
	case "github_user":
		return "GitHub user " + r.value
	case "email":
		return r.value
	case "domain":
		return "anyone at " + r.value
	}
	return r.kind + " " + r.value
}

type roleRules struct {
	admin, operator, viewer []rule
}

func (r roleRules) empty() bool {
	return len(r.admin)+len(r.operator)+len(r.viewer) == 0
}

func (r roleRules) all() []rule {
	return slices.Concat(r.admin, r.operator, r.viewer)
}

// Subject is who a rule is matched against.
type Subject struct {
	// Groups from the identity provider; GitHub groups carry the github:
	// prefix.
	Groups []string
	// Email is used only when verified.
	Email string
	// GitHubLogin is the GitHub username, when known.
	GitHubLogin string
}

func (r rule) matches(s Subject) bool {
	switch r.kind {
	case "everyone":
		return true
	case "group":
		return slices.ContainsFunc(s.Groups, func(g string) bool { return strings.EqualFold(g, r.value) })
	case "github_user":
		return s.GitHubLogin != "" && strings.EqualFold(s.GitHubLogin, r.value)
	case "email":
		return s.Email != "" && strings.EqualFold(s.Email, r.value)
	case "domain":
		_, d, ok := strings.Cut(s.Email, "@")
		return ok && strings.EqualFold(d, strings.TrimPrefix(r.value, "@"))
	}
	return false
}

func anyMatch(rules []rule, s Subject) bool {
	return slices.ContainsFunc(rules, func(x rule) bool { return x.matches(s) })
}

func (r roleRules) resolve(s Subject) Role {
	switch {
	case anyMatch(r.admin, s):
		return RoleAdmin
	case anyMatch(r.operator, s):
		return RoleOperator
	case anyMatch(r.viewer, s):
		return RoleViewer
	}
	return RoleNone
}

type repoPolicy struct {
	label   string
	matches func(repoID string) bool
	roles   roleRules
	unlock  Role // RoleNone means the global requirement
}

// Policy decides what each person may do, globally and per repository.
type Policy struct {
	roles        roleRules
	defaultRole  Role
	requirements map[Action]Role
	repos        []repoPolicy
	enforcePR    bool
}

// PolicyConfig is the input to NewPolicy: rules from server flags, and the
// access sections of the server-side repo config.
type PolicyConfig struct {
	Flags  RoleMapper
	Access *valid.Access
	Repos  []valid.Repo
}

func fromMapperRules(in []string) ([]rule, error) {
	var out []rule
	for _, s := range in {
		kind, value, err := parseRule(s)
		if err != nil {
			return nil, err
		}
		if kind == "*" {
			out = append(out, rule{kind: "everyone"})
			continue
		}
		out = append(out, rule{kind: kind, value: value})
	}
	return out, nil
}

func fromAccessRules(in []valid.AccessRule) []rule {
	var out []rule
	for _, r := range in {
		switch {
		case r.Everyone:
			out = append(out, rule{kind: "everyone"})
		case r.Group != "":
			out = append(out, rule{kind: "group", value: r.Group})
		case r.GitHub != "":
			out = append(out, rule{kind: "group", value: GitHubGroupPrefix + r.GitHub})
		case r.GitHubUser != "":
			out = append(out, rule{kind: "github_user", value: r.GitHubUser})
		case r.Email != "":
			out = append(out, rule{kind: "email", value: r.Email})
		case r.Domain != "":
			out = append(out, rule{kind: "domain", value: r.Domain})
		}
	}
	return out
}

func accessRoles(a valid.AccessRoles) roleRules {
	return roleRules{admin: fromAccessRules(a.Admin), operator: fromAccessRules(a.Operator), viewer: fromAccessRules(a.Viewer)}
}

// NewPolicy combines the role flags with the access sections of the
// server-side repo config. Rules from both places add up.
func NewPolicy(c PolicyConfig) (*Policy, error) {
	if err := c.Flags.Validate(); err != nil {
		return nil, err
	}
	p := &Policy{defaultRole: c.Flags.Default, requirements: map[Action]Role{}}
	maps.Copy(p.requirements, defaultRequirements)
	var err error
	if p.roles.admin, err = fromMapperRules(c.Flags.Admins); err != nil {
		return nil, err
	}
	if p.roles.operator, err = fromMapperRules(c.Flags.Operators); err != nil {
		return nil, err
	}
	if p.roles.viewer, err = fromMapperRules(c.Flags.Viewers); err != nil {
		return nil, err
	}
	if a := c.Access; a != nil {
		r := accessRoles(a.Roles)
		p.roles.admin = append(p.roles.admin, r.admin...)
		p.roles.operator = append(p.roles.operator, r.operator...)
		p.roles.viewer = append(p.roles.viewer, r.viewer...)
		if a.Default != "" {
			if p.defaultRole, err = ParseRole(a.Default); err != nil {
				return nil, fmt.Errorf("access.default: %w", err)
			}
		}
		p.enforcePR = a.EnforceInPRComments
		for _, req := range []struct {
			action Action
			value  string
		}{{ActionView, a.Permissions.View}, {ActionUnlock, a.Permissions.Unlock}, {ActionLockApplies, a.Permissions.LockApplies}} {
			if req.value == "" {
				continue
			}
			if p.requirements[req.action], err = ParseRole(req.value); err != nil {
				return nil, fmt.Errorf("access.permissions.%s: %w", req.action, err)
			}
		}
	}
	for _, repo := range c.Repos {
		if repo.Access == nil {
			continue
		}
		rp := repoPolicy{label: repo.IDString(), matches: repo.IDMatches, roles: accessRoles(repo.Access.Roles)}
		if repo.Access.Permissions.Unlock != "" {
			if rp.unlock, err = ParseRole(repo.Access.Permissions.Unlock); err != nil {
				return nil, fmt.Errorf("repos[%s].access.permissions.unlock: %w", rp.label, err)
			}
		}
		p.repos = append(p.repos, rp)
	}
	return p, nil
}

// HasRules reports whether anyone can be granted a role.
func (p *Policy) HasRules() bool {
	if !p.roles.empty() || p.defaultRole != RoleNone {
		return true
	}
	return slices.ContainsFunc(p.repos, func(r repoPolicy) bool { return !r.roles.empty() })
}

// EnforceInPRComments reports whether "atlantis unlock" comments are checked.
func (p *Policy) EnforceInPRComments() bool { return p.enforcePR }

// GlobalRole is a subject's role outside any repo-specific grants.
func (p *Policy) GlobalRole(s Subject) Role {
	return max(p.roles.resolve(s), p.defaultRole)
}

// RoleIn is a subject's role for a repository ID such as
// "github.com/acme/infra": the global role, raised by any matching repo
// grants. An empty repo ID gives the global role.
func (p *Policy) RoleIn(s Subject, repoID string) Role {
	role := p.GlobalRole(s)
	if repoID == "" {
		return role
	}
	for _, rp := range p.repos {
		if rp.matches(repoID) {
			role = max(role, rp.roles.resolve(s))
		}
	}
	return role
}

// Requires returns the role an action needs in a repository. For unlock,
// the last matching repo entry that sets a requirement wins, as with other
// server-side repo settings. Other actions are global.
func (p *Policy) Requires(action Action, repoID string) Role {
	need := p.requirements[action]
	if action != ActionUnlock || repoID == "" {
		return need
	}
	for _, rp := range p.repos {
		if rp.unlock != RoleNone && rp.matches(repoID) {
			need = rp.unlock
		}
	}
	return need
}

// Allows reports whether a subject may take an action in a repository. base
// is a role held regardless of rules, such as the basic-auth user's, and is
// RoleNone for people who signed in.
func (p *Policy) Allows(s Subject, base Role, action Action, repoID string) bool {
	if action != ActionUnlock {
		repoID = ""
	}
	return max(base, p.RoleIn(s, repoID)) >= p.Requires(action, repoID)
}

// RelevantGroups returns the groups that appear in some rule, so sessions
// only carry groups the policy can use.
func (p *Policy) RelevantGroups(groups []string) []string {
	all := p.roles.all()
	for _, rp := range p.repos {
		all = append(all, rp.roles.all()...)
	}
	var out []string
	for _, g := range groups {
		if slices.ContainsFunc(all, func(r rule) bool { return r.kind == "group" && strings.EqualFold(r.value, g) }) {
			out = append(out, g)
		}
	}
	return out
}

// GitHubTeamRules returns the org/team names that GitHub rules mention for
// the given org, for checking a commenter's team membership.
func (p *Policy) GitHubTeamRules(org string) []string {
	all := p.roles.all()
	for _, rp := range p.repos {
		all = append(all, rp.roles.all()...)
	}
	var out []string
	for _, r := range all {
		if r.kind != "group" {
			continue
		}
		v, ok := strings.CutPrefix(r.value, GitHubGroupPrefix)
		if !ok {
			continue
		}
		o, team, ok := strings.Cut(v, "/")
		if ok && strings.EqualFold(o, org) && !slices.Contains(out, team) {
			out = append(out, team)
		}
	}
	return out
}

// AllowsCommenterUnlock checks an "atlantis unlock" comment: the commenter
// is matched by VCS login and "github:org/team" groups. It reports whether
// the comment may unlock, and which role unlocking needs in the repo.
func (p *Policy) AllowsCommenterUnlock(repoID, login string, groups []string) (bool, string) {
	s := Subject{GitHubLogin: login, Groups: groups}
	return p.Allows(s, RoleNone, ActionUnlock, repoID), p.Requires(ActionUnlock, repoID).String()
}

// Summary describes the policy for the Access page.
type Summary struct {
	Default      Role
	Requirements []RequirementSummary
	Roles        []RoleSummary
	Repos        []RepoSummary
	EnforcePR    bool
}

// RequirementSummary is the role an action needs.
type RequirementSummary struct {
	Action Action
	Role   Role
}

// RoleSummary lists who holds a role.
type RoleSummary struct {
	Role  Role
	Rules []string
}

// RepoSummary describes one repos entry's access settings.
type RepoSummary struct {
	Match  string
	Roles  []RoleSummary
	Unlock Role
}

func summarizeRoles(r roleRules) []RoleSummary {
	var out []RoleSummary
	for _, set := range []struct {
		role  Role
		rules []rule
	}{{RoleAdmin, r.admin}, {RoleOperator, r.operator}, {RoleViewer, r.viewer}} {
		if len(set.rules) == 0 {
			continue
		}
		rs := RoleSummary{Role: set.role}
		for _, x := range set.rules {
			rs.Rules = append(rs.Rules, x.String())
		}
		out = append(out, rs)
	}
	return out
}

// Summarize describes the policy in plain words.
func (p *Policy) Summarize() Summary {
	s := Summary{Default: p.defaultRole, EnforcePR: p.enforcePR, Roles: summarizeRoles(p.roles)}
	for _, a := range Actions {
		s.Requirements = append(s.Requirements, RequirementSummary{Action: a, Role: p.requirements[a]})
	}
	for _, rp := range p.repos {
		s.Repos = append(s.Repos, RepoSummary{Match: rp.label, Roles: summarizeRoles(rp.roles), Unlock: rp.unlock})
	}
	return s
}
