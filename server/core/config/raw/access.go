// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"fmt"
	"strings"

	"github.com/runatlantis/atlantis/server/core/config/valid"
)

// Access is the raw schema of the web UI access policy:
//
//	access:
//	  sign_in:            # see SignIn
//	    providers: [...]
//	  roles:
//	    admin:
//	      - group: platform-admins
//	      - email: lead@acme.com
//	    operator:
//	      - github: acme/sre
//	      - gitlab: acme/platform
//	    viewer:
//	      - domain: acme.com
//	  default: none
//	  permissions:
//	    unlock: operator
//	    stop_job: operator
//	    approve_policies: operator
//	    maintenance: admin
//	    lock_applies: admin
//	  enforce_in_pr_comments: true
type Access struct {
	Roles               AccessRoles        `yaml:"roles" json:"roles,omitzero"`
	Default             string             `yaml:"default,omitempty" json:"default,omitempty"`
	Permissions         *AccessPermissions `yaml:"permissions,omitempty" json:"permissions,omitempty"`
	EnforceInPRComments bool               `yaml:"enforce_in_pr_comments,omitempty" json:"enforce_in_pr_comments,omitempty"`
	// SignIn is how people sign in to the web UI.
	SignIn *SignIn `yaml:"sign_in,omitempty" json:"sign_in,omitempty"`
}

// RepoAccess is the per-repo access policy under a repos entry. It grants
// roles for the matching repos and can require a different role to unlock,
// to stop jobs, or to approve policies.
type RepoAccess struct {
	Roles       AccessRoles        `yaml:"roles" json:"roles,omitzero"`
	Permissions *AccessPermissions `yaml:"permissions,omitempty" json:"permissions,omitempty"`
}

type AccessRoles struct {
	Admin    []AccessRule `yaml:"admin,omitempty" json:"admin,omitempty"`
	Operator []AccessRule `yaml:"operator,omitempty" json:"operator,omitempty"`
	Viewer   []AccessRule `yaml:"viewer,omitempty" json:"viewer,omitempty"`
}

// AccessRule matches people by exactly one attribute.
type AccessRule struct {
	Group      string `yaml:"group,omitempty" json:"group,omitempty"`
	GitHub     string `yaml:"github,omitempty" json:"github,omitempty"`
	GitHubUser string `yaml:"github_user,omitempty" json:"github_user,omitempty"`
	GitLab     string `yaml:"gitlab,omitempty" json:"gitlab,omitempty"`
	GitLabUser string `yaml:"gitlab_user,omitempty" json:"gitlab_user,omitempty"`
	Gitea      string `yaml:"gitea,omitempty" json:"gitea,omitempty"`
	GiteaUser  string `yaml:"gitea_user,omitempty" json:"gitea_user,omitempty"`
	Email      string `yaml:"email,omitempty" json:"email,omitempty"`
	Domain     string `yaml:"domain,omitempty" json:"domain,omitempty"`
	Everyone   bool   `yaml:"everyone,omitempty" json:"everyone,omitempty"`
}

type AccessPermissions struct {
	View        string `yaml:"view,omitempty" json:"view,omitempty"`
	Unlock      string `yaml:"unlock,omitempty" json:"unlock,omitempty"`
	LockApplies string `yaml:"lock_applies,omitempty" json:"lock_applies,omitempty"`
	StopJob     string `yaml:"stop_job,omitempty" json:"stop_job,omitempty"`
	Maintenance string `yaml:"maintenance,omitempty" json:"maintenance,omitempty"`
	// ApprovePolicies is the role needed to approve failing policies from
	// the web UI. The person must also be a policy owner.
	ApprovePolicies string `yaml:"approve_policies,omitempty" json:"approve_policies,omitempty"`
}

var accessRoleNames = []string{"none", "viewer", "operator", "admin"}

func validRoleName(where, value string) error {
	if value == "" {
		return nil
	}
	for _, n := range accessRoleNames {
		if strings.EqualFold(value, n) {
			return nil
		}
	}
	return fmt.Errorf("%s: unknown role %q; use none, viewer, operator, or admin", where, value)
}

func (r AccessRule) validate(where string) error {
	set := 0
	for _, v := range []string{r.Group, r.GitHub, r.GitHubUser, r.GitLab, r.GitLabUser, r.Gitea, r.GiteaUser, r.Email, r.Domain} {
		if strings.TrimSpace(v) != "" {
			set++
		}
	}
	if r.Everyone {
		set++
	}
	if set != 1 {
		return fmt.Errorf("%s: each rule needs exactly one of group, github, github_user, gitlab, gitlab_user, gitea, gitea_user, email, domain, or everyone: true", where)
	}
	if r.Email != "" && !strings.Contains(r.Email, "@") {
		return fmt.Errorf("%s: email %q is not an email address", where, r.Email)
	}
	return nil
}

func (r AccessRoles) validate(where string) error {
	for _, set := range []struct {
		role  string
		rules []AccessRule
	}{{"admin", r.Admin}, {"operator", r.Operator}, {"viewer", r.Viewer}} {
		for i, rule := range set.rules {
			if err := rule.validate(fmt.Sprintf("%s.roles.%s[%d]", where, set.role, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// Validate checks the global access policy.
func (a Access) Validate() error {
	if a.SignIn != nil {
		if err := a.SignIn.Validate(); err != nil {
			return err
		}
	}
	if err := a.Roles.validate("access"); err != nil {
		return err
	}
	if err := validRoleName("access.default", a.Default); err != nil {
		return err
	}
	if a.Permissions != nil {
		for _, p := range []struct{ name, value string }{{"view", a.Permissions.View}, {"unlock", a.Permissions.Unlock}, {"stop_job", a.Permissions.StopJob}, {"approve_policies", a.Permissions.ApprovePolicies}, {"maintenance", a.Permissions.Maintenance}, {"lock_applies", a.Permissions.LockApplies}} {
			if err := validRoleName("access.permissions."+p.name, p.value); err != nil {
				return err
			}
			if strings.EqualFold(p.value, "none") {
				return fmt.Errorf("access.permissions.%s: an action can't require the none role; use viewer, operator, or admin", p.name)
			}
		}
	}
	return nil
}

// Validate checks a per-repo access policy for the repo with the given id.
func (a RepoAccess) Validate(repoID string) error {
	where := fmt.Sprintf("repos[%s].access", repoID)
	if err := a.Roles.validate(where); err != nil {
		return err
	}
	if a.Permissions == nil {
		return nil
	}
	if a.Permissions.View != "" {
		return fmt.Errorf("%s.permissions.view: viewing is set for the whole server; set it in the top-level access section", where)
	}
	if a.Permissions.LockApplies != "" {
		return fmt.Errorf("%s.permissions.lock_applies: the apply lock covers every repo; set it in the top-level access section", where)
	}
	if a.Permissions.Maintenance != "" {
		return fmt.Errorf("%s.permissions.maintenance: maintenance windows are managed for every repo; set it in the top-level access section", where)
	}
	for _, p := range []struct{ name, value string }{{"unlock", a.Permissions.Unlock}, {"stop_job", a.Permissions.StopJob}, {"approve_policies", a.Permissions.ApprovePolicies}} {
		if err := validRoleName(where+".permissions."+p.name, p.value); err != nil {
			return err
		}
		if strings.EqualFold(p.value, "none") {
			return fmt.Errorf("%s.permissions.%s: an action can't require the none role", where, p.name)
		}
	}
	return nil
}

func (r AccessRoles) toValid() valid.AccessRoles {
	conv := func(in []AccessRule) []valid.AccessRule {
		out := make([]valid.AccessRule, 0, len(in))
		for _, x := range in {
			out = append(out, valid.AccessRule{
				Group:      strings.TrimSpace(x.Group),
				GitHub:     strings.TrimSpace(x.GitHub),
				GitHubUser: strings.TrimSpace(x.GitHubUser),
				GitLab:     strings.Trim(strings.TrimSpace(x.GitLab), "/"),
				GitLabUser: strings.TrimSpace(x.GitLabUser),
				Gitea:      strings.TrimSpace(x.Gitea),
				GiteaUser:  strings.TrimSpace(x.GiteaUser),
				Email:      strings.TrimSpace(x.Email),
				Domain:     strings.TrimSpace(x.Domain),
				Everyone:   x.Everyone,
			})
		}
		return out
	}
	return valid.AccessRoles{Admin: conv(r.Admin), Operator: conv(r.Operator), Viewer: conv(r.Viewer)}
}

func (p *AccessPermissions) toValid() valid.AccessPermissions {
	if p == nil {
		return valid.AccessPermissions{}
	}
	return valid.AccessPermissions{
		View:            strings.ToLower(p.View),
		Unlock:          strings.ToLower(p.Unlock),
		LockApplies:     strings.ToLower(p.LockApplies),
		StopJob:         strings.ToLower(p.StopJob),
		Maintenance:     strings.ToLower(p.Maintenance),
		ApprovePolicies: strings.ToLower(p.ApprovePolicies),
	}
}

// ToValid converts the policy; nil stays nil.
func (a *Access) ToValid() *valid.Access {
	if a == nil {
		return nil
	}
	return &valid.Access{
		Roles:               a.Roles.toValid(),
		Default:             strings.ToLower(a.Default),
		Permissions:         a.Permissions.toValid(),
		EnforceInPRComments: a.EnforceInPRComments,
		SignIn:              a.SignIn.ToValid(),
	}
}

// ToValid converts the per-repo policy; nil stays nil.
func (a *RepoAccess) ToValid() *valid.RepoAccess {
	if a == nil {
		return nil
	}
	return &valid.RepoAccess{Roles: a.Roles.toValid(), Permissions: a.Permissions.toValid()}
}
