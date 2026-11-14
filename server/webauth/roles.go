// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth

import (
	"fmt"
	"strings"
)

// RoleMapper turns an identity into a role.
//
// Each rule is one of:
//   - "*": anyone who signed in
//   - "group:NAME" or a bare "NAME": a group the provider reports
//   - "email:ADDRESS": a verified email address
//   - "domain:example.com": any verified email in that domain
//
// Matching ignores case. The highest matching role wins, so a user listed as
// both viewer and admin is an admin. Users matching no rule get Default,
// which is RoleNone unless configured otherwise.
type RoleMapper struct {
	Admins    []string
	Operators []string
	Viewers   []string
	Default   Role
}

// Validate rejects rules with an unknown prefix or an empty value.
func (m RoleMapper) Validate() error {
	for _, set := range []struct {
		name  string
		rules []string
	}{{"admins", m.Admins}, {"operators", m.Operators}, {"viewers", m.Viewers}} {
		for _, rule := range set.rules {
			if _, _, err := parseRule(rule); err != nil {
				return fmt.Errorf("role %s: %w", set.name, err)
			}
		}
	}
	return nil
}

// Resolve returns the role for an identity.
func (m RoleMapper) Resolve(id Identity) Role {
	switch {
	case matchesAny(m.Admins, id):
		return RoleAdmin
	case matchesAny(m.Operators, id):
		return RoleOperator
	case matchesAny(m.Viewers, id):
		return RoleViewer
	}
	return m.Default
}

func matchesAny(rules []string, id Identity) bool {
	for _, rule := range rules {
		kind, value, err := parseRule(rule)
		if err != nil {
			continue
		}
		if matches(kind, value, id) {
			return true
		}
	}
	return false
}

func parseRule(rule string) (kind, value string, err error) {
	rule = strings.TrimSpace(rule)
	if rule == "*" {
		return "*", "", nil
	}
	kind, value, found := strings.Cut(rule, ":")
	if !found {
		kind, value = "group", rule
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", fmt.Errorf("rule %q has no value", rule)
	}
	switch kind {
	case "group", "email", "domain":
		return kind, value, nil
	}
	return "", "", fmt.Errorf("rule %q: unknown kind %q; use group:, email:, domain:, or *", rule, kind)
}

func matches(kind, value string, id Identity) bool {
	switch kind {
	case "*":
		return true
	case "group":
		for _, g := range id.Groups {
			if strings.EqualFold(g, value) {
				return true
			}
		}
	case "email":
		return id.EmailVerified && strings.EqualFold(id.Email, value)
	case "domain":
		if !id.EmailVerified {
			return false
		}
		_, domain, ok := strings.Cut(id.Email, "@")
		return ok && strings.EqualFold(domain, strings.TrimPrefix(value, "@"))
	}
	return false
}
