package events

import (
	"strings"
)

// Wildcard matches all teams and all commands
const wildcard = "*"

// mapOfStrings is an alias for map[string]string
type mapOfStrings map[string]string

// TeamWhitelistChecker implements checking the teams and the operations that the members
// of a particular team are allowed to perform
type TeamWhitelistChecker struct {
	rules []mapOfStrings
}

// NewTeamWhitelistChecker constructs a new checker
func NewTeamWhitelistChecker(whitelist string) (*TeamWhitelistChecker, error) {
	var rules []mapOfStrings
	pairs := strings.Split(whitelist, ",")
	for _, pair := range pairs {
		values := strings.Split(pair, ":")
		team := strings.TrimSpace(values[0])
		command := strings.TrimSpace(values[1])
		m := mapOfStrings{team: command}
		rules = append(rules, m)
	}
	return &TeamWhitelistChecker{
		rules: rules,
	}, nil
}

// IsCommandAllowedForTeam returns true if the team is allowed to execute the command
// and false otherwise.
func (checker *TeamWhitelistChecker) IsCommandAllowedForTeam(team string, command string) bool {
	t := strings.TrimSpace(team)
	c := strings.TrimSpace(command)
	for _, rule := range checker.rules {
		for key, value := range rule {
			if (key == wildcard || strings.EqualFold(key, t)) && (value == wildcard || strings.EqualFold(value, c)) {
				return true
			}
		}
	}
	return false
}

// IsCommandAllowedForAnyTeam returns true if any of the teams is allowed to execute the command
// and false otherwise.
func (checker *TeamWhitelistChecker) IsCommandAllowedForAnyTeam(teams []string, command string) bool {
	c := strings.TrimSpace(command)
	if teams == nil || len(teams) == 0 {
		for _, rule := range checker.rules {
			for key, value := range rule {
				if (key == wildcard) && (value == wildcard || strings.EqualFold(value, c)) {
					return true
				}
			}
		}
	} else {
		for _, t := range teams {
			if checker.IsCommandAllowedForTeam(t, command) {
				return true
			}
		}
	}
	return false
}
