// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package valid

// Access is the web UI access policy from the server-side repo config. It
// says who holds each role and which role each action needs.
type Access struct {
	Roles       AccessRoles
	Default     string
	Permissions AccessPermissions
	// EnforceInPRComments applies the unlock permission to "atlantis unlock"
	// comments, matched against the commenter's VCS identity.
	EnforceInPRComments bool
}

// RepoAccess adjusts the policy for matching repositories. Its roles are
// granted in addition to the global ones, and its permissions replace the
// global requirement for these repositories.
type RepoAccess struct {
	Roles       AccessRoles
	Permissions AccessPermissions
}

// AccessRoles lists who holds each role.
type AccessRoles struct {
	Admin    []AccessRule
	Operator []AccessRule
	Viewer   []AccessRule
}

// AccessRule matches people by exactly one attribute.
type AccessRule struct {
	Group      string
	GitHub     string
	GitHubUser string
	Email      string
	Domain     string
	Everyone   bool
}

// AccessPermissions names the role each action needs. Empty means the
// default for that action.
type AccessPermissions struct {
	View        string
	Unlock      string
	LockApplies string
	StopJob     string
	Maintenance string
	// ApprovePolicies is the role needed to approve failing policies from
	// the web UI, on top of being a policy owner.
	ApprovePolicies string
}
