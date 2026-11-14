// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"time"
)

// The types in this file are the JSON shapes of the read-only web UI API
// under /ui/api/v1. They are documented in openapi.json; change both
// together. Field names are snake_case and stable. Times are RFC 3339 in
// UTC, or null when unknown. Some types convert directly from a store type;
// changing that store type's fields then breaks the build, so the API can't
// change shape by accident.

// apiList is a page of a collection. Next is the cursor of the following
// page, or null when there is none. The current stores return everything
// in one page, so Next is always null for now.
type apiList[T any] struct {
	Items        []T             `json:"items"`
	Next         *string         `json:"next"`
	Capabilities apiCapabilities `json:"capabilities"`
}

// apiItem wraps a single resource.
type apiItem[T any] struct {
	Item         T               `json:"item"`
	Capabilities apiCapabilities `json:"capabilities"`
}

type apiError struct {
	Error apiErrorBody `json:"error"`
}

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiCapabilities struct {
	RunHistory         bool `json:"run_history"`
	ClusterJobs        bool `json:"cluster_jobs"`
	AuditLog           bool `json:"audit_log"`
	SharedPlans        bool `json:"shared_plans"`
	SharedPolicyOutput bool `json:"shared_policy_output"`
	SharedMaintenance  bool `json:"shared_maintenance"`
	SharedDrift        bool `json:"shared_drift"`
}

func toAPICapabilities(c Capabilities) apiCapabilities {
	return apiCapabilities(c)
}

// apiTime renders a time as RFC 3339 in UTC, or null when it is zero.
func apiTime(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

type apiRepo struct {
	// VCSHost is empty when Atlantis doesn't know the host.
	VCSHost  string `json:"vcs_host"`
	FullName string `json:"full_name"`
}

func toAPIRepo(r Repository) apiRepo {
	return apiRepo(r)
}

type apiChanges struct {
	Known   bool `json:"known"`
	Import  int  `json:"import"`
	Add     int  `json:"add"`
	Change  int  `json:"change"`
	Destroy int  `json:"destroy"`
	Forget  int  `json:"forget"`
}

func toAPIChanges(c Changes) apiChanges {
	return apiChanges(c)
}

type apiViewer struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Role     string `json:"role"`
}

type apiGlobalPermissions struct {
	LockApplies bool `json:"lock_applies"`
	Maintenance bool `json:"maintenance"`
}

type apiInstance struct {
	Version              string               `json:"version"`
	ShuttingDown         bool                 `json:"shutting_down"`
	InProgressOperations int                  `json:"in_progress_operations"`
	DatabaseOK           bool                 `json:"database_ok"`
	DatabaseError        string               `json:"database_error"`
	LockingBackend       string               `json:"locking_backend"`
	StartedAt            *string              `json:"started_at"`
	Experiments          []string             `json:"experiments"`
	Viewer               apiViewer            `json:"viewer"`
	Permissions          apiGlobalPermissions `json:"permissions"`
}

type apiOwners struct {
	Users []string `json:"users"`
	Teams []string `json:"teams"`
}

func toAPIOwners(o PolicyOwners) apiOwners {
	return apiOwners{Users: nonNil(o.Users), Teams: nonNil(o.Teams)}
}

type apiApproval struct {
	By      string `json:"by"`
	Current bool   `json:"current"`
}

type apiPolicySet struct {
	Name               string        `json:"name"`
	Passed             bool          `json:"passed"`
	Cleared            bool          `json:"cleared"`
	Configured         bool          `json:"configured"`
	RequiredApprovals  int           `json:"required_approvals"`
	CurrentApprovals   int           `json:"current_approvals"`
	Approvals          []apiApproval `json:"approvals"`
	Owners             apiOwners     `json:"owners"`
	PreventSelfApprove bool          `json:"prevent_self_approve"`
}

func toAPIPolicySet(s PolicySet) apiPolicySet {
	out := apiPolicySet{
		Name: s.Name, Passed: s.Passed, Cleared: s.Cleared(), Configured: s.Configured,
		RequiredApprovals: s.Required, CurrentApprovals: s.CurrentApprovals(),
		Approvals: []apiApproval{}, Owners: toAPIOwners(s.Owners), PreventSelfApprove: s.PreventSelfApprove,
	}
	for _, a := range s.Approvals {
		out.Approvals = append(out.Approvals, apiApproval(a))
	}
	return out
}

type apiProject struct {
	Dir       string     `json:"dir"`
	Workspace string     `json:"workspace"`
	Name      string     `json:"name"`
	State     string     `json:"state"`
	Changes   apiChanges `json:"changes"`
	// LockID is empty when the project holds no lock.
	LockID string `json:"lock_id"`
	// LatestJobID is empty when this replica has no output for it.
	LatestJobID   string         `json:"latest_job_id"`
	PolicyFailing bool           `json:"policy_failing"`
	Policies      []apiPolicySet `json:"policies"`
}

func toAPIProject(p Project) apiProject {
	out := apiProject{
		Dir: p.Dir, Workspace: p.Workspace, Name: p.Name, State: string(p.State), Changes: toAPIChanges(p.Changes),
		LockID: p.LockID, LatestJobID: p.LatestJobID, PolicyFailing: p.PolicyFailing(), Policies: []apiPolicySet{},
	}
	for _, s := range p.Policies {
		out.Policies = append(out.Policies, toAPIPolicySet(s))
	}
	return out
}

type apiPullPermissions struct {
	Unlock          bool `json:"unlock"`
	ApprovePolicies bool `json:"approve_policies"`
}

type apiPull struct {
	Repo           apiRepo            `json:"repo"`
	Number         int                `json:"number"`
	URL            string             `json:"url"`
	Author         string             `json:"author"`
	HeadBranch     string             `json:"head_branch"`
	BaseBranch     string             `json:"base_branch"`
	HeadCommit     string             `json:"head_commit"`
	State          string             `json:"state"`
	Changes        apiChanges         `json:"changes"`
	PolicyFailing  bool               `json:"policy_failing"`
	LastActivityAt *string            `json:"last_activity_at"`
	Projects       []apiProject       `json:"projects"`
	Permissions    apiPullPermissions `json:"permissions"`
}

// apiPullDetail is a pull request with the locks it holds and the
// maintenance windows that cover its repository.
type apiPullDetail struct {
	apiPull
	Locks       []apiLock        `json:"locks"`
	Maintenance []apiMaintenance `json:"maintenance"`
}

type apiLockPull struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
	Author string `json:"author"`
	// Tracked is false when Atlantis has no status for the pull request,
	// which usually means it was closed while the lock survived.
	Tracked bool `json:"tracked"`
}

type apiLockPermissions struct {
	Unlock bool `json:"unlock"`
}

type apiLock struct {
	ID          string             `json:"id"`
	Repo        apiRepo            `json:"repo"`
	Dir         string             `json:"dir"`
	Workspace   string             `json:"workspace"`
	Project     string             `json:"project"`
	Pull        apiLockPull        `json:"pull"`
	User        string             `json:"user"`
	Since       *string            `json:"since"`
	Stale       bool               `json:"stale"`
	Permissions apiLockPermissions `json:"permissions"`
}

type apiApplyLock struct {
	Enabled     bool                 `json:"enabled"`
	Locked      bool                 `json:"locked"`
	Since       *string              `json:"since"`
	Permissions apiGlobalPermissions `json:"permissions"`
}

type apiMaintenance struct {
	ID        string  `json:"id"`
	Repo      apiRepo `json:"repo"`
	Dir       string  `json:"dir"`
	Workspace string  `json:"workspace"`
	Project   string  `json:"project"`
	Plans     bool    `json:"plans"`
	Reason    string  `json:"reason"`
	By        string  `json:"by"`
	Since     *string `json:"since"`
	Until     *string `json:"until"`
}

func toAPIMaintenance(w MaintenanceWindow) apiMaintenance {
	return apiMaintenance{
		ID: w.ID, Repo: toAPIRepo(w.Repo), Dir: w.Dir, Workspace: w.Workspace, Project: w.ProjectName,
		Plans: w.Plans, Reason: w.Reason, By: w.By, Since: apiTime(w.Since), Until: apiTime(w.Until),
	}
}

type apiJobStop struct {
	By     string  `json:"by"`
	At     *string `json:"at"`
	Killed bool    `json:"killed"`
}

type apiJobPermissions struct {
	Stop bool `json:"stop"`
}

type apiJob struct {
	ID           string            `json:"id"`
	Repo         apiRepo           `json:"repo"`
	PullNumber   int               `json:"pull_number"`
	Dir          string            `json:"dir"`
	Workspace    string            `json:"workspace"`
	Project      string            `json:"project"`
	Step         string            `json:"step"`
	Description  string            `json:"description"`
	Status       string            `json:"status"`
	LastOutputAt *string           `json:"last_output_at"`
	Lines        int               `json:"lines"`
	Stop         *apiJobStop       `json:"stop"`
	Permissions  apiJobPermissions `json:"permissions"`
}

// apiJobStatus is running, stalled, or done.
func apiJobStatus(j Job) string {
	switch {
	case j.Done:
		return "done"
	case j.Stalled:
		return "stalled"
	}
	return "running"
}

type apiAttribute struct {
	Path string `json:"path"`
	// Before and After are null when the value is absent or sensitive.
	Before            *string `json:"before"`
	After             *string `json:"after"`
	BeforeSensitive   bool    `json:"before_sensitive"`
	AfterSensitive    bool    `json:"after_sensitive"`
	AfterUnknown      bool    `json:"after_unknown"`
	ForcesReplacement bool    `json:"forces_replacement"`
}

func toAPIAttribute(a AttributeChange) apiAttribute {
	out := apiAttribute{
		Path: a.Path, BeforeSensitive: a.BeforeSensitive, AfterSensitive: a.AfterSensitive,
		AfterUnknown: a.AfterUnknown, ForcesReplacement: a.ForcesReplacement,
	}
	// The parser never keeps sensitive values; check again so a change
	// there can't leak them here.
	if !a.BeforeAbsent && !a.BeforeSensitive {
		v := a.Before
		out.Before = &v
	}
	if !a.AfterAbsent && !a.AfterSensitive && !a.AfterUnknown {
		v := a.After
		out.After = &v
	}
	return out
}

type apiResource struct {
	Address         string         `json:"address"`
	PreviousAddress string         `json:"previous_address"`
	Module          string         `json:"module"`
	Type            string         `json:"type"`
	Name            string         `json:"name"`
	Provider        string         `json:"provider"`
	Action          string         `json:"action"`
	ImportID        string         `json:"import_id"`
	Importing       bool           `json:"importing"`
	Deposed         string         `json:"deposed"`
	Reason          string         `json:"reason"`
	Attributes      []apiAttribute `json:"attributes"`
	Unchanged       int            `json:"unchanged_attributes"`
	Omitted         int            `json:"omitted_attributes"`
}

type apiPlan struct {
	Repo             apiRepo       `json:"repo"`
	PullNumber       int           `json:"pull_number"`
	Project          apiProjectRef `json:"project"`
	Status           string        `json:"status"`
	GeneratedAt      *string       `json:"generated_at"`
	SizeBytes        int64         `json:"size_bytes"`
	TerraformVersion string        `json:"terraform_version"`
	Changes          apiChanges    `json:"changes"`
	Resources        []apiResource `json:"resources"`
	TotalResources   int           `json:"total_resources"`
	// ResourcesOmitted is true when the resource limit dropped resources.
	ResourcesOmitted  bool `json:"resources_omitted"`
	AttributesOmitted bool `json:"attributes_omitted"`
}

type apiProjectRef struct {
	Dir       string `json:"dir"`
	Workspace string `json:"workspace"`
	Name      string `json:"name"`
}

func toAPIPlan(p PullRequest, ref ProjectRef, plan ProjectPlan) apiPlan {
	out := apiPlan{
		Repo: toAPIRepo(p.Repo), PullNumber: p.Num, Project: apiProjectRef(ref),
		Status: string(plan.Status), GeneratedAt: apiTime(plan.GeneratedAt), SizeBytes: plan.Size,
		Resources: []apiResource{},
	}
	if plan.Status != PlanReady {
		return out
	}
	pp := plan.Plan
	out.TerraformVersion = pp.TerraformVersion
	out.Changes = toAPIChanges(pp.Changes)
	out.TotalResources = pp.TotalResources
	out.ResourcesOmitted = pp.TotalResources > len(pp.Resources)
	out.AttributesOmitted = pp.AttributesOmitted
	for _, rc := range pp.Resources {
		res := apiResource{
			Address: rc.Address, PreviousAddress: rc.PreviousAddress, Module: rc.Module, Type: rc.Type, Name: rc.Name,
			Provider: rc.Provider, Action: string(rc.Action), ImportID: rc.ImportID, Importing: rc.Importing,
			Deposed: rc.Deposed, Reason: rc.Reason, Attributes: []apiAttribute{}, Unchanged: rc.Unchanged, Omitted: rc.Omitted,
		}
		for _, a := range rc.Attributes {
			res.Attributes = append(res.Attributes, toAPIAttribute(a))
		}
		out.Resources = append(out.Resources, res)
	}
	return out
}

type apiPolicySetDetail struct {
	apiPolicySet
	// Output is null when this replica doesn't have the policy output.
	Output *string `json:"output"`
	// CanApprove and Reason say whether the viewer could approve the set
	// in the web UI, and why not.
	CanApprove bool   `json:"can_approve"`
	Reason     string `json:"reason"`
}

type apiPolicies struct {
	Repo         apiRepo              `json:"repo"`
	PullNumber   int                  `json:"pull_number"`
	Project      apiProjectRef        `json:"project"`
	OutputStatus string               `json:"output_status"`
	CheckedAt    *string              `json:"checked_at"`
	Admins       apiOwners            `json:"admins"`
	Sets         []apiPolicySetDetail `json:"sets"`
}

type apiDriftCheck struct {
	Repo           apiRepo    `json:"repo"`
	Project        string     `json:"project"`
	Dir            string     `json:"dir"`
	Workspace      string     `json:"workspace"`
	Ref            string     `json:"ref"`
	BaseBranch     string     `json:"base_branch"`
	Commit         string     `json:"commit"`
	DetectionID    string     `json:"detection_id"`
	Status         string     `json:"status"`
	ChangesOutside bool       `json:"changes_outside"`
	Changes        apiChanges `json:"changes"`
	Summary        string     `json:"summary"`
	Error          string     `json:"error"`
	CheckedAt      *string    `json:"checked_at"`
	Stale          bool       `json:"stale"`
}

type apiDriftCounts struct {
	Total   int `json:"total"`
	Drifted int `json:"drifted"`
	Failed  int `json:"failed"`
	InSync  int `json:"in_sync"`
	Stale   int `json:"stale"`
}

// apiDriftList is the drift collection. Enabled is false when drift
// detection is off on this server.
type apiDriftList struct {
	apiList[apiDriftCheck]
	Enabled bool           `json:"enabled"`
	Counts  apiDriftCounts `json:"counts"`
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
