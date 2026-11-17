// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

// Package webui serves the experimental Atlantis web UI.
//
// Pages read through the Store interface, whose records follow the data model
// in ADR 0005 (repository, pull request, project, job). Today the store is
// backed by the lock database, pull status, and in-memory job output. When
// durable storage lands, a second Store implementation can serve the same
// pages with history that survives restarts and spans replicas.
package webui

import (
	"context"
	"strings"
	"time"
)

// ProjectState is where a project is in the plan and apply cycle.
type ProjectState string

const (
	StateRunning      ProjectState = "running"
	StatePlanned      ProjectState = "planned"
	StateNoChanges    ProjectState = "no_changes"
	StateApplied      ProjectState = "applied"
	StatePlanFailed   ProjectState = "plan_failed"
	StateApplyFailed  ProjectState = "apply_failed"
	StateDiscarded    ProjectState = "discarded"
	StatePolicyFailed ProjectState = "policy_failed"
	StatePolicyPassed ProjectState = "policy_passed"
)

// Repository identifies a repository on a VCS host.
type Repository struct {
	VCSHost  string
	FullName string
}

// Changes counts the resource changes in a plan. Known is false when the
// plan output is not available, for example after a restart.
type Changes struct {
	Known   bool
	Import  int
	Add     int
	Change  int
	Destroy int
	Forget  int
}

// Total is the number of resources the plan touches.
func (c Changes) Total() int {
	return c.Import + c.Add + c.Change + c.Destroy + c.Forget
}

// Project is a Terraform project inside a pull request.
type Project struct {
	Dir       string
	Workspace string
	Name      string
	State     ProjectState
	Changes   Changes
	LockID    string
	// LatestJobID is the newest job this replica has output for, if any.
	LatestJobID string
	// Policies are the policy set results of the project's latest policy
	// check, without the policy output. Empty when no check ran.
	Policies []PolicySet
}

// PolicyFailing reports whether a policy set of the project failed and
// still needs approvals.
func (p Project) PolicyFailing() bool {
	for _, s := range p.Policies {
		if !s.Cleared() {
			return true
		}
	}
	return false
}

// FailingPolicySets lists the names of the policy sets that failed and still
// need approvals.
func (p Project) FailingPolicySets() []string {
	var out []string
	for _, s := range p.Policies {
		if !s.Cleared() {
			out = append(out, s.Name)
		}
	}
	return out
}

// PolicyOwners are the people and GitHub teams who may approve a policy set.
// Teams are team slugs in the repository's organization.
type PolicyOwners struct {
	Users []string
	Teams []string
}

// Empty reports whether nobody is named.
func (o PolicyOwners) Empty() bool {
	return len(o.Users) == 0 && len(o.Teams) == 0
}

// PolicyApproval is one approval of a failing policy set.
type PolicyApproval struct {
	By string
	// Current is false when the approval was given for an earlier failure,
	// so it no longer counts.
	Current bool
}

// PolicySet is one policy set's result for a project.
type PolicySet struct {
	Name      string
	Passed    bool
	Approvals []PolicyApproval
	// Configured is false when the server-side repo config no longer has
	// the policy set, so the required approvals and owners are unknown.
	Configured bool
	// Required is how many approvals a failing set needs.
	Required int
	Owners   PolicyOwners
	// PreventSelfApprove is true when the pull request's author may not
	// approve the set.
	PreventSelfApprove bool
	// Output is the policy tool's output. It is only set by GetPolicies,
	// and only when this replica has it.
	Output string
}

// CurrentApprovals counts the approvals that still count.
func (s PolicySet) CurrentApprovals() int {
	n := 0
	for _, a := range s.Approvals {
		if a.Current {
			n++
		}
	}
	return n
}

// Cleared reports whether the set passed or has enough approvals.
func (s PolicySet) Cleared() bool {
	return s.Passed || (s.Configured && s.CurrentApprovals() >= s.Required)
}

// PolicyOutputStatus says whether the policy output can be shown.
type PolicyOutputStatus string

const (
	// PolicyOutputReady means the output was read.
	PolicyOutputReady PolicyOutputStatus = "ready"
	// PolicyOutputMissing means this replica has no policy output for the
	// project's current plan.
	PolicyOutputMissing PolicyOutputStatus = "missing"
	// PolicyOutputOutdated means the output is from an earlier plan.
	PolicyOutputOutdated PolicyOutputStatus = "outdated"
	// PolicyOutputUnreadable means the output file could not be read.
	PolicyOutputUnreadable PolicyOutputStatus = "unreadable"
)

// ProjectPolicies is the policy check of one project in a pull request.
type ProjectPolicies struct {
	Sets []PolicySet
	// Admins are the top-level policy owners, who may approve every set.
	Admins PolicyOwners
	// Output says whether the sets' Output fields were filled.
	Output PolicyOutputStatus
	// CheckedAt is when the policy output was written, when known.
	CheckedAt time.Time
}

// PullRequest is a pull request Atlantis has run commands for.
type PullRequest struct {
	Repo       Repository
	Num        int
	URL        string
	Author     string
	HeadBranch string
	BaseBranch string
	HeadCommit string
	Projects   []Project
	// LastActivity is the newest lock or job time this replica knows about.
	LastActivity time.Time
}

// PolicyFailing reports whether a project has a failing policy set that
// still needs approvals.
func (p PullRequest) PolicyFailing() bool {
	for _, proj := range p.Projects {
		if proj.PolicyFailing() {
			return true
		}
	}
	return false
}

// Changes sums the known plan changes across projects.
func (p PullRequest) Changes() Changes {
	var c Changes
	for _, proj := range p.Projects {
		if !proj.Changes.Known {
			continue
		}
		c.Known = true
		c.Import += proj.Changes.Import
		c.Add += proj.Changes.Add
		c.Change += proj.Changes.Change
		c.Destroy += proj.Changes.Destroy
		c.Forget += proj.Changes.Forget
	}
	return c
}

// Lock is a project lock held by a pull request.
type Lock struct {
	ID          string
	Repo        Repository
	Dir         string
	Workspace   string
	ProjectName string
	PullNum     int
	PullURL     string
	PullAuthor  string
	User        string
	Since       time.Time
	// PullTracked is false when Atlantis has no status for the pull request,
	// which usually means it was closed while the lock survived.
	PullTracked bool
}

// ApplyLock is the global apply lock.
type ApplyLock struct {
	Locked bool
	// Enabled is false when the server disables the global apply lock.
	Enabled bool
	Since   time.Time
}

// MaintenanceWindow freezes applies, and optionally plans, in a repository
// or in one directory, workspace, or project of it. Empty Dir, Workspace and
// ProjectName cover every value; an empty Repo.VCSHost covers every host.
type MaintenanceWindow struct {
	ID          string
	Repo        Repository
	Dir         string
	Workspace   string
	ProjectName string
	// Plans is true when plans are frozen too, not only applies.
	Plans  bool
	Reason string
	By     string
	Since  time.Time
	// Until is when the window ends by itself; zero means it lasts until
	// someone ends it.
	Until time.Time
}

// RepoWide reports whether the window covers the whole repository.
func (w MaintenanceWindow) RepoWide() bool {
	return w.Dir == "" && w.Workspace == "" && w.ProjectName == ""
}

// CoversRepo reports whether the window applies to some or all of a
// repository.
func (w MaintenanceWindow) CoversRepo(r Repository) bool {
	return strings.EqualFold(w.Repo.FullName, r.FullName) && sameHost(w.Repo.VCSHost, r.VCSHost)
}

// MaintenanceRequest asks for a new maintenance window.
type MaintenanceRequest struct {
	Repo        Repository
	Dir         string
	Workspace   string
	ProjectName string
	Plans       bool
	Reason      string
	// Until is zero for a window without an end time.
	Until time.Time
}

// Job is one command run for a project, such as a plan or an apply. Jobs are
// matched to pull requests by repository name, and carry the VCS host when
// the output handler recorded it.
type Job struct {
	ID          string
	Repo        Repository
	PullNum     int
	Dir         string
	Workspace   string
	ProjectName string
	Step        string
	Description string
	Done        bool
	// Stalled is true when an unfinished job has produced no output for a
	// long time, which usually means its process died.
	Stalled    bool
	LastOutput time.Time
	Lines      int
	// Stop says who stopped the job, if anyone did.
	Stop *JobStop
}

// JobStop records a request to stop a job.
type JobStop struct {
	By string
	At time.Time
	// Killed is true when the job's process ignored the interrupt and was
	// killed, so Terraform may still hold its state lock.
	Killed bool
}

// Running reports whether the job is still running, as far as this replica
// knows.
func (j Job) Running() bool {
	return !j.Done && !j.Stalled
}

// Stoppable reports whether the job can be stopped: it hasn't finished and
// nobody has stopped it yet. A stalled job counts, since its process may
// still be alive.
func (j Job) Stoppable() bool {
	return !j.Done && j.Stop == nil
}

// JobFilter narrows ListJobs.
type JobFilter struct {
	RepoFullName string
	PullNum      int
	RunningOnly  bool
}

// Instance describes the replica serving the request.
type Instance struct {
	Version        string
	ShuttingDown   bool
	InProgressOps  int
	DatabaseOK     bool
	DatabaseError  string
	LockingBackend string
	StartedAt      time.Time
	Experiments    []string
}

// Capabilities says which data the store can answer. Pages hide or explain
// the panels a store cannot fill instead of showing incomplete data.
type Capabilities struct {
	// RunHistory is true when job records and logs survive restarts.
	RunHistory bool
	// ClusterJobs is true when jobs from every replica are visible.
	ClusterJobs bool
	// AuditLog is true when user actions are stored and can be listed.
	AuditLog bool
	// SharedPlans is true when plan details are stored centrally and any
	// replica can show them.
	SharedPlans bool
	// SharedPolicyOutput is true when policy check output is stored
	// centrally and any replica can show it.
	SharedPolicyOutput bool
	// SharedMaintenance is true when maintenance windows are stored
	// centrally, so they block commands on every replica and survive
	// restarts.
	SharedMaintenance bool
	// SharedDrift is true when drift detection results are stored centrally,
	// so every replica shows every result and they survive restarts.
	SharedDrift bool
	// Traces is true when jobs record timing traces.
	Traces bool
	// SharedTraces is true when timing traces are stored centrally, so any
	// replica can show them and they survive restarts. When false, a trace
	// lives in memory on the replica that ran the job.
	SharedTraces bool
}

// ProjectRef identifies a project within a pull request.
type ProjectRef struct {
	Dir       string
	Workspace string
	Name      string
}

// Ref returns the reference to the project.
func (p Project) Ref() ProjectRef {
	return ProjectRef{Dir: p.Dir, Workspace: p.Workspace, Name: p.Name}
}

// PlanStatus says whether a project's plan details can be shown.
type PlanStatus string

const (
	// PlanReady means the plan details were read.
	PlanReady PlanStatus = "ready"
	// PlanNoSavedPlan means this replica has no saved plan for the project.
	PlanNoSavedPlan PlanStatus = "no_saved_plan"
	// PlanNoJSON means the plan was saved but not as JSON.
	PlanNoJSON PlanStatus = "no_json"
	// PlanOutdated means the JSON is from an earlier plan than the saved one.
	PlanOutdated PlanStatus = "outdated"
	// PlanTooLarge means the JSON is over the size the UI reads.
	PlanTooLarge PlanStatus = "too_large"
	// PlanUnreadable means the JSON could not be read as a Terraform plan.
	PlanUnreadable PlanStatus = "unreadable"
)

// ProjectPlan is the plan of one project in a pull request. Plan holds the
// details only when Status is PlanReady.
type ProjectPlan struct {
	Status PlanStatus
	// GeneratedAt is when the plan JSON was written.
	GeneratedAt time.Time
	// Size is the size of the plan JSON in bytes, when known.
	Size int64
	Plan ParsedPlan
}

// DriftStatus is the outcome of a project's latest drift check.
type DriftStatus string

const (
	// DriftDrifted means the plan found changes.
	DriftDrifted DriftStatus = "drifted"
	// DriftInSync means the plan found no changes.
	DriftInSync DriftStatus = "in_sync"
	// DriftFailed means the check failed before it could tell.
	DriftFailed DriftStatus = "failed"
)

// DriftCheck is the latest drift detection result for one project on one
// ref, from the drift detection API.
type DriftCheck struct {
	Repo        Repository
	ProjectName string
	Dir         string
	Workspace   string
	// Ref is the branch, tag, or commit that was checked.
	Ref string
	// BaseBranch is the branch context of a tag or commit check.
	BaseBranch string
	// Commit is the commit the check planned, when known.
	Commit      string
	DetectionID string
	Drifted     bool
	// ChangesOutside is true when Terraform reported changes made outside
	// Terraform.
	ChangesOutside bool
	// Changes is unknown when the check failed before a plan finished.
	Changes Changes
	// Summary is Terraform's plan summary line, when there was one.
	Summary   string
	Error     string
	CheckedAt time.Time
}

// Status is the outcome of the check. A check that found drift counts as
// drifted even when a later step, such as a policy check, failed.
func (c DriftCheck) Status() DriftStatus {
	switch {
	case c.Drifted:
		return DriftDrifted
	case c.Error != "":
		return DriftFailed
	}
	return DriftInSync
}

// DriftReport is every drift result the store has.
type DriftReport struct {
	// Enabled is false when drift detection is off on this server, so
	// there can be no results.
	Enabled bool
	Checks  []DriftCheck
}

// Store is the read side of the web UI.
type Store interface {
	Capabilities() Capabilities
	Instance(ctx context.Context) Instance
	ListPulls(ctx context.Context) ([]PullRequest, error)
	// GetPull returns nil when Atlantis has no status for the pull request.
	// An empty repo.VCSHost matches any host.
	GetPull(ctx context.Context, repo Repository, num int) (*PullRequest, error)
	// GetPlan returns the resource changes in a project's latest plan. It
	// returns nil when Atlantis has no such project in the pull request.
	GetPlan(ctx context.Context, repo Repository, num int, project ProjectRef) (*ProjectPlan, error)
	// GetPolicies returns a project's latest policy check. It returns nil
	// when Atlantis has no such project in the pull request.
	GetPolicies(ctx context.Context, repo Repository, num int, project ProjectRef) (*ProjectPolicies, error)
	ListLocks(ctx context.Context) ([]Lock, error)
	ApplyLock(ctx context.Context) (ApplyLock, error)
	// ListMaintenance returns the active maintenance windows, oldest first.
	ListMaintenance(ctx context.Context) []MaintenanceWindow
	// ListDrift returns the latest drift detection result of every project
	// and ref, drifted first.
	ListDrift(ctx context.Context) (DriftReport, error)
	ListJobs(ctx context.Context, f JobFilter) []Job
	GetJob(ctx context.Context, id string) (Job, bool)
	// JobLog streams a job's output starting after the first `from` lines,
	// then new lines as they arrive. The channel closes when the job has
	// finished and every line was sent, when the job's output is removed, or
	// when ctx is done.
	JobLog(ctx context.Context, id string, from int) <-chan LogLine
	// JobTrace returns a job's timing trace. Its Status says whether tracing
	// is off or the store has no trace for the job.
	JobTrace(ctx context.Context, id string) JobTrace
}

// TraceStatus says whether a job's timing trace can be shown.
type TraceStatus string

const (
	// TraceOff means the server doesn't record traces.
	TraceOff TraceStatus = "off"
	// TraceMissing means the store has no trace for the job, for example
	// because another replica ran it or it ran before a restart.
	TraceMissing TraceStatus = "missing"
	// TraceReady means the trace was read.
	TraceReady TraceStatus = "ready"
)

// TraceCategory groups spans for display.
type TraceCategory string

const (
	TraceJob      TraceCategory = "job"
	TraceStep     TraceCategory = "step"
	TraceCommand  TraceCategory = "command"
	TraceTool     TraceCategory = "tool"
	TraceProvider TraceCategory = "provider"
	TraceResource TraceCategory = "resource"
)

// TraceAttribute is a span attribute. A hidden attribute's value was not
// kept because it may be sensitive.
type TraceAttribute struct {
	Key    string
	Value  string
	Hidden bool
}

// TraceSpan is one timed operation in a job: an Atlantis step, a Terraform
// command, or work Terraform reported inside it.
type TraceSpan struct {
	ID       string
	ParentID string
	Name     string
	Category TraceCategory
	// Source is "atlantis", or the name the reporting tool gave, such as
	// "OpenTofu CLI".
	Source string
	Start  time.Time
	// End is zero while the span runs.
	End        time.Time
	Error      bool
	Message    string
	Attributes []TraceAttribute
}

// Running reports whether the span hasn't ended.
func (s TraceSpan) Running() bool {
	return s.End.IsZero()
}

// JobTrace is the timing trace of a job.
type JobTrace struct {
	Status  TraceStatus
	TraceID string
	Spans   []TraceSpan
	// Dropped counts spans over the per-job limit, which were not kept.
	Dropped int
	// Notes explain gaps in the trace.
	Notes []string
	// Finished is true once the job's own span ended.
	Finished bool
	// AllAttributes is true when every attribute value was kept, not only
	// the allowlisted ones.
	AllAttributes bool
	// Version changes whenever the trace changes.
	Version uint64
}

// LogLine is one line of job output. N is its 1-based position in the log.
type LogLine struct {
	N    int
	Text string
}

// Actions changes state on behalf of a user.
type Actions interface {
	// DiscardLock deletes a lock and its plan. It returns false when no lock
	// exists at id.
	DiscardLock(id string, actor string) (bool, error)
	LockApplies() error
	UnlockApplies() error
	// StopJob interrupts a job running on this replica on behalf of actor.
	// It returns the stop and whether this call made it; when the job was
	// already stopped, it returns the earlier stop.
	StopJob(id string, actor string) (JobStop, bool, error)
	// StartMaintenance starts a maintenance window on behalf of actor.
	StartMaintenance(req MaintenanceRequest, actor string) (MaintenanceWindow, error)
	// EndMaintenance ends a window. It returns false when no active window
	// has the ID.
	EndMaintenance(id string) (MaintenanceWindow, bool, error)
	// ApprovePolicies starts "atlantis approve_policies" for a pull request
	// on behalf of a VCS user, after commenting who asked for it. The
	// command runs in the background and posts its result on the pull
	// request.
	ApprovePolicies(req PolicyApprovalRequest) error
}

// PolicyApprovalRequest asks to approve failing policies.
type PolicyApprovalRequest struct {
	Repo Repository
	Num  int
	// Project limits the approval to one project; nil means every project.
	Project *ProjectRef
	// PolicySet limits the approval to one policy set; empty means every
	// failing set.
	PolicySet string
	// Login is the GitHub username the approval is recorded for and the
	// comment names. The command checks it against the policy owners again.
	Login string
}
