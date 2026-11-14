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
	ListLocks(ctx context.Context) ([]Lock, error)
	ApplyLock(ctx context.Context) (ApplyLock, error)
	ListJobs(ctx context.Context, f JobFilter) []Job
	GetJob(ctx context.Context, id string) (Job, bool)
	// JobLog streams a job's output starting after the first `from` lines,
	// then new lines as they arrive. The channel closes when the job has
	// finished and every line was sent, when the job's output is removed, or
	// when ctx is done.
	JobLog(ctx context.Context, id string, from int) <-chan LogLine
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
}
