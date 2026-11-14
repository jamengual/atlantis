// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/runatlantis/atlantis/server/core/locking"
	"github.com/runatlantis/atlantis/server/events"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/jobs"
)

// LockLister lists project locks keyed by lock ID.
type LockLister interface {
	List() (map[string]models.ProjectLock, error)
}

// PullStatusDB is the part of the lock database the store reads.
type PullStatusDB interface {
	ListPullStatuses() ([]models.PullStatus, error)
	Ping() error
}

// JobSource is the in-memory job output of this replica.
type JobSource interface {
	GetPullToJobMapping() []jobs.PullInfoWithJobIDs
	Register(jobID string, receiver chan string)
	Deregister(jobID string, receiver chan string)
}

// outputBufferReader is implemented by the async output handler. Stores fall
// back to unknown completion state when the job source does not implement it.
type outputBufferReader interface {
	GetProjectOutputBuffer(jobID string) jobs.OutputBuffer
}

// DrainStatusReader reports whether this replica is shutting down.
type DrainStatusReader interface {
	GetStatus() events.DrainStatus
}

// LegacyStore serves the web UI from the lock database, pull status, and
// in-memory job output. Job data only covers this replica and is lost on
// restart; Capabilities reports that.
type LegacyStore struct {
	Locks          LockLister
	DB             PullStatusDB
	ApplyLocks     locking.ApplyLockChecker
	Jobs           JobSource
	Drainer        DrainStatusReader
	Version        string
	LockingBackend string
	StartedAt      time.Time
	Experiments    []string
}

var _ Store = (*LegacyStore)(nil)

func (s *LegacyStore) Capabilities() Capabilities { return Capabilities{} }

func (s *LegacyStore) Instance(_ context.Context) Instance {
	inst := Instance{
		Version:        s.Version,
		LockingBackend: s.LockingBackend,
		StartedAt:      s.StartedAt,
		Experiments:    slices.Clone(s.Experiments),
		DatabaseOK:     true,
	}
	if s.Drainer != nil {
		st := s.Drainer.GetStatus()
		inst.ShuttingDown = st.ShuttingDown
		inst.InProgressOps = st.InProgressOps
	}
	if err := s.DB.Ping(); err != nil {
		inst.DatabaseOK = false
		inst.DatabaseError = err.Error()
	}
	return inst
}

func (s *LegacyStore) ListPulls(ctx context.Context) ([]PullRequest, error) {
	statuses, err := s.DB.ListPullStatuses()
	if err != nil {
		return nil, err
	}
	locks, err := s.Locks.List()
	if err != nil {
		return nil, err
	}
	jobList := s.ListJobs(ctx, JobFilter{})
	pulls := make([]PullRequest, 0, len(statuses))
	for _, st := range statuses {
		pulls = append(pulls, s.buildPull(st, locks, jobList))
	}
	slices.SortStableFunc(pulls, func(a, b PullRequest) int {
		if c := b.LastActivity.Compare(a.LastActivity); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Repo.FullName, b.Repo.FullName); c != 0 {
			return c
		}
		return cmp.Compare(b.Num, a.Num)
	})
	return pulls, nil
}

func (s *LegacyStore) GetPull(ctx context.Context, repoFullName string, num int) (*PullRequest, error) {
	pulls, err := s.ListPulls(ctx)
	if err != nil {
		return nil, err
	}
	for i := range pulls {
		if pulls[i].Repo.FullName == repoFullName && pulls[i].Num == num {
			return &pulls[i], nil
		}
	}
	return nil, nil
}

func (s *LegacyStore) buildPull(st models.PullStatus, locks map[string]models.ProjectLock, jobList []Job) PullRequest {
	pr := PullRequest{
		Repo:       Repository{VCSHost: st.Pull.BaseRepo.VCSHost.Hostname, FullName: st.Pull.BaseRepo.FullName},
		Num:        st.Pull.Num,
		URL:        st.Pull.URL,
		Author:     st.Pull.Author,
		HeadBranch: st.Pull.HeadBranch,
		BaseBranch: st.Pull.BaseBranch,
		HeadCommit: st.Pull.HeadCommit,
	}
	for _, l := range locks {
		if l.Pull.BaseRepo.FullName == pr.Repo.FullName && l.Pull.Num == pr.Num && l.Time.After(pr.LastActivity) {
			pr.LastActivity = l.Time
		}
	}
	for _, ps := range st.Projects {
		p := Project{
			Dir:       ps.RepoRelDir,
			Workspace: ps.Workspace,
			Name:      ps.ProjectName,
			State:     stateFor(ps.Status),
		}
		for id, l := range locks {
			if l.Pull.BaseRepo.FullName == pr.Repo.FullName && l.Pull.Num == pr.Num &&
				l.Project.Path == ps.RepoRelDir && l.Workspace == ps.Workspace && l.Project.ProjectName == ps.ProjectName {
				p.LockID = id
			}
		}
		var latestPlan *Job
		for i := range jobList {
			j := &jobList[i]
			if j.Repo.FullName != pr.Repo.FullName || j.PullNum != pr.Num || j.Dir != ps.RepoRelDir ||
				j.Workspace != ps.Workspace || j.ProjectName != ps.ProjectName {
				continue
			}
			if j.LastOutput.After(pr.LastActivity) {
				pr.LastActivity = j.LastOutput
			}
			if p.LatestJobID == "" {
				p.LatestJobID = j.ID // jobList is newest first
			}
			if !j.Done {
				p.State = StateRunning
			}
			if latestPlan == nil && j.Done && j.Step == command.Plan.String() {
				latestPlan = j
			}
		}
		if latestPlan != nil {
			p.Changes = s.planChanges(latestPlan.ID)
		}
		pr.Projects = append(pr.Projects, p)
	}
	slices.SortStableFunc(pr.Projects, func(a, b Project) int {
		if c := cmp.Compare(a.Dir, b.Dir); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Workspace, b.Workspace); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return pr
}

// planChanges reads the change counts from a finished plan job's output.
func (s *LegacyStore) planChanges(jobID string) Changes {
	r, ok := s.Jobs.(outputBufferReader)
	if !ok {
		return Changes{}
	}
	out := strings.Join(r.GetProjectOutputBuffer(jobID).Buffer, "\n")
	stats := models.NewPlanSuccessStats(out)
	if !stats.Changes && !strings.Contains(out, "No changes.") {
		return Changes{}
	}
	return Changes{
		Known:   true,
		Import:  stats.Import,
		Add:     stats.Add,
		Change:  stats.Change,
		Destroy: stats.Destroy,
		Forget:  stats.Forget,
	}
}

func stateFor(s models.ProjectPlanStatus) ProjectState {
	switch s {
	case models.PlannedPlanStatus:
		return StatePlanned
	case models.PlannedNoChangesPlanStatus:
		return StateNoChanges
	case models.AppliedPlanStatus:
		return StateApplied
	case models.ErroredApplyStatus:
		return StateApplyFailed
	case models.DiscardedPlanStatus:
		return StateDiscarded
	case models.ErroredPolicyCheckStatus:
		return StatePolicyFailed
	case models.PassedPolicyCheckStatus:
		return StatePolicyPassed
	default:
		return StatePlanFailed
	}
}

func (s *LegacyStore) ListLocks(_ context.Context) ([]Lock, error) {
	locks, err := s.Locks.List()
	if err != nil {
		return nil, err
	}
	statuses, err := s.DB.ListPullStatuses()
	if err != nil {
		return nil, err
	}
	tracked := map[string]bool{}
	for _, st := range statuses {
		tracked[pullKey(st.Pull.BaseRepo.FullName, st.Pull.Num)] = true
	}
	out := make([]Lock, 0, len(locks))
	for id, l := range locks {
		out = append(out, Lock{
			ID:          id,
			Repo:        Repository{VCSHost: l.Pull.BaseRepo.VCSHost.Hostname, FullName: l.Project.RepoFullName},
			Dir:         l.Project.Path,
			Workspace:   l.Workspace,
			ProjectName: l.Project.ProjectName,
			PullNum:     l.Pull.Num,
			PullURL:     l.Pull.URL,
			PullAuthor:  l.Pull.Author,
			User:        l.User.Username,
			Since:       l.Time,
			PullTracked: tracked[pullKey(l.Project.RepoFullName, l.Pull.Num)],
		})
	}
	slices.SortStableFunc(out, func(a, b Lock) int {
		if c := b.Since.Compare(a.Since); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}

func pullKey(repo string, num int) string {
	return repo + "#" + strconv.Itoa(num)
}

func (s *LegacyStore) ApplyLock(_ context.Context) (ApplyLock, error) {
	l, err := s.ApplyLocks.CheckApplyLock()
	if err != nil {
		return ApplyLock{}, err
	}
	return ApplyLock{Locked: l.Locked, Enabled: l.GlobalApplyLockEnabled, Since: l.Time}, nil
}

func (s *LegacyStore) ListJobs(_ context.Context, f JobFilter) []Job {
	reader, _ := s.Jobs.(outputBufferReader)
	var out []Job
	for _, m := range s.Jobs.GetPullToJobMapping() {
		if f.RepoFullName != "" && m.Pull.RepoFullName != f.RepoFullName {
			continue
		}
		if f.PullNum != 0 && m.Pull.PullNum != f.PullNum {
			continue
		}
		for _, info := range m.JobIDInfos {
			j := Job{
				ID:          info.JobID,
				Repo:        Repository{FullName: m.Pull.RepoFullName},
				PullNum:     m.Pull.PullNum,
				Dir:         m.Pull.Path,
				Workspace:   m.Pull.Workspace,
				ProjectName: m.Pull.ProjectName,
				Step:        info.JobStep,
				Description: info.JobDescription,
				LastOutput:  info.Time,
			}
			if reader != nil {
				buf := reader.GetProjectOutputBuffer(info.JobID)
				j.Done = buf.OperationComplete
				j.Lines = len(buf.Buffer)
			}
			if f.RunningOnly && j.Done {
				continue
			}
			out = append(out, j)
		}
	}
	slices.SortStableFunc(out, func(a, b Job) int {
		if c := b.LastOutput.Compare(a.LastOutput); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out
}

func (s *LegacyStore) GetJob(ctx context.Context, id string) (Job, bool) {
	for _, j := range s.ListJobs(ctx, JobFilter{}) {
		if j.ID == id {
			return j, true
		}
	}
	return Job{}, false
}

// SubscribeJobLog registers with the output handler, which first replays the
// buffered lines and then forwards new ones. Register blocks while it
// replays, so it runs in its own goroutine. When the caller cancels before
// the job ends, the channel keeps draining until registration finishes and is
// then deregistered, so the handler never blocks on a reader that left.
func (s *LegacyStore) SubscribeJobLog(id string) (<-chan string, func()) {
	in := make(chan string, 512)
	out := make(chan string, 512)
	registered := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		s.Jobs.Register(id, in)
		close(registered)
	}()
	go func() {
		defer close(out)
		for {
			select {
			case line, ok := <-in:
				if !ok {
					return
				}
				select {
				case out <- line:
				case <-stop:
					s.drain(id, in, registered)
					return
				}
			case <-stop:
				s.drain(id, in, registered)
				return
			}
		}
	}()
	var once sync.Once
	return out, func() { once.Do(func() { close(stop) }) }
}

func (s *LegacyStore) drain(id string, in chan string, registered <-chan struct{}) {
	for {
		select {
		case <-registered:
			s.Jobs.Deregister(id, in)
			return
		case _, ok := <-in:
			if !ok {
				return
			}
		}
	}
}

// LegacyActions performs UI actions with the existing lock controller and
// apply locker.
type LegacyActions struct {
	Discarder interface {
		DiscardLock(id string, actor string) (*models.ProjectLock, error)
	}
	ApplyLocker locking.ApplyLocker
}

var _ Actions = (*LegacyActions)(nil)

func (a *LegacyActions) DiscardLock(id string, actor string) (bool, error) {
	l, err := a.Discarder.DiscardLock(id, actor)
	return l != nil, err
}

func (a *LegacyActions) LockApplies() error {
	_, err := a.ApplyLocker.LockApply()
	return err
}

func (a *LegacyActions) UnlockApplies() error {
	return a.ApplyLocker.UnlockApply()
}
