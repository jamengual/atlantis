// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/core/boltdb"
	"github.com/runatlantis/atlantis/server/core/locking"
	"github.com/runatlantis/atlantis/server/events"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/jobs"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

type fixture struct {
	db      *boltdb.BoltDB
	locker  *locking.Client
	handler jobs.ProjectCommandOutputHandler
	store   *webui.LegacyStore
}

var testRepo = models.Repo{
	FullName: "acme/infra",
	Owner:    "acme",
	Name:     "infra",
	VCSHost:  models.VCSHost{Hostname: "github.com", Type: models.Github},
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := boltdb.New(t.TempDir())
	Ok(t, err)
	t.Cleanup(func() { _ = db.Close() })
	logger := logging.NewNoopLogger(t)
	ch := make(chan *jobs.ProjectCmdOutputLine)
	handler := jobs.NewAsyncProjectCommandOutputHandler(ch, logger)
	go handler.Handle()
	t.Cleanup(func() { close(ch) })
	locker := locking.NewClient(db)
	return &fixture{
		db:      db,
		locker:  locker,
		handler: handler,
		store: &webui.LegacyStore{
			Locks:          locker,
			DB:             db,
			ApplyLocks:     locking.NewApplyClient(db, false, false),
			Jobs:           handler,
			Drainer:        &events.Drainer{},
			Version:        "1.2.3",
			LockingBackend: "boltdb",
		},
	}
}

func pull(num int) models.PullRequest {
	return models.PullRequest{
		Num:        num,
		URL:        "https://github.com/acme/infra/pull/1",
		Author:     "mrivera",
		HeadBranch: "feature",
		BaseBranch: "main",
		HeadCommit: "abc123",
		State:      models.OpenPullState,
		BaseRepo:   testRepo,
	}
}

func (f *fixture) plan(t *testing.T, p models.PullRequest, dir string, success bool) {
	t.Helper()
	out := command.ProjectCommandOutput{Failure: "boom"}
	if success {
		out = command.ProjectCommandOutput{PlanSuccess: &models.PlanSuccess{TerraformOutput: "Plan: 1 to add, 0 to change, 0 to destroy."}}
	}
	_, err := f.db.UpdatePullWithResults(p, []command.ProjectResult{{
		Command: command.Plan, RepoRelDir: dir, Workspace: "default", ProjectCommandOutput: out,
	}})
	Ok(t, err)
}

func (f *fixture) job(t *testing.T, jobID string, p models.PullRequest, dir string, lines []string, done bool) {
	t.Helper()
	ctx := command.ProjectContext{
		JobID:       jobID,
		Pull:        p,
		BaseRepo:    p.BaseRepo,
		RepoRelDir:  dir,
		Workspace:   "default",
		CommandName: command.Plan,
	}
	for _, l := range lines {
		f.handler.Send(ctx, l, false)
	}
	if done {
		f.handler.Send(ctx, "", true)
	}
	waitFor(t, func() bool {
		j, ok := f.store.GetJob(context.Background(), jobID)
		return ok && j.Lines == len(lines) && j.Done == done
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLegacyStore_ListPullsBuildsProjects(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := pull(1)
	f.plan(t, p, "network", true)
	f.plan(t, p, "edge", false)
	_, err := f.locker.TryLock(models.NewProject("acme/infra", "network", ""), "default", p, models.User{Username: "mrivera"})
	Ok(t, err)
	f.job(t, "job-1", p, "network", []string{"Refreshing state...", "Plan: 2 to add, 1 to change, 0 to destroy."}, true)

	pulls, err := f.store.ListPulls(ctx)
	Ok(t, err)
	Equals(t, 1, len(pulls))
	pr := pulls[0]
	Equals(t, "acme/infra", pr.Repo.FullName)
	Equals(t, "github.com", pr.Repo.VCSHost)
	Equals(t, 2, len(pr.Projects))

	// Projects are sorted by directory.
	edge, network := pr.Projects[0], pr.Projects[1]
	Equals(t, "edge", edge.Dir)
	Equals(t, webui.StatePlanFailed, edge.State)
	Equals(t, false, edge.Changes.Known)
	Equals(t, "", edge.LockID)

	Equals(t, webui.StatePlanned, network.State)
	Equals(t, "job-1", network.LatestJobID)
	Assert(t, network.LockID != "", "network should be locked")
	Equals(t, webui.Changes{Known: true, Add: 2, Change: 1}, network.Changes)
	Equals(t, webui.Changes{Known: true, Add: 2, Change: 1}, pr.Changes())
	Assert(t, !pr.LastActivity.IsZero(), "last activity should come from the lock or job")

	got, err := f.store.GetPull(ctx, webui.Repository{FullName: "acme/infra"}, 1)
	Ok(t, err)
	Equals(t, 1, got.Num)
	missing, err := f.store.GetPull(ctx, webui.Repository{FullName: "acme/infra"}, 99)
	Ok(t, err)
	Assert(t, missing == nil, "unknown pull should be nil")
}

func TestLegacyStore_RunningJobMarksProjectRunning(t *testing.T) {
	f := newFixture(t)
	p := pull(2)
	f.plan(t, p, "network", true)
	f.job(t, "job-run", p, "network", []string{"Initializing..."}, false)

	pr, err := f.store.GetPull(context.Background(), webui.Repository{FullName: "acme/infra"}, 2)
	Ok(t, err)
	Equals(t, webui.StateRunning, pr.Projects[0].State)

	running := f.store.ListJobs(context.Background(), webui.JobFilter{RunningOnly: true})
	Equals(t, 1, len(running))
	Equals(t, "job-run", running[0].ID)
	Equals(t, "plan", running[0].Step)
}

func TestLegacyStore_ListLocksFlagsUntrackedPulls(t *testing.T) {
	f := newFixture(t)
	tracked, closed := pull(3), pull(4)
	f.plan(t, tracked, "a", true)
	_, err := f.locker.TryLock(models.NewProject("acme/infra", "a", ""), "default", tracked, models.User{Username: "u1"})
	Ok(t, err)
	_, err = f.locker.TryLock(models.NewProject("acme/infra", "b", ""), "default", closed, models.User{Username: "u2"})
	Ok(t, err)

	locks, err := f.store.ListLocks(context.Background())
	Ok(t, err)
	Equals(t, 2, len(locks))
	byDir := map[string]webui.Lock{}
	for _, l := range locks {
		byDir[l.Dir] = l
	}
	Equals(t, true, byDir["a"].PullTracked)
	Equals(t, false, byDir["b"].PullTracked)
	Equals(t, "u2", byDir["b"].User)
	Assert(t, byDir["a"].ID != "", "lock id is the key used to discard it")
}

func TestLegacyStore_ApplyLockAndInstance(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	al, err := f.store.ApplyLock(ctx)
	Ok(t, err)
	Equals(t, false, al.Locked)

	_, err = locking.NewApplyClient(f.db, false, false).LockApply()
	Ok(t, err)
	al, err = f.store.ApplyLock(ctx)
	Ok(t, err)
	Equals(t, true, al.Locked)

	inst := f.store.Instance(ctx)
	Equals(t, "1.2.3", inst.Version)
	Equals(t, "boltdb", inst.LockingBackend)
	Equals(t, true, inst.DatabaseOK)
	Equals(t, webui.Capabilities{}, f.store.Capabilities())
}

type pingFailDB struct{ *boltdb.BoltDB }

func (pingFailDB) Ping() error { return errors.New("connection refused") }

func TestLegacyStore_InstanceReportsDatabaseError(t *testing.T) {
	f := newFixture(t)
	f.store.DB = pingFailDB{f.db}
	inst := f.store.Instance(context.Background())
	Equals(t, false, inst.DatabaseOK)
	Equals(t, "connection refused", inst.DatabaseError)
}

func collect(t *testing.T, lines <-chan webui.LogLine, n int) []webui.LogLine {
	t.Helper()
	var got []webui.LogLine
	timeout := time.After(2 * time.Second)
	for len(got) < n {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("log closed after %d of %d lines", len(got), n)
			}
			got = append(got, l)
		case <-timeout:
			t.Fatalf("got %d of %d lines before timeout", len(got), n)
		}
	}
	return got
}

func expectClosed(t *testing.T, lines <-chan webui.LogLine) {
	t.Helper()
	select {
	case l, ok := <-lines:
		if ok {
			t.Fatalf("expected the log to close, got line %d %q", l.N, l.Text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("log did not close")
	}
}

func projCtx(id string, p models.PullRequest) command.ProjectContext {
	return command.ProjectContext{JobID: id, Pull: p, BaseRepo: p.BaseRepo, RepoRelDir: "network", Workspace: "default", CommandName: command.Plan}
}

func TestLegacyStore_JobLogReplaysStreamsAndCloses(t *testing.T) {
	f := newFixture(t)
	f.store.PollInterval = 5 * time.Millisecond
	p := pull(5)
	f.job(t, "job-log", p, "network", []string{"one", "two"}, false)

	lines := f.store.JobLog(context.Background(), "job-log", 0)
	Equals(t, []webui.LogLine{{N: 1, Text: "one"}, {N: 2, Text: "two"}}, collect(t, lines, 2))

	f.handler.Send(projCtx("job-log", p), "three", false)
	Equals(t, []webui.LogLine{{N: 3, Text: "three"}}, collect(t, lines, 1))
	f.handler.Send(projCtx("job-log", p), "", true)
	expectClosed(t, lines)
}

func TestLegacyStore_JobLogResumesAtExactLine(t *testing.T) {
	f := newFixture(t)
	f.store.PollInterval = 5 * time.Millisecond
	f.job(t, "job-resume", pull(6), "network", []string{"a", "b", "c", "d"}, true)

	lines := f.store.JobLog(context.Background(), "job-resume", 2)
	Equals(t, []webui.LogLine{{N: 3, Text: "c"}, {N: 4, Text: "d"}}, collect(t, lines, 2))
	expectClosed(t, lines)
}

func TestLegacyStore_JobLogSlowReaderMissesNothing(t *testing.T) {
	f := newFixture(t)
	f.store.PollInterval = 5 * time.Millisecond
	p := pull(7)
	f.job(t, "job-slow", p, "network", []string{"start"}, false)

	lines := f.store.JobLog(context.Background(), "job-slow", 0)
	// Produce far more output than any channel buffer while nobody reads.
	const extra = 3000
	for i := range extra {
		f.handler.Send(projCtx("job-slow", p), fmt.Sprintf("line %d", i), false)
	}
	f.handler.Send(projCtx("job-slow", p), "", true)

	got := collect(t, lines, extra+1)
	for i, l := range got {
		Equals(t, i+1, l.N)
	}
	Equals(t, "line 2999", got[len(got)-1].Text)
	expectClosed(t, lines)
}

func TestLegacyStore_JobLogFinishedJobCloses(t *testing.T) {
	f := newFixture(t)
	f.store.PollInterval = 5 * time.Millisecond
	f.job(t, "job-done", pull(8), "network", []string{"x"}, true)
	lines := f.store.JobLog(context.Background(), "job-done", 0)
	collect(t, lines, 1)
	expectClosed(t, lines)
}

func TestLegacyStore_JobLogStopsWhenReaderLeaves(t *testing.T) {
	f := newFixture(t)
	f.store.PollInterval = 5 * time.Millisecond
	f.job(t, "job-leave", pull(9), "network", []string{"x"}, false)
	ctx, cancel := context.WithCancel(context.Background())
	lines := f.store.JobLog(ctx, "job-leave", 0)
	collect(t, lines, 1)
	cancel()
	expectClosed(t, lines)
}

func TestLegacyStore_JobLogClosesWhenOutputCleanedUp(t *testing.T) {
	f := newFixture(t)
	f.store.PollInterval = 5 * time.Millisecond
	p := pull(10)
	f.job(t, "job-clean", p, "network", []string{"x"}, false)
	lines := f.store.JobLog(context.Background(), "job-clean", 0)
	collect(t, lines, 1)
	f.handler.CleanUp(jobs.PullInfo{PullNum: p.Num, Repo: p.BaseRepo.Name, RepoFullName: p.BaseRepo.FullName, Path: "network", Workspace: "default"})
	expectClosed(t, lines)
}

func TestLegacyStore_JobLogUnknownJobCloses(t *testing.T) {
	f := newFixture(t)
	expectClosed(t, f.store.JobLog(context.Background(), "nope", 0))
}

func TestLegacyStore_SameRepoNameOnTwoHostsStaysSeparate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	gh := pull(11)
	gl := pull(11)
	gl.BaseRepo.VCSHost = models.VCSHost{Hostname: "gitlab.com", Type: models.Gitlab}
	f.plan(t, gh, "network", true)
	f.plan(t, gl, "network", true)
	_, err := f.locker.TryLock(models.NewProject("acme/infra", "network", ""), "default", gl, models.User{Username: "gl-user"})
	Ok(t, err)

	ghPull, err := f.store.GetPull(ctx, webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, 11)
	Ok(t, err)
	glPull, err := f.store.GetPull(ctx, webui.Repository{VCSHost: "gitlab.com", FullName: "acme/infra"}, 11)
	Ok(t, err)
	Equals(t, "github.com", ghPull.Repo.VCSHost)
	Equals(t, "gitlab.com", glPull.Repo.VCSHost)
	Equals(t, "", ghPull.Projects[0].LockID)
	Assert(t, glPull.Projects[0].LockID != "", "the GitLab pull request holds the lock")

	locks, err := f.store.ListLocks(ctx)
	Ok(t, err)
	Equals(t, "gitlab.com", locks[0].Repo.VCSHost)
	Equals(t, true, locks[0].PullTracked)
}

func TestLegacyStore_LockWithoutBaseRepoStillMatches(t *testing.T) {
	f := newFixture(t)
	p := pull(12)
	f.plan(t, p, "network", true)
	// Locks written by older versions have no Pull.BaseRepo.
	old := models.PullRequest{Num: 12}
	_, err := f.locker.TryLock(models.NewProject("acme/infra", "network", ""), "default", old, models.User{Username: "u"})
	Ok(t, err)

	pr, err := f.store.GetPull(context.Background(), webui.Repository{FullName: "acme/infra"}, 12)
	Ok(t, err)
	Assert(t, pr.Projects[0].LockID != "", "old lock should match by project repo")
	locks, err := f.store.ListLocks(context.Background())
	Ok(t, err)
	Equals(t, "acme/infra", locks[0].Repo.FullName)
	Equals(t, true, locks[0].PullTracked)
}

func TestLegacyStore_StalledJobIsNotRunning(t *testing.T) {
	f := newFixture(t)
	p := pull(13)
	f.plan(t, p, "network", true)
	f.job(t, "job-stuck", p, "network", []string{"Initializing..."}, false)
	f.store.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }

	pr, err := f.store.GetPull(context.Background(), webui.Repository{FullName: "acme/infra"}, 13)
	Ok(t, err)
	Equals(t, webui.StatePlanned, pr.Projects[0].State)
	j, ok := f.store.GetJob(context.Background(), "job-stuck")
	Equals(t, true, ok)
	Equals(t, true, j.Stalled)
	Equals(t, 0, len(f.store.ListJobs(context.Background(), webui.JobFilter{RunningOnly: true})))
}
