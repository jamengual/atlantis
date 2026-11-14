// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"context"
	"errors"
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

	got, err := f.store.GetPull(ctx, "acme/infra", 1)
	Ok(t, err)
	Equals(t, 1, got.Num)
	missing, err := f.store.GetPull(ctx, "acme/infra", 99)
	Ok(t, err)
	Assert(t, missing == nil, "unknown pull should be nil")
}

func TestLegacyStore_RunningJobMarksProjectRunning(t *testing.T) {
	f := newFixture(t)
	p := pull(2)
	f.plan(t, p, "network", true)
	f.job(t, "job-run", p, "network", []string{"Initializing..."}, false)

	pr, err := f.store.GetPull(context.Background(), "acme/infra", 2)
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

func TestLegacyStore_SubscribeJobLogReplaysThenStreams(t *testing.T) {
	f := newFixture(t)
	p := pull(5)
	f.job(t, "job-log", p, "network", []string{"one", "two"}, false)

	lines, cancel := f.store.SubscribeJobLog("job-log")
	defer cancel()
	Equals(t, "one", <-lines)
	Equals(t, "two", <-lines)

	ctx := command.ProjectContext{JobID: "job-log", Pull: p, BaseRepo: p.BaseRepo, RepoRelDir: "network", Workspace: "default", CommandName: command.Plan}
	f.handler.Send(ctx, "three", false)
	Equals(t, "three", <-lines)
	f.handler.Send(ctx, "", true)
	_, open := <-lines
	Equals(t, false, open)
}

func TestLegacyStore_SubscribeJobLogCancelDoesNotBlockHandler(t *testing.T) {
	f := newFixture(t)
	p := pull(6)
	many := make([]string, 2000)
	for i := range many {
		many[i] = "line"
	}
	f.job(t, "job-big", p, "network", many, false)

	// Leave before reading the replay. The handler must keep accepting output.
	_, cancel := f.store.SubscribeJobLog("job-big")
	cancel()

	ctx := command.ProjectContext{JobID: "job-big", Pull: p, BaseRepo: p.BaseRepo, RepoRelDir: "network", Workspace: "default", CommandName: command.Plan}
	f.handler.Send(ctx, "after", false)
	waitFor(t, func() bool {
		j, ok := f.store.GetJob(context.Background(), "job-big")
		return ok && j.Lines == 2001
	})
}
