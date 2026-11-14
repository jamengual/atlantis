// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/events"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

// planFixture is a store whose pull request 7 has a planned project in
// "network", with its clone under dataDir.
type planFixture struct {
	*fixture
	dataDir string
	projDir string
}

func newPlanFixture(t *testing.T) *planFixture {
	t.Helper()
	f := newFixture(t)
	dataDir := t.TempDir()
	f.store.WorkingDir = &events.FileWorkspace{DataDir: dataDir}
	f.plan(t, pull(7), "network", true)
	projDir := filepath.Join(dataDir, "repos", "acme", "infra", "7", "default", "network")
	Ok(t, os.MkdirAll(projDir, 0o700))
	return &planFixture{fixture: f, dataDir: dataDir, projDir: projDir}
}

var networkRef = webui.ProjectRef{Dir: "network", Workspace: "default"}

// write creates a file in the project dir with a modification time offset
// from now, so tests control which of plan and JSON is newer.
func (f *planFixture) write(t *testing.T, name string, content []byte, age time.Duration) string {
	t.Helper()
	path := filepath.Join(f.projDir, name)
	Ok(t, os.WriteFile(path, content, 0o600))
	when := time.Now().Add(-age)
	Ok(t, os.Chtimes(path, when, when))
	return path
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	Ok(t, err)
	return b
}

func (f *planFixture) getPlan(t *testing.T) *webui.ProjectPlan {
	t.Helper()
	p, err := f.store.GetPlan(context.Background(), webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, 7, networkRef)
	Ok(t, err)
	Assert(t, p != nil, "project should be found")
	return p
}

func TestLegacyStore_GetPlanReadsShowfile(t *testing.T) {
	f := newPlanFixture(t)
	f.write(t, "default.tfplan", []byte("plan"), time.Minute)
	f.write(t, "default.json", fixtureBytes(t, "plan_aws.json"), 0)

	p := f.getPlan(t)
	Equals(t, webui.PlanReady, p.Status)
	Equals(t, 10, p.Plan.TotalResources)
	Equals(t, webui.Changes{Known: true, Import: 2, Add: 3, Change: 2, Destroy: 3, Forget: 1}, p.Plan.Changes)
	Assert(t, time.Since(p.GeneratedAt) < time.Minute, "generated time comes from the file")

	// Without plan output in memory, the ledger falls back to the JSON.
	pulls, err := f.store.ListPulls(context.Background())
	Ok(t, err)
	Equals(t, p.Plan.Changes, pulls[0].Projects[0].Changes)
}

func TestLegacyStore_GetPlanUnavailable(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *planFixture)
		want  webui.PlanStatus
	}{
		{"no clone on this replica", func(t *testing.T, f *planFixture) { Ok(t, os.RemoveAll(f.dataDir)) }, webui.PlanNoSavedPlan},
		{"no plan file", func(t *testing.T, f *planFixture) {
			f.write(t, "default.json", fixtureBytes(t, "plan_aws.json"), 0)
		}, webui.PlanNoSavedPlan},
		{"no showfile", func(t *testing.T, f *planFixture) {
			f.write(t, "default.tfplan", []byte("plan"), 0)
		}, webui.PlanNoJSON},
		{"showfile older than the plan", func(t *testing.T, f *planFixture) {
			f.write(t, "default.json", fixtureBytes(t, "plan_aws.json"), time.Hour)
			f.write(t, "default.tfplan", []byte("plan"), 0)
		}, webui.PlanOutdated},
		{"showfile is not a plan", func(t *testing.T, f *planFixture) {
			f.write(t, "default.tfplan", []byte("plan"), time.Minute)
			f.write(t, "default.json", []byte(`{"password":"hunter2"}`), 0)
		}, webui.PlanUnreadable},
		{"showfile is a symlink", func(t *testing.T, f *planFixture) {
			f.write(t, "default.tfplan", []byte("plan"), time.Minute)
			target := filepath.Join(t.TempDir(), "secret.json")
			Ok(t, os.WriteFile(target, fixtureBytes(t, "plan_aws.json"), 0o600))
			Ok(t, os.Symlink(target, filepath.Join(f.projDir, "default.json")))
		}, webui.PlanUnreadable},
		{"showfile too large", func(t *testing.T, f *planFixture) {
			f.write(t, "default.tfplan", []byte("plan"), time.Minute)
			path := f.write(t, "default.json", nil, 0)
			Ok(t, os.Truncate(path, webui.MaxPlanJSONBytes+1))
		}, webui.PlanTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newPlanFixture(t)
			c.setup(t, f)
			p := f.getPlan(t)
			Equals(t, c.want, p.Status)
			Equals(t, 0, len(p.Plan.Resources))
			pulls, err := f.store.ListPulls(context.Background())
			Ok(t, err)
			Assert(t, !pulls[0].Projects[0].Changes.Known, "unavailable plans give no counts")
		})
	}
}

func TestLegacyStore_GetPlanProjectDirIsASymlinkOutsideTheClone(t *testing.T) {
	f := newPlanFixture(t)
	outside := t.TempDir()
	Ok(t, os.WriteFile(filepath.Join(outside, "default.tfplan"), []byte("plan"), 0o600))
	Ok(t, os.WriteFile(filepath.Join(outside, "default.json"), fixtureBytes(t, "plan_aws.json"), 0o600))
	Ok(t, os.RemoveAll(f.projDir))
	Ok(t, os.Symlink(outside, f.projDir))
	Equals(t, webui.PlanUnreadable, f.getPlan(t).Status)
}

func TestLegacyStore_GetPlanUnknownProject(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	repo := webui.Repository{FullName: "acme/infra"}
	for _, ref := range []webui.ProjectRef{
		{Dir: "../../../etc", Workspace: "default"},
		{Dir: "network", Workspace: "prod"},
		{Dir: "network", Workspace: "default", Name: "other"},
	} {
		p, err := f.store.GetPlan(ctx, repo, 7, ref)
		Ok(t, err)
		Assert(t, p == nil, "untracked project %v should be nil", ref)
	}
	p, err := f.store.GetPlan(ctx, repo, 8, networkRef)
	Ok(t, err)
	Assert(t, p == nil, "unknown pull should be nil")
	p, err = f.store.GetPlan(ctx, webui.Repository{VCSHost: "gitlab.com", FullName: "acme/infra"}, 7, networkRef)
	Ok(t, err)
	Assert(t, p == nil, "same repo name on another host should be nil")
}

func TestLegacyStore_GetPlanWithoutWorkingDir(t *testing.T) {
	f := newPlanFixture(t)
	f.store.WorkingDir = nil
	Equals(t, webui.PlanNoSavedPlan, f.getPlan(t).Status)
}

func TestLegacyStore_GetPlanWithSharedPlanDir(t *testing.T) {
	f := newPlanFixture(t)
	shared := t.TempDir()
	f.store.SharePlanDir = shared
	planDir := filepath.Join(shared, "repos", "acme", "infra", "7", "default", "network")
	Ok(t, os.MkdirAll(planDir, 0o700))
	Ok(t, os.WriteFile(filepath.Join(planDir, "default.tfplan"), []byte("plan"), 0o600))
	old := time.Now().Add(-time.Minute)
	Ok(t, os.Chtimes(filepath.Join(planDir, "default.tfplan"), old, old))
	f.write(t, "default.json", fixtureBytes(t, "plan_terraform_data.json"), 0)
	p := f.getPlan(t)
	Equals(t, webui.PlanReady, p.Status)
	Equals(t, 8, p.Plan.TotalResources)
}

func TestLegacyStore_PlanCountsCacheFollowsFileChanges(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	f.write(t, "default.tfplan", []byte("plan"), time.Hour)
	f.write(t, "default.json", fixtureBytes(t, "plan_aws.json"), 30*time.Minute)
	pulls, err := f.store.ListPulls(ctx)
	Ok(t, err)
	Equals(t, 3, pulls[0].Projects[0].Changes.Add)

	f.write(t, "default.json", fixtureBytes(t, "plan_terraform_data.json"), 0)
	pulls, err = f.store.ListPulls(ctx)
	Ok(t, err)
	Equals(t, 2, pulls[0].Projects[0].Changes.Add)
	Equals(t, 3, pulls[0].Projects[0].Changes.Change)
}
