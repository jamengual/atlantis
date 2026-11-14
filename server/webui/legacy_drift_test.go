// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/core/drift"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

func TestLegacyDrift_Off(t *testing.T) {
	report, err := (&webui.LegacyStore{}).ListDrift(context.Background())
	Ok(t, err)
	Equals(t, webui.DriftReport{}, report)
}

// The UI reads the drift API's in-memory results, keyed by repository ID.
func TestLegacyDrift_ReadsDriftStorage(t *testing.T) {
	storage := drift.NewInMemoryStorage()
	checked := now.Add(-time.Hour)
	Ok(t, storage.Store("github.com/acme/infra", models.ProjectDrift{
		ProjectName: "net", Path: "network", Workspace: "default", Ref: "main", ResolvedCommit: "abc123", DetectionID: "d-1",
		Drift:      models.DriftSummary{HasDrift: true, ToAdd: 1, ToChange: 2, ToDestroy: 3, ToImport: 4, ToForget: 5, Summary: "Plan: ...", ChangesOutside: true},
		PlanOutput: "secret plan text", LastChecked: checked,
	}))
	Ok(t, storage.Store("github.com/acme/infra", models.ProjectDrift{Path: "dns", Workspace: "default", Ref: "main", LastChecked: checked}))
	Ok(t, storage.Store("gitlab.com/group/sub/app", models.ProjectDrift{Path: "app", Workspace: "default", Ref: "v1.0.0", BaseBranch: "main",
		Error: "running plan: exit status 1", LastChecked: checked}))
	// A policy check failure after a plan that found drift keeps the counts.
	Ok(t, storage.Store("github.com/acme/infra", models.ProjectDrift{Path: "edge", Workspace: "prod", Ref: "main",
		Drift: models.DriftSummary{HasDrift: true, ToAdd: 1}, Error: "policy_check failed: deny", LastChecked: checked}))

	report, err := (&webui.LegacyStore{Drift: storage}).ListDrift(context.Background())
	Ok(t, err)
	Assert(t, report.Enabled, "drift should be enabled")
	Equals(t, []webui.DriftCheck{
		{Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Dir: "edge", Workspace: "prod", Ref: "main", Drifted: true,
			Changes: webui.Changes{Known: true, Add: 1}, Error: "policy_check failed: deny", CheckedAt: checked},
		{Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, ProjectName: "net", Dir: "network", Workspace: "default", Ref: "main",
			Commit: "abc123", DetectionID: "d-1", Drifted: true, ChangesOutside: true, Summary: "Plan: ...",
			Changes: webui.Changes{Known: true, Add: 1, Change: 2, Destroy: 3, Import: 4, Forget: 5}, CheckedAt: checked},
		{Repo: webui.Repository{VCSHost: "gitlab.com", FullName: "group/sub/app"}, Dir: "app", Workspace: "default", Ref: "v1.0.0", BaseBranch: "main",
			Error: "running plan: exit status 1", CheckedAt: checked},
		{Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Dir: "dns", Workspace: "default", Ref: "main",
			Changes: webui.Changes{Known: true}, CheckedAt: checked},
	}, report.Checks)
	Equals(t, webui.DriftFailed, report.Checks[2].Status())
	Equals(t, webui.DriftInSync, report.Checks[3].Status())
}

type failingDrift struct{}

func (failingDrift) GetAll() (map[string][]models.ProjectDrift, error) {
	return nil, errors.New("boom")
}

func TestLegacyDrift_Error(t *testing.T) {
	report, err := (&webui.LegacyStore{Drift: failingDrift{}}).ListDrift(context.Background())
	ErrContains(t, "reading drift results: boom", err)
	Assert(t, report.Enabled, "drift should be reported as enabled")
}
