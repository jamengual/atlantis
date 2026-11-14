// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/runatlantis/atlantis/server/events/models"
)

// DriftSource is the drift detection API's result storage, keyed by
// repository ID such as github.com/acme/infra.
type DriftSource interface {
	GetAll() (map[string][]models.ProjectDrift, error)
}

// ListDrift reads the drift detection results this replica holds. The drift
// API keeps them in memory, so they cover the detections this replica ran
// since it started.
func (s *LegacyStore) ListDrift(_ context.Context) (DriftReport, error) {
	if s.Drift == nil {
		return DriftReport{}, nil
	}
	all, err := s.Drift.GetAll()
	if err != nil {
		return DriftReport{Enabled: true}, fmt.Errorf("reading drift results: %w", err)
	}
	report := DriftReport{Enabled: true}
	for id, projects := range all {
		repo := repoFromID(id)
		for _, p := range projects {
			report.Checks = append(report.Checks, driftCheck(repo, p))
		}
	}
	sortDrift(report.Checks)
	return report, nil
}

// repoFromID splits a repository ID such as github.com/acme/infra into host
// and full name.
func repoFromID(id string) Repository {
	host, name, ok := strings.Cut(id, "/")
	if !ok {
		return Repository{FullName: id}
	}
	return Repository{VCSHost: host, FullName: name}
}

func driftCheck(repo Repository, p models.ProjectDrift) DriftCheck {
	c := DriftCheck{
		Repo:           repo,
		ProjectName:    p.ProjectName,
		Dir:            p.Path,
		Workspace:      p.Workspace,
		Ref:            p.Ref,
		BaseBranch:     p.BaseBranch,
		Commit:         p.ResolvedCommit,
		DetectionID:    p.DetectionID,
		Drifted:        p.Drift.HasDrift,
		ChangesOutside: p.Drift.ChangesOutside,
		Summary:        p.Drift.Summary,
		Error:          p.Error,
		CheckedAt:      p.LastChecked,
	}
	// A check that failed without finding drift has no plan to count.
	if p.Error == "" || p.Drift.HasDrift {
		c.Changes = Changes{
			Known:   true,
			Import:  p.Drift.ToImport,
			Add:     p.Drift.ToAdd,
			Change:  p.Drift.ToChange,
			Destroy: p.Drift.ToDestroy,
			Forget:  p.Drift.ToForget,
		}
	}
	return c
}

var driftOrder = map[DriftStatus]int{DriftDrifted: 0, DriftFailed: 1, DriftInSync: 2}

// sortDrift puts drifted projects first, then failed checks, then projects
// in sync, each by repository, directory, workspace, project and ref.
func sortDrift(checks []DriftCheck) {
	slices.SortStableFunc(checks, func(a, b DriftCheck) int {
		return cmp.Or(
			cmp.Compare(driftOrder[a.Status()], driftOrder[b.Status()]),
			cmp.Compare(a.Repo.FullName, b.Repo.FullName),
			cmp.Compare(a.Repo.VCSHost, b.Repo.VCSHost),
			cmp.Compare(a.Dir, b.Dir),
			cmp.Compare(a.Workspace, b.Workspace),
			cmp.Compare(a.ProjectName, b.ProjectName),
			cmp.Compare(a.Ref, b.Ref),
			cmp.Compare(a.BaseBranch, b.BaseBranch),
		)
	})
}
