// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/runatlantis/atlantis/server/core/runtime"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/utils"
)

// WorkingDirFinder finds a pull request's clone on this replica.
type WorkingDirFinder interface {
	// GetWorkingDir returns an error wrapping fs.ErrNotExist when the clone
	// is not on this replica.
	GetWorkingDir(r models.Repo, p models.PullRequest, workspace string) (string, error)
}

// MaxPlanJSONBytes is the largest plan JSON the UI reads.
const MaxPlanJSONBytes = 64 << 20

// planFile is a project's plan JSON, the showfile that Atlantis's show step
// writes next to the project.
type planFile struct {
	status PlanStatus
	path   string
	info   fs.FileInfo
}

// locatePlan finds the showfile for a project and checks it belongs to the
// current saved plan. The showfile is only trusted when it is a regular file
// written after the plan file, which rules out a file of the same name that
// was committed to the repository, and when it resolves inside the clone.
func (s *LegacyStore) locatePlan(st models.PullStatus, ps models.ProjectStatus) (planFile, error) {
	if s.WorkingDir == nil {
		return planFile{status: PlanNoSavedPlan}, nil
	}
	wd, err := s.WorkingDir.GetWorkingDir(st.Pull.BaseRepo, st.Pull, ps.Workspace)
	if errors.Is(err, fs.ErrNotExist) {
		return planFile{status: PlanNoSavedPlan}, nil
	}
	if err != nil {
		return planFile{}, err
	}
	projDir := filepath.Join(wd, ps.RepoRelDir)
	if utils.EnsureSubPath(wd, projDir) != nil {
		return planFile{status: PlanUnreadable}, nil
	}
	pctx := command.ProjectContext{
		BaseRepo:          st.Pull.BaseRepo,
		Pull:              st.Pull,
		RepoRelDir:        ps.RepoRelDir,
		Workspace:         ps.Workspace,
		ProjectName:       ps.ProjectName,
		LocalSharePlanDir: s.SharePlanDir,
	}
	planInfo, err := os.Lstat(runtime.GetPlanFilePath(pctx, projDir))
	if err != nil || !planInfo.Mode().IsRegular() {
		return planFile{status: PlanNoSavedPlan}, nil
	}
	path := filepath.Join(projDir, pctx.GetShowResultFileName())
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return planFile{status: PlanNoJSON}, nil
	}
	if err != nil || !info.Mode().IsRegular() || utils.EnsureSubPathResolved(wd, path) != nil {
		return planFile{status: PlanUnreadable}, nil
	}
	if info.ModTime().Before(planInfo.ModTime()) || ps.Status == models.ErroredPlanStatus {
		return planFile{status: PlanOutdated, info: info}, nil
	}
	if info.Size() > MaxPlanJSONBytes {
		return planFile{status: PlanTooLarge, info: info}, nil
	}
	return planFile{status: PlanReady, path: path, info: info}, nil
}

// open opens the showfile and checks it is still the file locatePlan saw.
func (f planFile) open() (io.ReadCloser, bool) {
	// #nosec G304 -- path is inside the clone directory and was checked by locatePlan.
	fh, err := os.Open(f.path)
	if err != nil {
		return nil, false
	}
	info, err := fh.Stat()
	if err != nil || !os.SameFile(info, f.info) {
		_ = fh.Close()
		return nil, false
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(fh, MaxPlanJSONBytes), fh}, true
}

func (s *LegacyStore) findProject(repo Repository, num int, ref ProjectRef) (*models.PullStatus, *models.ProjectStatus, error) {
	statuses, err := s.DB.ListPullStatuses()
	if err != nil {
		return nil, nil, err
	}
	for i := range statuses {
		st := &statuses[i]
		if st.Pull.BaseRepo.FullName != repo.FullName || st.Pull.Num != num || !sameHost(repo.VCSHost, st.Pull.BaseRepo.VCSHost.Hostname) {
			continue
		}
		for j := range st.Projects {
			ps := &st.Projects[j]
			if ps.RepoRelDir == ref.Dir && ps.Workspace == ref.Workspace && ps.ProjectName == ref.Name {
				return st, ps, nil
			}
		}
	}
	return nil, nil, nil
}

func (s *LegacyStore) GetPlan(_ context.Context, repo Repository, num int, ref ProjectRef) (*ProjectPlan, error) {
	st, ps, err := s.findProject(repo, num, ref)
	if err != nil || st == nil {
		return nil, err
	}
	f, err := s.locatePlan(*st, *ps)
	if err != nil {
		return nil, err
	}
	out := &ProjectPlan{Status: f.status}
	if f.info != nil {
		out.GeneratedAt = f.info.ModTime()
		out.Size = f.info.Size()
	}
	if f.status != PlanReady {
		return out, nil
	}
	r, ok := f.open()
	if !ok {
		out.Status = PlanUnreadable
		return out, nil
	}
	defer r.Close()
	plan, err := ParsePlanJSON(r, s.planLimits())
	if err != nil {
		out.Status = PlanUnreadable
		return out, nil
	}
	out.Plan = plan
	return out, nil
}

func (s *LegacyStore) planLimits() PlanLimits {
	if s.PlanLimits != (PlanLimits{}) {
		return s.PlanLimits
	}
	return DefaultPlanLimits
}

type cachedCounts struct {
	modTime time.Time
	size    int64
	changes Changes
}

// jsonChanges counts a project's changes from its plan JSON, for when the
// plan output is no longer in memory. Results are cached per file version.
func (s *LegacyStore) jsonChanges(st models.PullStatus, ps models.ProjectStatus) Changes {
	f, err := s.locatePlan(st, ps)
	if err != nil || f.status != PlanReady {
		return Changes{}
	}
	if c, ok := s.countsCache.Load(f.path); ok {
		cc := c.(cachedCounts)
		if cc.modTime.Equal(f.info.ModTime()) && cc.size == f.info.Size() {
			return cc.changes
		}
	}
	r, ok := f.open()
	if !ok {
		return Changes{}
	}
	defer r.Close()
	c, err := CountPlanChanges(r)
	if err != nil {
		return Changes{}
	}
	s.countsCache.Store(f.path, cachedCounts{modTime: f.info.ModTime(), size: f.info.Size(), changes: c})
	return c
}
