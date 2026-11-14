// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package locking

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
)

// MaxMaintenanceWindows bounds how many windows can be active at once.
const MaxMaintenanceWindows = 100

// MaxMaintenanceReason is the longest reason a window can have, in runes.
const MaxMaintenanceReason = 300

// MaintenanceWindow freezes applies, and optionally plans, in a repository
// or in one directory, workspace, or project of it. Empty Dir, Workspace,
// and Project match any value; an empty Host matches any VCS host.
type MaintenanceWindow struct {
	ID       string
	Host     string
	RepoName string
	Dir      string
	// Workspace and Project narrow the window further.
	Workspace string
	Project   string
	// Plans also freezes plans, including autoplans.
	Plans  bool
	Reason string
	By     string
	Since  time.Time
	// Until is when the window ends by itself. Zero means it lasts until
	// someone ends it.
	Until time.Time
}

// RepoWide reports whether the window covers the whole repository.
func (w MaintenanceWindow) RepoWide() bool {
	return w.Dir == "" && w.Workspace == "" && w.Project == ""
}

// Blocks reports whether the window rejects a command. Applies, imports,
// and state changes are always blocked; plans only when Plans is set.
func (w MaintenanceWindow) Blocks(cmd command.Name) bool {
	switch cmd {
	case command.Apply, command.Import, command.State:
		return true
	case command.Plan, command.Autoplan:
		return w.Plans
	}
	return false
}

// Covers reports whether the window applies to a project in a repository.
func (w MaintenanceWindow) Covers(host, repoName, dir, workspace, project string) bool {
	if w.Host != "" && host != "" && !strings.EqualFold(w.Host, host) {
		return false
	}
	if !strings.EqualFold(w.RepoName, repoName) {
		return false
	}
	if w.Dir != "" && w.Dir != CleanMaintenanceDir(dir) {
		return false
	}
	if w.Workspace != "" && w.Workspace != workspace {
		return false
	}
	return w.Project == "" || w.Project == project
}

// Scope describes what the window covers, in plain words.
func (w MaintenanceWindow) Scope() string {
	if w.RepoWide() {
		return "the whole repository"
	}
	var parts []string
	if w.Dir != "" {
		parts = append(parts, fmt.Sprintf("directory %s", w.Dir))
	}
	if w.Workspace != "" {
		parts = append(parts, fmt.Sprintf("workspace %s", w.Workspace))
	}
	if w.Project != "" {
		parts = append(parts, fmt.Sprintf("project %s", w.Project))
	}
	return strings.Join(parts, ", ")
}

const maintenanceTimeFormat = "2006-01-02 15:04 MST"

// Explain says why a command was rejected, for a pull request comment. The
// text is plain, so callers put it in a code block.
func (w MaintenanceWindow) Explain(cmd command.Name) string {
	what := "atlantis " + cmd.String()
	switch cmd {
	case command.Autoplan:
		what = "Autoplan"
	case command.State:
		what = "atlantis state rm"
	}
	ends := "Ends: when someone ends it in the Atlantis web UI"
	if !w.Until.IsZero() {
		ends = "Ends: " + w.Until.UTC().Format(maintenanceTimeFormat)
	}
	return fmt.Sprintf("%s is blocked by a maintenance window on %s.\nScope: %s\nReason: %s\nSet by: %s at %s\n%s",
		what, w.RepoName, w.Scope(), w.Reason, w.By, w.Since.UTC().Format(maintenanceTimeFormat), ends)
}

// Maintenance holds the active maintenance windows in memory. They are
// known only to this process and are lost when it restarts. A nil
// *Maintenance has no windows.
type Maintenance struct {
	// Now returns the current time. Tests replace it.
	Now func() time.Time

	mu      sync.Mutex
	windows []MaintenanceWindow
}

// NewMaintenance returns an empty set of maintenance windows.
func NewMaintenance() *Maintenance {
	return &Maintenance{}
}

func (m *Maintenance) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// ErrTooManyMaintenanceWindows is returned when MaxMaintenanceWindows are
// already active.
var ErrTooManyMaintenanceWindows = fmt.Errorf("%d maintenance windows are already active; end one first", MaxMaintenanceWindows)

// CleanMaintenanceDir normalizes a repo-relative directory. The repository
// root is ".".
func CleanMaintenanceDir(dir string) string {
	if d := strings.TrimPrefix(path.Clean("/"+strings.TrimSpace(dir)), "/"); d != "" {
		return d
	}
	return "."
}

// commentSafe keeps text on one line and out of code spans, so it can't
// break out of the code block a PR comment puts it in.
func commentSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '`':
			return '\''
		case unicode.IsControl(r):
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// Start validates and adds a window. ID and Since are set here.
func (m *Maintenance) Start(w MaintenanceWindow) (MaintenanceWindow, error) {
	if m == nil {
		return MaintenanceWindow{}, errors.New("maintenance windows are not enabled")
	}
	w.Host = strings.TrimSpace(w.Host)
	w.RepoName = strings.Trim(strings.TrimSpace(w.RepoName), "/")
	w.Workspace = strings.TrimSpace(w.Workspace)
	w.Project = strings.TrimSpace(w.Project)
	w.Reason = commentSafe(w.Reason)
	w.By = commentSafe(w.By)
	if dir := strings.TrimSpace(w.Dir); dir != "" {
		if strings.HasPrefix(dir, "/") || slices.Contains(strings.Split(dir, "/"), "..") {
			return MaintenanceWindow{}, errors.New("the directory must be relative to the repository root and can't contain a .. element")
		}
		w.Dir = CleanMaintenanceDir(dir)
	}
	switch {
	case w.RepoName == "" || !strings.Contains(w.RepoName, "/") || strings.ContainsFunc(w.RepoName, unicode.IsSpace) || len(w.RepoName) > 200:
		return MaintenanceWindow{}, errors.New("the repository must be a full name such as acme/infra")
	case strings.ContainsFunc(w.Host+w.Workspace+w.Project+w.Dir, unicode.IsControl) || strings.ContainsFunc(w.Workspace, unicode.IsSpace):
		return MaintenanceWindow{}, errors.New("the directory, workspace, and project can't contain control characters, and the workspace can't contain spaces")
	case len(w.Dir) > 500 || len(w.Workspace) > 200 || len(w.Project) > 200 || len(w.Host) > 200:
		return MaintenanceWindow{}, errors.New("the directory, workspace, or project is too long")
	case w.Reason == "":
		return MaintenanceWindow{}, errors.New("a reason is required, so people know why their commands are blocked")
	case len([]rune(w.Reason)) > MaxMaintenanceReason:
		return MaintenanceWindow{}, fmt.Errorf("the reason is longer than %d characters", MaxMaintenanceReason)
	}
	now := m.now()
	if !w.Until.IsZero() && !w.Until.After(now) {
		return MaintenanceWindow{}, errors.New("the end time is in the past")
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return MaintenanceWindow{}, fmt.Errorf("generating a window id: %w", err)
	}
	w.ID = hex.EncodeToString(id)
	w.Since = now

	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	if len(m.windows) >= MaxMaintenanceWindows {
		return MaintenanceWindow{}, ErrTooManyMaintenanceWindows
	}
	m.windows = append(m.windows, w)
	return w, nil
}

// End removes a window. It returns false when no active window has the ID.
func (m *Maintenance) End(id string) (MaintenanceWindow, bool) {
	if m == nil {
		return MaintenanceWindow{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(m.now())
	for i, w := range m.windows {
		if w.ID == id {
			m.windows = slices.Delete(m.windows, i, i+1)
			return w, true
		}
	}
	return MaintenanceWindow{}, false
}

// Active lists the windows that haven't ended, oldest first.
func (m *Maintenance) Active() []MaintenanceWindow {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(m.now())
	return slices.Clone(m.windows)
}

// Blocking returns the first active window that rejects cmd for a project
// in repo.
func (m *Maintenance) Blocking(cmd command.Name, repo models.Repo, dir, workspace, project string) (MaintenanceWindow, bool) {
	for _, w := range m.Active() {
		if w.Blocks(cmd) && w.Covers(repo.VCSHost.Hostname, repo.FullName, dir, workspace, project) {
			return w, true
		}
	}
	return MaintenanceWindow{}, false
}

// BlockingRepo returns the first active repo-wide window that rejects cmd
// in repo. Windows for one directory, workspace, or project are checked
// per project, once Atlantis knows which projects a command runs.
func (m *Maintenance) BlockingRepo(cmd command.Name, repo models.Repo) (MaintenanceWindow, bool) {
	for _, w := range m.Active() {
		if w.RepoWide() && w.Blocks(cmd) && w.Covers(repo.VCSHost.Hostname, repo.FullName, "", "", "") {
			return w, true
		}
	}
	return MaintenanceWindow{}, false
}

func (m *Maintenance) pruneLocked(now time.Time) {
	m.windows = slices.DeleteFunc(m.windows, func(w MaintenanceWindow) bool {
		return !w.Until.IsZero() && !now.Before(w.Until)
	})
}
