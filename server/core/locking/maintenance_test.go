// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package locking_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/core/locking"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	. "github.com/runatlantis/atlantis/testing"
)

var maintNow = time.Date(2026, 11, 13, 14, 0, 0, 0, time.UTC)

func newMaintenance(now *time.Time) *locking.Maintenance {
	m := locking.NewMaintenance()
	m.Now = func() time.Time { return *now }
	return m
}

func ghRepo(name string) models.Repo {
	return models.Repo{FullName: name, VCSHost: models.VCSHost{Hostname: "github.com"}}
}

func TestMaintenance_RepoWideWindowBlocksAppliesOnly(t *testing.T) {
	now := maintNow
	m := newMaintenance(&now)
	w, err := m.Start(locking.MaintenanceWindow{Host: "github.com", RepoName: "acme/infra", Reason: "database upgrade", By: "Ada"})
	Ok(t, err)
	Assert(t, w.ID != "", "the window gets an id")
	Equals(t, maintNow, w.Since)

	for _, cmd := range []command.Name{command.Apply, command.Import, command.State} {
		_, blocked := m.BlockingRepo(cmd, ghRepo("acme/infra"))
		Assert(t, blocked, "%s should be blocked", cmd)
		_, blocked = m.Blocking(cmd, ghRepo("acme/infra"), "network", "default", "")
		Assert(t, blocked, "%s should be blocked for every project", cmd)
	}
	for _, cmd := range []command.Name{command.Plan, command.Autoplan, command.PolicyCheck, command.Unlock, command.Version} {
		_, blocked := m.BlockingRepo(cmd, ghRepo("acme/infra"))
		Assert(t, !blocked, "%s should not be blocked", cmd)
	}
	_, blocked := m.BlockingRepo(command.Apply, ghRepo("acme/other"))
	Assert(t, !blocked, "other repos are not blocked")
	_, blocked = m.BlockingRepo(command.Apply, models.Repo{FullName: "acme/infra", VCSHost: models.VCSHost{Hostname: "gitlab.com"}})
	Assert(t, !blocked, "the same name on another host is not blocked")
	_, blocked = m.BlockingRepo(command.Apply, ghRepo("ACME/Infra"))
	Assert(t, blocked, "repository names match without case")
}

func TestMaintenance_PlansCanBeFrozenToo(t *testing.T) {
	now := maintNow
	m := newMaintenance(&now)
	_, err := m.Start(locking.MaintenanceWindow{RepoName: "acme/infra", Plans: true, Reason: "incident", By: "Ada"})
	Ok(t, err)
	for _, cmd := range []command.Name{command.Plan, command.Autoplan, command.Apply} {
		_, blocked := m.BlockingRepo(cmd, ghRepo("acme/infra"))
		Assert(t, blocked, "%s should be blocked", cmd)
	}
	_, blocked := m.BlockingRepo(command.Apply, models.Repo{FullName: "acme/infra", VCSHost: models.VCSHost{Hostname: "gitlab.com"}})
	Assert(t, blocked, "a window without a host covers every host")
}

func TestMaintenance_ScopedWindowCoversOneProject(t *testing.T) {
	now := maintNow
	m := newMaintenance(&now)
	_, err := m.Start(locking.MaintenanceWindow{Host: "github.com", RepoName: "acme/infra", Dir: "./network/", Workspace: "prod", Reason: "migrating state", By: "Ada"})
	Ok(t, err)
	active := m.Active()
	Equals(t, 1, len(active))
	Equals(t, "network", active[0].Dir)
	Equals(t, "directory network, workspace prod", active[0].Scope())

	_, blocked := m.Blocking(command.Apply, ghRepo("acme/infra"), "network", "prod", "")
	Assert(t, blocked, "the project is blocked")
	_, blocked = m.Blocking(command.Apply, ghRepo("acme/infra"), "./network", "prod", "any-name")
	Assert(t, blocked, "dirs are compared cleaned, and any project name matches")
	_, blocked = m.Blocking(command.Apply, ghRepo("acme/infra"), "network", "default", "")
	Assert(t, !blocked, "other workspaces are not blocked")
	_, blocked = m.Blocking(command.Apply, ghRepo("acme/infra"), "edge", "prod", "")
	Assert(t, !blocked, "other dirs are not blocked")
	_, blocked = m.BlockingRepo(command.Apply, ghRepo("acme/infra"))
	Assert(t, !blocked, "a scoped window doesn't block the whole repo")

	_, err = m.Start(locking.MaintenanceWindow{RepoName: "acme/infra", Dir: ".", Reason: "root", By: "Ada"})
	Ok(t, err)
	_, blocked = m.BlockingRepo(command.Apply, ghRepo("acme/infra"))
	Assert(t, !blocked, "a window for the root directory is still scoped")
	_, blocked = m.Blocking(command.Apply, ghRepo("acme/infra"), ".", "default", "")
	Assert(t, blocked, "the root directory project is blocked")
}

func TestMaintenance_ExpiresAndEnds(t *testing.T) {
	now := maintNow
	m := newMaintenance(&now)
	short, err := m.Start(locking.MaintenanceWindow{RepoName: "acme/infra", Reason: "short", By: "Ada", Until: maintNow.Add(time.Hour)})
	Ok(t, err)
	long, err := m.Start(locking.MaintenanceWindow{RepoName: "acme/data", Reason: "long", By: "Ada"})
	Ok(t, err)
	Equals(t, 2, len(m.Active()))

	now = maintNow.Add(time.Hour)
	_, blocked := m.BlockingRepo(command.Apply, ghRepo("acme/infra"))
	Assert(t, !blocked, "an expired window doesn't block")
	Equals(t, []locking.MaintenanceWindow{long}, m.Active())
	_, ok := m.End(short.ID)
	Assert(t, !ok, "an expired window can't be ended")

	ended, ok := m.End(long.ID)
	Assert(t, ok, "the window ends")
	Equals(t, "long", ended.Reason)
	Equals(t, 0, len(m.Active()))
	_, ok = m.End(long.ID)
	Assert(t, !ok, "ending twice reports nothing to end")
}

func TestMaintenance_Validation(t *testing.T) {
	now := maintNow
	m := newMaintenance(&now)
	cases := map[string]struct {
		w    locking.MaintenanceWindow
		want string
	}{
		"no repo":         {locking.MaintenanceWindow{Reason: "x"}, "full name"},
		"no owner":        {locking.MaintenanceWindow{RepoName: "infra", Reason: "x"}, "full name"},
		"spaces in repo":  {locking.MaintenanceWindow{RepoName: "acme/in fra", Reason: "x"}, "full name"},
		"no reason":       {locking.MaintenanceWindow{RepoName: "acme/infra", Reason: "  \n "}, "reason is required"},
		"long reason":     {locking.MaintenanceWindow{RepoName: "acme/infra", Reason: strings.Repeat("a", 301)}, "longer than 300"},
		"absolute dir":    {locking.MaintenanceWindow{RepoName: "acme/infra", Dir: "/etc", Reason: "x"}, "relative"},
		"parent dir":      {locking.MaintenanceWindow{RepoName: "acme/infra", Dir: "a/../../b", Reason: "x"}, "relative"},
		"space workspace": {locking.MaintenanceWindow{RepoName: "acme/infra", Workspace: "a b", Reason: "x"}, "workspace"},
		"past end":        {locking.MaintenanceWindow{RepoName: "acme/infra", Reason: "x", Until: maintNow}, "in the past"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := m.Start(c.w)
			ErrContains(t, c.want, err)
		})
	}
	Equals(t, 0, len(m.Active()))
}

func TestMaintenance_ReasonCannotBreakOutOfACodeBlock(t *testing.T) {
	now := maintNow
	m := newMaintenance(&now)
	w, err := m.Start(locking.MaintenanceWindow{RepoName: "acme/infra", Reason: "upgrade\n```\n@everyone <b>hi</b>", By: "Ada `x`\nY", Until: maintNow.Add(2 * time.Hour)})
	Ok(t, err)
	Equals(t, "upgrade ''' @everyone <b>hi</b>", w.Reason)
	Equals(t, "Ada 'x' Y", w.By)
	msg := w.Explain(command.Apply)
	Assert(t, !strings.Contains(msg, "`"), "no backticks in %q", msg)
	Equals(t, "atlantis apply is blocked by a maintenance window on acme/infra.\n"+
		"Scope: the whole repository\n"+
		"Reason: upgrade ''' @everyone <b>hi</b>\n"+
		"Set by: Ada 'x' Y at 2026-11-13 14:00 UTC\n"+
		"Ends: 2026-11-13 16:00 UTC", msg)
	w.Until = time.Time{}
	assertContainsText(t, w.Explain(command.Autoplan), "Autoplan is blocked", "Ends: when someone ends it in the Atlantis web UI")
	assertContainsText(t, w.Explain(command.State), "atlantis state rm is blocked")
}

func assertContainsText(t *testing.T, s string, want ...string) {
	t.Helper()
	for _, w := range want {
		Assert(t, strings.Contains(s, w), "%q does not contain %q", s, w)
	}
}

func TestMaintenance_Limit(t *testing.T) {
	now := maintNow
	m := newMaintenance(&now)
	for range locking.MaxMaintenanceWindows {
		_, err := m.Start(locking.MaintenanceWindow{RepoName: "acme/infra", Reason: "x"})
		Ok(t, err)
	}
	_, err := m.Start(locking.MaintenanceWindow{RepoName: "acme/infra", Reason: "x"})
	Equals(t, locking.ErrTooManyMaintenanceWindows, err)
}

func TestMaintenance_NilHasNoWindows(t *testing.T) {
	var m *locking.Maintenance
	Equals(t, 0, len(m.Active()))
	_, blocked := m.BlockingRepo(command.Apply, ghRepo("acme/infra"))
	Assert(t, !blocked, "nil blocks nothing")
	_, blocked = m.Blocking(command.Apply, ghRepo("acme/infra"), ".", "default", "")
	Assert(t, !blocked, "nil blocks nothing")
	_, ok := m.End("x")
	Assert(t, !ok, "nil ends nothing")
	_, err := m.Start(locking.MaintenanceWindow{RepoName: "acme/infra", Reason: "x"})
	ErrContains(t, "not enabled", err)
}

func TestMaintenance_ConcurrentUse(t *testing.T) {
	m := locking.NewMaintenance()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			w, err := m.Start(locking.MaintenanceWindow{RepoName: "acme/infra", Reason: "x"})
			if err != nil {
				t.Error(err)
				return
			}
			m.BlockingRepo(command.Apply, ghRepo("acme/infra"))
			m.End(w.ID)
		})
	}
	wg.Wait()
	Equals(t, 0, len(m.Active()))
}
