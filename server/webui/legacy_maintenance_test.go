// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/core/locking"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

// The UI starts and ends windows in the same registry the command runners
// check, and lists them until they expire.
func TestLegacyMaintenance_RoundTrip(t *testing.T) {
	clock := now
	m := locking.NewMaintenance()
	m.Now = func() time.Time { return clock }
	store := &webui.LegacyStore{Maintenance: m}
	actions := &webui.LegacyActions{Maintenance: m}

	w, err := actions.StartMaintenance(webui.MaintenanceRequest{
		Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Dir: "network", Workspace: "default",
		Plans: true, Reason: "state migration", Until: now.Add(time.Hour),
	}, "Ada")
	Ok(t, err)
	Equals(t, webui.MaintenanceWindow{
		ID: w.ID, Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Dir: "network", Workspace: "default",
		Plans: true, Reason: "state migration", By: "Ada", Since: now, Until: now.Add(time.Hour),
	}, w)
	Equals(t, []webui.MaintenanceWindow{w}, store.ListMaintenance(context.Background()))

	repo := models.Repo{FullName: "acme/infra", VCSHost: models.VCSHost{Hostname: "github.com"}}
	_, blocked := m.Blocking(command.Plan, repo, "network", "default", "")
	Assert(t, blocked, "the command runners see the window")

	_, err = actions.StartMaintenance(webui.MaintenanceRequest{Repo: webui.Repository{FullName: "acme/infra"}}, "Ada")
	ErrContains(t, "a reason is required", err)

	ended, ok, err := actions.EndMaintenance(w.ID)
	Ok(t, err)
	Assert(t, ok, "the window ends")
	Equals(t, w.ID, ended.ID)
	Equals(t, 0, len(store.ListMaintenance(context.Background())))

	_, err = actions.StartMaintenance(webui.MaintenanceRequest{Repo: webui.Repository{FullName: "acme/infra"}, Reason: "short", Until: now.Add(time.Minute)}, "Ada")
	Ok(t, err)
	clock = now.Add(time.Minute)
	Equals(t, 0, len(store.ListMaintenance(context.Background())))
}

func TestLegacyMaintenance_Unavailable(t *testing.T) {
	store := &webui.LegacyStore{}
	actions := &webui.LegacyActions{}
	Equals(t, 0, len(store.ListMaintenance(context.Background())))
	_, err := actions.StartMaintenance(webui.MaintenanceRequest{Repo: webui.Repository{FullName: "acme/infra"}, Reason: "x"}, "Ada")
	Assert(t, errors.Is(err, webui.ErrMaintenanceUnavailable), "got %v", err)
	_, _, err = actions.EndMaintenance("x")
	Assert(t, errors.Is(err, webui.ErrMaintenanceUnavailable), "got %v", err)
}
