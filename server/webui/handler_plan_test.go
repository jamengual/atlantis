// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

var dnsRef = webui.ProjectRef{Dir: "dns", Workspace: "default"}

const dnsPlanPath = "/ui/repos/acme/infra/pulls/1482/plan?dir=dns&host=github.com&workspace=default"

func planStore(t *testing.T, fixture string) *fakeStore {
	t.Helper()
	store := sampleStore()
	store.plans = map[webui.ProjectRef]*webui.ProjectPlan{
		dnsRef: {Status: webui.PlanReady, GeneratedAt: now.Add(-3 * 60e9), Plan: parseFixture(t, fixture, webui.DefaultPlanLimits)},
	}
	return store
}

func TestPlanPage_ListsResourcesByAction(t *testing.T) {
	srv := newServer(t, planStore(t, "plan_aws.json"), &fakeActions{}, "")
	resp, body := get(t, srv, dnsPlanPath)
	Equals(t, http.StatusOK, resp.StatusCode)
	assertContains(t, body,
		"<title>Plan for dns · Atlantis</title>",
		"Resource changes",
		"Planned 3m ago", "Terraform 1.9.8",
		// Summary counts follow Terraform's Plan line.
		">+3</b>", ">~2</b>", ">-3</b>", "To import", "To remove from state",
		// Groups, riskiest first, with the ledger symbols.
		`data-plan-group="destroy"`, `data-plan-group="replace"`, `data-plan-group="change"`, `data-plan-group="add"`, `data-plan-group="other"`,
		`aws_instance.web[&#34;blue&#34;]`, "Deposed object 00000001",
		"module.vpc.module.subnets[&#34;a&#34;].aws_subnet.this[0]",
		"Import acme-logs", "Moved from aws_route53_record.root",
		"Terraform will replace this resource because a change forces replacement.",
		"Terraform will remove this resource from state without destroying it.",
		"Forces replacement", "(sensitive value)", "(known after apply)",
		"ingress[0].cidr_blocks", "8 unchanged attributes hidden.",
		// Filter chips, hidden until app.js shows them.
		`data-plan-filters hidden`, `data-plan-filter="replace"`, `data-plan-filter="other"`,
		"Values Terraform marks as sensitive are hidden.",
		"Plan details are read from the working directory of the replica that ran the plan.",
	)
	// Riskiest group first.
	Assert(t, strings.Index(body, `data-plan-group="destroy"`) < strings.Index(body, `data-plan-group="add"`), "destroys should come before adds")
	for _, secret := range []string{"hunter2", "arn:new", "arn:old"} {
		Assert(t, !strings.Contains(body, secret), "sensitive value %q rendered", secret)
	}
	// Large plans start collapsed.
	Assert(t, !strings.Contains(body, `<details class="res" open`), "resources should start collapsed for a 10-resource plan")
}

func TestPlanPage_EscapesPlanValues(t *testing.T) {
	srv := newServer(t, planStore(t, "plan_aws.json"), &fakeActions{}, "")
	_, body := get(t, srv, dnsPlanPath)
	Assert(t, !strings.Contains(body, "<script>alert(1)</script>"), "attribute value was not escaped")
	Assert(t, !strings.Contains(body, "<b>public</b>"), "attribute value was not escaped")
	assertContains(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestPlanPage_SmallPlanStartsExpanded(t *testing.T) {
	srv := newServer(t, planStore(t, "plan_terraform_data.json"), &fakeActions{}, "")
	_, body := get(t, srv, dnsPlanPath)
	assertContains(t, body, `<details class="res" open`, "terraform_data.replace_me", "module.app.terraform_data.inner", "input.password")
	Assert(t, !strings.Contains(body, "s3cr3t-v2"), "sensitive value rendered")
}

func TestPlanPage_EmptyPlan(t *testing.T) {
	store := sampleStore()
	store.plans = map[webui.ProjectRef]*webui.ProjectPlan{dnsRef: {Status: webui.PlanReady, Plan: webui.ParsedPlan{Changes: webui.Changes{Known: true}}}}
	srv := newServer(t, store, &fakeActions{}, "")
	_, body := get(t, srv, dnsPlanPath)
	assertContains(t, body, "This plan changes no resources.")
	Assert(t, !strings.Contains(body, "data-plan-filters"), "no filters for an empty plan")
}

func TestPlanPage_Truncated(t *testing.T) {
	store := planStore(t, "plan_aws.json")
	store.plans[dnsRef].Plan = parseFixture(t, "plan_aws.json", webui.PlanLimits{Resources: 2, AttributesPerResource: 1, Attributes: 1, ValueLength: 10})
	srv := newServer(t, store, &fakeActions{}, "")
	_, body := get(t, srv, dnsPlanPath)
	assertContains(t, body, "Showing the first 2 of 10 resource changes.", "Some attribute details were left out", "more changed attribute")
}

func TestPlanPage_NotAvailable(t *testing.T) {
	cases := []struct {
		status webui.PlanStatus
		state  webui.ProjectState
		want   []string
	}{
		{webui.PlanNoSavedPlan, webui.StatePlanned, []string{"There&#39;s no saved plan for this project on this replica", "planned on another replica"}},
		{webui.PlanNoJSON, webui.StatePlanned, []string{"Atlantis didn&#39;t save this plan as JSON", "add a show step after plan", "steps: [init, plan, show]"}},
		{webui.PlanOutdated, webui.StatePlanned, []string{"The plan JSON is from an earlier plan"}},
		{webui.PlanOutdated, webui.StatePlanFailed, []string{"The latest plan failed"}},
		{webui.PlanTooLarge, webui.StatePlanned, []string{"This plan is too large to show here", "up to 64 MB"}},
		{webui.PlanUnreadable, webui.StatePlanned, []string{"Atlantis couldn&#39;t read the plan JSON"}},
	}
	for _, c := range cases {
		t.Run(string(c.status)+"/"+string(c.state), func(t *testing.T) {
			store := sampleStore()
			store.pulls[0].Projects[2].State = c.state
			store.plans = map[webui.ProjectRef]*webui.ProjectPlan{dnsRef: {Status: c.status, Size: 70 << 20}}
			srv := newServer(t, store, &fakeActions{}, "")
			resp, body := get(t, srv, dnsPlanPath)
			Equals(t, http.StatusOK, resp.StatusCode)
			assertContains(t, body, c.want...)
			assertContains(t, body, `id="plan-unavailable"`, "Plan details are read from the working directory of the replica that ran the plan.")
			Assert(t, !strings.Contains(body, "Resource changes"), "no resource list when the plan is not available")
		})
	}
}

func TestPlanPage_NotFound(t *testing.T) {
	srv := newServer(t, planStore(t, "plan_aws.json"), &fakeActions{}, "")
	for _, path := range []string{
		"/ui/repos/acme/infra/pulls/9/plan?dir=dns&workspace=default",
		"/ui/repos/acme/infra/pulls/1482/plan?dir=dns&workspace=prod",
		"/ui/repos/acme/infra/pulls/1482/plan?dir=..%2F..%2Fetc&workspace=default",
		"/ui/repos/acme/infra/pulls/1482/plan",
	} {
		resp, body := get(t, srv, path)
		Equals(t, http.StatusNotFound, resp.StatusCode)
		Assert(t, strings.Contains(body, "Atlantis has no such project in this pull request") || strings.Contains(body, "Atlantis has nothing for this pull request"), "unexpected body for %s", path)
	}
}

func TestPlanPage_StoreError(t *testing.T) {
	store := planStore(t, "plan_aws.json")
	srv := newServer(t, store, &fakeActions{}, "")
	store.err = errors.New("dial tcp: connection refused")
	resp, body := get(t, srv, dnsPlanPath)
	Equals(t, http.StatusServiceUnavailable, resp.StatusCode)
	assertContains(t, body, "Reading the plan failed")
}

func TestPullPage_LinksEachProjectToItsPlan(t *testing.T) {
	srv := newServer(t, sampleStore(), &fakeActions{}, "/atlantis")
	_, body := get(t, srv, "/ui/repos/acme/infra/pulls/1482?host=github.com")
	assertContains(t, body,
		`href="/atlantis/ui/repos/acme/infra/pulls/1482/plan?dir=dns&amp;host=github.com&amp;workspace=default"`,
		`href="/atlantis/ui/repos/acme/infra/pulls/1482/plan?dir=edge&amp;host=github.com&amp;workspace=prod"`,
		`aria-label="Plan for edge (prod)"`)
}

func TestPlanPage_ViewersCanReadPlans(t *testing.T) {
	srv, idp := newSignInServer(t, planStore(t, "plan_aws.json"), &fakeActions{})
	b := newBrowser(t, srv.URL)
	signIn(t, b, idp, map[string]any{"sub": "v", "name": "Vera Viewer", "email": "vera@acme.com", "email_verified": true})
	status, body := b.get(t, dnsPlanPath)
	Equals(t, http.StatusOK, status)
	assertContains(t, body, "Resource changes", "aws_db_instance.main")

	// An account without a role gets no session, so it is sent to sign in,
	// like a signed-out visitor.
	other := newBrowser(t, srv.URL)
	idp.SetUser(map[string]any{"sub": "x", "name": "Xavier Outsider", "email": "x@elsewhere.org", "email_verified": true})
	status, _ = other.get(t, "/ui/login/oidc")
	Equals(t, http.StatusForbidden, status)
	resp, err := other.noFollow().Get(srv.URL + dnsPlanPath)
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusSeeOther, resp.StatusCode)
	Assert(t, strings.HasPrefix(resp.Header.Get("Location"), "/ui/login?return="), "visitors without a role go to sign-in")
}
