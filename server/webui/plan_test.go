// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

func parseFixture(t *testing.T, name string, limits webui.PlanLimits) webui.ParsedPlan {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	Ok(t, err)
	defer f.Close()
	p, err := webui.ParsePlanJSON(f, limits)
	Ok(t, err)
	return p
}

func resource(t *testing.T, p webui.ParsedPlan, addr string) webui.ResourceChange {
	t.Helper()
	for _, r := range p.Resources {
		if r.Address == addr {
			return r
		}
	}
	t.Fatalf("plan has no resource %q", addr)
	return webui.ResourceChange{}
}

func attr(t *testing.T, r webui.ResourceChange, path string) webui.AttributeChange {
	t.Helper()
	for _, a := range r.Attributes {
		if a.Path == path {
			return a
		}
	}
	t.Fatalf("resource %q has no attribute change %q; have %v", r.Address, path, r.Attributes)
	return webui.AttributeChange{}
}

func hasAttr(r webui.ResourceChange, path string) bool {
	for _, a := range r.Attributes {
		if a.Path == path {
			return true
		}
	}
	return false
}

// The terraform_data fixture is real terraform show -json output. Terraform
// printed "Plan: 2 to add, 3 to change, 2 to destroy." for it.
func TestParsePlanJSON_RealTerraformPlan(t *testing.T) {
	p := parseFixture(t, "plan_terraform_data.json", webui.DefaultPlanLimits)
	stats := models.NewPlanSuccessStats("Plan: 2 to add, 3 to change, 2 to destroy.")
	Equals(t, webui.Changes{Known: true, Add: stats.Add, Change: stats.Change, Destroy: stats.Destroy, Forget: 1}, p.Changes)
	Equals(t, "1.17.1", p.TerraformVersion)
	Equals(t, 8, p.TotalResources)

	actions := map[string]webui.PlanAction{}
	for _, r := range p.Resources {
		actions[r.Address] = r.Action
	}
	Equals(t, map[string]webui.PlanAction{
		"terraform_data.creds":            webui.PlanUpdate,
		"terraform_data.doomed":           webui.PlanDelete,
		"terraform_data.forgotten":        webui.PlanForget,
		"terraform_data.fresh":            webui.PlanCreate,
		"terraform_data.keep":             webui.PlanUpdate,
		"terraform_data.new_name":         webui.PlanMove,
		"terraform_data.replace_me":       webui.PlanReplace,
		"module.app.terraform_data.inner": webui.PlanUpdate,
	}, actions)

	// A sensitive input is flagged and its value is dropped on both sides.
	creds := resource(t, p, "terraform_data.creds")
	pw := attr(t, creds, "input.password")
	Assert(t, pw.BeforeSensitive && pw.AfterSensitive, "password should be sensitive: %+v", pw)
	Equals(t, "", pw.Before)
	Equals(t, "", pw.After)
	Assert(t, !hasAttr(creds, "input.user"), "unchanged attributes are not listed")
	for _, r := range p.Resources {
		for _, a := range r.Attributes {
			Assert(t, !strings.Contains(a.Before+a.After, "s3cr3t-v2"), "sensitive value leaked in %s %s", r.Address, a.Path)
		}
	}

	// Values known only after apply.
	out := attr(t, creds, "output")
	Assert(t, out.AfterUnknown, "output should be known after apply")
	fresh := resource(t, p, "terraform_data.fresh")
	Assert(t, attr(t, fresh, "id").AfterUnknown, "new id should be known after apply")
	Assert(t, !hasAttr(fresh, "store"), "null attributes of a create are not listed")

	keep := resource(t, p, "terraform_data.keep")
	Equals(t, "443", attr(t, keep, "input.port").Before)
	Equals(t, "8443", attr(t, keep, "input.port").After)
	role := attr(t, keep, `input.tags["kubernetes.io/role"]`)
	Assert(t, role.BeforeAbsent, "added map key has no before value")
	Equals(t, `"lb"`, role.After)

	repl := resource(t, p, "terraform_data.replace_me")
	Equals(t, "a change forces replacement", repl.Reason)
	trig := attr(t, repl, "triggers_replace")
	Assert(t, trig.ForcesReplacement, "replace path should be flagged")
	Equals(t, `["a"]`, trig.Before)
	Equals(t, `["b"]`, trig.After)

	moved := resource(t, p, "terraform_data.new_name")
	Equals(t, "terraform_data.old_name", moved.PreviousAddress)
	inner := resource(t, p, "module.app.terraform_data.inner")
	Equals(t, "module.app", inner.Module)
	Equals(t, "terraform_data", inner.Type)
	Equals(t, "terraform.io/builtin/terraform", inner.Provider)
}

func TestParsePlanJSON_Actions(t *testing.T) {
	p := parseFixture(t, "plan_aws.json", webui.DefaultPlanLimits)
	// Counts match the Plan line Terraform prints for the same changes.
	stats := models.NewPlanSuccessStats("Plan: 2 to import, 3 to add, 2 to change, 3 to destroy, 1 to forget.")
	Equals(t, webui.Changes{Known: true, Import: stats.Import, Add: stats.Add, Change: stats.Change, Destroy: stats.Destroy, Forget: stats.Forget}, p.Changes)
	Equals(t, 10, p.TotalResources)

	cases := map[string]webui.PlanAction{
		"data.aws_iam_policy_document.assume":               webui.PlanRead,
		"aws_security_group.alb":                            webui.PlanUpdate,
		"aws_db_instance.main":                              webui.PlanReplace,
		`aws_instance.web["blue"]`:                          webui.PlanDelete,
		`module.vpc.module.subnets["a"].aws_subnet.this[0]`: webui.PlanCreate,
		"aws_s3_bucket.logs":                                webui.PlanImport,
		"aws_iam_role.ci":                                   webui.PlanUpdate,
		"aws_lb.public":                                     webui.PlanReplace,
		"aws_kms_key.legacy":                                webui.PlanForget,
		"aws_route53_record.www":                            webui.PlanMove,
	}
	for addr, want := range cases {
		Equals(t, want, resource(t, p, addr).Action)
	}
	for _, r := range p.Resources {
		Assert(t, r.Address != "aws_vpc.main", "no-op resources are not listed")
	}

	Equals(t, "00000001", resource(t, p, `aws_instance.web["blue"]`).Deposed)
	logs := resource(t, p, "aws_s3_bucket.logs")
	Assert(t, logs.Importing, "import should be flagged")
	Equals(t, "acme-logs", logs.ImportID)
	ci := resource(t, p, "aws_iam_role.ci")
	Assert(t, ci.Importing, "import with an update keeps the update action and the import flag")
	Equals(t, "replacement was requested", resource(t, p, "aws_lb.public").Reason)
	Equals(t, `module.vpc.module.subnets["a"]`, resource(t, p, `module.vpc.module.subnets["a"].aws_subnet.this[0]`).Module)
	Equals(t, "hashicorp/aws", logs.Provider)
	Equals(t, "aws_route53_record.root", resource(t, p, "aws_route53_record.www").PreviousAddress)
}

func TestParsePlanJSON_NestedBlocksAndSensitiveBlocks(t *testing.T) {
	p := parseFixture(t, "plan_aws.json", webui.DefaultPlanLimits)
	sg := resource(t, p, "aws_security_group.alb")
	cidr := attr(t, sg, "ingress[0].cidr_blocks")
	Equals(t, `["0.0.0.0/0"]`, cidr.Before)
	Equals(t, `["10.40.0.0/16"]`, cidr.After)
	Assert(t, !hasAttr(sg, "ingress[0].from_port"), "unchanged nested attributes are not listed")
	Equals(t, 8, sg.Unchanged)
	owner := attr(t, sg, "tags.owner")
	Equals(t, `"<script>alert(1)</script>"`, owner.After)

	db := resource(t, p, "aws_db_instance.main")
	Assert(t, attr(t, db, "engine_version").ForcesReplacement, "engine_version forces replacement")
	secret := attr(t, db, "master_user_secret")
	Assert(t, secret.BeforeSensitive && secret.AfterSensitive, "a sensitive block is one sensitive value")
	pw := attr(t, db, "password")
	Assert(t, pw.BeforeSensitive && pw.AfterSensitive, "password is sensitive")
	Assert(t, attr(t, db, "id").AfterUnknown, "id is known after apply")
	Assert(t, attr(t, db, "endpoint").AfterUnknown, "an unknown attribute missing from after is still listed")
	Assert(t, attr(t, db, "endpoint").BeforeAbsent, "endpoint had no value before")
	for _, r := range p.Resources {
		for _, a := range r.Attributes {
			Assert(t, !strings.Contains(a.Before+a.After, "hunter2") && !strings.Contains(a.Before+a.After, "arn:new"),
				"sensitive value leaked in %s %s", r.Address, a.Path)
		}
	}

	// A delete lists the prior values that go away.
	web := resource(t, p, `aws_instance.web["blue"]`)
	Equals(t, `"t3.micro"`, attr(t, web, "instance_type").Before)
	Assert(t, attr(t, web, "instance_type").AfterAbsent, "deleted attributes have no after value")
	Assert(t, !hasAttr(web, "user_data"), "null prior values are not listed")

	read := resource(t, p, "data.aws_iam_policy_document.assume")
	Assert(t, attr(t, read, "json").AfterUnknown, "data source result is known after apply")
}

func TestParsePlanJSON_Limits(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"format_version":"1.2","resource_changes":[`)
	for i := range 30 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"address":"null_resource.n[%d]","mode":"managed","change":{"actions":["create"],"before":null,"after":{"a":"%s","b":2,"c":3,"d":4}}}`, i, strings.Repeat("x", 50))
	}
	b.WriteString(`]}`)
	p, err := webui.ParsePlanJSON(strings.NewReader(b.String()), webui.PlanLimits{Resources: 10, AttributesPerResource: 3, Attributes: 20, ValueLength: 10})
	Ok(t, err)
	Equals(t, 30, p.TotalResources)
	Equals(t, 30, p.Changes.Add)
	Equals(t, 10, len(p.Resources))
	Equals(t, 3, len(p.Resources[0].Attributes))
	Equals(t, 1, p.Resources[0].Omitted)
	Equals(t, `"xxxxxxxxx…`, p.Resources[0].Attributes[0].After)
	total := 0
	for _, r := range p.Resources {
		total += len(r.Attributes)
	}
	Equals(t, 20, total)
	Assert(t, p.AttributesOmitted, "plan-wide limit should be reported")
}

func TestParsePlanJSON_RejectsOtherJSON(t *testing.T) {
	_, err := webui.ParsePlanJSON(strings.NewReader(`{"hello":"world"}`), webui.DefaultPlanLimits)
	Assert(t, err != nil, "JSON without format_version is not a plan")
	_, err = webui.ParsePlanJSON(strings.NewReader(`not json`), webui.DefaultPlanLimits)
	Assert(t, err != nil, "invalid JSON is an error")
	c, err := webui.CountPlanChanges(strings.NewReader(`{"format_version":"1.2","resource_changes":[]}`))
	Ok(t, err)
	Equals(t, webui.Changes{Known: true}, c)
}
