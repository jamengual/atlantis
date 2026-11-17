// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package tfclient

import (
	"strings"
	"testing"

	version "github.com/hashicorp/go-version"
	"github.com/runatlantis/atlantis/server/core/terraform"
	terraform_mocks "github.com/runatlantis/atlantis/server/core/terraform/mocks"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/jobs/mocks"
	"github.com/runatlantis/atlantis/server/jobtrace"
	"github.com/runatlantis/atlantis/server/logging"
	. "github.com/runatlantis/atlantis/testing"
)

const printTraceEnv = `echo "parent=$TRACEPARENT endpoint=$OTEL_EXPORTER_OTLP_ENDPOINT exporter=$OTEL_TRACES_EXPORTER protocol=$OTEL_EXPORTER_OTLP_PROTOCOL"`

func tracedClient(t *testing.T) (*DefaultClient, *jobtrace.Recorder, command.ProjectContext) {
	v, err := version.NewVersion("1.10.0")
	Ok(t, err)
	rec := jobtrace.NewRecorder()
	rec.SetEndpoint("http://127.0.0.1:4318")
	c := &DefaultClient{
		defaultVersion:          v,
		terraformPluginCacheDir: t.TempDir(),
		overrideTF:              "sh",
		projectCmdOutputHandler: mocks.NewMockProjectCommandOutputHandler(),
	}
	c.TraceCommands(rec)
	ctx := command.ProjectContext{Log: logging.NewNoopLogger(t), JobID: "job-1", Workspace: "default", SuppressJobOutput: true}
	return c, rec, ctx
}

func tofu() terraform.Distribution {
	return terraform.NewDistributionOpenTofuWithDownloader(terraform_mocks.NewMockDownloader())
}

func TestTraceCommands_PassesTheTraceToEachCommand(t *testing.T) {
	c, rec, ctx := tracedClient(t)
	step := rec.Start("job-1", "plan", jobtrace.CategoryStep)

	out, err := c.RunCommandWithVersion(ctx, t.TempDir(), []string{"-c", printTraceEnv}, nil, tofu(), nil, "default")
	Ok(t, err)
	_, outCh := c.RunCommandAsync(ctx, t.TempDir(), []string{"-c", printTraceEnv + "; exit 3"}, nil, tofu(), nil, "default")
	asyncOut, asyncErr := waitCh(outCh)
	Assert(t, asyncErr != nil, "async command should fail")
	step.End(nil)

	tr, ok := rec.Snapshot("job-1")
	Assert(t, ok, "no trace")
	Equals(t, 3, len(tr.Spans))
	sync, async := tr.Spans[1], tr.Spans[2]
	Equals(t, "tofu -c", sync.Name)
	Equals(t, jobtrace.CategoryCommand, sync.Category)
	Equals(t, step.ID(), sync.ParentID)
	Equals(t, step.ID(), async.ParentID)
	Assert(t, !sync.End.IsZero() && !async.End.IsZero(), "command spans left open")
	Assert(t, !sync.Error, "sync span failed")
	Assert(t, async.Error, "failed command's span not marked failed")

	want := "parent=00-" + tr.TraceID + "-" + sync.ID + "-01 endpoint=http://127.0.0.1:4318 exporter=otlp protocol=http/protobuf"
	Equals(t, want+"\n", out)
	Assert(t, strings.Contains(asyncOut, "-"+async.ID+"-01"), "async command got the wrong parent: %s", asyncOut)
}

func TestTraceCommands_RespectsTheWorkflowsOwnCollector(t *testing.T) {
	c, rec, ctx := tracedClient(t)
	rec.Start("job-1", "plan", jobtrace.CategoryStep)
	out, err := c.RunCommandWithVersion(ctx, t.TempDir(), []string{"-c", printTraceEnv}, map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector:4318"}, tofu(), nil, "default")
	Ok(t, err)
	Equals(t, "parent= endpoint=https://collector:4318 exporter= protocol=\n", out)
	tr, _ := rec.Snapshot("job-1")
	Equals(t, 1, len(tr.Notes))
}

func TestTraceCommands_OffChangesNothing(t *testing.T) {
	c, _, ctx := tracedClient(t)
	c.TraceCommands(nil)
	out, err := c.RunCommandWithVersion(ctx, t.TempDir(), []string{"-c", printTraceEnv}, nil, tofu(), nil, "default")
	Ok(t, err)
	Equals(t, "parent= endpoint= exporter= protocol=\n", out)
}

func TestCommandSpanName(t *testing.T) {
	for args, want := range map[string]string{
		"":                             "tofu",
		"plan -var password=hunter2":   "tofu plan",
		"workspace select prod":        "tofu workspace select",
		"workspace -h":                 "tofu workspace",
		"state rm aws_instance.web":    "tofu state rm",
		"init -backend-config=key=abc": "tofu init",
	} {
		Equals(t, want, commandSpanName("tofu", strings.Fields(args)))
	}
}
