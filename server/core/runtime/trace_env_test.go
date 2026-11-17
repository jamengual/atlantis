// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package runtime_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-version"
	. "github.com/petergtz/pegomock/v4"
	"github.com/runatlantis/atlantis/server/core/runtime"
	tf "github.com/runatlantis/atlantis/server/core/terraform"
	"github.com/runatlantis/atlantis/server/core/terraform/mocks"
	tfclientmocks "github.com/runatlantis/atlantis/server/core/terraform/tfclient/mocks"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	jobmocks "github.com/runatlantis/atlantis/server/jobs/mocks"
	"github.com/runatlantis/atlantis/server/jobtrace"
	"github.com/runatlantis/atlantis/server/logging"
	. "github.com/runatlantis/atlantis/testing"
)

const traceEnvCommand = `echo "parent=$TRACEPARENT endpoint=$OTEL_EXPORTER_OTLP_ENDPOINT"`

func traceRecorder() *jobtrace.Recorder {
	r := jobtrace.NewRecorder()
	r.SetEndpoint("http://127.0.0.1:4318")
	return r
}

func runStepRunner(t *testing.T, traces *jobtrace.Recorder) runtime.RunStepRunner {
	RegisterMockTestingT(t)
	terraform := tfclientmocks.NewMockClient()
	When(terraform.EnsureVersion(Any[logging.SimpleLogging](), Any[tf.Distribution](), Any[*version.Version]())).ThenReturn(nil)
	v, err := version.NewVersion("1.10.0")
	Ok(t, err)
	return runtime.RunStepRunner{
		TerraformExecutor:       terraform,
		DefaultTFDistribution:   tf.NewDistributionOpenTofuWithDownloader(mocks.NewMockDownloader()),
		DefaultTFVersion:        v,
		ProjectCmdOutputHandler: jobmocks.NewMockProjectCommandOutputHandler(),
		Traces:                  traces,
	}
}

func TestRunStepRunner_PassesTheStepSpanToCommands(t *testing.T) {
	traces := traceRecorder()
	r := runStepRunner(t, traces)
	step := traces.Start("job-1", "run: tofu", jobtrace.CategoryStep)
	ctx := command.ProjectContext{Log: logging.NewNoopLogger(t), Workspace: "default", JobID: "job-1"}
	out, err := r.Run(ctx, nil, traceEnvCommand, t.TempDir(), nil, false, nil, nil)
	Ok(t, err)
	tr, _ := traces.Snapshot("job-1")
	Equals(t, "parent=00-"+tr.TraceID+"-"+step.ID()+"-01 endpoint=http://127.0.0.1:4318\n", out)

	// A workflow that sets its own collector keeps it.
	out, err = r.Run(ctx, nil, traceEnvCommand, t.TempDir(), map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://mine"}, false, nil, nil)
	Ok(t, err)
	Equals(t, "parent= endpoint=https://mine\n", out)
}

func TestRunStepRunner_NoTracesNoVariables(t *testing.T) {
	r := runStepRunner(t, nil)
	ctx := command.ProjectContext{Log: logging.NewNoopLogger(t), Workspace: "default", JobID: "job-1"}
	out, err := r.Run(ctx, nil, traceEnvCommand, t.TempDir(), nil, false, nil, nil)
	Ok(t, err)
	Equals(t, "parent= endpoint=\n", out)
}

func TestWorkflowHooks_AreTracedJobs(t *testing.T) {
	RegisterMockTestingT(t)
	traces := traceRecorder()
	dir := t.TempDir()
	ctx := models.WorkflowHookCommandContext{Log: logging.NewNoopLogger(t), HookID: "hook-1", CommandName: "plan", SuppressJobOutput: true}
	pre := runtime.DefaultPreWorkflowHookRunner{OutputHandler: jobmocks.NewMockProjectCommandOutputHandler(), Traces: traces}
	out, _, err := pre.Run(ctx, traceEnvCommand+" > trace.txt", "sh", "-c", dir)
	Ok(t, err)
	Equals(t, "", out)
	b, err := os.ReadFile(filepath.Join(dir, "trace.txt"))
	Ok(t, err)
	tr, ok := traces.Snapshot("hook-1")
	Assert(t, ok, "hook not traced")
	Equals(t, 1, len(tr.Spans))
	Equals(t, "pre-workflow hook", tr.Spans[0].Name)
	Assert(t, tr.Finished, "hook span left open")
	Equals(t, "parent=00-"+tr.TraceID+"-"+tr.Spans[0].ID+"-01 endpoint=http://127.0.0.1:4318", strings.TrimSpace(string(b)))

	ctx.HookID = "hook-2"
	post := runtime.DefaultPostWorkflowHookRunner{OutputHandler: jobmocks.NewMockProjectCommandOutputHandler(), Traces: traces}
	_, _, err = post.Run(ctx, "exit 2", "sh", "-c", dir)
	Assert(t, err != nil, "failing hook succeeded")
	tr, _ = traces.Snapshot("hook-2")
	Equals(t, "post-workflow hook", tr.Spans[0].Name)
	Assert(t, tr.Spans[0].Error, "failed hook's span not marked failed")
}
