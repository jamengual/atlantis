// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package runtime_test

import (
	"strings"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/core/runtime"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/jobs"
	"github.com/runatlantis/atlantis/server/logging"
	. "github.com/runatlantis/atlantis/testing"
)

// recordingOutput keeps workflow hook output lines.
type recordingOutput struct {
	jobs.NoopProjectOutputHandler
	lines chan string
}

func (r *recordingOutput) SendWorkflowHook(_ models.WorkflowHookCommandContext, msg string, _ bool) {
	r.lines <- msg
}

func TestWorkflowHookRunners_StopInterruptsTheHook(t *testing.T) {
	for name, run := range map[string]func(runtime.DefaultPreWorkflowHookRunner, models.WorkflowHookCommandContext, string) (string, string, error){
		"pre": func(r runtime.DefaultPreWorkflowHookRunner, ctx models.WorkflowHookCommandContext, cmd string) (string, string, error) {
			return r.Run(ctx, cmd, "sh", "-c", t.TempDir())
		},
		"post": func(r runtime.DefaultPreWorkflowHookRunner, ctx models.WorkflowHookCommandContext, cmd string) (string, string, error) {
			return runtime.DefaultPostWorkflowHookRunner(r).Run(ctx, cmd, "sh", "-c", t.TempDir())
		},
	} {
		t.Run(name, func(t *testing.T) {
			processes := jobs.NewProcessRegistry()
			out := &recordingOutput{lines: make(chan string, 16)}
			r := runtime.DefaultPreWorkflowHookRunner{OutputHandler: out, Processes: processes}
			ctx := models.WorkflowHookCommandContext{Log: logging.NewNoopLogger(t), HookID: "hook-1"}

			type result struct {
				out string
				err error
			}
			done := make(chan result, 1)
			go func() {
				o, _, err := run(r, ctx, `trap 'echo hook-interrupted; exit 1' INT; while :; do sleep 0.05; done`)
				done <- result{o, err}
			}()
			for processes.Running("hook-1") == 0 {
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(100 * time.Millisecond) // let the shell install its trap
			processes.Stop("hook-1", "alice")
			select {
			case res := <-done:
				ErrContains(t, "stopped by alice", res.err)
				Assert(t, strings.Contains(res.out, "hook-interrupted"), "hook did not get the interrupt: %q", res.out)
			case <-time.After(5 * time.Second):
				t.Fatal("hook still running after the stop")
			}
			Assert(t, strings.Contains(<-out.lines, "Stopped by alice"), "hook output should say who stopped it")
		})
	}
}
