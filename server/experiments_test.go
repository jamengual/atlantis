// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/urfave/negroni/v3"

	"github.com/gorilla/mux"
	"github.com/runatlantis/atlantis/server"
	"github.com/runatlantis/atlantis/server/controllers"
	. "github.com/runatlantis/atlantis/testing"
)

func TestValidateExperiments(t *testing.T) {
	const token = "do-not-log-this-token"
	cases := []struct {
		name   string
		config server.UserConfig
		err    string
	}{
		{name: "default"},
		{name: "API permission alone", config: server.UserConfig{Experiments: []string{"api"}}},
		{name: "drift permission alone", config: server.UserConfig{Experiments: []string{"drift-detection"}}},
		{name: "API configured", config: server.UserConfig{Experiments: []string{"api"}, APISecret: token}},
		{name: "drift configured independently", config: server.UserConfig{Experiments: []string{"drift-detection"}, APISecret: token, EnableDriftDetection: true}},
		{name: "both configured", config: server.UserConfig{Experiments: []string{"api", "drift-detection"}, APISecret: token, EnableDriftDetection: true, EnableDriftRemediation: true}},
		{name: "duplicate permissions", config: server.UserConfig{Experiments: []string{"api", "api"}, APISecret: token}},
		{name: "secret without permission", config: server.UserConfig{APISecret: token}, err: "api-secret requires"},
		{name: "drift flag without permission", config: server.UserConfig{EnableDriftDetection: true}, err: `enable-drift-detection requires the "drift-detection" experiment`},
		{name: "API does not permit drift", config: server.UserConfig{Experiments: []string{"api"}, APISecret: token, EnableDriftDetection: true}, err: `enable-drift-detection requires the "drift-detection" experiment`},
		{name: "remediation flag without permission", config: server.UserConfig{EnableDriftRemediation: true}, err: `enable-drift-remediation requires the "drift-detection" experiment`},
		{name: "remediation requires detection", config: server.UserConfig{Experiments: []string{"drift-detection"}, APISecret: token, EnableDriftRemediation: true}, err: "--enable-drift-remediation requires --enable-drift-detection"},
		{name: "drift requires authentication", config: server.UserConfig{Experiments: []string{"drift-detection"}, EnableDriftDetection: true}, err: "enable-drift-detection requires api-secret"},
		{name: "unknown", config: server.UserConfig{Experiments: []string{"unknown"}}, err: `unknown server experiment "unknown"`},
		{name: "traces with the web UI", config: server.UserConfig{Experiments: []string{"web-ui", "web-traces"}, WebTracesAllAttributes: true}},
		{name: "traces need the web UI", config: server.UserConfig{Experiments: []string{"web-traces"}}, err: `the "web-traces" experiment shows traces in the web UI and requires the "web-ui" experiment`},
		{name: "all attributes need traces", config: server.UserConfig{Experiments: []string{"web-ui"}, WebTracesAllAttributes: true}, err: `web-traces-all-attributes requires the "web-traces" experiment`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.ValidateExperiments()
			if tc.err == "" {
				Ok(t, err)
				return
			}
			ErrContains(t, tc.err, err)
			ErrContains(t, server.ExperimentsDocumentationURL, err)
			Assert(t, !strings.Contains(err.Error(), token), "error leaked the API secret")
			_, err = server.NewServer(tc.config, server.Config{})
			ErrContains(t, tc.err, err)
		})
	}
}

func TestExperimentPermissionsDoNotSetActivationFlags(t *testing.T) {
	for _, names := range [][]string{{"api"}, {"drift-detection"}, {"api", "drift-detection"}} {
		cfg := server.UserConfig{Experiments: names}
		Ok(t, cfg.ValidateExperiments())
		Equals(t, "", cfg.APISecret)
		Assert(t, !cfg.EnableDriftDetection && !cfg.EnableDriftRemediation, "permission changed activation flags")
	}
}

func TestNewServer_WiresAPIExperimentPermission(t *testing.T) {
	s, err := server.NewServer(server.UserConfig{
		DataDir: t.TempDir(), AtlantisURL: testAtlantisUrl,
		LockingDBType: testLockingDBType, GithubHostname: testGitHubHostName, GithubUser: testGitHubUser,
		APISecret: "token", Experiments: []string{"api"},
	}, server.Config{AtlantisVersion: testAtlantisVersion})
	Ok(t, err)
	Equals(t, []string{"api"}, s.Experiments)
	s.SetupRoutes()
	var match mux.RouteMatch
	Assert(t, s.Router.Match(httptest.NewRequest("POST", "/api/plan", nil), &match), "API permission was not wired to routing")
	Assert(t, !s.Router.Match(httptest.NewRequest("POST", "/api/drift/detect", nil), &match), "API permission exposed drift")
	Assert(t, s.APIController.DriftStorage == nil, "API permission initialized drift storage")
}

func TestSetupRoutes_ExperimentGates(t *testing.T) {
	routes := []struct{ method, path, experiment string }{
		{"POST", "/api/plan", "api"},
		{"POST", "/api/apply", "api"},
		{"GET", "/api/locks", "api"},
		{"GET", "/api/drift/status", "drift-detection"},
		{"POST", "/api/drift/detect", "drift-detection"},
		{"POST", "/api/drift/remediate", "drift-detection"},
		{"GET", "/api/drift/remediate", "drift-detection"},
		{"GET", "/api/drift/remediate/id", "drift-detection"},
	}
	for _, names := range [][]string{nil, {"api"}, {"drift-detection"}, {"api", "drift-detection"}} {
		t.Run(strings.Join(names, ","), func(t *testing.T) {
			s := &server.Server{Router: mux.NewRouter(), Experiments: names, APIController: &controllers.APIController{}}
			s.SetupRoutes()
			for _, route := range routes {
				permitted := false
				for _, name := range names {
					permitted = permitted || name == route.experiment
				}
				request := httptest.NewRequest(route.method, route.path, nil)
				var match mux.RouteMatch
				Equals(t, permitted, s.Router.Match(request, &match))
				if !permitted {
					response := httptest.NewRecorder()
					s.Router.ServeHTTP(response, request)
					Equals(t, http.StatusNotFound, response.Code)
				}
			}
			for _, path := range []string{"/healthz", "/readyz", "/status"} {
				var match mux.RouteMatch
				Assert(t, s.Router.Match(httptest.NewRequest("GET", path, nil), &match), "health route %s was gated", path)
			}
		})
	}
}

func TestNewServer_WiresWebUIExperiment(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			var names []string
			if enabled {
				names = []string{"web-ui"}
			}
			s, err := server.NewServer(server.UserConfig{
				DataDir: t.TempDir(), AtlantisURL: testAtlantisUrl,
				LockingDBType: testLockingDBType, GithubHostname: testGitHubHostName, GithubUser: testGitHubUser,
				Experiments: names,
			}, server.Config{AtlantisVersion: testAtlantisVersion})
			Ok(t, err)
			Equals(t, enabled, s.WebUI != nil)
			s.SetupRoutes()
			for _, path := range []string{"/ui", "/ui/pulls", "/ui/locks", "/ui/static/app.css"} {
				var match mux.RouteMatch
				Equals(t, enabled, s.Router.Match(httptest.NewRequest("GET", path, nil), &match))
			}
			if enabled {
				response := httptest.NewRecorder()
				s.Router.ServeHTTP(response, httptest.NewRequest("GET", "/ui", nil))
				Equals(t, http.StatusOK, response.Code)
				Assert(t, strings.Contains(response.Body.String(), "Overview"), "overview did not render")
			}
			// The existing UI keeps serving the root either way.
			var match mux.RouteMatch
			Assert(t, s.Router.Match(httptest.NewRequest("GET", "/", nil), &match), "index route missing")
		})
	}
}

// The job log stream must flush through the production middleware stack, not
// only through a bare router.
func TestWebUI_JobStreamFlushesThroughMiddleware(t *testing.T) {
	s, err := server.NewServer(server.UserConfig{
		DataDir: t.TempDir(), AtlantisURL: testAtlantisUrl,
		LockingDBType: testLockingDBType, GithubHostname: testGitHubHostName, GithubUser: testGitHubUser,
		Experiments: []string{"web-ui"},
	}, server.Config{AtlantisVersion: testAtlantisVersion})
	Ok(t, err)
	s.SetupRoutes()
	go s.ProjectCmdOutputHandler.Handle()

	repo := models.Repo{FullName: "acme/infra", Name: "infra", VCSHost: models.VCSHost{Hostname: "github.com"}}
	pctx := command.ProjectContext{JobID: "job-mw", Pull: models.PullRequest{Num: 1, BaseRepo: repo}, BaseRepo: repo,
		RepoRelDir: "network", Workspace: "default", CommandName: command.Plan}
	s.ProjectCmdOutputHandler.Send(pctx, "first line", false)

	n := negroni.New(server.NewRequestLogger(s))
	n.UseHandler(s.Router)
	srv := httptest.NewServer(n)
	defer srv.Close()

	// Wait until the job is visible, then stream it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(srv.URL + "/ui/jobs/job-mw")
		Ok(t, err)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job never became visible")
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp, err := http.Get(srv.URL + "/ui/jobs/job-mw/events")
	Ok(t, err)
	defer resp.Body.Close()
	Equals(t, "text/event-stream", resp.Header.Get("Content-Type"))

	sc := bufio.NewScanner(resp.Body)
	readUntil := func(want string) {
		t.Helper()
		done := make(chan bool, 1)
		go func() {
			for sc.Scan() {
				if sc.Text() == want {
					done <- true
					return
				}
			}
			done <- false
		}()
		select {
		case ok := <-done:
			Assert(t, ok, "stream ended before %q", want)
		case <-time.After(3 * time.Second):
			t.Fatalf("%q was not flushed to the client", want)
		}
	}
	// The first line arrives while the job is still running, which only
	// happens if the middleware passes flushes through.
	readUntil("data: first line")
	s.ProjectCmdOutputHandler.Send(pctx, "second line", false)
	readUntil("data: second line")
	s.ProjectCmdOutputHandler.Send(pctx, "", true)
	readUntil("event: done")
}
