// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/webauth"
	"github.com/runatlantis/atlantis/server/webui"
	. "github.com/runatlantis/atlantis/testing"
)

// apiStore has data for every API endpoint: pull requests with plans and
// policy checks, locks, jobs, maintenance windows, and drift results.
func apiStore(t *testing.T) *fakeStore {
	t.Helper()
	s := policyStore()
	s.pulls[0].URL = "https://github.com/acme/infra/pull/1482"
	s.pulls[0].LastActivity = now.Add(-time.Minute)
	s.pulls[0].Projects[1].Changes = webui.Changes{Known: true, Add: 3}
	s.plans = map[webui.ProjectRef]*webui.ProjectPlan{
		dnsRef: {Status: webui.PlanReady, GeneratedAt: now.Add(-3 * time.Minute), Size: 4096, Plan: parseFixture(t, "plan_aws.json", webui.DefaultPlanLimits)},
	}
	s.locks = append(s.locks, webui.Lock{
		ID: "acme/infra/network/default", Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Dir: "network", Workspace: "default",
		PullNum: 1482, PullURL: "https://github.com/acme/infra/pull/1482", PullAuthor: "mrivera", User: "mrivera", Since: now.Add(-time.Hour), PullTracked: true,
	})
	s.jobs = stopStore().jobs
	s.jobs[0].Stop = &webui.JobStop{By: "Omar", At: now.Add(-30 * time.Second)}
	s.maint = []webui.MaintenanceWindow{
		{ID: "mw-1", Repo: webui.Repository{VCSHost: "github.com", FullName: "acme/infra"}, Dir: "network", Reason: "Rotating keys", By: "Ada", Since: now.Add(-time.Hour), Until: now.Add(time.Hour)},
		{ID: "mw-2", Repo: webui.Repository{FullName: "acme/data"}, Plans: true, Reason: "Freeze", By: "Ada", Since: now.Add(-2 * time.Hour)},
	}
	s.drift = driftStore().drift
	return s
}

// apiPaths are concrete requests for each documented path.
var apiPaths = map[string]string{
	"/openapi.json":                      "/ui/api/v1/openapi.json",
	"/instance":                          "/ui/api/v1/instance",
	"/pulls":                             "/ui/api/v1/pulls",
	"/repos/{repo}/pulls/{num}":          "/ui/api/v1/repos/acme/infra/pulls/1482?host=github.com",
	"/repos/{repo}/pulls/{num}/plan":     "/ui/api/v1/repos/acme/infra/pulls/1482/plan?host=github.com&dir=dns&workspace=default",
	"/repos/{repo}/pulls/{num}/policies": "/ui/api/v1/repos/acme/infra/pulls/1482/policies?host=github.com&dir=network&workspace=default",
	"/locks":                             "/ui/api/v1/locks",
	"/apply-lock":                        "/ui/api/v1/apply-lock",
	"/jobs":                              "/ui/api/v1/jobs",
	"/jobs/{id}":                         "/ui/api/v1/jobs/infra-plan",
	"/maintenance":                       "/ui/api/v1/maintenance",
	"/drift":                             "/ui/api/v1/drift",
}

func loadOpenAPI(t *testing.T) map[string]any {
	t.Helper()
	srv := newServer(t, sampleStore(), &fakeActions{}, "")
	resp, body := get(t, srv, "/ui/api/v1/openapi.json")
	Equals(t, http.StatusOK, resp.StatusCode)
	var doc map[string]any
	Ok(t, json.Unmarshal([]byte(body), &doc))
	Equals(t, "3.1.0", doc["openapi"])
	return doc
}

func getJSON(t *testing.T, c *http.Client, u string) (*http.Response, any, string) {
	t.Helper()
	resp, err := c.Get(u)
	Ok(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	Ok(t, err)
	var v any
	Ok(t, json.Unmarshal(b, &v))
	return resp, v, string(b)
}

// Every API route is documented, and every documented path is served.
func TestAPI_OpenAPIDocumentsEveryRoute(t *testing.T) {
	doc := loadOpenAPI(t)
	Equals(t, "/ui/api/v1", doc["servers"].([]any)[0].(map[string]any)["url"])
	var documented []string
	for p := range doc["paths"].(map[string]any) {
		documented = append(documented, p)
	}

	h := &webui.Handler{Store: sampleStore(), Logger: logging.NewNoopLogger(t)}
	r := mux.NewRouter()
	h.Register(r)
	param := regexp.MustCompile(`\{([a-z]+):[^}]*\}`)
	var registered []string
	Ok(t, r.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tpl, err := route.GetPathTemplate()
		if err != nil || !strings.HasPrefix(tpl, "/ui/api/v1/") {
			return nil
		}
		if methods, err := route.GetMethods(); err != nil || !slices.Contains(methods, http.MethodGet) {
			// The prefix and the catch-all for unknown paths.
			return nil
		}
		registered = append(registered, param.ReplaceAllString(strings.TrimPrefix(tpl, "/ui/api/v1"), "{$1}"))
		return nil
	}))
	sort.Strings(documented)
	sort.Strings(registered)
	Equals(t, documented, registered)

	var sampled []string
	for p := range apiPaths {
		sampled = append(sampled, p)
	}
	sort.Strings(sampled)
	Equals(t, documented, sampled)
}

// Each endpoint's response has exactly the fields its schema documents, of
// the documented types, and error responses match the Error schema.
func TestAPI_ResponsesMatchTheSchema(t *testing.T) {
	doc := loadOpenAPI(t)
	srv := newServer(t, apiStore(t), &fakeActions{}, "")
	paths := doc["paths"].(map[string]any)
	for p, item := range paths {
		if p == "/openapi.json" {
			continue
		}
		t.Run(p, func(t *testing.T) {
			resp, body, raw := getJSON(t, http.DefaultClient, srv.URL+apiPaths[p])
			Equals(t, http.StatusOK, resp.StatusCode)
			op := item.(map[string]any)["get"].(map[string]any)
			schema := responseSchema(t, doc, op["responses"].(map[string]any)["200"])
			validate(t, doc, schema, body, "$")
			// Lists aren't empty, so the item schemas were checked too.
			if m, ok := body.(map[string]any); ok && m["items"] != nil {
				Assert(t, len(m["items"].([]any)) > 0, "sample for %s has no items: %s", p, raw)
			}
		})
	}

	errSchema := doc["components"].(map[string]any)["schemas"].(map[string]any)["Error"].(map[string]any)
	for _, u := range []string{"/ui/api/v1/jobs/nope", "/ui/api/v1/repos/acme/infra/pulls/9999", "/ui/api/v1/nope"} {
		resp, body, _ := getJSON(t, http.DefaultClient, srv.URL+u)
		Equals(t, http.StatusNotFound, resp.StatusCode)
		validate(t, doc, errSchema, body, u)
	}
}

func responseSchema(t *testing.T, doc map[string]any, resp any) map[string]any {
	t.Helper()
	r := resolve(t, doc, resp.(map[string]any))
	return r["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
}

func resolve(t *testing.T, doc map[string]any, s map[string]any) map[string]any {
	t.Helper()
	ref, ok := s["$ref"].(string)
	if !ok {
		return s
	}
	var cur any = doc
	for part := range strings.SplitSeq(strings.TrimPrefix(ref, "#/"), "/") {
		cur = cur.(map[string]any)[part]
	}
	Assert(t, cur != nil, "unresolved $ref %q", ref)
	return resolve(t, doc, cur.(map[string]any))
}

// validate checks the subset of JSON Schema the document uses: types,
// enums, object properties (required, no others), arrays, and oneOf.
func validate(t *testing.T, doc map[string]any, schema map[string]any, v any, at string) {
	t.Helper()
	if err := check(t, doc, schema, v, at); err != nil {
		t.Error(err)
	}
}

func check(t *testing.T, doc map[string]any, schema map[string]any, v any, at string) error {
	schema = resolve(t, doc, schema)
	if alts, ok := schema["oneOf"].([]any); ok {
		for _, alt := range alts {
			if check(t, doc, alt.(map[string]any), v, at) == nil {
				return nil
			}
		}
		return fmt.Errorf("%s: matches no oneOf alternative", at)
	}
	var types []string
	switch ty := schema["type"].(type) {
	case string:
		types = []string{ty}
	case []any:
		for _, x := range ty {
			types = append(types, x.(string))
		}
	}
	got := jsonType(v)
	if len(types) > 0 && !slices.Contains(types, got) && (got != "integer" || !slices.Contains(types, "number")) {
		return fmt.Errorf("%s: type %s, want %v", at, got, types)
	}
	if enum, ok := schema["enum"].([]any); ok && v != nil && !slices.Contains(enum, v) {
		return fmt.Errorf("%s: %v is not one of %v", at, v, enum)
	}
	switch val := v.(type) {
	case map[string]any:
		props, _ := schema["properties"].(map[string]any)
		if props == nil {
			return nil
		}
		for k := range val {
			if _, ok := props[k]; !ok {
				return fmt.Errorf("%s: undocumented field %q", at, k)
			}
		}
		for _, req := range schema["required"].([]any) {
			if _, ok := val[req.(string)]; !ok {
				return fmt.Errorf("%s: missing required field %q", at, req)
			}
		}
		for k, sub := range val {
			if err := check(t, doc, props[k].(map[string]any), sub, at+"."+k); err != nil {
				return err
			}
		}
	case []any:
		items := schema["items"].(map[string]any)
		for i, sub := range val {
			if err := check(t, doc, items, sub, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func jsonType(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		if x == float64(int64(x)) {
			return "integer"
		}
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func TestAPI_HeadersAndContent(t *testing.T) {
	srv := newServer(t, apiStore(t), &fakeActions{}, "")
	for _, u := range []string{"/ui/api/v1/pulls", "/ui/api/v1/openapi.json", "/ui/api/v1/nope"} {
		resp, _ := get(t, srv, u)
		Equals(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
		Equals(t, "no-store", resp.Header.Get("Cache-Control"))
		Equals(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		Equals(t, "DENY", resp.Header.Get("X-Frame-Options"))
		Assert(t, strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'"), "missing CSP on %s", u)
	}
}

func TestAPI_IsReadOnly(t *testing.T) {
	actions := &fakeActions{}
	srv := newServer(t, apiStore(t), actions, "")
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req, _ := http.NewRequest(m, srv.URL+"/ui/api/v1/locks", strings.NewReader(`{"id":"acme/infra/network/default"}`))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := http.DefaultClient.Do(req)
		Ok(t, err)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		Equals(t, http.StatusMethodNotAllowed, resp.StatusCode)
		Equals(t, "GET", resp.Header.Get("Allow"))
		assertContains(t, string(b), `"code":"method_not_allowed"`)
	}
	Equals(t, 0, len(actions.discarded))
}

func TestAPI_EscapesUserData(t *testing.T) {
	store := apiStore(t)
	store.pulls[0].Author = "<script>alert(1)</script>"
	store.maint[0].Reason = `</script><img src=x onerror=alert(1)>`
	srv := newServer(t, store, &fakeActions{}, "")
	for _, u := range []string{"/ui/api/v1/pulls", "/ui/api/v1/maintenance", "/ui/api/v1/repos/acme/infra/pulls/1482/policies?host=github.com&dir=network&workspace=default"} {
		_, body := get(t, srv, u)
		Assert(t, !strings.Contains(body, "<script>") && !strings.Contains(body, "<img"), "unescaped markup in %s", u)
	}
	_, body := get(t, srv, "/ui/api/v1/pulls")
	assertContains(t, body, "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e")
}

// The plan endpoint never returns values Terraform marks as sensitive.
func TestAPI_PlanHidesSensitiveValues(t *testing.T) {
	srv := newServer(t, apiStore(t), &fakeActions{}, "")
	resp, body := get(t, srv, apiPaths["/repos/{repo}/pulls/{num}/plan"])
	Equals(t, http.StatusOK, resp.StatusCode)
	for _, secret := range []string{"hunter2", "arn:new", "arn:old"} {
		Assert(t, !strings.Contains(body, secret), "sensitive value %q in the API", secret)
	}
	assertContains(t, body, `"status":"ready"`, `"terraform_version":"1.9.8"`, `"after_sensitive":true`, `"after_unknown":true`)

	var out struct {
		Item struct {
			Resources []struct {
				Attributes []struct {
					Before          *string `json:"before"`
					After           *string `json:"after"`
					BeforeSensitive bool    `json:"before_sensitive"`
					AfterSensitive  bool    `json:"after_sensitive"`
					AfterUnknown    bool    `json:"after_unknown"`
				} `json:"attributes"`
			} `json:"resources"`
		} `json:"item"`
	}
	Ok(t, json.Unmarshal([]byte(body), &out))
	sensitive := 0
	for _, r := range out.Item.Resources {
		for _, a := range r.Attributes {
			if a.BeforeSensitive {
				sensitive++
				Assert(t, a.Before == nil, "sensitive before value returned")
			}
			if a.AfterSensitive || a.AfterUnknown {
				sensitive++
				Assert(t, a.After == nil, "sensitive or unknown after value returned")
			}
		}
	}
	Assert(t, sensitive > 0, "fixture should have sensitive attributes")
}

func TestAPI_NotFoundAndUnavailable(t *testing.T) {
	store := apiStore(t)
	srv := newServer(t, store, &fakeActions{}, "")
	for _, u := range []string{
		"/ui/api/v1/repos/acme/infra/pulls/1482/plan?host=github.com&dir=nope&workspace=default",
		"/ui/api/v1/repos/acme/infra/pulls/1482/policies?host=github.com&dir=dns",
		"/ui/api/v1/repos/acme/infra/pulls/1482?host=gitlab.com",
	} {
		resp, body := get(t, srv, u)
		Equals(t, http.StatusNotFound, resp.StatusCode)
		assertContains(t, body, `"code":"not_found"`)
	}

	// Slashes in the repository name may be percent-encoded.
	resp, _ := get(t, srv, "/ui/api/v1/repos/acme%2Finfra/pulls/1482")
	Equals(t, http.StatusOK, resp.StatusCode)

	store.err = errors.New("dial tcp 10.0.0.7:6379: connection refused")
	for _, u := range []string{"/ui/api/v1/pulls", "/ui/api/v1/locks"} {
		resp, body := get(t, srv, u)
		Equals(t, http.StatusServiceUnavailable, resp.StatusCode)
		assertContains(t, body, `"code":"unavailable"`, "lock database")
		Assert(t, !strings.Contains(body, "10.0.0.7"), "store error leaked into %s", u)
	}
}

// Without web sign-in, the basic-auth user has full access, as on the pages.
func TestAPI_WithoutSignIn(t *testing.T) {
	srv := newServer(t, apiStore(t), &fakeActions{}, "")
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/ui/api/v1/instance", nil)
	req.SetBasicAuth("alice", "pw")
	resp, err := http.DefaultClient.Do(req)
	Ok(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	Equals(t, http.StatusOK, resp.StatusCode)
	assertContains(t, string(b), `"viewer":{"name":"alice","provider":"basic","role":"admin"}`, `"permissions":{"lock_applies":true,"maintenance":true}`, `"version":"9.9.9"`)
	Assert(t, !strings.Contains(string(b), "pw"), "password echoed")
}

// Signed-out requests get 401 JSON, not a redirect, and see no data.
func TestAPI_SignedOut(t *testing.T) {
	srv, _ := newSignInServer(t, apiStore(t), &fakeActions{})
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for p, u := range apiPaths {
		resp, body, raw := getJSON(t, c, srv.URL+u)
		Equals(t, http.StatusUnauthorized, resp.StatusCode)
		Equals(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
		Equals(t, "unauthorized", body.(map[string]any)["error"].(map[string]any)["code"])
		for _, leak := range []string{"acme", "9.9.9", "mrivera", "redis"} {
			Assert(t, !strings.Contains(raw, leak), "signed-out %s leaked %q", p, leak)
		}
	}
	// A forged session cookie doesn't help.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/ui/api/v1/pulls", nil)
	req.AddCookie(&http.Cookie{Name: "atlantis_session", Value: "forged", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	resp, err := c.Do(req)
	Ok(t, err)
	resp.Body.Close()
	Equals(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPI_RolesSetPermissions(t *testing.T) {
	cases := []struct {
		name                string
		claims              map[string]any
		role                string
		unlock, lockApplies bool
	}{
		{"viewer", map[string]any{"sub": "v", "name": "Vera Viewer", "email": "vera@acme.com", "email_verified": true}, "viewer", false, false},
		{"operator", map[string]any{"sub": "o", "name": "Omar Operator", "groups": []string{"sre"}}, "operator", true, false},
		{"admin", map[string]any{"sub": "a", "name": "Ada Admin", "groups": []string{"platform-admins"}}, "admin", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, idp := newSignInServer(t, apiStore(t), &fakeActions{})
			b := newBrowser(t, srv.URL)
			signIn(t, b, idp, tc.claims)
			for p, u := range apiPaths {
				status, _ := b.get(t, u)
				Equals(t, http.StatusOK, status)
				_ = p
			}
			_, body := b.get(t, "/ui/api/v1/instance")
			assertContains(t, body, fmt.Sprintf(`"viewer":{"name":%q,"provider":"oidc","role":%q}`, tc.claims["name"], tc.role),
				fmt.Sprintf(`"permissions":{"lock_applies":%t,"maintenance":%t}`, tc.lockApplies, tc.lockApplies))
			// No session or identity details beyond the display name.
			for _, leak := range []string{"vera@acme.com", "platform-admins", `"sub"`, "atlantis_session"} {
				Assert(t, !strings.Contains(body, leak), "instance leaked %q", leak)
			}
			_, locks := b.get(t, "/ui/api/v1/locks")
			assertContains(t, locks, fmt.Sprintf(`"permissions":{"unlock":%t}`, tc.unlock))
		})
	}
}

// A person whose account has no role gets 403 JSON with the reason.
func TestAPI_ForbiddenWithoutARole(t *testing.T) {
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	proxy, err := webauth.NewProxyAuthenticator(webauth.ProxyConfig{Type: webauth.ProxyHeader, UserHeader: "X-Forwarded-User", GroupsHeader: "X-Forwarded-Groups", TrustedCIDRs: []*net.IPNet{loopback}})
	Ok(t, err)
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer srv.Close()
	public, _ := url.Parse(srv.URL)
	auth, err := webauth.NewManager(webauth.Config{PublicURL: public, Proxy: proxy, Roles: signInRoles, Logger: logging.NewNoopLogger(t)})
	Ok(t, err)
	h := &webui.Handler{Store: apiStore(t), Actions: &fakeActions{}, Logger: logging.NewNoopLogger(t), Now: func() time.Time { return now }, Auth: auth}
	r := mux.NewRouter()
	h.Register(r)
	handler = r

	do := func(user, groups, path string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if user != "" {
			req.Header.Set("X-Forwarded-User", user)
			req.Header.Set("X-Forwarded-Groups", groups)
		}
		resp, err := http.DefaultClient.Do(req)
		Ok(t, err)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	resp, body := do("", "", "/ui/api/v1/pulls")
	Equals(t, http.StatusUnauthorized, resp.StatusCode)
	assertContains(t, body, `"code":"unauthorized"`, "authenticating proxy")

	for p, u := range apiPaths {
		resp, body = do("xavier", "contractors", u)
		Equals(t, http.StatusForbidden, resp.StatusCode)
		assertContains(t, body, `"code":"forbidden"`, "no Atlantis role")
		Assert(t, !strings.Contains(body, "acme/infra"), "forbidden %s leaked data", p)
	}

	resp, body = do("omar", "sre", "/ui/api/v1/instance")
	Equals(t, http.StatusOK, resp.StatusCode)
	assertContains(t, body, `"provider":"proxy","role":"operator"`)
}

// Per-item permissions match what the pages show the same person, with
// repository rules in the access policy.
func TestAPI_PermissionsMatchThePages(t *testing.T) {
	store := apiStore(t)
	gh := func(name string) webui.Repository { return webui.Repository{VCSHost: "github.com", FullName: name} }
	store.locks = []webui.Lock{
		{ID: "lake-lock", Repo: gh("acme/data-lake"), Dir: "glue", Workspace: "default", PullNum: 77, PullTracked: true, Since: now},
		{ID: "infra-lock", Repo: gh("acme/infra"), Dir: "network", Workspace: "default", PullNum: 1482, PullTracked: true, Since: now},
		{ID: "prod-lock", Repo: gh("acme/prod-network"), Dir: "vpc", Workspace: "default", PullNum: 9, PullTracked: true, Since: now},
	}
	store.jobs = stopStore().jobs
	people := map[string]map[string]any{
		"viewer":   {"sub": "v", "name": "Vera", "email": "vera@acme.com", "email_verified": true},
		"data-eng": {"sub": "d", "name": "Dana", "email": "dana@acme.com", "email_verified": true, "groups": []string{"data-eng"}},
		"operator": {"sub": "o", "name": "Omar", "groups": []string{"sre"}},
		"admin":    {"sub": "a", "name": "Ada", "groups": []string{"platform-admins"}},
	}
	for name, claims := range people {
		t.Run(name, func(t *testing.T) {
			srv, idp := newPolicyServer(t, store, &fakeActions{})
			b := newBrowser(t, srv.URL)
			signIn(t, b, idp, claims)

			_, page := b.get(t, "/ui/locks")
			var locks struct {
				Items []struct {
					ID          string `json:"id"`
					Permissions struct {
						Unlock bool `json:"unlock"`
					} `json:"permissions"`
				} `json:"items"`
			}
			_, raw := b.get(t, "/ui/api/v1/locks")
			Ok(t, json.Unmarshal([]byte(raw), &locks))
			Equals(t, len(store.locks), len(locks.Items))
			for _, l := range locks.Items {
				Equals(t, strings.Contains(page, `name="id" value="`+l.ID+`"`), l.Permissions.Unlock)
			}

			_, page = b.get(t, "/ui/jobs")
			var jobs struct {
				Items []struct {
					ID          string `json:"id"`
					Permissions struct {
						Stop bool `json:"stop"`
					} `json:"permissions"`
				} `json:"items"`
			}
			_, raw = b.get(t, "/ui/api/v1/jobs")
			Ok(t, json.Unmarshal([]byte(raw), &jobs))
			Equals(t, len(store.jobs), len(jobs.Items))
			for _, j := range jobs.Items {
				Equals(t, strings.Contains(page, "/ui/jobs/"+j.ID+"/stop"), j.Permissions.Stop)
			}

			// Viewing isn't scoped by repository, so everyone with a role
			// sees every pull request, as on the pages.
			_, raw = b.get(t, "/ui/api/v1/pulls")
			var pulls struct {
				Items []json.RawMessage `json:"items"`
			}
			Ok(t, json.Unmarshal([]byte(raw), &pulls))
			Equals(t, len(store.pulls), len(pulls.Items))
		})
	}
}

func TestAPI_JobsAndPolicies(t *testing.T) {
	srv := newServer(t, apiStore(t), &fakeActions{}, "")
	_, body := get(t, srv, "/ui/api/v1/jobs/infra-plan")
	assertContains(t, body, `"status":"running"`, `"stop":{"by":"Omar","at":"2026-11-13T13:59:30Z","killed":false}`)
	_, body = get(t, srv, "/ui/api/v1/jobs/done-plan")
	assertContains(t, body, `"status":"done"`, `"stop":null`, `"permissions":{"stop":false}`)

	_, body = get(t, srv, apiPaths["/repos/{repo}/pulls/{num}/policies"])
	assertContains(t, body, `"output_status":"ready"`, `"name":"security"`, `"current_approvals":1`, `"required_approvals":2`,
		`"output":"1 test, 1 passed"`, `"admins":{"users":["root"],"teams":[]}`, `"can_approve":false`, "needs GitHub sign-in")

	_, body = get(t, srv, apiPaths["/repos/{repo}/pulls/{num}"])
	assertContains(t, body, `"locks":[{"id":"acme/infra/network/default"`, `"maintenance":[{"id":"mw-1"`)
	Assert(t, !strings.Contains(body, `"id":"mw-2"`), "maintenance for another repo shown on the pull request")

	_, body = get(t, srv, "/ui/api/v1/drift")
	assertContains(t, body, `"enabled":true`, `"counts":{"total":3,"drifted":1,"failed":1,"in_sync":1,"stale":1}`, `"next":null`)
}
