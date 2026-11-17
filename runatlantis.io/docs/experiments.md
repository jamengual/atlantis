# Experiments

Experimental features may change or be removed before becoming stable. Read the feature's documentation before using it.

## Server opt-in

The `experiments` server setting grants permission to use experimental features. It is empty by default and read at startup. An experiment's HTTP routes are unavailable without its permission. Its own settings still control authentication and activation.

Atlantis refuses to start when an experimental feature's settings are enabled without the required permission or prerequisites. Errors name the setting, explain how to fix it, and link to this page. These checks apply to command-line flags, environment variables, and YAML configuration.

Use a command-line flag:

```sh
atlantis server --experiments=api,drift-detection
```

Or an environment variable:

```sh
ATLANTIS_EXPERIMENTS=api,drift-detection atlantis server
```

Or a YAML list in the [server configuration file](server-configuration.md):

```yaml
experiments:
  - api
  - drift-detection
```

Flags and environment variables accept comma-separated names. Repeating `--experiments` appends names. Flags override environment variables, which override the configuration file. Lists from different sources are not combined. `--experiments=` clears the list.

Names are lowercase and match exactly. Unknown names, wildcard values, `all`, and empty list entries prevent startup. Duplicate names have no additional effect. Repository `atlantis.yaml` files cannot grant experiment permissions.

## Feature status

| Feature | Experiment name | Stage | Releases | Availability | Design | Tracking |
| --- | --- | --- | --- | --- | --- | --- |
| [API](api-endpoints.md#main-endpoints) | `api` | Experimental | Plan/apply: v0.19.8+. Experiment gate: unreleased (Main only). | Requires `api`; authenticated commands also require `api-secret` | [ADR 0002](/contributing/adr/0002-api-enhancement-drift-detection.md) | [API development #6162](https://github.com/runatlantis/atlantis/issues/6162) |
| [Drift detection](api-endpoints.md#drift-detection-and-remediation-alpha) | `drift-detection` | Experimental | Legacy API: v0.45.0+. Experiment gate: unreleased (Main only). | Requires `drift-detection`, `api-secret`, and drift enable flags | [ADR 0002](/contributing/adr/0002-api-enhancement-drift-detection.md) | [Development #7033](https://github.com/runatlantis/atlantis/issues/7033) |
| [Web UI](#web-ui) | `web-ui` | Experimental | Unreleased (Main only). | Requires `web-ui` | [ADR 0005](/contributing/adr/0005-use-durable-storage-with-one-data-model.md) data model | [Web UI #6158](https://github.com/runatlantis/atlantis/issues/6158) |
| [Job timing traces](#job-timing-traces-experimental) | `web-traces` | Prototype | Unreleased (Main only). | Requires `web-traces` and `web-ui` | [ADR 0005](/contributing/adr/0005-use-durable-storage-with-one-data-model.md) data model | [Web UI #6158](https://github.com/runatlantis/atlantis/issues/6158) |

The supported names are `api`, `drift-detection`, `web-ui`, and `web-traces`. Each permits its own route group and does not grant the others' permissions; `web-traces` adds to the web UI and needs `web-ui` too. No current release tag contains this setting.

Both experiments share ADR 0002, but have separate tracking issues and graduation criteria. Graduating either one does not make the other stable.

## Upgrading existing alpha features

::: warning New permissions required
Existing API and drift installations must add the matching experiment names when upgrading to a release containing this gate. An existing `api-secret` or enabled drift flag without permission now prevents startup. Routes without permission return HTTP 404, including the previously public lock-listing route.
:::

For an installation using both API commands and drift detection:

```yaml
experiments:
  - api
  - drift-detection
api-secret: replace-with-your-existing-secret
enable-drift-detection: true
```

Keep `enable-drift-remediation` enabled only if you intend to permit destructive remediation apply. For a drift-only installation, omit `api`; drift routes remain available while command and lock routes stay disabled. The shared `api-secret` is permitted by either experiment.

Before rolling back to a binary that predates `--experiments`, remove the experiments setting from flags, environment variables, and YAML. Older binaries continue to use their legacy API and drift settings; follow that release's recovery guidance.

## API

The `api` experiment covers the command and lock endpoints, including `POST /api/plan`, `POST /api/apply`, and `GET /api/locks`. Drift detection, remediation, and their endpoints belong to the separate [drift detection experiment](#drift-detection).

Add `api` to `experiments` to permit command and lock routes. To use authenticated command endpoints, configure [`api-secret`](server-configuration.md#api-secret) and send its value in `X-Atlantis-Token`. Permission alone does not configure authentication or enable command execution.

Request and response fields, error handling, supported providers, and non-PR execution remain experimental. Command and lock responses currently use legacy top-level bodies; drift endpoints use a different envelope. See the [API documentation](api-endpoints.md) for endpoint-specific behavior and limitations.

To disable all command and lock routes, remove `api` from `experiments` and restart. Remove `api-secret` too unless a permitted drift installation still needs it. These routes return HTTP 404 without permission. When `api` is permitted but no secret is configured, the existing read-only lock listing remains available; command requests require a secret.

### API graduation checklist

- [x] Require API permission for command and lock routes and reject settings without permission at startup. Evidence: [configuration and route tests in #7030](https://github.com/runatlantis/atlantis/pull/7030/files).
- [ ] Review the request/response contract, error serialization, HTTP statuses, and compatibility of legacy response bodies against the [command response tests](https://github.com/runatlantis/atlantis/blob/main/server/events/command/result_test.go).
- [ ] Verify authentication, repository/team authorization, and plan/apply requirements for PR and non-PR requests against the [API controller tests](https://github.com/runatlantis/atlantis/blob/main/server/controllers/api_controller_test.go).
- [ ] Verify concurrent request isolation, lock cleanup, and shutdown behavior against the [API controller tests](https://github.com/runatlantis/atlantis/blob/main/server/controllers/api_controller_test.go); resolve the contract for [lock cleanup #6956](https://github.com/runatlantis/atlantis/issues/6956) and [shutdown #6934](https://github.com/runatlantis/atlantis/issues/6934).
- [ ] Verify supported-provider documentation and enable, disable, upgrade, and rollback instructions against the [API documentation](api-endpoints.md) and target release.
- [ ] Record the API graduation decision and first stable release in [API tracker #6162](https://github.com/runatlantis/atlantis/issues/6162).

## Drift detection

Add `drift-detection` to `experiments`, configure `api-secret`, and enable `enable-drift-detection`. Missing permission or authentication configuration prevents startup when detection is enabled. Drift remediation apply additionally requires `enable-drift-remediation`. See the [drift API documentation](api-endpoints.md#drift-detection-and-remediation-alpha) for configuration and limitations.

To disable drift detection and remediation, disable both enable flags, remove `drift-detection` from `experiments`, and restart. Keep `api-secret` only if the `api` experiment still needs it. Leaving a drift flag enabled after removing its permission prevents startup.

Results currently use in-memory storage and are lost on restart. Drift detection runs the configured plan lifecycle, including hooks and custom steps. Remediation apply requires its own enable flag and still enforces repository apply requirements. See the [API documentation](api-endpoints.md#drift-detection-and-remediation-alpha) for request formats and limits.

### Drift detection graduation checklist

- [x] Require drift permission for drift routes and reject enabled drift/remediation flags without permission at startup. Evidence: [configuration and route tests in #7030](https://github.com/runatlantis/atlantis/pull/7030/files).
- [ ] Verify drift classification, project/ref/workspace identity, and partial-failure behavior against the [drift controller tests](https://github.com/runatlantis/atlantis/blob/main/server/controllers/api_controller_test.go).
- [ ] Review drift detection/status, remediation/history, and webhook contracts against the [drift controller tests](https://github.com/runatlantis/atlantis/blob/main/server/controllers/api_controller_test.go) and [drift API documentation](api-endpoints.md#drift-detection-and-remediation-alpha).
- [ ] Verify persistence and restart behavior against the [drift storage tests](https://github.com/runatlantis/atlantis/blob/main/server/core/drift/storage_test.go), and document the supported retention policy.
- [ ] Review remediation authorization and execution requirements against the [remediation tests](https://github.com/runatlantis/atlantis/blob/main/server/controllers/api_remediation_executor_internal_test.go).
- [ ] Verify enable, disable, upgrade, and rollback instructions with the target release.
- [ ] Record the graduation decision and first stable release in [development tracker #7033](https://github.com/runatlantis/atlantis/issues/7033).

## Web UI

Add `web-ui` to `experiments` to serve a new web UI at `/ui`. The existing UI at `/` is unchanged. The new UI shows pull requests with per-project status and plan changes, project locks with single and bulk unlock, the global apply lock, maintenance windows, policy check results with a way for policy owners to approve them, [drift detection results](#web-ui-drift-page), live job logs with a way to stop a running job, and the health of the replica serving the page.

Without [web UI sign-in](#web-ui-sign-in), the UI uses the same access control as the existing UI: [basic auth](server-configuration.md#web-basic-auth) when enabled, and nothing otherwise. In that case anyone who can reach `/ui` can discard plans, stop jobs, start maintenance windows, and lock applies, but nobody can [approve policies](#policy-checks-and-approvals). Actions reject cross-origin requests, and pages are served with a Content Security Policy that blocks inline scripts and styles. The pull request comment for a discarded plan names the user who discarded it.

Locks, the apply lock, and pull request status come from the locking database, so every replica shows the same values. Job lists and logs live in memory on the replica that ran the job and are cleared on restart. With several replicas behind a load balancer, a job page may show "no output" when the request reaches a different replica. The pages are built on the [ADR 0005](/contributing/adr/0005-use-durable-storage-with-one-data-model.md) data model so that durable storage can add history, cluster-wide jobs, and an audit log without changing them.

### Stopping a running job

A running plan, apply, policy check, or workflow hook has a **Stop** button on its job page and in the job lists. Stopping a job works like pressing Ctrl-C in a terminal:

1. Atlantis sends an interrupt (`SIGINT`) to the job's process and everything it started. Terraform stops scheduling new work, waits for the operations in progress, saves state, and releases its state lock, so a stop normally leaves no lock behind. Creating or destroying some resources takes minutes, and Terraform waits for them.
2. The job runs no further steps. A stopped plan fails and its plan file is deleted, even when Terraform finished just as the interrupt arrived, so nothing from it can be applied. A stopped apply is reported as failed. Run `atlantis plan` again to continue.
3. If the process is still running 10 minutes after the interrupt, Atlantis kills it. Terraform can't release its state lock then, and resources it was creating may be missing from state. The job page and log say so; check the backend and run `terraform force-unlock` if needed.

The job log and page say who stopped the job, and the pull request comment for the failed plan or apply names them. Atlantis logs every stop with the user's identity.

Stopping needs the operator role by default. Set `access.permissions.stop_job`, or `permissions.stop_job` on a `repos` entry, to change that (see [the access policy](#access-policy-in-the-server-side-repo-config)).

Each job runs on one replica, and only that replica can stop it. With several replicas behind a load balancer, a request that reaches another replica is told that replica isn't running the job; try again. Atlantis only tracks processes to stop when the `web-ui` experiment is on; it starts each Terraform command in its own process group then. On Windows, stopping a job kills its process right away.

### Unlocking every lock of a pull request

A pull request page has an **Unlock all** button when the pull request holds locks. Its confirmation lists every project and workspace that will be released. On the **Locks** page, locks are grouped by pull request: select several and choose **Unlock selected**, or choose **Release all** on a pull request that holds more than one lock.

Each lock is released as if it were unlocked on its own: its plan is discarded and Atlantis comments on the pull request. You need permission to unlock every lock in the request, or none is released. If the lock database fails partway, Atlantis still tries the remaining locks, then lists which locks were unlocked and which weren't, with the error for each.

### Maintenance windows

A maintenance window freezes `atlantis apply`, `atlantis import`, and `atlantis state rm` in one repository, or in one directory, workspace, or project of it, for example during an incident or an upgrade. Optionally it freezes plans too, including autoplans. Start one from **Start maintenance** on the **Locks** page with a required reason and an optional end time. Active windows are listed on the overview, the **Locks** page, and the pages of pull requests in the affected repository.

While a window is active, a frozen command is rejected with a pull request comment that gives the reason, who started the window, and when it ends:

```text
Error: atlantis apply is blocked by a maintenance window on acme/infra.
Scope: the whole repository
Reason: Upgrading the state bucket; see INC-4211
Set by: Ada Admin at 2026-11-13 14:00 UTC
Ends: 2026-11-13 18:00 UTC
```

A repo-wide window rejects the command before Atlantis clones the repository. A window for a directory, workspace, or project fails only the projects it covers, so other projects in the same pull request still run. Windows don't touch project locks or the [global apply lock](locking.md); use the apply lock to stop applies in every repository at once.

Starting and ending windows needs the admin role by default. Set `access.permissions.maintenance` to change that. It is set only at the top level, like the apply lock, because a window can block everyone who works in a repository.

::: warning
Maintenance windows are kept in memory on the replica where they were started. They only block commands that replica runs, and they end when it restarts. With several replicas, a webhook that reaches another replica isn't blocked. Durable storage ([ADR 0005](/contributing/adr/0005-use-durable-storage-with-one-data-model.md)) will share them across replicas.
:::

### Policy checks and approvals

When [policy checking](policy-checking.md) is on, a pull request page has a **Policy checks** panel that lists the projects with failing policy sets, and each checked project has a **Policies** page. The page shows each policy set's result, how many approvals it has and needs, who approved it, who can approve it, and the policy tool's output. The overview lists pull requests waiting for a policy approval, and the **Needs policy approval** filter on the pull request list finds them.

Approval counts come from the pull request status in the locking database, so every replica shows them. An approval given for an earlier failure is listed but no longer counts, as with `atlantis approve_policies`. The policy output is read from the `-policyout.json` file the policy check step writes in the project's clone (see [data for custom run steps](policy-checking.md#data-for-custom-run-steps)), and is used only when it is a regular file in the clone that is no older than the saved plan. Other replicas, and every replica once the plan is applied or the pull request closes, show it as unavailable; the pull request comment still has it.

A policy owner can approve from the UI: **Approve policies** on the pull request page approves every failing set they own, **Approve all** on a **Policies** page approves the sets of that project, and **Approve** on a set approves only that set. Each one asks for confirmation, then comments on the pull request with who approved and the equivalent command, and runs `atlantis approve_policies` with the same flags (`-p` or `-d` and `-w`, and `--policy-set`) as that GitHub user. The command checks ownership again with GitHub, records the approval, updates the commit status, and comments the result, exactly as when the person comments the command.

Approving from the UI needs all of:

- The `approve_policies` permission, operator by default. Set `access.permissions.approve_policies`, or `permissions.approve_policies` on a `repos` entry, to change that (see [the access policy](#access-policy-in-the-server-side-repo-config)).
- [GitHub sign-in](#github) on the same host as the repository. Policy owners are GitHub users and teams, so Atlantis approves as the GitHub login you signed in with. Your teams come from your session; Atlantis keeps the teams named in `policies.owners` or a policy set's `owners` that you're a direct member of. As with the comment command, being in a child team doesn't make you an owner through its parent team, although it counts for the access policy.
- Being a policy owner: a user or team in `policies.owners`, which approves every set, or in the set's own `owners`. Authors can't approve a set with `prevent_self_approve`, and an owner's approval counts once.

The UI explains which of these is missing. People who signed in with an OpenID Connect provider or a proxy have no GitHub login, so they can't approve from the UI. Without web sign-in, including with basic auth, nobody can approve from the UI, because Atlantis can't tell which policy owner someone is; comment `atlantis approve_policies` on the pull request instead. Approving from the UI works only for GitHub repositories.

To disable the new UI, remove `web-ui` from `experiments` and restart. Routes under `/ui` then return HTTP 404.

### Web UI plan details

Each project on a pull request page has a **Plan** page that lists every resource the plan creates, updates, destroys, replaces, imports, moves, reads, or removes from state, grouped by action, with filters and attribute-level changes. Values Terraform marks as sensitive are hidden; values known only after apply are labeled. Every other value appears as it does in the plan output, so anyone who can view the UI can read it.

The page reads the JSON plan that the `show` step writes next to the project, the same file [policy checks](policy-checking.md) use. With policy checks enabled, every plan has it. Without them, add `show` after `plan` in the workflow:

```yaml
workflows:
  default:
    plan:
      steps: [init, plan, show]
```

Atlantis uses the JSON only when it is a regular file in the project's clone that is newer than the saved plan, and reads up to 64 MB. The web UI doesn't run Terraform itself. Plan details live in the working directory of the replica that ran the plan, so other replicas show them as unavailable, and they're gone once the plan is applied or discarded or the pull request closes. When job output is no longer in memory, the change counts on pull request pages also come from this file.

### Web UI drift page

When [drift detection](#drift-detection) is enabled, the **Drift** page lists the latest result of every project and ref that `POST /api/drift/detect` checked: whether it drifted, the check failed, or it is in sync, the resource changes Terraform reported, the commit, and when it was checked. Drifted projects come first, and filters show only drifted, failed, in-sync, or stale projects. A check older than a day is marked stale, which usually means the schedule that calls the API stopped. When an open pull request plans the same project, a link opens that plan's [details](#web-ui-plan-details). The overview has a summary of the counts, and the navigation shows how many projects drifted.

The page only reads results. Run detection the same way as before, for example from a scheduled CI job; the UI has no button to start a check, because detection runs a full plan inside the API request. Drift detection keeps no plan file, so the page shows Terraform's counts but not each resource change. Viewing the page needs the viewer role, like the other pages.

::: warning
Drift results are kept in memory on the replica that ran the detection and are lost when it restarts, as with the drift API. With several replicas, each one shows only the checks it ran. Durable storage ([ADR 0005](/contributing/adr/0005-use-durable-storage-with-one-data-model.md)) will share them.
:::

Without drift detection enabled, the page explains how to turn it on and the overview has no drift summary.

### Job timing traces (experimental)

With the `web-traces` experiment, Atlantis records how long each part of a job takes and shows it on a **Timing** tab on the job page, as a waterfall in the style of Jaeger or an APM tool. It needs the `web-ui` experiment:

```sh
atlantis server --experiments=web-ui,web-traces
```

Atlantis records a span for the job, for cloning the repository, and for each workflow step, such as `init`, `plan`, `show`, `policy_check`, `apply`, and `run` steps, and one for each Terraform or OpenTofu command it starts. Pre- and post-workflow hooks are traced as their own jobs. Atlantis then asks each command to report its own spans: it starts an OTLP/HTTP receiver on `127.0.0.1` on a random port, and gives every command, run step, and hook these environment variables:

| Variable | Value |
| --- | --- |
| `OTEL_TRACES_EXPORTER` | `otlp` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://127.0.0.1:<port>` |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` |
| `TRACEPARENT` | The job's trace ID, with the step or command span as the parent |

OpenTofu 1.10 and later export traces when `OTEL_TRACES_EXPORTER=otlp` is set, and so does Terraform, so the waterfall shows `init` broken into backend setup, module installs, and each provider install, and `plan` and `apply` broken into each resource. Older versions ignore the variables, and the waterfall shows only the Atlantis spans.

The receiver only accepts spans whose trace ID Atlantis issued for a job that is still running, or ended less than a minute ago. It accepts protobuf and JSON, limits a request to 4 MiB, and keeps at most 20,000 spans per job; it counts the rest and says so on the page. Spans that arrive after the job, or for traces Atlantis didn't start, are rejected. If the server or a workflow `env` step already sets any `OTEL_` variable, Atlantis leaves that command's environment alone, so its spans go to your collector, and the Timing tab says so.

The waterfall has a time axis and one row per span, nested under its parent, with bars placed by start time and sized by duration. Bars are colored by kind: Atlantis steps, OpenTofu or Terraform work (labeled by whichever reported the spans), providers, and resources. Failed spans are red, and the critical path, the chain of spans the job waited on, is outlined. Select a span to see its timing, status, and attributes. You can collapse a span's children, find spans by name, show the slowest spans first, or show only the critical path; a list of the ten slowest spans sits under the waterfall. HTTP requests, such as registry lookups and provider downloads, are grouped into one collapsed "N HTTP requests" row under their parent and left out of the slowest list unless you select **Include HTTP requests**; a search that matches a request opens its group, and failed requests stay visible. While the job runs the waterfall updates as spans arrive. When a job has more than 300 spans, short spans that each took under half a percent of the job are grouped into "N more spans" rows. The full trace is available from the [JSON API](#web-ui-json-api) at `/ui/api/v1/jobs/{id}/trace`. Viewing traces needs the viewer role, like the job's output.

#### What OpenTofu puts in a trace

A plan of a small configuration with the `null`, `random`, and `time` providers and a local module, traced end to end with OpenTofu 1.13, produced spans named `Init`, `Initialize Backend`, `Get Providers`, `Install Providers - darwin_arm64`, `Install Provider "registry.opentofu.org/hashicorp/null"`, `Install Module "pets"`, `Validate provider configuration`, `Configure provider`, `Plan phase`, `Plan resource instance changes`, `Apply phase`, `Apply resource instance changes`, and an `HTTP GET` for each registry and download request. Attributes name resources (`opentofu.resource_instance.address`), providers, modules, and the plan mode. Variable values, including sensitive ones, did not appear.

Terraform 1.17 reports fewer spans: `initialize backend`, `install modules`, `install providers`, and `HashiCorp Checkpoint` for `init`, and no spans per resource. It names its root span after the whole command line, which can hold `-var` values, so Atlantis keeps only the binary and subcommand, such as `terraform plan`, of any span reported directly under an Atlantis span.

OpenTofu 1.13 marks `Install Module` spans of local modules as errors with the message `no diagnostics` even when `init` succeeds. When a span reported as an error has no message or only `no diagnostics`, and the command it ran under succeeded, the waterfall does not count it as failed; its details still show the reported status. The JSON API returns spans as reported.

Some attributes can be sensitive, though: `url.full` and `http.response.header.location` hold provider download URLs, which can be signed links with tokens in them, and the resource attributes of every span include the command line (`process.command_args`), which can contain `-var` values, the host name, and the user. So by default Atlantis keeps the values of an allowlist of attributes only: resource, provider and module addresses, plan mode, target platform, HTTP method and status, server address, and error type and message. Other attributes keep their key with the value hidden, and resource attributes other than the service name are dropped. [`--web-traces-all-attributes`](server-configuration.md#web-traces-all-attributes) keeps every span attribute value. Atlantis never logs attribute values.

::: warning
Traces are kept in memory on the replica that ran the job, next to its output, and are removed with it when the pull request closes or the server restarts. Other replicas can't show them. Durable storage ([ADR 0005](/contributing/adr/0005-use-durable-storage-with-one-data-model.md)) will share them.
:::

### Web UI JSON API

The data the web UI shows is also available as read-only JSON under `/ui/api/v1`, for scripts and dashboards. `GET /ui/api/v1/openapi.json` returns its OpenAPI 3.1 description. The API is part of the `web-ui` experiment and may change before the UI graduates.

| Path | Returns |
| --- | --- |
| `/instance` | The replica that answered, who you are, and your global permissions |
| `/pulls` | Pull requests with their projects, states, and change counts |
| `/repos/{repo}/pulls/{num}` | One pull request with its locks and maintenance windows |
| `/repos/{repo}/pulls/{num}/plan?dir=&workspace=&project=` | A project's plan details, as on the [plan page](#web-ui-plan-details) |
| `/repos/{repo}/pulls/{num}/policies?dir=&workspace=&project=` | A project's policy check, as on the **Policies** page |
| `/locks` and `/apply-lock` | Project locks and the global apply lock |
| `/jobs` and `/jobs/{id}` | Jobs this replica has a record of. Logs aren't part of the API. |
| `/jobs/{id}/trace` | A job's [timing trace](#job-timing-traces-experimental): every span with its parent, times, status, and attributes |
| `/maintenance` | Active maintenance windows |
| `/drift` | The latest drift detection results |

`{repo}` is the full name, such as `acme/infra`; add `?host=github.com` to pick the VCS host when the same name exists on several. Lists have the shape `{"items": [...], "next": null}`. `next` is always `null` today; clients that follow it when it isn't will keep working once lists are paginated. Times are RFC 3339 in UTC, and unknown values are `null`.

The API uses the same sign-in and rules as the pages:

- With [web UI sign-in](#web-ui-sign-in), requests need the session cookie of a signed-in browser, or the identity headers of the authenticating proxy. A request without one gets HTTP 401 with a JSON error instead of a redirect to the sign-in page. Someone without the viewer role gets HTTP 403 with the reason.
- Without web UI sign-in, the server's [basic auth](server-configuration.md#web-basic-auth) applies, as for the pages.
- Every endpoint needs the `view` permission. Viewing isn't scoped by repository, so the API lists the same pull requests, locks, and jobs as the pages. Each item has a `permissions` object, such as `{"unlock": true}`, that matches the buttons the pages show the same person.

There are no API tokens yet; use the API from a signed-in browser session or behind the authenticating proxy. The API doesn't change anything: unlocking, stopping jobs, maintenance windows, and policy approvals are only on the pages. Requests other than `GET` get HTTP 405.

Responses are never cached (`Cache-Control: no-store`) and contain no session data. Plan details leave out values Terraform marks as sensitive, as the plan page does. Every response that comes from the store has a `capabilities` object that says which data lives only on the replica that answered, for example `"shared_plans": false` for plan details and `"cluster_jobs": false` for jobs. With several replicas behind a load balancer, two requests can get different answers for that data.

### Web UI sign-in

Web UI sign-in replaces basic auth for the pages at `/ui` with your identity provider, and gives each person a role. It only applies to `/ui`; the existing UI and the API keep their current authentication. Sign-in requires the `web-ui` experiment.

| Role | Can |
| --- | --- |
| Viewer | See pull requests, plans, locks, and job logs |
| Operator | Also discard plans, unlock projects, stop running jobs, and approve failing policies they own |
| Admin | Also start and end maintenance windows, and lock and unlock applies for every repository |

Roles come from [`--web-role-admins`](server-configuration.md#web-role-admins), [`--web-role-operators`](server-configuration.md#web-role-operators), and [`--web-role-viewers`](server-configuration.md#web-role-viewers). Each rule is `group:NAME` (or a bare `NAME`) for your identity provider's groups, `github:ORG` or `github:ORG/TEAM` for GitHub, `email:ADDRESS`, `domain:example.com`, or `*` for everyone who signed in. Email and domain rules only match emails the provider marks as verified. The highest matching role wins. People who match no rule are turned away unless you set [`--web-role-default`](server-configuration.md#web-role-default). Atlantis refuses to start with sign-in enabled and no role rules.

There are two ways to sign in:

- **Sign-in pages.** Atlantis redirects to an OpenID Connect provider or GitHub, using the authorization code flow with PKCE. Sessions are encrypted cookies, so any replica can serve any request without sticky sessions. Give every replica the same [`--web-session-secrets`](server-configuration.md#web-session-secrets).
- **An authenticating proxy.** A load balancer or proxy in front of Atlantis signs people in and passes their identity on. Atlantis verifies it on every request and shows no sign-in page.

Register `https://ATLANTIS_URL/ui/auth/callback/oidc` or `https://ATLANTIS_URL/ui/auth/callback/github` as the redirect URI, using your [`--atlantis-url`](server-configuration.md#atlantis-url).

#### Access policy in the server-side repo config

For more than a few rules, or rules that differ per repository, put the policy in the `access` section of the [server-side repo config](server-side-repo-config.md). Rules there add to the `--web-role-*` flags.

```yaml
# repos.yaml
access:
  roles:
    admin:
      - group: platform-admins          # identity provider group
      - email: lead@acme.com            # one person
    operator:
      - github: acme/sre                # GitHub team (child teams count)
      - github_user: octocat            # one GitHub user
    viewer:
      - domain: acme.com
  default: none                         # anyone else is turned away
  permissions:                          # optional; these are the defaults
    view: viewer
    unlock: operator
    stop_job: operator
    approve_policies: operator          # policy owners only, with GitHub sign-in
    maintenance: admin
    lock_applies: admin
  enforce_in_pr_comments: true          # also check "atlantis unlock" comments

repos:
  - id: /.*/
  - id: /github\.com\/acme\/prod-.*/
    access:
      permissions:
        unlock: admin                   # stricter on production repos
        stop_job: admin
        approve_policies: admin
  - id: github.com/acme/data-lake
    access:
      roles:
        operator:
          - group: data-eng             # data-eng can unlock this repo only
```

- Each rule matches exactly one of `group`, `github` (`ORG` or `ORG/TEAM`), `github_user`, `email`, `domain`, or `everyone: true`.
- A `repos` entry can grant extra roles for matching repositories and require a different role to unlock, to stop jobs, or to approve policies there. Viewing, maintenance windows, and the apply lock cover the whole server, so they are set only at the top level. When several entries match, the last one that sets a requirement wins, as with other repo settings.
- With `enforce_in_pr_comments: true`, an `atlantis unlock` comment is checked against the same unlock rule, matching the commenter's GitHub user and teams. Identity provider groups and emails don't apply to comments.
- When sign-in is on, the existing UI's pages redirect to the new UI, and its unlock and apply lock actions follow this policy too.
- The **Access** page in the UI shows the policy in plain words and what you can do in each repository. Atlantis checks the policy at startup and refuses to start with mistakes such as a rule with two attributes or an unknown role.

#### Microsoft Entra ID

Register an application, add the redirect URI as a web platform, and create a client secret. Define app roles such as `atlantis-admins` and `atlantis-operators`, assign them to groups, and read them from the `roles` claim. App roles avoid Entra ID's group limit: when a user belongs to more than 200 groups, Entra ID leaves groups out of the token, and Atlantis turns the sign-in away with an explanation rather than guessing.

```sh
ATLANTIS_EXPERIMENTS=web-ui
ATLANTIS_WEB_SSO_PROVIDERS=oidc
ATLANTIS_WEB_OIDC_NAME="Microsoft Entra ID"
ATLANTIS_WEB_OIDC_ISSUER_URL=https://login.microsoftonline.com/TENANT_ID/v2.0
ATLANTIS_WEB_OIDC_CLIENT_ID=APPLICATION_ID
ATLANTIS_WEB_OIDC_CLIENT_SECRET=...
ATLANTIS_WEB_OIDC_GROUPS_CLAIMS=roles
ATLANTIS_WEB_ROLE_ADMINS=atlantis-admins
ATLANTIS_WEB_ROLE_OPERATORS=atlantis-operators
ATLANTIS_WEB_SESSION_SECRETS="$(openssl rand -hex 32)"
```

Use the tenant-specific issuer; the multi-tenant `common` endpoint is not supported.

#### Google Workspace

Create an OAuth client of type "Web application" with `https://ATLANTIS_URL/ui/auth/callback/google` as an authorized redirect URI. Google has its own provider so it can run next to another OIDC provider such as Entra ID. [`--web-google-allowed-domains`](server-configuration.md#web-google-allowed-domains) is required, because anyone can create a Google account.

```sh
ATLANTIS_WEB_SSO_PROVIDERS=oidc,google   # or just google
ATLANTIS_WEB_GOOGLE_CLIENT_ID=0123-abc.apps.googleusercontent.com
ATLANTIS_WEB_GOOGLE_CLIENT_SECRET=...
ATLANTIS_WEB_GOOGLE_ALLOWED_DOMAINS=acme.com
ATLANTIS_WEB_ROLE_ADMINS=email:platform-lead@acme.com
ATLANTIS_WEB_ROLE_VIEWERS=domain:acme.com
```

Google doesn't include groups in tokens, so grant roles by domain or email. For Google group membership, put [Dex](https://dexidp.io/docs/connectors/google/) in between or use [Identity-Aware Proxy](#google-cloud-identity-aware-proxy).

#### Okta, Keycloak, Auth0, GitLab, Amazon Cognito, and Dex

Use the provider's issuer URL and configure it to send groups. Okta needs a groups claim on the authorization server and the `groups` scope. Keycloak needs a group membership mapper. Auth0 needs an Action that adds a groups claim, and then [`--web-oidc-groups-claims`](server-configuration.md#web-oidc-groups-claims) set to that claim's name. GitLab reports groups from its userinfo endpoint, which Atlantis reads when the ID token has none. Cognito puts groups in `cognito:groups`.

#### GitHub

Create a GitHub OAuth app, or use a GitHub App with user authorization, with the callback URL. [`--web-github-allowed-orgs`](server-configuration.md#web-github-allowed-orgs) is required, because anyone can create a GitHub account. Organizations become groups named `github:ORG` and teams become `github:ORG/TEAM`; a child team's members also count as members of its parent team. The `github:` prefix keeps a GitHub organization from matching a group of the same name from another provider. GitHub Enterprise uses [`--gh-hostname`](server-configuration.md#gh-hostname).

```sh
ATLANTIS_WEB_SSO_PROVIDERS=github
ATLANTIS_WEB_GITHUB_CLIENT_ID=...
ATLANTIS_WEB_GITHUB_CLIENT_SECRET=...
ATLANTIS_WEB_GITHUB_ALLOWED_ORGS=acme
ATLANTIS_WEB_ROLE_ADMINS=github:acme/platform
ATLANTIS_WEB_ROLE_OPERATORS=github:acme/sre
ATLANTIS_WEB_ROLE_VIEWERS=github:acme
```

`--web-sso-providers=oidc,github` shows both buttons.

#### AWS Application Load Balancer and IAM Identity Center

Configure the load balancer listener to authenticate users, then let Atlantis verify the signed `x-amzn-oidc-data` header. IAM Identity Center supports only SAML for application sign-in, so connect it to an Amazon Cognito user pool as a SAML identity provider and point the load balancer at Cognito. Pass groups from Cognito as a `groups` claim to use group rules.

```sh
ATLANTIS_WEB_PROXY_AUTH=alb
ATLANTIS_WEB_PROXY_ALB_ARN=arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/atlantis/abc
ATLANTIS_WEB_ROLE_VIEWERS=domain:acme.com
```

Atlantis checks the signature with the region's public key and that the header was signed by this load balancer. Every listener rule that forwards to Atlantis must authenticate users; otherwise a header issued for another application behind the same load balancer could be replayed. Atlantis trusts the email only when the identity provider sends `email_verified: true`.

#### Google Cloud Identity-Aware Proxy

```sh
ATLANTIS_WEB_PROXY_AUTH=iap
ATLANTIS_WEB_PROXY_IAP_AUDIENCE=/projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID
ATLANTIS_WEB_ROLE_VIEWERS=domain:acme.com
```

#### oauth2-proxy, Pomerium, and other proxies

Have the proxy pass the user, email, and groups in headers, and tell Atlantis which networks the proxy connects from. Atlantis checks the connection's address, not `X-Forwarded-For`, so other clients can't set these headers. Anything else that can connect from those networks can also set them, so keep the networks narrow; Atlantis rejects networks broader than `/8` for IPv4 or `/16` for IPv6.

```sh
ATLANTIS_WEB_PROXY_AUTH=header
ATLANTIS_WEB_PROXY_USER_HEADER=X-Forwarded-User
ATLANTIS_WEB_PROXY_EMAIL_HEADER=X-Forwarded-Email
ATLANTIS_WEB_PROXY_GROUPS_HEADER=X-Forwarded-Groups
ATLANTIS_WEB_PROXY_TRUSTED_CIDRS=10.0.0.0/8
```

#### Sessions and auditing

A sign-in lasts [`--web-session-lifetime`](server-configuration.md#web-session-lifetime), 4 hours by default. The role is decided at sign-in and kept for the whole session, so someone removed from a group keeps their role until the session ends. Signing out clears the session in that browser only. To end every session at once, for example after removing an administrator, replace all session secrets and restart. Session cookies are `Secure` unless Atlantis runs on `localhost` over plain http.

Sign-ins, sign-outs, denials, and every action are logged with the user, provider, and role; discarded-plan and policy approval comments on pull requests name the user. When a sign-in fails for a reason the user can't fix, the page shows a short reference that matches the detailed log entry.

### Web UI graduation checklist

- [x] Serve the UI only with the `web-ui` permission. Evidence: route tests in `server/experiments_test.go`.
- [ ] Accept the ADR for web sign-in and role-based access; sign-in is implemented behind this experiment.
- [ ] Serve job history and logs from durable storage when the `durable-storage` experiment is enabled.
- [ ] Decide whether the new UI replaces the UI at `/`, and document the migration.
- [ ] Record the graduation decision and first stable release in [web UI tracker #6158](https://github.com/runatlantis/atlantis/issues/6158).

See the [feature lifecycle ADR](/contributing/adr/0004-govern-feature-lifecycles.md) for the lifecycle policy and graduation requirements.
