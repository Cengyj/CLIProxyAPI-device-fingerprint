# Codex device fingerprint patch

## Scope and operation

This opt-in local source patch converges the installation identity of Codex OAuth
Responses requests. It is disabled by default. It does not implement `session`
or `full`, change CPA's existing session/cache behavior, or emulate an entire
physical device. It provides no guarantee about account enforcement or quota.
UA/Originator cloaking remains an independent existing feature.

The built-in stage rewrites an existing
`client_metadata.x-codex-installation-id`, and an existing top-level
`installation_id` in the JSON string
`client_metadata.x-codex-turn-metadata`. It also processes every case variant and
value of `X-Codex-Turn-Metadata`, dropping invalid JSON-object values individually.
It removes every standalone `X-Codex-Installation-Id` header before administrator
header overrides. It does not create turn metadata or add `installation_id` to an
existing turn object that lacks that key. Invalid body turn metadata is deleted.
Other metadata, large numbers, Unicode, and escaped strings retain their values.
Duplicate device keys are normalized locally; duplicate outer `client_metadata`
keys are rejected with a request-scoped 400 instead of forwarding an ambiguous
identity. Invalid outer shapes remain subject to CPA's existing validation.

Session, thread, window, turn, request ID, turn state, prompt cache key, message,
tool, response, and continuation IDs are outside this module's mutation scope.
"Off preserves behavior" means no additional changes relative to upstream CPA;
CPA already performs its own request normalization.

## Configuration

Default, explicitly disabled:

```yaml
oauth:
  providers:
    codex:
      device-fingerprint-mode: off
      device-fingerprint-inject-missing: false
```

For initial rollout, keep this global configuration and add top-level metadata to
only the intended OAuth auth file, using your normal credential administration
workflow:

```json
{
  "codex_device_fingerprint": "device"
}
```

The fragment is an addition to an existing credential, not a complete credential
file. No production credential or actual configuration was edited by this patch.
To pin an identity across environments, optionally add an administrator-chosen
UUIDv4:

```json
{
  "codex_device_fingerprint": "device",
  "codex_installation_id": "11111111-2222-4333-8444-555555555555"
}
```

That UUID is an example, never a common default. Assigning the same explicit ID
to two accounts intentionally removes automatic isolation between them. An ID
alone does not enable the feature. Set an account's
`codex_device_fingerprint` to `off` to override global `device`.

Global enablement:

```yaml
oauth:
  providers:
    codex:
      device-fingerprint-mode: device
      device-fingerprint-inject-missing: false
```

Only `off` and `device` are recognized after trimming whitespace and normalizing
case. Omitted, empty, or unknown modes disable processing. Unknown-mode warnings
are bounded and never include the supplied string. A nonempty Attributes value
wins over the corresponding top-level Metadata value, which wins over global
mode. Invalid explicit IDs fall through to valid lower-priority identity sources.

`device-fingerprint-inject-missing` is an optional boolean; omission and explicit
false remain distinguishable in configuration snapshots. True permits adding the
installation field to a valid metadata object, or creating that object when
absent. It never converts null/array/scalar metadata into an object. SIWC and
steer/interrupt control frames never inject missing fields.

These settings belong under `oauth.providers.codex`, not `upstream.codex`.
Existing legacy `codex:` parsing, v8 migration, saving and YAML snapshots use the
existing automatic mapping. API-key credentials always bypass the feature,
including legacy global or per-credential enablement. Existing credential refresh
and save merging preserves the custom fields; tests exercise synthetic refresh,
file persistence and concurrent administrator edits.

## Identity selection and stability

A request resolves one immutable policy from its selected OAuth credential and
actual upstream route. The same snapshot drives body and headers. HTTP compression
fallback retains it; a newly selected credential starts a fresh snapshot.

Selection order:

1. A valid `siwc.device_id` only when the existing per-request routing decision
   actually selects SIWC. The presence of SIWC credentials alone is insufficient.
2. Valid explicit `codex_installation_id` in Attributes, then Metadata.
3. `account_id`, falling back to the existing ID-token parser's
   `chatgpt_account_id`. Explicit Team/Business/Enterprise/Edu plans include
   `chatgpt_user_id` to distinguish members.
4. Stable `auth.ID` when no safe account identity is available. With neither,
   convergence is skipped; unknown accounts never share a default identity.

The parser is used only for existing credential metadata, not a new authentication
protocol. Missing plan claims are not treated as the parser's default `free`.
A token associated with a different account cannot supply its old member/plan.
Team-like identities without a user ID fall back to `auth.ID` with a bounded
warning, rather than merging members by workspace ID. Explicit IDs avoid this
fallback.

The namespace and complete-identity vectors follow the reference PR:

```text
prefix = "cli-proxy-api:codex:device-fingerprint:v2:"
account:      prefix + "account\x00" + accountID
account-user: prefix + "account-user\x00" + accountID + "\x00" + userID
auth fallback:prefix + "auth-id\x00" + authID
```

Here `\x00` is a NUL byte. SHA-256 is calculated over the complete seed; the first
16 bytes receive UUID version-4 and RFC 4122 variant bits and are emitted in
lowercase. This is deterministic, not a new random UUID on each request. Explicit
IDs require the standard hyphenated UUIDv4 form and valid variant; URNs, braces,
compact forms, nil IDs and other versions are rejected.

Normal account-derived IDs survive token refresh, email removal, credential object
replacement, file renaming and process restart when account identity is unchanged.
Each executor retains at most 512 recent identity hints in a mutex-protected LRU;
there are no token caches, background workers, database changes or per-request
credential writes. Hints fill temporarily missing fields only for a compatible
account, and cannot mix a new account with the previous account's user/plan.
Executor replacement during configuration reload also discards these hints.
Warnings are bounded by reason per executor and contain no account, user, email,
JWT, token or full device value.

Fallback IDs can change when an account becomes known, an auth ID changes, or
missing-field hints are evicted/lost on restart. Independent instances derive the
same ID from the same complete identity; they do not share hints. Use an explicit
ID when permanent cross-environment pinning is required.

## Final administrator rules and WebSockets

Device JSON processing runs before `helps.FinalizePayloadDoc`, on the same main
`*ojson.Doc`. User default/override/filter rules execute once per constructed
attempt and remain the last semantic mutation. Rule matching can observe built-in
convergence. Filtering the installation field, turn metadata or whole metadata
object remains final. The original translated bytes supply shape validation without flattening a mutated
main Doc; the final serialized body also receives a read-only ambiguity check.
Nested JSON strings use local Docs; no whole-body
`map[string]any` decode/re-encode is introduced.

Built-in header handling precedes auth `header:` attributes, which retain their
existing priority relative to model `override_header`. Administrators may therefore
explicitly restore a standalone header, override device values or create conflicts
between body/header. Body/header equality is guaranteed for built-in values only
when no conflicting explicit rules apply. The module never rewrites final payloads
to repair such a conflict.

Each physical WS connection holds its policy and a minimal identity made from
final device values and mode/SIWC scope. It ignores turn/session/thread/cache fields.
Missing device fields impose no new identity and do not generate random reconnects.
Effective explicit overrides participate in compatibility; derived IDs alone are
not used as the reuse key. Ordinary complete requests reconnect at an existing safe
boundary when incompatible. Required-socket, previous-response and instruction-chain
continuations fail through the existing replay/session recovery mechanism instead
of moving an incremental request to another connection.

An active duplex freezes device mode, installation policy, injection and SIWC
semantics. Subsequent create/append pass through the normal final business barrier;
steer rewrites only existing device fields before its business rules. Its `type`
discriminator remains necessary transport framing. Interrupt uses the target
connection's locked snapshot and existing pointer/state rechecks, preserves its
control fields, and does not acquire ordinary payload rules. Device values first
presented by an interrupt are bound under the connection lock before sending,
so later business frames cannot silently adopt a different identity. Ambiguous configured
control identities are rejected rather than sent on an incompatible connection.
Connection detach, invalidate, close and competing dial paths clear device state
alongside connection state. Existing lock order, lifecycle End/close-once behavior
and liveness deadlines are preserved; no post-connect timeout was added.

Hot reload applies to new HTTP requests and ordinary WS requests at a reconnectable
boundary. An active duplex keeps its device snapshot. Restart operationally when all
connections must switch together. Turning mode off restores existing CPA behavior,
not removal of CPA cloaking; an active duplex must end or be restarted to switch.

## Routes and limits

Included: Codex OAuth requests whose final target is Responses or
Responses/compact, including custom OAuth base URLs and local test servers. HTTP
Execute/ExecuteStream/compact share the request builder. Legacy image-tool requests
converted to Responses also enter that builder. WS Execute, ExecuteStream, fallback,
subsequent duplex business frames and existing-field controls are integrated.

Excluded: API-key credentials, direct `/images/*`, alpha/search, Live media,
arbitrary plugin `HttpRequest`, management api-call, and other providers. These are
not expanded just because an incoming client URL resembles Responses. CountTokens
is local and has no device/network side effect. No translator, scheduler, quota,
cache ownership, TLS identity, management endpoint, UI or plugin framework was
changed. This scope is not a claim about uninspected future upstream routes.

## Provenance and patch organization

- Official remote: `upstream`, `https://github.com/router-for-me/CLIProxyAPI.git`.
- Official baseline: tag `v8.1.4`, commit
  `38fe929502f19f7cce03c69c19aacddf30f1ef5e`.
- Working checkout: `/Users/ceng/Downloads/CLIProxyAPI-device-fingerprint`.
- Working branch: `feat/codex-device-fingerprint`.
- Original `/Users/ceng/Downloads/CLIProxyAPI-8.1.4` is preserved. At implementation
  time it had an isolated local baseline commit, no official remote/history, and
  all 2,670 official files matched the verified tag. Nothing private was migrated.
- Reference: [zyaireleo/CLIProxyAPI PR 22](https://github.com/zyaireleo/CLIProxyAPI/pull/22),
  fixed head `f79ef07a59ca5c327a110f739943c43c3c20d6a9`, base
  `dbb706215a3afd2f0ea3c96482d4233856466caa`, merge
  `fd4fdcf222828309eb011a296e92acc5d07d0aa8`, targeting that fork's
  `upstream-v8-dbb70621`. The actual fixed diff/source, not the fork's default
  branch, informed this implementation.
- The repository [MIT license](../LICENSE), including Luis Pater and Router-For.ME
  notices, is preserved. The reference PR uses the same license. sub2api supplied
  semantic comparison only; its LGPL implementation was not copied.

Local patch commits are recorded in the delivery record below. They are deliberately
small in number; code and tests form one buildable unit and the documentation forms
a separate commit. To identify the documentation commit without a self-referential
hash, use `git log -1 --format=%H -- docs/codex-device-fingerprint.md`.

Intentional differences from the reference PR include OAuth-only scope enforcement,
final administrator payload/header precedence, moego Docs, an executor-scoped
bounded identity cache, no raw secret/identity logging, Team missing-user fallback,
account-change isolation, raw duplicate-metadata rejection, and WS compatibility
based on final effective values including session-instruction continuations and
controls. Helper files live in `helps/`, not alongside executor implementations.

## Official integration points to inspect on upgrade

| Official file / functions | Reason for the edit and invariant to preserve |
|---|---|
| `.gitignore` | Allow this maintenance document to be versioned under the existing ignored `docs/` directory. |
| `config.example.yaml` / `oauth.providers.codex` | Describe defaults and opt-in behavior without changing real configuration. |
| `internal/config/config_types.go` / `CodexConfig` | Add mode string and optional inject boolean. Keep automatic OAuth mapping; do not move them under shared upstream settings. |
| `internal/watcher/diff/config_diff.go` / `BuildConfigChangeDetails` | Expose hot reload changes using bounded/sanitized mode descriptions and optional boolean values, with no device/account data. |
| `internal/runtime/executor/codex_executor.go` / `CodexExecutor`, `NewCodexExecutor` | Own bounded resolver state for the executor lifetime, never a global current ID. |
| `internal/runtime/executor/codex_executor_request.go` / `cacheHelper`, `cacheHelperDoc` | Resolve selected auth/route once, validate ambiguity, mutate the same Doc before `FinalizePayloadDoc`; carry snapshot on the resulting request context through compression fallback. |
| `internal/runtime/executor/codex_executor_execute.go` / `Execute`, `executeCompact`; `codex_executor_stream.go` / `ExecuteStream`; `codex_openai_images.go` / `executeOpenAIImage`, `executeOpenAIImageStream` | Pass the original translated business bytes to the shared builder for object/duplicate validation without flattening the mutated main Doc, including multipart image conversion. Keep all semantics in the shared finalization path. |
| Same request file / `applyCodexHeadersWithSIWC` | Both normal and SIWC early-return branches run built-ins before `ApplyCustomHeadersFromAttrs`; model overrides remain later. No independent identity resolution in header helpers. |
| `internal/runtime/executor/codex_websockets_execute.go` / `Execute` | Snapshot and modify before finalizer, derive compatibility from final body/handshake, gate required/connection-bound reuse and retry with the same snapshot. |
| `internal/runtime/executor/codex_websockets_stream.go` / `ExecuteStream`, `codexWebsocketPrepared`, `prepareCodexWebsocketStream`, `prepareCodexWebsocketStreamWithDevice` | Prepared state carries policy/effective identity; normal attempts resolve anew, duplex supplies frozen policy; final rules execute once before serialization/framing. |
| `internal/runtime/executor/codex_websockets_request.go` / `prepareSessionInstructions`, `applyCodexWebsocketHeaders` | Exclude incompatible connection proof, check final identity before sending, and process both handshake branches before administrator header overrides. |
| `internal/runtime/executor/codex_websockets_session.go` / `codexWebsocketSession`, device binding/reuse helpers, `ensureUpstreamConnWithSIWC`, detach/invalidate/close | Physical identity is protected by `connMu`. Install/clear it with the connection; no lock held across dial or auth-manager work, and no stale state after losing a dial race. Shared transport users keep existing behavior. |
| `internal/runtime/executor/codex_websockets_duplex.go` / `streamCodexDuplex` | Freeze device policy for create/append; steer changes existing fields before final business rules; validate effective compatibility without modifying final values. |
| `internal/runtime/executor/codex_websockets_executor.go` / `InterruptExecutionSession` | Read target policy inside existing connection-pointer/state checks; only existing fields, no ordinary business payload rules; reject incompatible control identity. |

Independent implementation files:

- `internal/runtime/executor/helps/codex_device_fingerprint.go`: resolver, immutable
  policy, bounded state, UUID/claims selection, local Doc/header handling, final
  effective identity compatibility.
- `internal/runtime/executor/helps/codex_device_fingerprint_connection.go`: complete
  source header forwarding and identity checks against a frozen duplex policy.
- `internal/runtime/executor/helps/codex_device_fingerprint_test.go`: identity,
  golden vectors, shapes/duplicates/precision, scope, state bounds and concurrency.
- `internal/runtime/executor/codex_device_fingerprint_test.go`: HTTP wire captures,
  final rules, compression fallback, auth reselection, scope and header precedence.
- `internal/runtime/executor/codex_device_fingerprint_ws_test.go`: real handshakes,
  frames, reuse/reconnect/continuations, duplex and interrupt lifecycle.
- `internal/runtime/executor/codex_device_fingerprint_persist_test.go`: synthetic
  refresh/save preservation and administrator edits.
- `internal/config/codex_device_fingerprint_test.go` and
  `internal/watcher/diff/codex_device_fingerprint_test.go`: mapping, migration,
  snapshots, scope, defaults and change visibility.

Inspected but intentionally unchanged: `config_v8.go`, `oauth_scope.go`,
`oauth_scope_executor.go` (API-key views share a resolver pointer instead of copying
a mutex), `codex_executor_tokens.go` (local CountTokens), `helps/payload_finalizer.go`,
`helps/codex_session_instructions.go`, `codex_executor_auth.go`, and
`sdk/cliproxy/auth/codex_persist.go`. Upgrade review must revisit these dependencies
as well as changed files, especially if a request path stops using the shared
builder or moves the final barrier.

## Updating the official baseline safely

Prefer replaying the small feature commits on a new candidate branch. Preserve the
current working branch until validation and operational adoption are complete.
Choose a specific official tag/commit deliberately; do not select "latest"
automatically. For an already shared release branch, follow its established merge
workflow and never rewrite its published history.

Example manual workflow (replace placeholders after reviewing actual history):

```bash
git status --short
git remote -v
git fetch upstream --tags
git show --no-patch --format=fuller <chosen-official-tag-or-commit>
git switch -c <new-upgrade-candidate> <chosen-official-tag-or-commit>
git cherry-pick <feature-code-commit> <maintenance-document-commit>
```

Resolve conflicts semantically and inspect every integration point. Never use
`merge --allow-unrelated-histories`, force-push, overwrite complete files to resolve
conflicts, or copy an old executor over a newer official implementation. There is
no automated stash/reset/rebase/update script in this patch.

A conflict-free Git operation is insufficient. Enumerate every Codex request exit,
including newly added routes. Recheck finalizer position, one evaluation per
attempt, SIWC early returns, auth/model header priority, frozen WS policy and
actual effective values, required reuse, session-instruction proofs, steer,
interrupt, disconnect/replay behavior, compressed retries and HTTP fallback.
Review the independent helper/tests separately from these official integration
points. Update this inventory and the validation record before deciding whether to
replace the working version.

If upstream introduces an equivalent feature, compare defaults, UUID algorithm,
explicit override priority, migration/scope, SIWC behavior, WS lifecycle and test
coverage. Prefer migrating to upstream and removing this patch after validating
identity continuity. Do not run two independent rewrites or change installation
IDs silently.

## Regression commands

The prefix `TestCodexDeviceFingerprint` is shared by all new tests and is selected
by the commands below. Verify the command actually reports tests, never treat
`[no tests to run]` as coverage. Baseline and candidate must use the same Go version
and environment. Do not upgrade dependencies or modify `go.sum` just to pass.

```bash
gofmt -w .
go test -mod=readonly ./internal/config ./internal/watcher/diff ./internal/runtime/executor/helps ./internal/runtime/executor -run 'CodexDeviceFingerprint' -count=1
go test -mod=readonly ./internal/runtime/executor/helps ./internal/runtime/executor -run '^(TestPayloadRulesMatchFinalBodyAndTrackPaths|TestFinalizePayloadDocCrossMethodPipeline|TestCodexSessionInstructionsHTTP|TestCodexSessionInstructionsWebsocket|TestCodexDuplexSteerPayloadBarrier)$' -count=1
go test -mod=readonly ./internal/config ./internal/watcher/diff ./internal/runtime/executor/helps ./internal/runtime/executor -count=1
go test -mod=readonly -race ./internal/runtime/executor/helps ./internal/runtime/executor -run 'CodexDeviceFingerprint' -count=1
go vet ./internal/config ./internal/watcher/diff ./internal/runtime/executor/helps ./internal/runtime/executor
go test -mod=readonly ./...
go build -o test-output ./cmd/server && rm test-output
git diff --check
```

Tests use local HTTP/WS servers, synthetic credentials and deterministic cache
operations; no production account is required. Do not use wall-clock sleeps for
cache eviction or ordering assertions. Report any race/platform block or failure
honestly; reproduce suspected pre-existing failures against the exact official
baseline in the same environment before attributing them to upstream.

## Rollback

For configuration rollback, set global mode to `off` and remove/disable per-auth
`device` overrides; a per-auth override still wins over the global default.
No credential/token rollback is needed. New HTTP attempts use the disabled policy;
ordinary full WS requests switch at a safe reconnect boundary. Finish/restart
active duplex streams or restart the service if every socket must switch now.

For code rollback on a local candidate, preserve the current branch and create a
new branch at the recorded official baseline, or revert the feature code commit
and then the documentation commit on an established branch. Verify build/tests
and review any now-unrecognized configuration fields before adoption. Do not reset
unrelated local work. Code rollback restores upstream CPA's own cloaking and
session logic, not a promise of raw client-byte forwarding.

## Delivery validation record

Validated on 2026-11-26 with Go `go1.27.1 darwin/arm64` (`go.mod` requires
`1.26.10`). Dependencies and `go.sum` are unchanged. No live account or production
upstream was used. The original official baseline passed both the five named
barrier/session tests and an initial `go test -mod=readonly ./...`.

Patch commit list:

1. `2d5e1b9c19a4e56f484681d16021fc387c856ace` — feature code, configuration,
   HTTP/WS integration and tests (buildable independently).
2. `docs(codex): document device fingerprint operation and upstream patch maintenance`
   — this document and its `.gitignore` exception. Resolve its exact SHA with
   `git log -1 --format=%H -- docs/codex-device-fingerprint.md`; the delivery reply
   also records it. This avoids embedding a commit's own hash into its content.

New test count: 40 top-level `TestCodexDeviceFingerprint*` tests with table-driven
subtests. Required feature tests, the five named payload/session regressions,
feature `-race`, vet, final related-package suite, build and whitespace checks
passed. Full-suite result is recorded below after the final run.

`gofmt -w .` was run. The installed Go formatter also reformatted two unrelated
baseline test files (`claude_thinking_replay_test.go` and
`codex_stream_bootstrap_buffering_test.go`); those formatting-only changes were
restored so this patch does not touch unrelated official files.

One early related-package run encountered
`TestAIStudioExecutorClaudeMalformedFunctionCallCancelAfterErrorRecordsConductorFailure/stream_end`,
which timed out waiting for a conductor result. The exact unchanged official
baseline reproduced it twice in 20 repetitions using:

```bash
go test -mod=readonly ./internal/runtime/executor -run '^TestAIStudioExecutorClaudeMalformedFunctionCallCancelAfterErrorRecordsConductorFailure$' -count=20
```

All 2,670 official files were reverified against the baseline after reproduction.
This establishes a pre-existing intermittent failure, not its precise cause. No
unrelated test was weakened or fixed. A subsequent final related-package run passed.

A separate package run encountered
`TestClaudeExecutor_ExecuteStream_Translated_ClientDisconnectAfterTerminalEventIsNotFailed`
with an unexpected refusal usage record. Its baseline investigation and final
full-suite status are recorded below. These intermittent failures are retained in
this record even when later required runs pass.

No validation was blocked by the environment. Production deployment, multi-instance
operation with real credentials, and future official versions are intentionally
unverified. The golden vectors, same-account/recreated credentials, bounded hints,
HTTP fallback/reselection, local WS lifecycle and final-rule behavior are covered
by local tests, not a claim about account safety or quota.


Final results for feature code commit `2d5e1b9c19a4e56f484681d16021fc387c856ace`:

| Check | Result |
|---|---|
| New feature selection in four packages | PASS; 40 top-level tests, with subtests |
| Five named payload/session regression tests | PASS |
| Complete config/diff/helpers/executor tests (`-count=1`) | PASS on final run; executor 80.911s |
| New helpers/executor tests with `-race` | PASS |
| `go vet` for all four relevant packages | PASS |
| `go test -mod=readonly ./...` | PASS on final run; executor 79.092s |
| Server build and removal of `test-output` | PASS |
| `git diff --check` | PASS |
| Dependency changes | None |

The separate Claude failure was **not reproduced on the official baseline**:
its isolated test passed 20 repetitions, its combination with the relevant refusal
test passed 20 repetitions, and all `TestClaude*` tests passed five repetitions
(233.557s). It remains an unexplained intermittent observation, not a confirmed
upstream defect. The final relevant-package and full-suite runs passed; no
workaround or unrelated code change was introduced.

Detailed local run logs are available for this implementation session at
`/tmp/codex-device-feature-tests.log`, `/tmp/codex-device-barrier-tests.log`,
`/tmp/codex-device-packages-delivery.log`, `/tmp/codex-device-race-tests.log`,
`/tmp/codex-device-vet.log`, `/tmp/codex-device-full-delivery.log`,
`/tmp/codex-device-baseline-aistudio-repro.log`, and
`/tmp/codex-device-second-baseline-status.txt`. These temporary logs are supporting
local evidence, not required build inputs or durable release artifacts.
