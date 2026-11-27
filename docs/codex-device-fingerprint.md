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
The internal `plan_type_defaulted` marker preserves this distinction through local
OAuth exchange/refresh, login storage, refresh receipts, file saves and synthesis.
It does not change the default `free` seen by existing catalog/scheduling code.
The marker belongs to its own Attributes or Metadata source; an explicit `free`
without a true marker remains a real plan transition. Explicit false clears an
older default marker. Legacy files/receipts that already contain `free` without
provenance are inherently ambiguous and are treated as explicit. Do not edit this
internal marker as a device-mode setting. A separately versioned Home credential
producer must preserve the same provenance; that remote producer was not available
for validation in this checkout. Use an explicit installation override when its
missing-plan recovery cannot be established.
A token associated with a different account cannot supply its old member/plan.
When refresh adopts newer credentials already rotated on disk, it replaces or
clears the old account, member, plan and auxiliary token hints as one identity
partition. A newly supplied disk member or token cannot be shadowed by the old
in-memory member, including when both members use the same explicit installation ID.
Absent versioned account/token fields are explicitly cleared through the existing
refresh patch, keeping Manager version checks intact. A late refresh whose outer
credential partition has been superseded cannot replace the current identity
hints, even when its independent SIWC partition can still be applied.
The current `Metadata.id_token` takes precedence over an auxiliary
`Attributes.id_token`, matching OAuth refresh persistence; mode and explicit
installation overrides retain their separate Attributes-first priority.
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
Each automatic Codex executor shares at most 512 recent identity hints between
its HTTP and WS implementations in a mutex-protected LRU;
there are no token caches, background workers, database changes or per-request
credential writes. Hints fill temporarily missing fields only for a compatible
account, and cannot mix a new account with the previous account's user/plan.
If partial metadata contradicts a cached member while its account is absent, the
old hint is evicted immediately; a later empty refresh cannot resurrect it.
Executor replacement during configuration reload also discards these hints.
Warnings are bounded by reason per executor and contain no account, user, email,
JWT, token or full device value.

Fallback IDs can change when an account becomes known, an auth ID changes, or
missing-field hints are evicted/lost on restart. Independent instances (including
separately constructed HTTP/WS executors) derive the same ID from the same complete
identity; they do not share hints. Use an explicit
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
final device values, mode/SIWC scope, and a private digest of the selected credential
subject. The subject guard prevents an authenticated socket from being reused for
a different account or Team member even when an administrator assigns the same
public UUID or filters all device fields. It does not change public UUID derivation
or make shared administrator UUIDs automatically isolated. If metadata cannot
reveal a subject change, the guard cannot infer one from unchanged auth/device IDs. It ignores turn/session/thread/cache fields.
Missing device fields impose no new identity and do not generate random reconnects.
Removing a configured handshake header does not unsend it on a retained socket;
the next fresh handshake omits it. End the session/restart to require immediate
removal from all physical connections.
A newly requested device handshake header requires a new handshake: an ordinary
complete request reconnects; a continuation or active duplex requests replay.
Candidate headers are never remembered as sent when the socket was merely reused.
Effective explicit overrides participate in compatibility; derived IDs alone are
not used as the reuse key. Ordinary complete requests reconnect at an existing safe
boundary when incompatible. Required-socket, previous-response and instruction-chain
continuations fail through the existing replay/session recovery mechanism instead
of moving an incremental request to another connection.

An active duplex freezes device mode, installation policy, injection and SIWC
semantics from the actual physical socket, including when the initial complete
request reused that socket through an administrator override. A later policy
masked by final rules cannot silently become the connection policy. Subsequent create/append pass through the normal final business barrier;
steer rewrites only existing device fields before its business rules. Its `type`
discriminator remains necessary transport framing. Interrupt uses the target
connection's locked snapshot and existing pointer/state rechecks, preserves its
control fields, and does not acquire ordinary payload rules. Device values first
presented by an interrupt are bound under the connection lock before sending,
so later business frames cannot silently adopt a different identity. Ambiguous configured
control identities are rejected rather than sent on an incompatible connection.
An independent duplex local-summary HTTP request resolves its own attempt policy;
its synthetic-parent append returns to the frozen WS policy and still passes the
final business barrier. An incompatible new explicit identity requires replay.
A failed interrupt write retires the enabled socket and clears device state,
because a partial frame may already have exposed its identity.
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
| `internal/config/config_yaml.go` / `renderConfigSave`, `isKnownDefaultValue` | Preserve newly added explicit inject false and its provider mapping; remove the saved field when the optional value returns to nil. Clearing mode must also remove the old saved mode instead of retaining device through the comment-preserving merge. |
| `internal/watcher/synthesizer/file.go` / `synthesizeFileAuths` | Label parser-defaulted free in synthesized attributes while preserving existing plan defaults and explicit values. A foreign-account JWT cannot supply the selected account's plan. |
| `internal/auth/codex/openai.go`, `token.go` / token data, `SaveTokenToFile` and outer credential allowlist, `openai_auth.go` / exchange, refresh, storage creation/update, `refresh_journal.go` / `decodeRefreshReceipt` | Carry source provenance with refreshed credentials, including false to clear prior true. Persist member and claim-plan hints with the selected credential partition. Ordinary saves retain administrator edits/deletions, re-login clears absent old credential fields, and an empty disk object preserves incoming credentials. Preserve existing access-token-only replacement semantics. |
| `internal/auth/codex/refresh_patch.go` / `CanApplyOuterTo`, `Apply`, `applyCredentialFields`, `sdk/cliproxy/auth/metadata_merge.go` / `mergeAuthContent`, `MergeExistingAuthMetadata` | Validate the outer credential version before adopting or clearing identity fields, independently of SIWC. Keep Metadata and auxiliary Attributes with accepted outer credentials. Codex re-login inherits administrator settings while excluding the previous credential's identity hints. Other providers retain their merge behavior. |
| `sdk/auth/codex_device.go` / `buildAuthRecord` | Populate account, JWT, member and plan hints from the acquired credential, with matching-account validation and plan-default provenance. These fields must survive Storage flattening and existing-file metadata merging. |
| `sdk/cliproxy/auth/codex_persist.go` / `PersistCodexAuthFile`, `synchronizeCodexIdentityAttributes` | Keep the returned Metadata, auxiliary Attributes and Storage consistent with the actually persisted credential partition. Clone shared auxiliary state and preserve administrator device/header settings. File, Postgres, Git and ObjectStore call this boundary. |
| `internal/runtime/executor/codex_executor_auth.go` / `refreshLocked` | Local OAuth refresh and rotated-disk adoption replace or clear account/member/token/plan hints together in Metadata and Attributes. Preserve plan-default provenance, bounded missing-claim recovery and administrator overrides. |
| `internal/runtime/executor/helps/home_refresh.go` / `AdoptCodexHomeIdentity` | Adopt the returned Home credential's identity after its overlay. Clear inherited absent hints, validate token-account agreement and retain administrator/SIWC settings. The remote producer protocol requires separate integration validation. |
| `internal/watcher/diff/config_diff.go` / `BuildConfigChangeDetails` | Expose hot reload changes using bounded/sanitized mode descriptions and optional boolean values, with no device/account data. |
| `internal/runtime/executor/codex_executor.go` / `CodexExecutor`, `NewCodexExecutor` | Own bounded resolver state for the executor lifetime, never a global current ID. |
| `internal/runtime/executor/codex_executor_request.go` / `cacheHelper`, `cacheHelperDoc` | Resolve selected auth/route once, validate ambiguity, mutate the same Doc before `FinalizePayloadDoc`; carry snapshot on the resulting request context through compression fallback. |
| `internal/runtime/executor/codex_executor_execute.go` / `Execute`, `executeCompact`; `codex_executor_stream.go` / `ExecuteStream`; `codex_openai_images.go` / `executeOpenAIImage`, `executeOpenAIImageStream` | Pass the original translated business bytes to the shared builder for object/duplicate validation without flattening the mutated main Doc, including multipart image conversion. Keep all semantics in the shared finalization path. |
| Same request file / `applyCodexHeadersWithSIWC` | Both normal and SIWC early-return branches run built-ins before `ApplyCustomHeadersFromAttrs`; model overrides remain later. No independent identity resolution in header helpers. |
| `internal/runtime/executor/codex_websockets_execute.go` / `Execute` | Snapshot and modify before finalizer, derive compatibility from final body/handshake, gate required/connection-bound reuse and retry with the same snapshot. |
| `internal/runtime/executor/codex_websockets_stream.go` / `ExecuteStream`, `codexWebsocketPrepared`, `prepareCodexWebsocketStream`, `prepareCodexWebsocketStreamWithDevice` | Prepared state carries policy/effective identity; normal attempts resolve anew, duplex supplies frozen policy; final rules execute once before serialization/framing. |
| `internal/runtime/executor/codex_websockets_request.go` / `prepareSessionInstructions`, `applyCodexWebsocketHeaders` | Exclude incompatible connection proof using one locked target/device snapshot, without a second off-mode transport check; check final identity before sending, and process both handshake branches before administrator header overrides. |
| `internal/runtime/executor/codex_websockets_session.go` / `codexWebsocketSession`, device binding/reuse helpers, `ensureUpstreamConnWithSIWC`, detach/invalidate/close | Physical identity is protected by `connMu`. Install/clear it with the connection; no lock held across dial or auth-manager work, and no stale state after losing a dial race. Require a new handshake for newly requested device headers; omitted candidate headers remain unconstrained. Shared transport users keep existing behavior. |
| `internal/runtime/executor/codex_websockets_duplex.go` / `streamCodexDuplex` | Freeze the actual physical socket policy for create/append, including a reused initial connection; reject candidate handshake changes. Steer changes existing fields before final business rules, and only its body contributes new observed identity; validate compatibility without modifying final values. |
| `internal/runtime/executor/codex_websockets_executor.go` / `NewCodexAutoExecutor` | Share the bounded resolver between HTTP and WS for this executor lifetime, so transport selection does not lose temporary identity hints. |
| `internal/runtime/executor/codex_websockets_executor.go` / `InterruptExecutionSession` | Read target policy inside existing connection-pointer/state checks; only existing fields, no ordinary business payload rules; reject incompatible control identity. Invalidate an enabled socket after a failed control write to clear uncertain bindings. |

Independent implementation files:

- `internal/runtime/executor/helps/codex_device_fingerprint.go`: resolver, immutable
  policy, bounded state, UUID/claims selection, private credential subject binding,
  local Doc/header handling, final effective identity compatibility.
- `internal/runtime/executor/helps/codex_device_fingerprint_connection.go`: complete
  source header forwarding with deterministic case-variant ordering on retries,
  handshake compatibility and identity checks against a frozen duplex policy.
- `internal/runtime/executor/helps/codex_device_fingerprint_test.go`: identity,
  golden vectors, shapes/duplicates/precision, scope, state bounds and concurrency.
- `internal/runtime/executor/codex_device_fingerprint_test.go`: HTTP wire captures,
  final rules, compression fallback, auth reselection, scope and header precedence.
- `internal/runtime/executor/codex_device_fingerprint_ws_test.go`: real handshakes,
  frames, reuse/reconnect/continuations, duplex and interrupt lifecycle.
- `internal/runtime/executor/helps/codex_device_fingerprint_review_test.go`: strict
  review regressions for credential subject, canonical refreshed token, handshake
  compatibility, stale hint invalidation, escaped duplicate keys and pending Doc
  mutations.
- `internal/runtime/executor/codex_device_fingerprint_review_http_test.go`: excluded
  direct-image route with an inherited Responses attempt context.
- `internal/runtime/executor/codex_device_fingerprint_review_ws_test.go`: subject
  changes, physical policy handoff, handshake changes and failed interrupt cleanup.
- `internal/runtime/executor/codex_device_fingerprint_persist_test.go`: synthetic
  refresh/save preservation and administrator edits.
- `internal/config/codex_device_fingerprint_test.go` and
  `internal/watcher/diff/codex_device_fingerprint_test.go`: mapping, migration,
  snapshots, scope, defaults and change visibility, including optional injection
  save transitions.
- `internal/runtime/executor/codex_device_fingerprint_acceptance_http_test.go`: real
  translation paths, cross-transport hints, compression 400/415 multivalue retries,
  Manager request-error isolation, inherited scope and JSON wire edge cases.
- `internal/runtime/executor/codex_device_fingerprint_acceptance_ws_test.go`: actual
  handshake transitions, competing dials, stale lifecycle callbacks, local summary,
  create/append/steer/interrupt, bind failure and concurrent interrupt/close.
- `internal/runtime/executor/helps/codex_device_fingerprint_plan_test.go`,
  `internal/watcher/synthesizer/codex_device_fingerprint_plan_test.go`,
  `internal/auth/codex/codex_device_fingerprint_plan_test.go`, and
  `sdk/auth/codex_device_fingerprint_test.go`: plan source precedence, real
  synthesis, login/storage, OAuth, journal, eviction and reconstruction.
- `sdk/cliproxy/codex_device_fingerprint_test.go`: real file save/migration, watcher
  reload/dispatch, Service executor replacement and Manager HTTP/WS captures.
  It synchronizes on the production reload/queue path, not fsnotify debounce timing.
- The `codex_device_fingerprint_round3_*_test.go` executor files and
  `codex_device_fingerprint_round3_test.go` config/Service files cover escaped
  singleton keys, final non-string/duplicate device identities, newly observed
  business-frame identity, rotated disk members, Manager partition/version merging,
  stale storage save/reload and clearing/removing overrides.
- `sdk/auth/codex_device_fingerprint_integration_test.go` exercises actual login
  record construction, SDK Manager login, persistence, synthesis, Manager
  registration and captured HTTP requests. The existing identity/persistence tests
  also cover actual mock OAuth refresh, current/legacy receipts, member/account
  changes and ordinary Metadata/Storage saves through the selected executor.

Inspected but intentionally unchanged: `config_v8.go`, `oauth_scope.go`,
`oauth_scope_executor.go` (API-key views share a resolver pointer instead of copying
a mutex), `codex_executor_tokens.go` (local CountTokens), `helps/payload_finalizer.go`,
`helps/codex_session_instructions.go`. Upgrade review must revisit these dependencies
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
git cherry-pick <feature-code-commit> <maintenance-document-commit> <review-fix-commit> <review-document-commit> <acceptance-fix-commit> <acceptance-document-commit>
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
go test -mod=readonly ./internal/auth/codex ./internal/watcher/synthesizer ./sdk/auth ./sdk/cliproxy ./sdk/cliproxy/auth -count=1
go test -mod=readonly -race ./internal/auth/codex ./internal/watcher/synthesizer ./sdk/auth ./sdk/cliproxy -run CodexDeviceFingerprint -count=1
go test -mod=readonly -race ./internal/auth/codex ./sdk/cliproxy/auth -run 'Test(MergeRefreshedAuth|MergeRefreshedAndExistingAuthMetadataPreservesSIWC|CredentialRefreshPatchChecksPartitionsIndependently|Issue6819_)' -count=1
go vet ./internal/config ./internal/watcher/diff ./internal/runtime/executor/helps ./internal/runtime/executor ./internal/auth/codex ./internal/watcher/synthesizer ./sdk/auth ./sdk/cliproxy ./sdk/cliproxy/auth
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
new branch at the recorded official baseline, or revert the documented patch commits in reverse order on an established branch. Verify build/tests
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
2. `ddd7715baac03dd0bc257cdcf5c34c2880996d03` — initial operation and maintenance
   document and its `.gitignore` exception.
3. The subsequent strict-review fix and documentation commits are listed in the
   follow-up record below.
4. `6291e9cae8f4615d833f9833f06777adaf148306` synchronizes credential identity
   across OAuth/Home refresh, ordinary persistence, re-login and versioned merges.
   Its final local verification on 2026-11-27 passed the full suite, feature race
   checks in seven affected packages, affected-package vet and the server build.
   Local HTTP/WS captures verify adopted tokens and identities. Actual deployment,
   remote storage services and the remote Home producer remain unverified.

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


## Strict review follow-up (2026-11-26)

Three review rounds combined adversarial helper probes, captured HTTP/WS requests,
and a final cross-path/lifecycle review. Demonstrated issues were fixed locally:

1. An unchanged administrator/SIWC UUID could conceal an account or Team member
   change on an authenticated socket. A private subject digest now participates in
   ordinary connection and frozen duplex checks, independently of the public UUID.
2. An old `Attributes.id_token` could displace refreshed `Metadata.id_token` and
   lose the current Team member claims. The canonical metadata token now wins.
3. Conflicting partial member metadata left an old LRU hint available for a later
   empty refresh. Both map and list entries are now removed on that contradiction.
4. A complete request could reuse a socket through final administrator overrides
   and then start duplex with a newly resolved policy. Handoff now freezes the
   socket's actual policy; subsequent incompatible input requires replay.
5. A newly configured device handshake header could be recorded without ever
   being sent. Reuse now compares requested headers with the actual handshake;
   full requests reconnect, while continuation/duplex rejects before sending.
   Steer only contributes body identity because it performs no handshake.
6. An interrupt write failure could leave the connection and its newly bound
   identity retained. The enabled socket now retires through existing lifecycle
   invalidation, without changing lock order or adding timeouts.
7. The new device binding guard also ran while both policies were disabled. If
   the socket disconnected before binding, this converted an existing transport
   recovery into a replay-required error. Disabled binding now delegates to the
   original transport-loss path. The existing refused-create/idle-loss integration
   test passed 300 repetitions on the exact official baseline, failed 101 of 300
   on the pre-fix candidate, and passed 300 after the fix.

The ordinary coherent identity comparison also skips map allocation and parsing
of canonical value lists; conflict checks retain their conservative behavior.
No throughput or latency benchmark claim is made. Public UUID golden vectors,
explicit override precedence, default-off semantics and final payload barriers
are unchanged. No dependency, actual configuration, auth file or remote was changed.

The retained strict-review regressions extend the original 40 top-level tests;
the final count is recorded in the acceptance table below. A temporary comparison probe ran against the exact official baseline
and the candidate: final HTTP Execute, ExecuteStream and compact body bytes and
header maps were identical with the feature disabled. All 2,670 baseline tracked
file contents were reverified against Git blob hashes before accepting that result.
The probe was removed from both trees after comparison. The retained HTTP review
test also captures the direct-image route with an inherited enabled Responses
context and verifies the route replaces it with a disabled snapshot.

Follow-up commits and final acceptance results are recorded below. Earlier
intermittent failures remain in the initial delivery record; they are not silently
reclassified or erased by this review.


The first follow-up full-suite run exposed an Antigravity credit-hint recovery
failure and the disabled WS loss regression described above. The Antigravity test
`TestAntigravityManagerExecuteAndStream_ToppedUpCreditsRecoverDuringQuotaCooldown`
reproduced twice in 30 repetitions on the exact official baseline, with the same
line-985 unknown-hint assertion (the initial candidate full run failed the stream
variant). It is a baseline intermittent failure; no Antigravity code or test was
changed. The WS loss failure did not reproduce on that baseline and was therefore
investigated and fixed as a patch regression, not dismissed as an upstream flake.

Follow-up patch commits (apply after the two initial commits):

3. `c7b601ac8e7990bcb8a2e6967b8a8ee0ad8f5e2f` — strict-review fixes and 14 new
   regression tests; independently buildable.
4. `docs(codex): record strict review fixes and final validation` — this follow-up
   maintenance record. Resolve its SHA with
   `git log -1 --format=%H -- docs/codex-device-fingerprint.md` or the delivery reply.

Final acceptance for review-fix commit `c7b601ac8e7990bcb8a2e6967b8a8ee0ad8f5e2f`:

| Check | Result |
|---|---|
| Feature selection in config/diff/helpers/executor | PASS; 54 top-level tests with subtests (14 added in this review) |
| Five named payload/session final-barrier tests | PASS |
| Complete config/diff/helpers/executor tests, `-count=1` | PASS on final confirmation; executor 45.829s |
| Feature tests with `-race` | PASS in both helpers and executor |
| Existing WS loss regression, 300 repetitions | PASS after fix |
| Existing session-instructions/duplex/interrupt/lifecycle selection | PASS |
| `go vet` for the four relevant packages | PASS |
| `go test -mod=readonly ./...` | PASS on final run; executor 43.221s, OpenAI handlers 10.484s |
| Server build and removal of `test-output` | PASS |
| `gofmt -w .`, `git diff --check` | PASS; only the same two unrelated formatter changes were restored |
| Official baseline off-mode HTTP wire comparison | PASS for Execute, ExecuteStream and compact |
| Dependency changes / production calls / remote writes | None |

An intermediate related-package run also encountered the previously baseline-proven
AIStudio conductor timeout and the newly baseline-proven Antigravity hint failure.
The final confirmation and full-suite runs passed. Neither unrelated test was
weakened. No validation was blocked by the environment. Real-account operation,
production rollout, future official versions and complete physical-device
emulation remain outside this local validation.

Review logs are in `/tmp/codex-device-strict-review/`: `feature-confirmation.log`,
`test-inventory.log`, `barriers-delivery.log`, `packages-confirmation.log`,
`race-delivery.log`, `vet-delivery.log`, `full-delivery.log`,
`baseline-new-failures.log`, `baseline-ws-loss-300.log`,
`candidate-ws-loss-300.log`, `candidate-ws-loss-bind-noop.log`,
`ws-off-followup-loss300.log`, and `off-parity-result.txt`. Earlier failed runs
(`full-final.log`, `packages-delivery.log`) remain available for comparison.
These temporary files are review evidence, not dependencies of the patch.

## Acceptance follow-up (2026-11-26)

Apply these after the four original and strict-review commits:

5. `eb9ec2a5dd0cbeb5c84146a60a10fe3cea5f7506` — preserve plan provenance and
   transport identity hints, retain optional injection settings on save, stabilize
   multivalue header retries, and add loading/refresh/Service/wire regressions.
6. Resolve the accompanying maintenance-document commit with
   `git log -1 --format=%H -- docs/codex-device-fingerprint.md`.

Final source has 79 top-level `TestCodexDeviceFingerprint*` tests (25 added in this
follow-up), plus table-driven cases. Required feature selections, five named
payload/session barriers, complete config/diff/helpers/executor packages,
additional auth/synthesis/SDK/Service/Manager packages, extended feature race,
vet, `go test -mod=readonly ./...`, server build and `git diff --check` passed.
No final acceptance failure or environment block occurred. Earlier observations
above are historical records, not failures of this final source.

A fresh same-environment comparison captured identical final body bytes and
header maps for disabled HTTP Execute, ExecuteStream and compact against the
official baseline. All 2,670 baseline tracked file hashes were checked again;
temporary comparison probes were removed. The original directory was not changed.

Evidence is in `/tmp/codex-device-acceptance/`: `final-test-inventory.log`,
`final-feature.log`, `final-feature-extra.log`, `final-barriers.log`,
`final-packages.log`, `final-packages-extra.log`, `final-race.log`, `final-vet.log`,
`final-full.log`, and `final-off-parity.txt`. These local logs are supporting
artifacts, not build inputs. No separate audit document was added to the repository.

Tests use synthetic credentials and local upstreams. Running-program/configuration
enablement, production accounts, remote Home credential producers, fsnotify
debounce timing, live media exchange and external billing are not established by
these tests. Alpha/search, Live and management api-call retain their existing
non-Responses paths; device route guards and inherited-context exclusion are
tested without expanding these routes. Passing repository regressions does not
mean every excluded protocol was exercised against a real upstream. The feature
remains off by default; no deployment, real credential/configuration modification,
dependency change or remote write was performed.


## Additional review rounds (2026-11-26)

Apply after the preceding six implementation/maintenance commits:

7. `30e777e0320efff0f752f45a8a09e71ffa9a2cf4` — configuration rollback,
   adopted credential identity, partition-aware Manager merging and 12 retained
   regressions. Production changes are limited to four existing files.
8. Resolve this accompanying documentation commit with
   `git log -1 --format=%H -- docs/codex-device-fingerprint.md`.

The reviews reproduced and corrected three behavior gaps:

- Clearing a previously enabled mode was omitted from generated YAML, leaving
  the old `device` value in the comment-preserving save. Empty mode now removes
  the old entry, verified through save, watcher, Service, Manager and captured
  HTTP/WS requests across legacy, migration and v8 layouts.
- Adopting credentials rotated on disk could retain an old member or auxiliary
  identity hint. Adoption now replaces the identity partition. The intermediate
  repair also exposed a Manager version-check failure when account/token fields
  were deleted before merging; explicit empty values now travel through the
  existing credential patch. Captured bearer, account header and installation
  values agree before and after file persistence and synthesis. Stale token
  storage cannot restore the prior credential, and concurrent administrator
  settings remain intact.
- A late dual-partition refresh could retain valid SIWC changes while merging
  an obsolete outer member into newer outer credentials. A read-only outer
  version check now preserves current identity Metadata and Attributes when that
  partition is superseded. Real Manager and HTTP tests confirm both the current
  outer subject and independently refreshed SIWC bearer.

Additional HTTP/WS captures cover escaped singleton keys, escaped interrupt
metadata, administrator-provided non-string/duplicate final identity values,
required-socket replay rejection and identity first introduced in a business
frame. These cases required no further WS production changes. Normal compatible
connections remain reusable; final administrator values are never rewritten.

Final acceptance for code commit `30e777e0320efff0f752f45a8a09e71ffa9a2cf4`:

| Check | Result |
|---|---|
| Feature selection across eight packages | PASS; 91 top-level tests, 12 added in this review |
| Five named payload/session barriers | PASS |
| Nine complete affected/dependent packages, `-count=1` | PASS |
| Extended feature race and existing credential/Manager merge race selections | PASS; selectors matched tests |
| `go vet` across all nine relevant packages | PASS |
| `go test -mod=readonly ./...` | PASS on final source |
| Server build and removal of `test-output` | PASS |
| `gofmt -w .`, `git diff --check` | PASS; the same two unrelated formatting-only changes were restored |
| Dependencies, real credentials/configuration, deployment, remote writes | Unchanged / none |

An earlier full run failed the new Manager regression before its repair and
`TestServiceHeartbeatFailoverDoesNotDrainBlockingScope`. The latter reproduced
3 times in 30 runs on the exact official baseline, whose 2,670 tracked file
hashes were independently reverified. Its 100ms heartbeat detection plus up to
approximately 1s randomized retry can exceed the test's approximately 1.05s
wait. No Home source or assertion was changed; the later passing run does not
mean that pre-existing timing issue was fixed. No final feature failure or
environment blocker remains in this validation.

Evidence is retained locally under `/tmp/codex-device-round3/`: the final
`accepted-feature.log`, `accepted-inventory.log`, `accepted-race.log`,
`accepted-manager-race.log`, `accepted-barriers.log`, `accepted-packages.log`,
`accepted-vet.log` and `accepted-full.log`; reproduction/classification details
are in `identity-cross-fix-status.txt`, `cross-concurrency-status.txt` and
`heartbeat-baseline-status.txt`. Temporary evidence files are not build inputs.

The feature remains disabled by default. Local request verification is complete;
running-program/configuration enablement remains unverified. No production
upstream was contacted. Missing or historically ambiguous account/plan metadata,
remote Home producers, actual external billing and full device emulation retain
the limits documented above. Upgrade review must now also preserve outer/SIWC
partition version checks at the Manager identity merge boundary.
