package helps

import (
	"container/list"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/MoeForge/moego/ojson"
	"github.com/google/uuid"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	codexDeviceSeedPrefix   = "cli-proxy-api:codex:device-fingerprint:v2:"
	codexDeviceCacheLimit   = 512
	codexDeviceInstallation = "x-codex-installation-id"
	codexDeviceTurnMetadata = "x-codex-turn-metadata"
)

// CodexDevicePolicy is an immutable snapshot for one attempt or physical socket.
// Its zero value disables all device processing, including parsing and logging.
type CodexDevicePolicy struct {
	Enabled       bool
	ID            string
	InjectMissing bool
	SIWC          bool
	// credentialSubject binds active sockets independently of administrator-chosen IDs.
	credentialSubject [32]byte
}

type codexDeviceAccount struct {
	account string
	user    string
	plan    string
}

func (i codexDeviceAccount) clone() codexDeviceAccount {
	return codexDeviceAccount{account: strings.Clone(i.account), user: strings.Clone(i.user), plan: strings.Clone(i.plan)}
}

type codexDeviceCacheEntry struct {
	key      string
	identity codexDeviceAccount
}

// CodexDeviceResolver retains at most 512 recent auth identities in one executor.
// It owns no goroutine, stores no tokens, and is discarded with the executor.
// Eviction or a restart can lose missing-field recovery; explicit IDs avoid it.
type CodexDeviceResolver struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	recent   list.List
	warnings uint32
}

const (
	codexDeviceWarnMode uint32 = 1 << iota
	codexDeviceWarnOverride
	codexDeviceWarnSIWC
	codexDeviceWarnTeamUser
	codexDeviceWarnFallback
	codexDeviceWarnJWT
)

func (r *CodexDeviceResolver) warn(kind uint32, reason string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	seen := r.warnings&kind != 0
	r.warnings |= kind
	r.mu.Unlock()
	if !seen {
		log.WithField("reason", reason).Warn("codex device fingerprint: identity fallback (further warnings of this kind suppressed for this executor)")
	}
}

// Resolve reads credentials only once. The executor supplies the actual SIWC
// route decision and final upstream URL, not the downstream entrypoint.
func (r *CodexDeviceResolver) Resolve(cfg *config.Config, auth *cliproxyauth.Auth, useSIWC bool, targetURL string) CodexDevicePolicy {
	if auth == nil || (auth.Provider != "" && !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex")) ||
		auth.AuthKind() == cliproxyauth.AuthKindAPIKey || strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		return CodexDevicePolicy{}
	}
	mode := codexDeviceAuthString(auth, "codex_device_fingerprint")
	if mode == "" && cfg != nil {
		mode = cfg.Codex.DeviceFingerprintMode
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "device":
	case "", "off":
		return CodexDevicePolicy{}
	default:
		r.warn(codexDeviceWarnMode, "unknown-mode")
		return CodexDevicePolicy{}
	}
	if !codexDeviceResponsesURL(targetURL) {
		return CodexDevicePolicy{}
	}
	identity := r.accountIdentity(auth)
	identity = r.remember(strings.TrimSpace(auth.ID), identity)
	policy := CodexDevicePolicy{Enabled: true, SIWC: useSIWC, credentialSubject: identity.subject(strings.TrimSpace(auth.ID))}
	if !useSIWC && cfg != nil && cfg.Codex.DeviceFingerprintInjectMissing != nil {
		policy.InjectMissing = *cfg.Codex.DeviceFingerprintInjectMissing
	}
	if useSIWC {
		if siwc, ok := auth.Metadata["siwc"].(map[string]any); ok {
			if raw, okID := siwc["device_id"].(string); okID && strings.TrimSpace(raw) != "" {
				if id, valid := codexDeviceValidUUID(raw); valid {
					policy.ID = id
					return policy
				}
				r.warn(codexDeviceWarnSIWC, "invalid-siwc-device")
			}
		}
	}
	for _, raw := range []string{auth.Attributes["codex_installation_id"], codexDeviceMetadataString(auth, "codex_installation_id")} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if id, valid := codexDeviceValidUUID(raw); valid {
			policy.ID = id
			return policy
		}
		r.warn(codexDeviceWarnOverride, "invalid-explicit-device")
	}
	if identity.account != "" {
		switch strings.ToLower(strings.TrimSpace(identity.plan)) {
		case "team", "business", "enterprise", "edu":
			if identity.user != "" {
				policy.ID = codexDeviceUUID("account-user\x00" + identity.account + "\x00" + identity.user)
				return policy
			}
			r.warn(codexDeviceWarnTeamUser, "team-member-missing")
		default:
			policy.ID = codexDeviceUUID("account\x00" + identity.account)
			return policy
		}
	}
	if authID := strings.TrimSpace(auth.ID); authID != "" {
		r.warn(codexDeviceWarnFallback, "auth-id-fallback")
		policy.ID = codexDeviceUUID("auth-id\x00" + authID)
		return policy
	}
	return CodexDevicePolicy{}
}

// accountIdentity reads only explicit metadata and token claims, never parser defaults.
func (r *CodexDeviceResolver) accountIdentity(auth *cliproxyauth.Auth) codexDeviceAccount {
	// Match the executor's selected OAuth account header when metadata has it.
	// Explicit device overrides and mode use the separate Attributes-first rule.
	account := codexDeviceMetadataString(auth, "account_id")
	if account == "" {
		account = strings.TrimSpace(auth.Attributes["account_id"])
	}
	identity := codexDeviceAccount{account: account, user: codexDeviceAuthString(auth, "chatgpt_user_id"), plan: codexDeviceAuthString(auth, "plan_type")}
	if identity.plan == "" {
		identity.plan = codexDeviceAuthString(auth, "chatgpt_plan_type")
	}
	// OAuth refresh writes the canonical token to Metadata. An old auxiliary
	// attribute must not displace that token and lose the current member claims.
	token := codexDeviceMetadataString(auth, "id_token")
	if token == "" {
		token = strings.TrimSpace(auth.Attributes["id_token"])
	}
	if token != "" {
		claims, errParse := codexauth.ParseJWTToken(token)
		if errParse != nil {
			r.warn(codexDeviceWarnJWT, "unreadable-id-token")
		} else if claims != nil {
			claimAccount := strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
			if identity.account == "" {
				identity.account = claimAccount
			}
			// A token from an old account must never contribute its member or plan.
			if claimAccount == "" || claimAccount == identity.account {
				if identity.user == "" {
					identity.user = strings.TrimSpace(claims.CodexAuthInfo.ChatgptUserID)
				}
				// GetPlanType supplies a default; only explicit claims identify a plan.
				if identity.plan == "" {
					identity.plan = strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType)
				}
			}
		}
	}
	return identity
}

// subject deliberately excludes the public installation ID: two administrators
// may choose one UUID, but a physical authenticated socket still has one subject.
func (i codexDeviceAccount) subject(authID string) [32]byte {
	seed := "auth-id\x00" + authID
	if i.account != "" {
		seed = "account\x00" + i.account
		switch strings.ToLower(strings.TrimSpace(i.plan)) {
		case "team", "business", "enterprise", "edu":
			if i.user != "" {
				seed = "account-user\x00" + i.account + "\x00" + i.user
			} else {
				seed = "account-auth\x00" + i.account + "\x00" + authID
			}
		}
	}
	return sha256.Sum256([]byte(seed))
}

func codexDeviceAuthString(auth *cliproxyauth.Auth, key string) string {
	if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
		return value
	}
	return codexDeviceMetadataString(auth, key)
}

func codexDeviceMetadataString(auth *cliproxyauth.Auth, key string) string {
	value, _ := auth.Metadata[key].(string)
	return strings.TrimSpace(value)
}

func (r *CodexDeviceResolver) remember(key string, identity codexDeviceAccount) codexDeviceAccount {
	if r == nil || key == "" {
		return identity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[string]*list.Element)
	}
	if element := r.entries[key]; element != nil {
		cached := element.Value.(codexDeviceCacheEntry).identity
		if identity.account == "" || identity.account == cached.account {
			// When the account is absent but a new member is present, we
			// cannot safely attach that member to the cached workspace.
			if identity.account == "" && identity.user != "" && identity.user != cached.user {
				delete(r.entries, key)
				r.recent.Remove(element)
				return identity
			}
			if identity.account == "" {
				identity.account = cached.account
			}
			planChanged := identity.plan != "" && cached.plan != "" && !strings.EqualFold(identity.plan, cached.plan)
			if identity.user == "" && !planChanged {
				identity.user = cached.user
			}
			if identity.plan == "" {
				identity.plan = cached.plan
			}
		}
		element.Value = codexDeviceCacheEntry{key: strings.Clone(key), identity: identity.clone()}
		r.recent.MoveToFront(element)
		return identity
	}
	if identity.account == "" {
		return identity
	}
	if len(r.entries) >= codexDeviceCacheLimit {
		oldest := r.recent.Back()
		delete(r.entries, oldest.Value.(codexDeviceCacheEntry).key)
		r.recent.Remove(oldest)
	}
	key = strings.Clone(key)
	r.entries[key] = r.recent.PushFront(codexDeviceCacheEntry{key: key, identity: identity.clone()})
	return identity
}

func codexDeviceResponsesURL(rawURL string) bool {
	parsed, errParse := url.Parse(rawURL)
	if errParse != nil {
		return false
	}
	path := strings.TrimSuffix(parsed.Path, "/")
	return strings.HasSuffix(path, "/responses") || strings.HasSuffix(path, "/responses/compact")
}

func codexDeviceValidUUID(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) != 36 || raw[8] != '-' || raw[13] != '-' || raw[18] != '-' || raw[23] != '-' {
		return "", false
	}
	id, errParse := uuid.Parse(raw)
	if errParse != nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 {
		return "", false
	}
	return id.String(), true
}

func codexDeviceUUID(seed string) string {
	sum := sha256.Sum256([]byte(codexDeviceSeedPrefix + seed))
	id := uuid.UUID([16]byte(sum[:16]))
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return id.String()
}

type codexDevicePolicyContextKey struct{}

// WithCodexDevicePolicy carries an immutable snapshot, including disabled mode.
// Callers replace it when an attempt selects a different credential.
func WithCodexDevicePolicy(ctx context.Context, policy CodexDevicePolicy) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, codexDevicePolicyContextKey{}, policy)
}

func CodexDevicePolicyFromContext(ctx context.Context) (CodexDevicePolicy, bool) {
	if ctx == nil {
		return CodexDevicePolicy{}, false
	}
	policy, ok := ctx.Value(codexDevicePolicyContextKey{}).(CodexDevicePolicy)
	return policy, ok
}

type codexDeviceInputError struct{}

func (*codexDeviceInputError) Error() string {
	return "codex device fingerprint: duplicate client_metadata objects are ambiguous"
}
func (*codexDeviceInputError) StatusCode() int       { return http.StatusBadRequest }
func (*codexDeviceInputError) IsRequestScoped() bool { return true }

// ValidateInput rejects ambiguous metadata before other built-ins can remove a
// duplicate. Other malformed shapes remain subject to existing request checks.
func (p CodexDevicePolicy) ValidateInput(raw []byte) error {
	if !p.Enabled {
		return nil
	}
	return codexDeviceCheckRoot(ojson.ParseBytes(raw))
}

func codexDeviceCheckRoot(root ojson.Result) error {
	if !root.IsObject() {
		return nil
	}
	count := 0
	root.ForEach(func(key, value ojson.Result) bool {
		if key.String() == "client_metadata" {
			count++
		}
		return count < 2
	})
	if count > 1 {
		return &codexDeviceInputError{}
	}
	return nil
}

// ApplyDoc is a built-in mutation stage and MUST precede FinalizePayloadDoc.
// Control frames only rewrite existing device fields, never inject them.
func (p CodexDevicePolicy) ApplyDoc(doc *ojson.Doc, control bool, original ...[]byte) error {
	if !p.Enabled || p.ID == "" || doc == nil {
		return nil
	}
	// Executors supply the original object so inspecting its shape never flattens
	// a main Doc that already contains pending built-in mutations. Standalone
	// callers may omit it when applying to a fresh local Doc.
	var root ojson.Result
	if len(original) > 0 {
		root = ojson.ParseBytes(original[0])
	} else {
		root = doc.Get("@this")
	}
	if !root.IsObject() || !ojson.Valid(root.Raw) {
		return nil
	}
	if errRoot := codexDeviceCheckRoot(root); errRoot != nil {
		return errRoot
	}
	metadata := doc.Get("client_metadata")
	inject := p.InjectMissing && !p.SIWC && !control
	if !metadata.Exists() {
		if inject {
			return doc.Set("client_metadata."+codexDeviceInstallation, p.ID)
		}
		return nil
	}
	if !metadata.IsObject() {
		return nil
	}
	installationCount, turnCount := 0, 0
	var turn ojson.Result
	metadata.ForEach(func(key, value ojson.Result) bool {
		switch key.String() {
		case codexDeviceInstallation:
			installationCount++
		case codexDeviceTurnMetadata:
			turnCount++
			turn = value
		}
		return true
	})
	// Mutating a local Doc preserves raw numbers and all unrelated members,
	// including duplicate unknown keys. Only target keys are normalized.
	local := ojson.NewDocString(metadata.Raw)
	changed := false
	if installationCount > 0 || inject {
		current := local.Get(codexDeviceInstallation)
		if installationCount != 1 || current.Type != ojson.String || current.Str != p.ID {
			if installationCount > 1 {
				if errDelete := codexDeviceDeleteAll(local, codexDeviceInstallation); errDelete != nil {
					return errDelete
				}
			}
			if errSet := local.Set(codexDeviceInstallation, p.ID); errSet != nil {
				return errSet
			}
			changed = true
		}
	}
	if turnCount > 0 {
		inner, keep := "", false
		if turn.Type == ojson.String {
			inner, keep = codexDeviceRewriteTurn(turn.Str, p.ID)
		}
		if !keep || turnCount > 1 {
			if errDelete := codexDeviceDeleteAll(local, codexDeviceTurnMetadata); errDelete != nil {
				return errDelete
			}
			changed = true
		}
		if keep && (turnCount > 1 || inner != turn.Str) {
			if errSet := local.Set(codexDeviceTurnMetadata, inner); errSet != nil {
				return errSet
			}
			changed = true
		}
	}
	if changed {
		return doc.SetRaw("client_metadata", local.String())
	}
	return nil
}

func codexDeviceDeleteAll(doc *ojson.Doc, path string) error {
	for doc.Get(path).Exists() {
		before := doc.Len()
		if errDelete := doc.Delete(path); errDelete != nil {
			return errDelete
		}
		if doc.Len() >= before {
			return fmt.Errorf("codex device fingerprint: could not normalize duplicate device key")
		}
	}
	return nil
}

func codexDeviceRewriteTurn(raw, id string) (string, bool) {
	if !ojson.Valid(raw) {
		return "", false
	}
	root := ojson.Parse(raw)
	if !root.IsObject() {
		return "", false
	}
	count := 0
	already := true
	root.ForEach(func(key, value ojson.Result) bool {
		if key.String() == "installation_id" {
			count++
			already = already && value.Type == ojson.String && value.Str == id
		}
		return true
	})
	if count == 0 || (count == 1 && already) {
		return raw, true
	}
	doc := ojson.NewDocString(raw)
	if count > 1 {
		if errDelete := codexDeviceDeleteAll(doc, "installation_id"); errDelete != nil {
			return "", false
		}
	}
	if errSet := doc.Set("installation_id", id); errSet != nil {
		return "", false
	}
	return doc.String(), true
}

// ApplyHeaders runs before administrator header overrides. It does not mutate
// input slices shared with client headers; malformed values are dropped singly.
func (p CodexDevicePolicy) ApplyHeaders(headers http.Header) {
	if !p.Enabled || p.ID == "" {
		return
	}
	for key, values := range headers {
		switch {
		case strings.EqualFold(key, "X-Codex-Installation-Id"):
			delete(headers, key)
		case strings.EqualFold(key, "X-Codex-Turn-Metadata"):
			updated := make([]string, 0, len(values))
			for _, value := range values {
				if rewritten, keep := codexDeviceRewriteTurn(value, p.ID); keep {
					updated = append(updated, rewritten)
				}
			}
			if len(updated) == 0 {
				delete(headers, key)
			} else {
				headers[key] = updated
			}
		}
	}
}

// CodexDeviceIdentity describes the authenticated subject and effective device
// values on the wire, without session, thread, turn, or cache identifiers.
// Missing values impose no new device identity. Values in different locations
// remain separate so explicit conflicting administrator rules stay observable.
type CodexDeviceIdentity struct {
	Enabled           bool
	SIWC              bool
	values            [4]string
	single            string
	conflicting       bool
	credentialSubject [32]byte
}

// EffectiveID reports a single UUID device actually represented by final values.
// Conflicting or non-UUID administrator overrides have no unambiguous control ID.
func (i CodexDeviceIdentity) EffectiveID() (string, bool) {
	if !i.Enabled || i.conflicting || !strings.HasPrefix(i.single, "s:") {
		return "", false
	}
	return codexDeviceValidUUID(strings.TrimPrefix(i.single, "s:"))
}

// Identity is read-only and may be called after the final user payload barrier.
// It intentionally ignores the derived ID when final rules replace every ID.
func (p CodexDevicePolicy) Identity(doc *ojson.Doc, headers http.Header) CodexDeviceIdentity {
	identity := CodexDeviceIdentity{Enabled: p.Enabled, SIWC: p.SIWC, credentialSubject: p.credentialSubject}
	if !p.Enabled {
		return identity
	}
	var values [4][]string
	if doc != nil {
		metadata := doc.Get("client_metadata")
		if metadata.IsObject() {
			metadata.ForEach(func(key, value ojson.Result) bool {
				switch key.String() {
				case codexDeviceInstallation:
					values[0] = append(values[0], codexDeviceIdentityValue(value))
				case codexDeviceTurnMetadata:
					if value.Type == ojson.String {
						values[1] = append(values[1], codexDeviceTurnIdentityValues(value.Str)...)
					}
				}
				return true
			})
		}
	}
	for key, list := range headers {
		if strings.EqualFold(key, "X-Codex-Installation-Id") {
			for _, value := range list {
				if id, valid := codexDeviceValidUUID(value); valid {
					value = id
				}
				values[2] = append(values[2], "s:"+value)
			}
		}
		if strings.EqualFold(key, "X-Codex-Turn-Metadata") {
			for _, value := range list {
				values[3] = append(values[3], codexDeviceTurnIdentityValues(value)...)
			}
		}
	}
	for i, list := range values {
		if len(list) == 0 {
			continue
		}
		sort.Strings(list)
		unique := list[:0]
		for _, value := range list {
			if len(unique) == 0 || unique[len(unique)-1] != value {
				unique = append(unique, value)
			}
			if identity.single == "" {
				identity.single = value
			} else if identity.single != value {
				identity.conflicting = true
			}
		}
		canonical := ojson.NewDocString(`{}`)
		_ = canonical.Set("values", unique)
		identity.values[i] = canonical.String()
	}
	return identity
}

func codexDeviceIdentityValue(value ojson.Result) string {
	if value.Type == ojson.String {
		if id, valid := codexDeviceValidUUID(value.Str); valid {
			return "s:" + id
		}
		return "s:" + value.Str
	}
	return "j:" + value.Raw
}

func codexDeviceTurnIdentityValues(raw string) []string {
	if !ojson.Valid(raw) {
		return nil
	}
	root := ojson.Parse(raw)
	if !root.IsObject() {
		return nil
	}
	var values []string
	root.ForEach(func(key, value ojson.Result) bool {
		if key.String() == "installation_id" {
			values = append(values, codexDeviceIdentityValue(value))
		}
		return true
	})
	return values
}

func (i CodexDeviceIdentity) Compatible(other CodexDeviceIdentity) bool {
	if i.Enabled != other.Enabled || i.SIWC != other.SIWC {
		return false
	}
	if i.Enabled && i.credentialSubject != other.credentialSubject {
		return false
	}
	if !i.conflicting && !other.conflicting && i.single != "" && other.single != "" && i.single != other.single {
		return false
	}
	for field, value := range i.values {
		if value != "" && other.values[field] != "" && value != other.values[field] {
			return false
		}
	}
	// A newly present location may repeat an established device, but must not
	// introduce a third identity into an explicitly conflicting connection.
	if i.single != "" && (i.conflicting || other.conflicting) {
		newLocation := false
		for field, value := range other.values {
			newLocation = newLocation || (i.values[field] == "" && value != "")
		}
		if !newLocation {
			return true
		}
		known := make(map[string]bool)
		for _, value := range i.values {
			ojson.Get(value, "values").ForEach(func(_, member ojson.Result) bool {
				known[member.String()] = true
				return true
			})
		}
		for field, value := range other.values {
			if i.values[field] != "" || value == "" {
				continue
			}
			compatible := true
			ojson.Get(value, "values").ForEach(func(_, member ojson.Result) bool {
				compatible = known[member.String()]
				return compatible
			})
			if !compatible {
				return false
			}
		}
	}
	return true
}

// Merge remembers values first observed on a reused physical connection. Call
// only after Compatible; absent fields never erase an established identity.
func (i CodexDeviceIdentity) Merge(other CodexDeviceIdentity) CodexDeviceIdentity {
	for field, value := range other.values {
		if i.values[field] == "" {
			i.values[field] = value
		}
	}
	if i.single == "" {
		i.single = other.single
	} else if other.single != "" && i.single != other.single {
		i.conflicting = true
	}
	i.conflicting = i.conflicting || other.conflicting
	return i
}
