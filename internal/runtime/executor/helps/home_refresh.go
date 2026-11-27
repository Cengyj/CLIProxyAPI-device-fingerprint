package helps

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MoeForge/moego/json"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/home"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type homeStatusErr struct {
	code       int
	msg        string
	diagnostic string
	errorType  string
	upstream   bool
}

// ErrHomeRefreshRecordMismatch rejects the entire response before either partition is adopted.
var ErrHomeRefreshRecordMismatch error = homeStatusErr{code: http.StatusBadGateway, msg: "home refresh returned a different credential record or provider"}

func (e homeStatusErr) Error() string {
	if e.upstream {
		return e.msg
	}
	if e.msg != "" {
		return e.msg
	}
	return fmt.Sprintf("status %d", e.code)
}

func (e homeStatusErr) StatusCode() int { return e.code }

func (e homeStatusErr) LogDiagnostic() string {
	if strings.TrimSpace(e.diagnostic) != "" {
		return logging.SafeDiagnosticForLog(e.diagnostic)
	}
	if e.upstream {
		return fmt.Sprintf("Home refresh upstream response: status=%d", e.code)
	}
	if errorType := strings.ToLower(strings.TrimSpace(e.errorType)); errorType != "" {
		return logging.SafeDiagnosticForLog("Home refresh failed: type=" + errorType)
	}
	return logging.SafeDiagnosticForLog(e.Error())
}

func (e homeStatusErr) DirectResponse() bool { return e.upstream }

func (e homeStatusErr) ResponseBody() []byte {
	if !e.upstream {
		return nil
	}
	return []byte(e.msg)
}

type homeErrorEnvelope struct {
	Error *homeErrorDetail `json:"error"`
}

type homeRefreshAuthEnvelope struct {
	Auth      json.RawMessage `json:"auth"`
	AuthIndex string          `json:"auth_index"`
}

type homeErrorDetail struct {
	Type       string                `json:"type"`
	Message    string                `json:"message"`
	Code       string                `json:"code,omitempty"`
	Diagnostic string                `json:"diagnostic,omitempty"`
	Upstream   *homeUpstreamResponse `json:"upstream,omitempty"`
}

type homeUpstreamResponse struct {
	Status int    `json:"status"`
	Body   []byte `json:"body"`
}

type homeRefreshClient interface {
	HeartbeatOK() bool
	GetRefreshAuth(ctx context.Context, authIndex string, accessTokenSHA256 string) ([]byte, error)
}

var currentHomeRefreshClient = func() homeRefreshClient {
	return home.Current()
}

// CodexHomeRefreshIdentity selects the identity to persist with a Home renewal.
// A matching bearer permits sparse updates until an explicit subject hint changes.
func CodexHomeRefreshIdentity(current, returned *cliproxyauth.Auth) *cliproxyauth.Auth {
	if current == nil || returned == nil {
		return returned
	}
	currentAccess, _ := current.Metadata["access_token"].(string)
	nextAccess, _ := returned.Metadata["access_token"].(string)
	if strings.TrimSpace(currentAccess) == "" || strings.TrimSpace(currentAccess) != strings.TrimSpace(nextAccess) {
		return returned
	}
	identity := current.Clone()
	AdoptCodexHomeIdentity(identity, current)
	for _, key := range []string{"account_id", "id_token", "chatgpt_user_id"} {
		if value, present := returned.Metadata[key]; present {
			text, valid := value.(string)
			if !valid || strings.TrimSpace(text) == "" || strings.TrimSpace(text) != identity.Metadata[key] {
				return returned
			}
		} else if value, present := returned.Attributes[key]; present {
			if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != identity.Metadata[key] {
				return returned
			}
		}
	}
	// Plans can change without replacing the account or member. Treat each
	// explicitly supplied plan source as authoritative over inherited aliases.
	planChanged := false
	for _, key := range []string{"plan_type", "chatgpt_plan_type"} {
		if _, present := returned.Metadata[key]; present {
			planChanged = true
		} else if _, present := returned.Attributes[key]; present {
			planChanged = true
		}
	}
	if planChanged {
		for _, key := range []string{"plan_type", "chatgpt_plan_type", "plan_type_defaulted"} {
			delete(identity.Metadata, key)
			delete(identity.Attributes, key)
		}
	}
	_, canonicalPlan := returned.Metadata["plan_type"]
	_, canonicalClaimPlan := returned.Metadata["chatgpt_plan_type"]
	for _, key := range []string{"plan_type", "chatgpt_plan_type", "plan_type_defaulted"} {
		if value, present := returned.Metadata[key]; present {
			identity.Metadata[key] = value
		} else if value, present := returned.Attributes[key]; present {
			if canonicalPlan || canonicalClaimPlan {
				continue
			}
			if key == "plan_type_defaulted" {
				flag, _ := strconv.ParseBool(strings.TrimSpace(value))
				identity.Metadata[key] = flag
			} else {
				identity.Metadata[key] = value
			}
		}
	}
	if planChanged {
		planValue, hasPlan := identity.Metadata["plan_type"]
		if !hasPlan {
			planValue = identity.Metadata["chatgpt_plan_type"]
		}
		plan, _ := planValue.(string)
		if strings.TrimSpace(plan) == "" {
			// The retained ID token describes the preceding snapshot. Keep an
			// explicit clearing marker so its old plan cannot reappear on reload.
			identity.Metadata["plan_type"] = codexauth.DefaultPlanType
			identity.Metadata["plan_type_defaulted"] = true
			identity.Metadata["chatgpt_plan_type"] = ""
		} else if hasPlan {
			defaulted, _ := identity.Metadata["plan_type_defaulted"].(bool)
			if _, hasAlias := identity.Metadata["chatgpt_plan_type"]; !hasAlias && !defaulted {
				identity.Metadata["chatgpt_plan_type"] = ""
			}
		}
	}
	return identity
}

// AdoptCodexHomeIdentity replaces identity hints with the adopted Home credential.
func AdoptCodexHomeIdentity(target, source *cliproxyauth.Auth) {
	if target == nil || source == nil {
		return
	}
	metadataString := func(key string) (string, bool) {
		raw, exists := source.Metadata[key]
		value, _ := raw.(string)
		return strings.TrimSpace(value), exists
	}
	token, tokenPresent := metadataString("id_token")
	claims, _ := codexauth.ParseJWTToken(token)
	account, accountPresent := metadataString("account_id")
	if accountPresent && account == "" {
		// An explicit canonical clear outranks a repeated token snapshot. The
		// token must also be cleared so later readers cannot restore its account.
		token = ""
		claims = nil
	}
	if !accountPresent {
		// A canonical token can supply an omitted canonical account before
		// consulting an auxiliary snapshot of the previous credential.
		if claims != nil {
			account = strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
		}
		if account == "" {
			account = strings.TrimSpace(source.Attributes["account_id"])
		}
	}
	// An explicitly empty, null or mistyped canonical field blocks auxiliary
	// fallback. Absence still supports legacy Attributes-only Home responses.
	auxiliary := !accountPresent || account != ""
	if auxiliaryAccount := strings.TrimSpace(source.Attributes["account_id"]); auxiliaryAccount != "" && auxiliaryAccount != account {
		auxiliary = false
	}
	if !tokenPresent && auxiliary {
		token = strings.TrimSpace(source.Attributes["id_token"])
		claims, _ = codexauth.ParseJWTToken(token)
	}
	if tokenPresent && token == "" {
		auxiliary = false
	}
	claimMember, tokenPlan := "", ""
	if claims != nil {
		claimAccount := strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
		if account == "" {
			account = claimAccount
		}
		if claimAccount == "" || claimAccount == account {
			claimMember = strings.TrimSpace(claims.CodexAuthInfo.ChatgptUserID)
			tokenPlan = strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType)
		} else {
			auxiliary = false
			if !tokenPresent {
				// A rejected auxiliary token must not become a canonical field
				// merely because its claims were ignored during resolution.
				token = ""
			}
		}
	}
	if auxiliaryToken := strings.TrimSpace(source.Attributes["id_token"]); auxiliaryToken != "" {
		if claims, errParse := codexauth.ParseJWTToken(auxiliaryToken); errParse == nil && claims != nil {
			claimAccount := strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
			if claimAccount != "" && claimAccount != account {
				auxiliary = false
			}
		}
	}
	identityHint := func(key, claim string) string {
		if value, present := metadataString(key); present {
			return value
		}
		// Claims from the adopted, matching-account token precede auxiliary
		// hints, which may still describe the previous member of that account.
		if claim != "" {
			return claim
		}
		if auxiliary {
			return strings.TrimSpace(source.Attributes[key])
		}
		return ""
	}
	member := identityHint("chatgpt_user_id", claimMember)
	plan, planPresent := metadataString("plan_type")
	claimPlan, claimPlanPresent := metadataString("chatgpt_plan_type")
	if !claimPlanPresent {
		claimPlan = tokenPlan
		if claimPlan == "" && !planPresent && auxiliary {
			claimPlan = strings.TrimSpace(source.Attributes["chatgpt_plan_type"])
		}
	}
	defaulted := false
	if planPresent {
		// The provenance marker belongs to the same source as the plan.
		// Legacy explicit free without a boolean true remains explicit free.
		defaulted, _ = source.Metadata["plan_type_defaulted"].(bool)
	} else {
		plan, _ = metadataString("chatgpt_plan_type")
		if plan == "" && tokenPresent {
			plan = tokenPlan
		}
		if plan == "" && !claimPlanPresent && auxiliary {
			plan = strings.TrimSpace(source.Attributes["plan_type"])
			defaulted = strings.EqualFold(strings.TrimSpace(source.Attributes["plan_type_defaulted"]), "true")
		}
		if plan == "" {
			plan = claimPlan
		}
	}
	if plan == "" {
		// A cleared plan may still be derived from the adopted token, but
		// cannot revive a plan from an auxiliary source through claim-plan.
		plan, _ = metadataString("chatgpt_plan_type")
		if plan == "" {
			plan = tokenPlan
		}
		defaulted = plan == ""
		if defaulted {
			plan = codexauth.DefaultPlanType
		}
	}
	clearedPlan := claimPlanPresent && claimPlan == "" && planPresent && defaulted

	metadata := make(map[string]any, len(target.Metadata)+6)
	for key, value := range target.Metadata {
		metadata[key] = value
	}
	// Empty account and token values also clear them in a versioned refresh patch.
	metadata["account_id"] = account
	metadata["id_token"] = token
	delete(metadata, "chatgpt_user_id")
	delete(metadata, "chatgpt_plan_type")
	if _, memberPresent := source.Metadata["chatgpt_user_id"]; member != "" || memberPresent {
		// Retain a canonical clearing marker so a repeated ID token, auxiliary
		// attribute or warm resolver cannot restore an explicitly removed member.
		metadata["chatgpt_user_id"] = member
	}
	if claimPlan != "" || clearedPlan {
		metadata["chatgpt_plan_type"] = claimPlan
	}
	metadata["plan_type"] = plan
	metadata["plan_type_defaulted"] = defaulted
	target.Metadata = metadata

	attributes := make(map[string]string, len(target.Attributes)+2)
	for key, value := range target.Attributes {
		attributes[key] = value
	}
	for _, key := range []string{"account_id", "id_token", "chatgpt_user_id", "chatgpt_plan_type"} {
		delete(attributes, key)
	}
	attributes["plan_type"] = plan
	attributes["plan_type_defaulted"] = strconv.FormatBool(defaulted)
	target.Attributes = attributes
}

// HomeRenewedSIWC distinguishes a completed SIWC renewal from a Home response
// that echoes the current grant while refreshing the outer OAuth partition.
func HomeRenewedSIWC(current, result *cliproxyauth.Auth, now time.Time) bool {
	previous, _ := current.Metadata["siwc"].(map[string]any)
	returned, _ := result.Metadata["siwc"].(map[string]any)
	token := codexauth.SIWCAccessToken(returned)
	if token == "" || token == current.RejectedSIWCAccessToken || token == current.RejectedAccessToken {
		return false
	}
	newExpiry, hasExpiry := result.SIWCRenewalExpirationTime()
	if token != codexauth.SIWCAccessToken(previous) {
		// Changed bytes can still describe an expired credential. Preserve
		// unknown-lifetime compatibility, but honor any known renewal window.
		return !hasExpiry || newExpiry.After(now.Add(cliproxyauth.CodexSIWCRefreshLead))
	}
	oldExpiry, _ := current.SIWCRenewalExpirationTime()
	return hasExpiry && newExpiry.After(oldExpiry) && newExpiry.After(now.Add(cliproxyauth.CodexSIWCRefreshLead))
}

// AdoptCodexHomeSIWC completes a sparse renewal without reviving an identity
// or expiration belonging to a replaced bearer. Registration and an omitted
// refresh token remain usable until Home explicitly replaces or clears them.
func AdoptCodexHomeSIWC(current, returned map[string]any) map[string]any {
	adopted := make(map[string]any, len(current)+len(returned))
	for key, value := range current {
		adopted[key] = value
	}
	sameBearer := codexauth.SIWCAccessToken(current) == codexauth.SIWCAccessToken(returned)
	delete(adopted, "access_token")
	delete(adopted, "access")
	if !sameBearer {
		for _, key := range []string{"id_token", "earliest_refresh_at", "last_refresh", "lastRefresh"} {
			delete(adopted, key)
		}
	}
	for key, value := range returned {
		adopted[key] = value
	}
	cliproxyauth.ReplaceCodexSIWCExpiration(adopted, current, returned, sameBearer)
	codexauth.NormalizeSIWCAccessToken(adopted)
	return adopted
}

// RefreshAuthViaHome replaces local refresh logic when home control plane integration is enabled.
// It returns (updatedAuth, true, nil) when home refresh succeeds; (nil, true, err) when home is
// enabled but refresh fails; and (nil, false, nil) when home is disabled.
func RefreshAuthViaHome(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, bool, error) {
	return refreshAuthViaHome(ctx, cfg, auth, nil)
}

// RefreshCodexAuthViaHome checks the record selected for the file lock before
// interpreting its state or either OAuth partition.
func RefreshCodexAuthViaHome(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, bool, error) {
	return refreshAuthViaHome(ctx, cfg, auth, func(updated *cliproxyauth.Auth) error {
		if updated.ID != "" && updated.ID != auth.ID {
			return ErrHomeRefreshRecordMismatch
		}
		if updated.Provider != "" && !strings.EqualFold(strings.TrimSpace(updated.Provider), "codex") {
			return ErrHomeRefreshRecordMismatch
		}
		// The watcher reads the persisted file type as its provider on restart.
		if rawType, exists := updated.Metadata["type"]; exists {
			fileType, _ := rawType.(string)
			if !strings.EqualFold(strings.TrimSpace(fileType), "codex") {
				return ErrHomeRefreshRecordMismatch
			}
		}
		// Home owns credential contents, not this process's storage location.
		// A remote path could redirect a later save or its read-before-write
		// adoption to another record even when the returned ID matches.
		for _, key := range []string{cliproxyauth.AttributePath, cliproxyauth.AttributeSource, cliproxyauth.AttributeSourceBackend, cliproxyauth.AttributeRuntimeOnly} {
			delete(updated.Attributes, key)
			if value, present := auth.Attributes[key]; present {
				if updated.Attributes == nil {
					updated.Attributes = make(map[string]string)
				}
				updated.Attributes[key] = value
			}
		}
		return nil
	})
}

func refreshAuthViaHome(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, validate func(*cliproxyauth.Auth) error) (*cliproxyauth.Auth, bool, error) {
	if cfg == nil || !cfg.Home.Enabled {
		return nil, false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if auth == nil {
		return nil, true, homeStatusErr{code: http.StatusInternalServerError, msg: "home refresh: auth is nil"}
	}

	client := currentHomeRefreshClient()
	if client == nil || !client.HeartbeatOK() {
		return nil, true, homeStatusErr{code: http.StatusServiceUnavailable, msg: "home control center unavailable"}
	}

	authIndex := strings.TrimSpace(auth.Index)
	if authIndex == "" {
		authIndex = strings.TrimSpace(auth.EnsureIndex())
	}
	if authIndex == "" {
		return nil, true, homeStatusErr{code: http.StatusBadGateway, msg: "home refresh: auth_index is empty"}
	}

	raw, err := client.GetRefreshAuth(ctx, authIndex, authAccessTokenSHA256(auth))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, true, err
		}
		return nil, true, homeStatusErr{
			code:       http.StatusServiceUnavailable,
			msg:        "home refresh temporarily unavailable",
			diagnostic: "Home refresh transport failed: " + logging.SafeErrorDiagnostic(err),
		}
	}

	var env homeErrorEnvelope
	if errUnmarshal := json.Unmarshal(raw, &env); errUnmarshal == nil && env.Error != nil {
		code := strings.TrimSpace(env.Error.Type)
		if code == "" {
			code = strings.TrimSpace(env.Error.Code)
		}
		if env.Error.Upstream != nil {
			return nil, true, homeStatusErr{
				code:       env.Error.Upstream.Status,
				msg:        string(env.Error.Upstream.Body),
				diagnostic: env.Error.Diagnostic,
				errorType:  code,
				upstream:   true,
			}
		}
		statusCode := statusFromHomeErrorCode(code)
		message := "credential refresh temporarily unavailable"
		switch statusCode {
		case http.StatusUnauthorized:
			message = "credential unauthorized"
		case http.StatusNotFound:
			message = "credential refresh target not found"
		}
		return nil, true, homeStatusErr{code: statusCode, msg: message, diagnostic: env.Error.Diagnostic, errorType: code}
	}

	updated, returnedIndex, errParse := parseHomeRefreshAuth(raw)
	if errParse != nil {
		return nil, true, homeStatusErr{
			code:       http.StatusBadGateway,
			msg:        "home returned invalid auth payload",
			diagnostic: "Home refresh response decode failed: " + logging.SafeErrorDiagnostic(errParse),
		}
	}
	if validate != nil {
		if errValidate := validate(updated); errValidate != nil {
			return nil, true, errValidate
		}
	}
	if updated.Disabled || updated.Status == cliproxyauth.StatusDisabled {
		return nil, true, homeStatusErr{code: http.StatusUnauthorized, msg: "credential unauthorized"}
	}
	if returnedIndex != "" {
		authIndex = returnedIndex
	}
	updated.Index = authIndex
	updated.EnsureIndex()
	return updated, true, nil
}

func authAccessTokenSHA256(auth *cliproxyauth.Auth) string {
	return cliproxyauth.AccessTokenSHA256(auth)
}

func parseHomeRefreshAuth(raw []byte) (*cliproxyauth.Auth, string, error) {
	var envelope homeRefreshAuthEnvelope
	if errUnmarshal := json.Unmarshal(raw, &envelope); errUnmarshal != nil {
		return nil, "", errUnmarshal
	}
	index := ""
	if envelope.Auth != nil {
		raw = envelope.Auth
		index = strings.TrimSpace(envelope.AuthIndex)
	}
	var updated cliproxyauth.Auth
	if errUnmarshal := json.Unmarshal(raw, &updated); errUnmarshal != nil {
		return nil, "", errUnmarshal
	}
	// Metadata and attributes are provider-defined, including plugin credentials.
	// A disabled record is meaningful even without any credential or identifier.
	if strings.TrimSpace(updated.ID) == "" && strings.TrimSpace(updated.Provider) == "" &&
		len(updated.Metadata) == 0 && len(updated.Attributes) == 0 && !updated.Disabled && updated.Status != cliproxyauth.StatusDisabled {
		return nil, "", errors.New("missing auth record in refresh response")
	}
	return &updated, index, nil
}

func statusFromHomeErrorCode(code string) int {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "authentication_error", "unauthorized", "invalid_grant", "refresh_token_expired", "refresh_token_revoked", "refresh_token_reused":
		return http.StatusUnauthorized
	case "model_not_found":
		return http.StatusNotFound
	case "auth_not_found", "auth_unavailable", "refresh_temporarily_unavailable", "refresh_unsupported", "home_unavailable":
		return http.StatusServiceUnavailable
	default:
		return http.StatusServiceUnavailable
	}
}
