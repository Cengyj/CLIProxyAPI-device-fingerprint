package helps

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

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
	Auth      cliproxyauth.Auth `json:"auth"`
	AuthIndex string            `json:"auth_index"`
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

	metadata := make(map[string]any, len(target.Metadata)+6)
	for key, value := range target.Metadata {
		metadata[key] = value
	}
	// Empty account and token values also clear them in a versioned refresh patch.
	metadata["account_id"] = account
	metadata["id_token"] = token
	delete(metadata, "chatgpt_user_id")
	delete(metadata, "chatgpt_plan_type")
	if member != "" {
		metadata["chatgpt_user_id"] = member
	}
	if claimPlan != "" {
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

// RefreshAuthViaHome replaces local refresh logic when home control plane integration is enabled.
// It returns (updatedAuth, true, nil) when home refresh succeeds; (nil, true, err) when home is
// enabled but refresh fails; and (nil, false, nil) when home is disabled.
func RefreshAuthViaHome(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, bool, error) {
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
	var rawObject map[string]json.RawMessage
	if errUnmarshal := json.Unmarshal(raw, &rawObject); errUnmarshal != nil {
		return nil, "", errUnmarshal
	}
	if len(rawObject) == 0 {
		return nil, "", errors.New("empty auth object")
	}
	if authRaw, ok := rawObject["auth"]; ok {
		var authObject map[string]json.RawMessage
		if errUnmarshal := json.Unmarshal(authRaw, &authObject); errUnmarshal != nil {
			return nil, "", errUnmarshal
		}
		if len(authObject) == 0 {
			return nil, "", errors.New("empty auth envelope")
		}
		var envelope homeRefreshAuthEnvelope
		if errUnmarshal := json.Unmarshal(raw, &envelope); errUnmarshal != nil {
			return nil, "", errUnmarshal
		}
		return &envelope.Auth, strings.TrimSpace(envelope.AuthIndex), nil
	}
	var updated cliproxyauth.Auth
	if errUnmarshal := json.Unmarshal(raw, &updated); errUnmarshal != nil {
		return nil, "", errUnmarshal
	}
	return &updated, "", nil
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
