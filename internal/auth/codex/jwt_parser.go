package codex

import (
	"fmt"
	"strings"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/json"
)

// JWTClaims represents the claims section of a JSON Web Token (JWT).
// It includes standard claims like issuer, subject, and expiration time, as well as
// custom claims specific to OpenAI's authentication.
type JWTClaims struct {
	AtHash        string        `json:"at_hash"`
	Aud           []string      `json:"aud"`
	AuthProvider  string        `json:"auth_provider"`
	AuthTime      int           `json:"auth_time"`
	Email         string        `json:"email"`
	EmailVerified bool          `json:"email_verified"`
	Exp           int           `json:"exp"`
	CodexAuthInfo CodexAuthInfo `json:"https://api.openai.com/auth"`
	Iat           int           `json:"iat"`
	Iss           string        `json:"iss"`
	Jti           string        `json:"jti"`
	Rat           int           `json:"rat"`
	Sid           string        `json:"sid"`
	Sub           string        `json:"sub"`
}

// Organizations defines the structure for organization details within the JWT claims.
// It holds information about the user's organization, such as ID, role, and title.
type Organizations struct {
	ID        string `json:"id"`
	IsDefault bool   `json:"is_default"`
	Role      string `json:"role"`
	Title     string `json:"title"`
}

// CodexAuthInfo contains authentication-related details specific to Codex.
// This includes ChatGPT account information, subscription status, and user/organization IDs.
type CodexAuthInfo struct {
	ChatgptAccountID               string          `json:"chatgpt_account_id"`
	ChatgptPlanType                string          `json:"chatgpt_plan_type"`
	ChatgptSubscriptionActiveStart any             `json:"chatgpt_subscription_active_start"`
	ChatgptSubscriptionActiveUntil any             `json:"chatgpt_subscription_active_until"`
	ChatgptSubscriptionLastChecked time.Time       `json:"chatgpt_subscription_last_checked"`
	ChatgptUserID                  string          `json:"chatgpt_user_id"`
	Groups                         []any           `json:"groups"`
	Organizations                  []Organizations `json:"organizations"`
	UserID                         string          `json:"user_id"`
}

// ParseJWTToken parses a JWT token string and extracts its claims without performing
// cryptographic signature verification. This is useful for introspecting the token's
// contents to retrieve user information from an ID token after it has been validated
// by the authentication server.
func ParseJWTToken(token string) (*JWTClaims, error) {
	var claims JWTClaims
	// JWT audiences may be a single string or a list. Decode this union
	// separately without changing the public claims shape or other type checks.
	type claimsFields JWTClaims
	wire := struct {
		*claimsFields
		Audience json.RawMessage `json:"aud"`
	}{claimsFields: (*claimsFields)(&claims)}
	if errDecode := decodeJWTClaims(token, &wire); errDecode != nil {
		return nil, errDecode
	}
	if len(wire.Audience) != 0 {
		if errAudience := json.Unmarshal(wire.Audience, &claims.Aud); errAudience != nil {
			var audience string
			if errString := json.Unmarshal(wire.Audience, &audience); errString != nil {
				return nil, fmt.Errorf("failed to unmarshal JWT audience: %w", errAudience)
			}
			claims.Aud = []string{audience}
		}
	}
	return &claims, nil
}

// JWTSubject contains only stable identity claims used for socket reuse. SIWC
// tokens may use an OIDC subject without the ChatGPT claim namespace.
type JWTSubject struct {
	Issuer  string
	Subject string
	Account string
	User    string
}

// ParseJWTSubject inspects identity claims independently of optional claims
// such as aud (which may be either a string or a list). No token is retained.
func ParseJWTSubject(token string) (JWTSubject, bool) {
	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
		Auth    struct {
			Account string `json:"chatgpt_account_id"`
			User    string `json:"chatgpt_user_id"`
			UserID  string `json:"user_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if decodeJWTClaims(token, &claims) != nil {
		return JWTSubject{}, false
	}
	user := strings.TrimSpace(claims.Auth.User)
	if user == "" {
		user = strings.TrimSpace(claims.Auth.UserID)
	}
	subject := JWTSubject{Issuer: strings.TrimSpace(claims.Issuer), Subject: strings.TrimSpace(claims.Subject), Account: strings.TrimSpace(claims.Auth.Account), User: user}
	return subject, subject.Subject != "" || subject.User != ""
}

func decodeJWTClaims(token string, claims any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT token format: expected 3 parts, got %d", len(parts))
	}

	// Decode the claims (payload) part
	claimsData, err := base64URLDecode(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode JWT claims: %w", err)
	}

	if err = json.Unmarshal(claimsData, claims); err != nil {
		return fmt.Errorf("failed to unmarshal JWT claims: %w", err)
	}
	return nil
}

// base64URLDecode decodes a Base64 URL-encoded string, adding padding if necessary.
// JWTs use a URL-safe Base64 alphabet and omit padding, so this function ensures
// correct decoding by re-adding the padding before decoding.
func base64URLDecode(data string) ([]byte, error) {
	if decoded, errDecode := base64.RawURLEncoding.DecodeString(data); errDecode == nil {
		return decoded, nil
	}
	// Add padding if necessary
	switch len(data) % 4 {
	case 2:
		data += "=="
	case 3:
		data += "="
	}
	return base64.URLEncoding.DecodeString(data)
}

// GetUserEmail extracts the user's email address from the JWT claims.
func (c *JWTClaims) GetUserEmail() string {
	return c.Email
}

// GetAccountID extracts the user's account ID (subject) from the JWT claims.
// It retrieves the unique identifier for the user's ChatGPT account.
func (c *JWTClaims) GetAccountID() string {
	return c.CodexAuthInfo.ChatgptAccountID
}

// DefaultPlanType defines the default subscription plan type when not present in claims.
const DefaultPlanType = "free"

// GetPlanType extracts the ChatGPT plan type from the JWT claims.
// If the claim is missing or empty, it defaults to "free".
func (c *JWTClaims) GetPlanType() string {
	if c == nil {
		return DefaultPlanType
	}
	if pt := strings.TrimSpace(c.CodexAuthInfo.ChatgptPlanType); pt != "" {
		return pt
	}
	return DefaultPlanType
}
