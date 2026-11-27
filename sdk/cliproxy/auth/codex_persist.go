package auth

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

// IsCodexAuthRecord reports whether auth represents a Codex credential record.
func IsCodexAuthRecord(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return true
	}
	if auth.Metadata != nil {
		if t, ok := auth.Metadata["type"].(string); ok && strings.EqualFold(strings.TrimSpace(t), "codex") {
			return true
		}
	}
	if _, ok := auth.Storage.(*codex.CodexTokenStorage); ok {
		return true
	}
	return false
}

// PersistCodexAuthFile persists a Codex auth record to path using inter-process file locking,
// read-before-write merging, and scoped refresh patches when present.
// It returns handled=false when auth is not a Codex credential record.
func PersistCodexAuthFile(ctx context.Context, path string, auth *Auth) (bool, error) {
	if !IsCodexAuthRecord(auth) {
		return false, nil
	}

	type metadataSetter interface {
		SetMetadata(map[string]any)
	}

	switch {
	case auth.CodexRefreshPatch != nil:
		errRefresh := codex.WithFileLock(path, func() error {
			existing, errRead := os.ReadFile(path)
			if errRead != nil {
				if os.IsNotExist(errRead) {
					if auth.Metadata == nil {
						auth.Metadata = make(map[string]any)
					}
					auth.Metadata["disabled"] = auth.Disabled
					NormalizeCredentialMetadata(auth.Metadata)
					return codex.WriteJSONFileAtomic(path, auth.Metadata)
				}
				return fmt.Errorf("auth filestore: read refresh source failed: %w", errRead)
			}
			var diskMap map[string]any
			if errUnmarshal := json.Unmarshal(existing, &diskMap); errUnmarshal != nil || diskMap == nil {
				return fmt.Errorf("auth filestore: invalid refresh source JSON")
			}
			merged := auth.CodexRefreshPatch.Apply(diskMap)
			NormalizeCredentialMetadata(merged)
			if errWrite := codex.WriteJSONFileAtomic(path, merged); errWrite != nil {
				return errWrite
			}
			auth.Metadata = merged
			return nil
		})
		if errRefresh != nil {
			return true, errRefresh
		}
		auth.CodexRefreshPatch = nil
		auth.Storage = nil
		synchronizeCodexIdentityAttributes(auth)
		if disabled, ok := auth.Metadata["disabled"].(bool); ok {
			auth.Disabled = disabled
		}
		return true, nil

	case auth.Storage != nil:
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		auth.Metadata["disabled"] = auth.Disabled
		if storage, ok := auth.Storage.(*codex.CodexTokenStorage); ok && storage != nil {
			clonedStorage := *storage
			clonedStorage.ReplaceCredentials = HasAuthCreationIntent(ctx)
			auth.Storage = &clonedStorage
		}
		if setter, ok := auth.Storage.(metadataSetter); ok {
			setter.SetMetadata(auth.Metadata)
		}
		if errSave := auth.Storage.SaveTokenToFile(path); errSave != nil {
			return true, errSave
		}
		if persistedBytes, errReadPersisted := os.ReadFile(path); errReadPersisted == nil && len(persistedBytes) > 0 {
			var diskMap map[string]any
			if errUnmarshal := json.Unmarshal(persistedBytes, &diskMap); errUnmarshal == nil && len(diskMap) > 0 {
				auth.Metadata = diskMap
				NormalizeCredentialMetadata(auth.Metadata)
				synchronizeCodexIdentityAttributes(auth)
				if _, ok := auth.Storage.(*codex.CodexTokenStorage); ok {
					var savedStorage codex.CodexTokenStorage
					if errDecode := json.Unmarshal(persistedBytes, &savedStorage); errDecode == nil {
						savedStorage.SetMetadata(auth.Metadata)
						auth.Storage = &savedStorage
					}
				}
			}
		}
		return true, nil

	case auth.Metadata != nil:
		auth.Metadata["disabled"] = auth.Disabled
		errLock := codex.WithFileLock(path, func() error {
			existing, errRead := os.ReadFile(path)
			if errRead == nil && len(existing) > 0 {
				var diskMap map[string]any
				if errUnmarshal := json.Unmarshal(existing, &diskMap); errUnmarshal == nil && len(diskMap) > 0 {
					if !HasAuthCreationIntent(ctx) {
						auth.Metadata = codex.MergeCodexCredentialsFromDisk(diskMap, auth.Metadata)
					}
					auth.Metadata["disabled"] = auth.Disabled
					NormalizeCredentialMetadata(auth.Metadata)
					if raw, errMarshal := json.Marshal(auth.Metadata); errMarshal == nil && string(existing) == string(raw) {
						return nil
					}
				}
			} else if errRead != nil && !os.IsNotExist(errRead) {
				return fmt.Errorf("auth filestore: read existing failed: %w", errRead)
			}
			return codex.WriteJSONFileAtomic(path, auth.Metadata)
		})
		if errLock != nil {
			return true, errLock
		}
		synchronizeCodexIdentityAttributes(auth)
		return true, nil

	default:
		return false, nil
	}
}

// synchronizeCodexIdentityAttributes keeps auxiliary hints with the persisted
// credential partition. Administrator device and header overrides are independent.
func synchronizeCodexIdentityAttributes(auth *Auth) {
	if auth.Attributes == nil {
		return
	}
	attributes := make(map[string]string, len(auth.Attributes))
	for key, value := range auth.Attributes {
		attributes[key] = value
	}
	auth.Attributes = attributes
	for _, key := range []string{"account_id", "id_token", "chatgpt_user_id", "chatgpt_plan_type", "plan_type", "plan_type_defaulted"} {
		delete(auth.Attributes, key)
		if value, ok := auth.Metadata[key].(string); ok && strings.TrimSpace(value) != "" {
			auth.Attributes[key] = value
		}
	}
	if defaulted, ok := auth.Metadata["plan_type_defaulted"].(bool); ok {
		auth.Attributes["plan_type_defaulted"] = strconv.FormatBool(defaulted)
	}
	if strings.TrimSpace(auth.Attributes["plan_type"]) == "" {
		if idToken, ok := auth.Metadata["id_token"].(string); ok {
			if claims, errParse := codex.ParseJWTToken(idToken); errParse == nil && claims != nil {
				account, _ := auth.Metadata["account_id"].(string)
				claimAccount := strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
				if strings.TrimSpace(account) == "" || claimAccount == "" || strings.TrimSpace(account) == claimAccount {
					auth.Attributes["plan_type"] = claims.GetPlanType()
					auth.Attributes["plan_type_defaulted"] = strconv.FormatBool(strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType) == "")
				}
			}
		}
	}
}
