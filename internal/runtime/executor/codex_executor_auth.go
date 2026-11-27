package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/MoeForge/moego/json"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

const defaultOpenAISIWCBaseURL = "https://api.openai.com/v1"

func codexUseSIWC(auth *cliproxyauth.Auth) bool {
	if auth == nil {
		return false
	}
	enabled := false
	if len(auth.Attributes) > 0 {
		if raw := strings.TrimSpace(auth.Attributes["use_siwc"]); raw != "" {
			if parsed, errParse := strconv.ParseBool(raw); errParse == nil {
				enabled = parsed
			}
		}
	}
	if !enabled && auth.Metadata != nil {
		switch v := auth.Metadata["use_siwc"].(type) {
		case bool:
			enabled = v
		case string:
			if parsed, errParse := strconv.ParseBool(strings.TrimSpace(v)); errParse == nil {
				enabled = parsed
			}
		}
	}
	return enabled
}

func codexUseSIWCForRequest(ctx context.Context, auth *cliproxyauth.Auth, clientHeaders ...http.Header) bool {
	return cliproxyauth.IsCodexUseSIWCForRequest(ctx, auth, clientHeaders...)
}

func ensureCodexSIWCCredentials(auth *cliproxyauth.Auth, apiKey string) error {
	return ensureCodexSIWCCredentialsForRequest(context.Background(), auth, apiKey)
}

func ensureCodexSIWCCredentialsForRequest(ctx context.Context, auth *cliproxyauth.Auth, apiKey string, clientHeaders ...http.Header) error {
	if !codexUseSIWC(auth) {
		return nil
	}
	if cliproxyauth.IsCodexClientRequest(ctx, clientHeaders...) {
		if strings.TrimSpace(apiKey) == "" {
			return statusErr{code: 401, msg: "codex executor: original OAuth access_token is required for Codex client requests"}
		}
		return nil
	}
	if strings.TrimSpace(apiKey) == "" {
		return statusErr{code: 401, msg: "codex executor: use_siwc is enabled but siwc access_token is missing"}
	}
	return nil
}

func codexSIWCAccessToken(auth *cliproxyauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	siwcMap, _ := auth.Metadata["siwc"].(map[string]any)
	return codexauth.SIWCAccessToken(siwcMap)
}

func cloneSIWCMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		switch typed := v.(type) {
		case []string:
			s := make([]string, len(typed))
			copy(s, typed)
			dst[k] = s
		case []any:
			s := make([]any, len(typed))
			copy(s, typed)
			dst[k] = s
		default:
			dst[k] = v
		}
	}
	return dst
}

func resolveCodexAuthDiskPath(cfg *config.Config, auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", nil
	}
	var candidates []string
	explicitPath := ""
	if len(auth.Attributes) > 0 {
		if p := strings.TrimSpace(auth.Attributes[cliproxyauth.AttributePath]); p != "" {
			explicitPath = p
			candidates = append(candidates, p)
		}
		if s := strings.TrimSpace(auth.Attributes[cliproxyauth.AttributeSource]); s != "" && !strings.Contains(s, ":") {
			candidates = append(candidates, s)
		}
	}
	for _, name := range []string{strings.TrimSpace(auth.FileName), strings.TrimSpace(auth.ID)} {
		if name == "" {
			continue
		}
		if filepath.IsAbs(name) {
			candidates = append(candidates, name)
		} else if cfg != nil && strings.TrimSpace(cfg.AuthDir) != "" {
			candidates = append(candidates, filepath.Join(strings.TrimSpace(cfg.AuthDir), name))
		}
	}
	for _, candidate := range candidates {
		info, errStat := os.Stat(candidate)
		if errStat != nil {
			if os.IsNotExist(errStat) {
				// An established source may have been deleted before its watcher
				// event reaches Manager. Do not turn it into a memory-only refresh.
				if candidate == explicitPath {
					return "", fmt.Errorf("codex executor: credential source removed: %w", errStat)
				}
				continue
			}
			return "", fmt.Errorf("codex executor: stat credential file %s: %w", candidate, errStat)
		}
		if !info.IsDir() {
			canonical, errCanonical := filepath.EvalSymlinks(candidate)
			if errCanonical != nil {
				return "", fmt.Errorf("codex executor: resolve credential path: %w", errCanonical)
			}
			return filepath.Abs(canonical)
		}
	}
	return "", nil
}

func (e *CodexExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	log.Debugf("codex executor: refresh called")
	var cfg *config.Config
	if e != nil {
		cfg = e.cfg
	}
	homeEnabled := cfg != nil && cfg.Home.Enabled
	if auth == nil {
		if refreshed, handled, err := helps.RefreshCodexAuthViaHome(ctx, cfg, auth); handled {
			return refreshed, err
		}
		return nil, statusErr{code: 500, msg: "codex executor: auth is nil"}
	}

	diskPath, errPath := resolveCodexAuthDiskPath(cfg, auth)
	if errPath != nil {
		return nil, errPath
	}
	if diskPath != "" {
		var outAuth *cliproxyauth.Auth
		errLock := codexauth.WithFileLock(diskPath, func() error {
			var errInner error
			outAuth, errInner = e.refreshLocked(ctx, auth, diskPath, homeEnabled)
			return errInner
		})
		return outAuth, errLock
	}
	return e.refreshLocked(ctx, auth, "", homeEnabled)
}

func (e *CodexExecutor) refreshLocked(ctx context.Context, auth *cliproxyauth.Auth, diskPath string, homeEnabled bool) (refreshed *cliproxyauth.Auth, err error) {
	defer func() {
		if refreshed == nil || refreshed.CodexRefreshPatch == nil {
			return
		}
		refreshed.CodexRefreshPatch = refreshed.CodexRefreshPatch.WithSourceFile(diskPath)
		if storage, ok := refreshed.Storage.(*codexauth.CodexTokenStorage); ok && storage != nil {
			snapshot := storage.WithMetadataSnapshot(refreshed.Metadata)
			snapshot.RefreshPatch = refreshed.CodexRefreshPatch
			refreshed.Storage = snapshot
		}
	}()
	var cfg *config.Config
	if e != nil {
		cfg = e.cfg
	}
	beforeRefresh := auth
	auth = auth.Clone()
	auth.CodexRefreshPatch = nil
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}

	now := time.Now()
	_, _, initNeedOuter := cliproxyauth.CodexOuterNeedsRefresh(auth, now)
	_, _, initNeedSIWC := cliproxyauth.CodexSIWCNeedsRefresh(auth, now)
	explicitUnscheduled := !initNeedOuter && !initNeedSIWC

	diskRotatedOuter := false
	diskRotatedSIWC := false
	var diskBaseline map[string]any
	if diskPath != "" {
		existingBytes, errRead := os.ReadFile(diskPath)
		if errRead != nil {
			return nil, fmt.Errorf("codex executor: read credential file %s: %w", diskPath, errRead)
		}
		var diskMap map[string]any
		if errUnmarshal := json.Unmarshal(existingBytes, &diskMap); errUnmarshal != nil || len(diskMap) == 0 {
			return nil, fmt.Errorf("codex executor: invalid credential JSON in %s: %w", diskPath, errUnmarshal)
		}
		diskBaseline = cloneSIWCMap(diskMap)
		if siwcSub, okSub := diskMap["siwc"].(map[string]any); okSub {
			diskBaseline["siwc"] = cloneSIWCMap(siwcSub)
		}
		if !codexauth.SameOuterCredentialSnapshot(auth.Metadata, diskMap) {
			diskRotatedOuter = true
			cliproxyauth.ReplaceCodexOuterExpiration(auth.Metadata, diskMap, false)
			cliproxyauth.ReplaceCodexOuterRefreshTime(auth, &cliproxyauth.Auth{Metadata: diskMap}, false)
			for _, key := range []string{"id_token", "access_token", "refresh_token", "account_id", "last_refresh", "email", "plan_type", "plan_type_defaulted", "chatgpt_user_id", "chatgpt_plan_type", "type"} {
				if val, exists := diskMap[key]; exists {
					auth.Metadata[key] = val
				} else {
					switch key {
					case "account_id", "id_token", "access_token", "refresh_token", "email":
						// Keep versioned fields in the refresh patch so Manager's
						// generic deletion pass cannot invalidate its baseline. A full
						// disk replacement must not inherit the previous grant.
						auth.Metadata[key] = ""
					case "plan_type", "plan_type_defaulted", "chatgpt_user_id", "chatgpt_plan_type":
						delete(auth.Metadata, key)
					}
				}
			}
			// Identity hints belong to the adopted credential partition. Retaining
			// an old member or auxiliary token can conceal a replacement subject.
			clonedAttributes := make(map[string]string, len(auth.Attributes)+2)
			for k, v := range auth.Attributes {
				clonedAttributes[k] = v
			}
			for _, key := range []string{"account_id", "id_token", "chatgpt_user_id", "chatgpt_plan_type", "plan_type", "plan_type_defaulted"} {
				delete(clonedAttributes, key)
			}
			if planType, okPlan := auth.Metadata["plan_type"].(string); okPlan && strings.TrimSpace(planType) != "" {
				clonedAttributes["plan_type"] = strings.TrimSpace(planType)
				defaulted, _ := auth.Metadata["plan_type_defaulted"].(bool)
				clonedAttributes["plan_type_defaulted"] = strconv.FormatBool(defaulted)
			}
			auth.Attributes = clonedAttributes
		}
		diskSIWC, _ := diskMap["siwc"].(map[string]any)
		inSIWC, _ := auth.Metadata["siwc"].(map[string]any)
		if !codexauth.SameSIWCCredentialSnapshot(inSIWC, diskSIWC) {
			if len(diskSIWC) > 0 {
				diskRotatedSIWC = true
				codexauth.NormalizeSIWCAccessToken(diskSIWC)
				// This is a complete disk snapshot, not a sparse Home response.
				// Carry removed grant and registration fields through the versioned
				// patch instead of inheriting them from the previous credential.
				for _, key := range []string{"access_token", "refresh_token", "id_token", "client_id", "device_id", "scope", "scopes"} {
					if _, present := diskSIWC[key]; !present {
						diskSIWC[key] = ""
					}
				}
				auth.Metadata["siwc"] = diskSIWC
			} else {
				// Absent, null and empty disk partitions cannot supply an old grant.
				diskRotatedSIWC = true
				delete(auth.Metadata, "siwc")
			}
		}
		if diskUse, hasDiskUse := diskMap["use_siwc"]; hasDiskUse {
			auth.Metadata["use_siwc"] = diskUse
		}
	}

	var outerRefreshToken string
	var existingSIWC map[string]any
	var siwcRefreshToken, siwcClientID, siwcDeviceID string
	var preservedUseSIWC any
	hasPreservedUseSIWC := false

	if v, ok := auth.Metadata["refresh_token"].(string); ok && strings.TrimSpace(v) != "" {
		outerRefreshToken = strings.TrimSpace(v)
	}
	if v, exists := auth.Metadata["use_siwc"]; exists {
		preservedUseSIWC = v
		hasPreservedUseSIWC = true
	}
	if siwcRaw, ok := auth.Metadata["siwc"].(map[string]any); ok && len(siwcRaw) > 0 {
		existingSIWC = cloneSIWCMap(siwcRaw)
		if v, okStr := existingSIWC["refresh_token"].(string); okStr {
			siwcRefreshToken = strings.TrimSpace(v)
		}
		if v, okStr := existingSIWC["client_id"].(string); okStr {
			siwcClientID = strings.TrimSpace(v)
		}
		if v, okStr := existingSIWC["device_id"].(string); okStr {
			siwcDeviceID = strings.TrimSpace(v)
		}
	}

	_, hasOuter, needOuter := cliproxyauth.CodexOuterNeedsRefresh(auth, now)
	if outerRefreshToken == "" && !homeEnabled {
		hasOuter = false
		needOuter = false
	} else if homeEnabled && !hasOuter {
		hasOuter = true
		if outerExp, okExp := auth.OuterExpirationTime(); okExp && !outerExp.IsZero() && !outerExp.After(now.Add(cliproxyauth.CodexOuterRefreshLead)) {
			needOuter = true
		}
	}
	_, hasSIWC, needSIWC := cliproxyauth.CodexSIWCNeedsRefresh(auth, now)
	if siwcRefreshToken == "" || siwcClientID == "" {
		hasSIWC = false
		needSIWC = false
	}

	if cliproxyauth.IsForceRefreshContext(ctx) {
		needOuter = hasOuter
		needSIWC = hasSIWC
	} else if explicitUnscheduled {
		if !diskRotatedOuter {
			needOuter = hasOuter
		}
		if !diskRotatedSIWC {
			needSIWC = hasSIWC
		}
	}
	// Explicit refresh requests must also respect the server's renewal window.
	if earliest, okEarliest := auth.SIWCEarliestRefreshTime(); okEarliest && now.Before(earliest) {
		needSIWC = false
	}
	suppressedRejectedOuter := false
	if auth.RejectedRefreshToken != "" && outerRefreshToken == strings.TrimSpace(auth.RejectedRefreshToken) {
		if needOuter {
			suppressedRejectedOuter = true
		}
		needOuter = false
	}
	suppressedRejectedSIWC := false
	if auth.RejectedSIWCRefreshToken != "" && siwcRefreshToken == strings.TrimSpace(auth.RejectedSIWCRefreshToken) {
		if needSIWC {
			suppressedRejectedSIWC = true
		}
		needSIWC = false
	}

	if !needOuter && !needSIWC {
		if diskRotatedOuter || diskRotatedSIWC {
			patch := codexauth.NewCredentialRefreshPatchWithDiskBaseline(beforeRefresh.Metadata, diskBaseline, auth.Metadata, diskRotatedOuter, diskRotatedSIWC)
			patch.SetUpstreamRefreshed(false)
			auth.CodexRefreshPatch = patch
			return auth, nil
		}
		if suppressedRejectedOuter || suppressedRejectedSIWC {
			if auth.RefreshError != nil {
				return nil, auth.RefreshError
			}
			return nil, statusErr{code: http.StatusUnauthorized, msg: "codex executor: refresh token is invalid; sign-in required"}
		}
		return auth, nil
	}

	svc := codexauth.NewCodexAuthWithProxyURL(cfg, auth.ProxyURL)
	if diskPath != "" && (cfg == nil || cfg.AuthDir == "") {
		svc.SetRefreshJournal(&codexauth.FileRefreshJournal{Dir: filepath.Dir(diskPath)})
	}
	store := sdkauth.GetTokenStore()
	if _, isFileStore := store.(*sdkauth.FileTokenStore); !isFileStore {
		if journal, okJournal := store.(codexauth.RefreshJournal); okJournal {
			svc.SetRefreshJournal(journal)
		}
	}

	outerRefreshed := false
	var outerErr error
	siwcRefreshed := false
	siwcAdopted := false
	var siwcErr error

	// Execute refreshes sequentially so outer and SIWC never race on the same credential state.
	if needOuter {
		if homeEnabled {
			if refreshed, handled, errHome := helps.RefreshCodexAuthViaHome(ctx, cfg, auth); handled {
				if errors.Is(errHome, helps.ErrHomeRefreshRecordMismatch) {
					return nil, errHome
				}
				if errHome != nil {
					outerErr = errHome
				} else if refreshed != nil {
					// Home can complete either credential partition independently.
					// A returned bearer confirms an outer result even if it did not
					// rotate; identity-only or SIWC-only responses do not replace it.
					if homeSIWC, okSIWC := refreshed.Metadata["siwc"].(map[string]any); okSIWC && codexauth.SIWCAccessToken(homeSIWC) != "" {
						siwcRefreshed = helps.HomeRenewedSIWC(auth, refreshed, now)
						adoptedSIWC := helps.AdoptCodexHomeSIWC(existingSIWC, homeSIWC)
						siwcAdopted = !reflect.DeepEqual(existingSIWC, adoptedSIWC)
						existingSIWC = adoptedSIWC
						auth.Metadata["siwc"] = cloneSIWCMap(existingSIWC)
						// A rotated renewal grant must be saved even when Home did
						// not renew the bearer. Any remaining renewal uses that grant.
						siwcRefreshToken, _ = existingSIWC["refresh_token"].(string)
						siwcClientID, _ = existingSIWC["client_id"].(string)
						siwcDeviceID, _ = existingSIWC["device_id"].(string)
						siwcRefreshToken = strings.TrimSpace(siwcRefreshToken)
						siwcClientID = strings.TrimSpace(siwcClientID)
						siwcDeviceID = strings.TrimSpace(siwcDeviceID)
						_, hasSIWC, dueSIWC := cliproxyauth.CodexSIWCNeedsRefresh(auth, now)
						needSIWC = !siwcRefreshed && hasSIWC && (needSIWC || dueSIWC)
						if earliest, okEarliest := auth.SIWCEarliestRefreshTime(); okEarliest && now.Before(earliest) {
							needSIWC = false
						}
						if siwcRefreshToken == strings.TrimSpace(auth.RejectedSIWCRefreshToken) {
							needSIWC = false
						}
					}
					homeAccess, _ := refreshed.Metadata["access_token"].(string)
					if strings.TrimSpace(homeAccess) == "" {
						outerErr = statusErr{code: http.StatusBadGateway, msg: "home returned no outer OAuth credential"}
					} else {
						outerRefreshed = true
						identity := helps.CodexHomeRefreshIdentity(auth, refreshed)
						oldAccess, _ := auth.Metadata["access_token"].(string)
						cliproxyauth.ReplaceCodexOuterExpiration(auth.Metadata, refreshed.Metadata, strings.TrimSpace(homeAccess) == strings.TrimSpace(oldAccess))
						cliproxyauth.ReplaceCodexOuterRefreshTime(auth, refreshed, strings.TrimSpace(homeAccess) == strings.TrimSpace(oldAccess))
						auth.Index = refreshed.Index
						if refreshed.Metadata != nil {
							for k, val := range refreshed.Metadata {
								if k == "siwc" || k == "use_siwc" || codexauth.IsCodexExpirationKey(k) || codexauth.IsCodexRefreshTimeKey(k) {
									continue
								}
								auth.Metadata[k] = val
							}
						}
						if len(refreshed.Attributes) > 0 {
							clonedAttributes := make(map[string]string, len(auth.Attributes)+len(refreshed.Attributes))
							for k, v := range auth.Attributes {
								clonedAttributes[k] = v
							}
							for k, v := range refreshed.Attributes {
								if codexauth.IsCodexRefreshTimeKey(k) {
									continue
								}
								clonedAttributes[k] = v
							}
							auth.Attributes = clonedAttributes
						}
						helps.AdoptCodexHomeIdentity(auth, identity)
					}
				}
			}
		} else {
			td, errOuter := svc.RefreshTokensWithRetry(ctx, outerRefreshToken, 3)
			if errOuter != nil {
				outerErr = errOuter
			} else if td != nil {
				outerRefreshed = true
				auth.Metadata["id_token"] = td.IDToken
				auth.Metadata["access_token"] = td.AccessToken
				if td.RefreshToken != "" {
					auth.Metadata["refresh_token"] = td.RefreshToken
				}
				// Hints belong to the adopted OAuth credential, including absent
				// claims. Keep absence out of persistence and let the bounded device
				// resolver recover transient omissions only for a compatible subject.
				auth.Metadata["account_id"] = td.AccountID
				delete(auth.Metadata, "chatgpt_user_id")
				delete(auth.Metadata, "chatgpt_plan_type")
				if claims, errParse := codexauth.ParseJWTToken(td.IDToken); errParse == nil && claims != nil {
					if member := strings.TrimSpace(claims.CodexAuthInfo.ChatgptUserID); member != "" {
						auth.Metadata["chatgpt_user_id"] = member
					}
					if plan := strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType); plan != "" {
						auth.Metadata["chatgpt_plan_type"] = plan
					}
				}
				auth.Metadata["email"] = td.Email
				cliproxyauth.ReplaceCodexOuterExpiration(auth.Metadata, map[string]any{"expired": td.Expire}, false)
				cliproxyauth.ReplaceCodexOuterRefreshTime(auth, &cliproxyauth.Auth{}, false)
				auth.Metadata["type"] = "codex"
				auth.Metadata["last_refresh"] = time.Now().Format(time.RFC3339)

				planType := strings.TrimSpace(td.PlanType)
				planTypeDefaulted := td.PlanTypeDefaulted || planType == ""
				if planType == "" && td.IDToken != "" {
					if claims, errParse := codexauth.ParseJWTToken(td.IDToken); errParse == nil && claims != nil {
						planType = claims.GetPlanType()
						planTypeDefaulted = strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType) == ""
					}
				}
				if planType == "" {
					planType = codexauth.DefaultPlanType
				}
				auth.Metadata["plan_type"] = planType
				auth.Metadata["plan_type_defaulted"] = planTypeDefaulted
				clonedAttributes := make(map[string]string, len(auth.Attributes)+1)
				for k, v := range auth.Attributes {
					clonedAttributes[k] = v
				}
				for _, key := range []string{"account_id", "id_token", "chatgpt_user_id", "chatgpt_plan_type"} {
					delete(clonedAttributes, key)
				}
				clonedAttributes["plan_type"] = planType
				clonedAttributes["plan_type_defaulted"] = strconv.FormatBool(planTypeDefaulted)
				auth.Attributes = clonedAttributes
			}
		}
	}

	if needSIWC {
		siwcTD, errSIWC := svc.RefreshSIWCTokensWithRetry(ctx, siwcRefreshToken, siwcClientID, siwcDeviceID, 3)
		if errSIWC != nil {
			siwcErr = errSIWC
		} else if siwcTD != nil {
			siwcRefreshed = true
			localSIWC := siwcTD.ToMap()
			existingSIWC = helps.AdoptCodexHomeSIWC(existingSIWC, localSIWC)
			if _, present := localSIWC["earliest_refresh_at"]; !present {
				delete(existingSIWC, "earliest_refresh_at")
			}
		}
	}

	// Preserve route selection alongside the accepted credential partitions.
	if hasPreservedUseSIWC {
		auth.Metadata["use_siwc"] = preservedUseSIWC
	}
	if len(existingSIWC) > 0 {
		auth.Metadata["siwc"] = cloneSIWCMap(existingSIWC)
	}

	if !outerRefreshed && !siwcRefreshed && !siwcAdopted && !diskRotatedOuter && !diskRotatedSIWC {
		if errCombined := codexauth.NewPartitionRefreshError(outerErr, siwcErr); errCombined != nil {
			return nil, errCombined
		}
		return nil, fmt.Errorf("codex executor: refresh failed")
	}
	if outerErr != nil {
		log.Warnf("codex executor: SIWC token refreshed but outer token refresh failed for %s: %v", auth.ID, outerErr)
	}
	if siwcErr != nil {
		log.Warnf("codex executor: outer token refreshed but SIWC token refresh failed for %s: %v", auth.ID, siwcErr)
	}

	patch := codexauth.NewCredentialRefreshPatchWithDiskBaseline(beforeRefresh.Metadata, diskBaseline, auth.Metadata, outerRefreshed || diskRotatedOuter, siwcRefreshed || siwcAdopted || diskRotatedSIWC)
	patch.SetUpstreamRefreshed(outerRefreshed || siwcRefreshed)
	patch.SetPartitionErrors(outerErr, siwcErr)
	if siwcErr != nil {
		patch.SetFailedSIWCRefreshToken(siwcRefreshToken)
	}
	auth.CodexRefreshPatch = patch
	if diskPath != "" {
		latestBytes, errReadLatest := os.ReadFile(diskPath)
		if errReadLatest != nil {
			return auth, fmt.Errorf("codex executor: re-read credential file %s before write: %w", diskPath, errReadLatest)
		}
		var latestDisk map[string]any
		if errUnmarshal := json.Unmarshal(latestBytes, &latestDisk); errUnmarshal != nil || len(latestDisk) == 0 {
			return auth, fmt.Errorf("codex executor: invalid credential JSON in %s before write: %w", diskPath, errUnmarshal)
		}
		mergedDisk := patch.Apply(latestDisk)
		if errWrite := codexauth.WriteJSONFileAtomic(diskPath, mergedDisk); errWrite != nil {
			return auth, fmt.Errorf("codex executor: persist refreshed credentials to %s: %w", diskPath, errWrite)
		}
		auth.Metadata = mergedDisk
	}
	if siwcRefreshed {
		log.Debug("SIWC token renewal completed")
	}
	return auth, nil
}

func codexCreds(a *cliproxyauth.Auth) (apiKey, baseURL string) {
	return codexCredsForRequest(context.Background(), a)
}

func codexCredsForRequest(ctx context.Context, a *cliproxyauth.Auth, clientHeaders ...http.Header) (apiKey, baseURL string) {
	if a == nil {
		return "", ""
	}
	if a.Attributes != nil {
		baseURL = a.Attributes["base_url"]
	}
	if codexUseSIWCForRequest(ctx, a, clientHeaders...) {
		apiKey = codexSIWCAccessToken(a)
		if strings.TrimSpace(baseURL) == "" {
			baseURL = defaultOpenAISIWCBaseURL
		}
		return
	}
	if a.Attributes != nil {
		apiKey = a.Attributes["api_key"]
	}
	if apiKey == "" && a.Metadata != nil {
		if v, ok := a.Metadata["access_token"].(string); ok {
			apiKey = v
		}
	}
	return
}

func (e *CodexExecutor) resolveCodexConfig(auth *cliproxyauth.Auth) *config.CodexKey {
	if e == nil {
		return nil
	}
	return resolveCodexKeyConfig(e.cfg, auth)
}

func resolveCodexKeyConfig(cfg *config.Config, auth *cliproxyauth.Auth) *config.CodexKey {
	if auth == nil || cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
		if index, errIndex := strconv.Atoi(strings.TrimSpace(auth.Attributes[cliproxyauth.AttributeConfigIndex])); errIndex == nil && index >= 0 && index < len(cfg.CodexKey) {
			entry := &cfg.CodexKey[index]
			cfgKey := strings.TrimSpace(entry.APIKey)
			cfgBase := strings.TrimSpace(entry.BaseURL)
			if (attrKey == "" || strings.EqualFold(cfgKey, attrKey)) && (attrBase == "" || strings.EqualFold(cfgBase, attrBase)) {
				return entry
			}
		}
	}
	for i := range cfg.CodexKey {
		entry := &cfg.CodexKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && attrBase != "" {
			if strings.EqualFold(cfgKey, attrKey) && strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	if attrKey != "" {
		for i := range cfg.CodexKey {
			entry := &cfg.CodexKey[i]
			if strings.EqualFold(strings.TrimSpace(entry.APIKey), attrKey) {
				return entry
			}
		}
	}
	return nil
}

func (e *CodexExecutor) resolveCodexModelIsCompat(auth *cliproxyauth.Auth, req cliproxyexecutor.Request, baseModel string) bool {
	if modelInfo, ok := cliproxyauth.ResolvedModelInfo(req); ok && modelInfo != nil {
		return modelInfo.IsCompat
	}
	entry := e.resolveCodexConfig(auth)
	if entry != nil && len(entry.Models) > 0 {
		requested := strings.TrimSpace(req.Model)
		target := strings.TrimSpace(baseModel)
		for i := range entry.Models {
			name := strings.TrimSpace(entry.Models[i].Name)
			alias := strings.TrimSpace(entry.Models[i].Alias)
			if (target != "" && (strings.EqualFold(name, target) || strings.EqualFold(alias, target))) ||
				(requested != "" && (strings.EqualFold(name, requested) || strings.EqualFold(alias, requested))) {
				return entry.Models[i].IsCompat
			}
		}
		return false
	}
	if cliproxyauth.CodexAPIKeyModelIsCompat(e.cfg, auth, baseModel) || cliproxyauth.CodexAPIKeyModelIsCompat(e.cfg, auth, req.Model) {
		return true
	}
	return false
}
