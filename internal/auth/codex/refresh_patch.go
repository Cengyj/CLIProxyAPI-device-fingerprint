package codex

import (
	"bytes"
	"reflect"
	"strings"

	"github.com/MoeForge/moego/json"
)

var codexSIWCCredentialKeys = []string{
	"access_token", "refresh_token", "id_token", "client_id", "device_id",
	"earliest_refresh_at", "last_refresh", "lastRefresh", "scope", "scopes",
}

// CredentialRefreshPatch is an immutable, partition-specific refresh result.
// Its original token identities (both in-memory and on-disk baselines) act as versions,
// independent of timestamp precision.
type CredentialRefreshPatch struct {
	outerBefore          map[string]any
	outerDiskBefore      map[string]any
	outerAfter           map[string]any
	siwcBefore           map[string]any
	siwcDiskBefore       map[string]any
	siwcAfter            map[string]any
	siwcRemoved          bool
	hadDiskBaseline      bool
	sourceFile           string
	baselineOuterRefresh string
	baselineSIWCRefresh  string
	upstreamRefreshed    bool
	outerErr             error
	siwcErr              error
}

// NewCredentialRefreshPatch records only credential partitions actually refreshed.
func NewCredentialRefreshPatch(before, after map[string]any, outer, siwc bool) *CredentialRefreshPatch {
	patch := NewCredentialRefreshPatchWithDiskBaseline(before, nil, after, outer, siwc)
	patch.upstreamRefreshed = outer || siwc
	return patch
}

// NewCredentialRefreshPatchWithDiskBaseline records both the in-memory baseline (before)
// and the on-disk baseline (diskBefore) observed under the file lock before refreshing to after.
func NewCredentialRefreshPatchWithDiskBaseline(before, diskBefore, after map[string]any, outer, siwc bool) *CredentialRefreshPatch {
	patch := &CredentialRefreshPatch{
		hadDiskBaseline:      diskBefore != nil,
		upstreamRefreshed:    outer || siwc,
		baselineOuterRefresh: lookupRefreshTokenField(diskBefore, before, false),
		baselineSIWCRefresh:  lookupRefreshTokenField(diskBefore, before, true),
	}
	if outer {
		patch.outerBefore = outerCredentialFields(before)
		if len(diskBefore) > 0 {
			patch.outerDiskBefore = outerCredentialFields(diskBefore)
		}
		patch.outerAfter = outerCredentialFields(after)
	}
	if siwc {
		beforeSIWC, _ := before["siwc"].(map[string]any)
		diskBeforeSIWC, _ := diskBefore["siwc"].(map[string]any)
		afterSIWC, _ := after["siwc"].(map[string]any)
		patch.siwcBefore = siwcCredentialFields(beforeSIWC)
		if len(diskBeforeSIWC) > 0 {
			patch.siwcDiskBefore = siwcCredentialFields(diskBeforeSIWC)
		}
		patch.siwcAfter = siwcCredentialFields(afterSIWC)
		_, hasSIWCAfter := after["siwc"]
		patch.siwcRemoved = !hasSIWCAfter
	}
	return patch
}

// WithSourceFile binds a snapshot to its original source without changing the
// shared patch. Saving an accepted snapshot to a new destination remains allowed.
func (p *CredentialRefreshPatch) WithSourceFile(path string) *CredentialRefreshPatch {
	if p == nil || strings.TrimSpace(path) == "" {
		return p
	}
	cloned := *p
	cloned.sourceFile = canonicalLockPath(path)
	return &cloned
}

// RequiresExistingFile prevents a late refresh save from recreating its removed
// source. Legacy patches without a source path conservatively require a file.
func (p *CredentialRefreshPatch) RequiresExistingFile(path string) bool {
	return p != nil && p.hadDiskBaseline && (p.sourceFile == "" || p.sourceFile == canonicalLockPath(path))
}

func lookupRefreshTokenField(diskBefore, memBefore map[string]any, siwc bool) string {
	for _, src := range []map[string]any{diskBefore, memBefore} {
		if len(src) == 0 {
			continue
		}
		target := src
		if siwc {
			nested, ok := src["siwc"].(map[string]any)
			if !ok || len(nested) == 0 {
				continue
			}
			target = nested
		}
		if rt, ok := target["refresh_token"].(string); ok && rt != "" {
			return rt
		}
	}
	return ""
}

func credentialFields(metadata map[string]any, keys []string) map[string]any {
	fields := make(map[string]any)
	for _, key := range keys {
		if value, ok := metadata[key]; ok {
			fields[key] = value
		}
	}
	return cloneStringAnyMap(fields)
}

func siwcCredentialFields(siwc map[string]any) map[string]any {
	fields := credentialFields(siwc, codexSIWCCredentialKeys)
	ReplaceExpirationFields(fields, siwc)
	if token := SIWCAccessToken(siwc); token != "" {
		fields["access_token"] = token
	}
	return fields
}

func outerCredentialFields(metadata map[string]any) map[string]any {
	fields := credentialFields(metadata, codexOuterCredentialKeys)
	ReplaceExpirationFields(fields, metadata)
	return fields
}

// SameOuterCredentialSnapshot compares the fields owned by the outer credential,
// excluding administrator settings and unrelated data in legacy token containers.
func SameOuterCredentialSnapshot(a, b map[string]any) bool {
	return sameCredentialSnapshot(outerCredentialFields(a), outerCredentialFields(b))
}

// SameSIWCCredentialSnapshot includes renewal, identity and registration fields,
// even when a disk edit keeps both token strings unchanged.
func SameSIWCCredentialSnapshot(a, b map[string]any) bool {
	return sameCredentialSnapshot(siwcCredentialFields(a), siwcCredentialFields(b))
}

func sameCredentialSnapshot(a, b map[string]any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	// Disk decoding represents numbers differently from typed login metadata.
	// Compare their JSON values to avoid inventing a rotation after a round trip.
	aJSON, errA := json.Marshal(a)
	bJSON, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(aJSON, bJSON)
}

func sameCredentialVersion(a, b map[string]any) bool {
	for _, key := range []string{"access_token", "refresh_token", "id_token", "account_id", "client_id", "device_id"} {
		if !reflect.DeepEqual(a[key], b[key]) {
			return false
		}
	}
	return true
}

func matchesBaselineOrAfter(target, memBefore, diskBefore, after map[string]any) (matched bool, effectiveBefore map[string]any) {
	matches := func(baseline map[string]any) bool {
		if !sameCredentialVersion(target, baseline) {
			return false
		}
		// When token identity did not change, token strings alone cannot order
		// sparse renewals. Keep a newer expiry or registration snapshot intact.
		return !sameCredentialVersion(baseline, after) || sameCredentialSnapshot(target, baseline)
	}
	if len(diskBefore) > 0 && matches(diskBefore) {
		return true, diskBefore
	}
	if matches(memBefore) {
		return true, memBefore
	}
	if len(after) > 0 && sameCredentialSnapshot(target, after) {
		return true, after
	}
	return false, nil
}

func applyCredentialFields(disk, before, after map[string]any, clearMissing []string) {
	for key, value := range after {
		if IsCodexExpirationKey(key) {
			continue
		}
		// Preserve fields changed on disk that the refresh did not modify.
		oldValue, existed := before[key]
		if !existed || !reflect.DeepEqual(oldValue, value) {
			disk[key] = value
		}
	}
	for _, key := range clearMissing {
		if _, had := before[key]; had {
			if _, has := after[key]; !has {
				delete(disk, key)
			}
		}
	}
}

// IsCodexCredentialKey reports whether key belongs to a Codex credential partition or switch
// managed by CredentialRefreshPatch.
func IsCodexCredentialKey(key string) bool {
	if key == "siwc" || key == "use_siwc" || IsCodexExpirationKey(key) {
		return true
	}
	for _, k := range codexOuterCredentialKeys {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

// RefreshedOuter reports whether p carries a refreshed outer Codex credential partition.
func (p *CredentialRefreshPatch) RefreshedOuter() bool {
	return p != nil && p.outerAfter != nil
}

// RefreshedSIWC reports whether p carries a refreshed SIWC credential partition.
func (p *CredentialRefreshPatch) RefreshedSIWC() bool {
	return p != nil && p.siwcAfter != nil
}

// SetUpstreamRefreshed records whether an upstream OAuth token refresh actually succeeded
// (as opposed to only adopting rotated credentials already present on disk).
func (p *CredentialRefreshPatch) SetUpstreamRefreshed(refreshed bool) {
	if p == nil {
		return
	}
	p.upstreamRefreshed = refreshed
}

// UpstreamRefreshed reports whether p includes an upstream OAuth token refresh.
func (p *CredentialRefreshPatch) UpstreamRefreshed() bool {
	if p == nil {
		return false
	}
	return p.upstreamRefreshed
}

// SetPartitionErrors records any per-partition refresh failures that occurred alongside a partial refresh.
func (p *CredentialRefreshPatch) SetPartitionErrors(outerErr, siwcErr error) {
	if p == nil {
		return
	}
	p.outerErr = outerErr
	p.siwcErr = siwcErr
}

// OuterError returns any error encountered while refreshing the outer OAuth partition.
func (p *CredentialRefreshPatch) OuterError() error {
	if p == nil {
		return nil
	}
	return p.outerErr
}

// SIWCError returns any error encountered while refreshing the SIWC partition.
func (p *CredentialRefreshPatch) SIWCError() error {
	if p == nil {
		return nil
	}
	return p.siwcErr
}

// FailedOuterRefreshToken returns the baseline outer refresh token that was submitted when OuterError occurred.
func (p *CredentialRefreshPatch) FailedOuterRefreshToken() string {
	if p == nil || p.outerErr == nil {
		return ""
	}
	return p.baselineOuterRefresh
}

// FailedSIWCRefreshToken returns the baseline SIWC refresh token that was submitted when SIWCError occurred.
func (p *CredentialRefreshPatch) FailedSIWCRefreshToken() string {
	if p == nil || p.siwcErr == nil {
		return ""
	}
	return p.baselineSIWCRefresh
}

// SetFailedSIWCRefreshToken records the grant actually submitted after adopting
// a rotated Home grant within the same partition refresh.
func (p *CredentialRefreshPatch) SetFailedSIWCRefreshToken(token string) {
	if p != nil && p.siwcErr != nil {
		p.baselineSIWCRefresh = strings.TrimSpace(token)
	}
}

// PartitionRefreshError carries per-partition refresh errors when a credential refresh fails.
type PartitionRefreshError struct {
	outerErr error
	siwcErr  error
}

// NewPartitionRefreshError returns a combined error carrying both outer and SIWC refresh errors when present.
func NewPartitionRefreshError(outerErr, siwcErr error) error {
	if outerErr == nil && siwcErr == nil {
		return nil
	}
	if outerErr != nil && siwcErr == nil {
		return outerErr
	}
	if siwcErr != nil && outerErr == nil {
		return siwcErr
	}
	return &PartitionRefreshError{outerErr: outerErr, siwcErr: siwcErr}
}

func (e *PartitionRefreshError) Error() string {
	if e == nil {
		return ""
	}
	if e.outerErr != nil && e.siwcErr != nil {
		return e.outerErr.Error() + "; " + e.siwcErr.Error()
	}
	if e.outerErr != nil {
		return e.outerErr.Error()
	}
	if e.siwcErr != nil {
		return e.siwcErr.Error()
	}
	return ""
}

func (e *PartitionRefreshError) Unwrap() []error {
	if e == nil {
		return nil
	}
	var errs []error
	if e.outerErr != nil {
		errs = append(errs, e.outerErr)
	}
	if e.siwcErr != nil {
		errs = append(errs, e.siwcErr)
	}
	return errs
}

func (e *PartitionRefreshError) OuterRefreshError() error {
	if e == nil {
		return nil
	}
	return e.outerErr
}

func (e *PartitionRefreshError) SIWCRefreshError() error {
	if e == nil {
		return nil
	}
	return e.siwcErr
}

// CanApplyOuterTo reports whether the refreshed outer partition matches the target version.
func (p *CredentialRefreshPatch) CanApplyOuterTo(target map[string]any) bool {
	if p == nil || p.outerAfter == nil {
		return false
	}
	matched, _ := matchesBaselineOrAfter(outerCredentialFields(target), p.outerBefore, p.outerDiskBefore, p.outerAfter)
	return matched
}

// CanApplySIWCTo reports whether the refreshed nested partition matches the target version.
func (p *CredentialRefreshPatch) CanApplySIWCTo(target map[string]any) bool {
	if p == nil || p.siwcAfter == nil {
		return false
	}
	siwc, _ := target["siwc"].(map[string]any)
	matched, _ := matchesBaselineOrAfter(siwcCredentialFields(siwc), p.siwcBefore, p.siwcDiskBefore, p.siwcAfter)
	return matched
}

// CanApplyTo reports whether at least one refreshed partition in p still matches disk's version.
func (p *CredentialRefreshPatch) CanApplyTo(disk map[string]any) bool {
	if p == nil {
		return false
	}
	if p.outerAfter != nil {
		if ok, _ := matchesBaselineOrAfter(outerCredentialFields(disk), p.outerBefore, p.outerDiskBefore, p.outerAfter); ok {
			return true
		}
	}
	diskSIWC, _ := disk["siwc"].(map[string]any)
	if p.siwcAfter != nil {
		if ok, _ := matchesBaselineOrAfter(siwcCredentialFields(diskSIWC), p.siwcBefore, p.siwcDiskBefore, p.siwcAfter); ok {
			return true
		}
	}
	return false
}

// Apply overlays successful refreshes on the locked disk snapshot. A partition
// rotated since refresh began is retained, without blocking the other partition.
func (p *CredentialRefreshPatch) Apply(disk map[string]any) map[string]any {
	merged := cloneStringAnyMap(disk)
	if merged == nil {
		merged = make(map[string]any)
	}
	if p.outerAfter != nil {
		if ok, base := matchesBaselineOrAfter(outerCredentialFields(disk), p.outerBefore, p.outerDiskBefore, p.outerAfter); ok {
			after := cloneStringAnyMap(p.outerAfter)
			applyCredentialFields(merged, base, after, RefreshTimeMetadataKeys())
			ReplaceExpirationFields(merged, after)
			// Identity hints belong to the adopted credential snapshot,
			// including unchanged and absent fields.
			for _, key := range []string{"account_id", "id_token", "chatgpt_user_id", "chatgpt_plan_type", "plan_type", "plan_type_defaulted"} {
				if value, exists := after[key]; exists {
					merged[key] = value
				} else {
					delete(merged, key)
				}
			}
		}
	}
	diskSIWC, _ := disk["siwc"].(map[string]any)
	if p.siwcAfter != nil {
		if ok, base := matchesBaselineOrAfter(siwcCredentialFields(diskSIWC), p.siwcBefore, p.siwcDiskBefore, p.siwcAfter); ok {
			if p.siwcRemoved {
				delete(merged, "siwc")
				return merged
			}
			mergedSIWC := cloneStringAnyMap(diskSIWC)
			if mergedSIWC == nil {
				mergedSIWC = make(map[string]any)
			}
			NormalizeSIWCAccessToken(mergedSIWC)
			// Applied snapshots are independently editable; they must never
			// expose the immutable patch's maps or registration slices.
			after := cloneStringAnyMap(p.siwcAfter)
			applyCredentialFields(mergedSIWC, base, after, []string{"earliest_refresh_at", "last_refresh", "lastRefresh"})
			ReplaceExpirationFields(mergedSIWC, after)
			if _, hasID := after["id_token"]; !hasID && SIWCAccessToken(base) != SIWCAccessToken(after) {
				delete(mergedSIWC, "id_token")
			}
			merged["siwc"] = mergedSIWC
		}
	}
	return merged
}
