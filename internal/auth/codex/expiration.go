package codex

import (
	"reflect"
	"strings"

	baseauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth"
)

// RefreshTimeMetadataKeys returns supported outer refresh timestamps in read order.
func RefreshTimeMetadataKeys() []string {
	return []string{"last_refresh", "lastRefresh", "last_refreshed_at", "lastRefreshedAt"}
}

// IsCodexRefreshTimeKey reports refresh timestamps owned by the outer credential.
func IsCodexRefreshTimeKey(key string) bool {
	for _, candidate := range RefreshTimeMetadataKeys() {
		if strings.EqualFold(key, candidate) {
			return true
		}
	}
	return false
}

// IsCodexExpirationKey reports top-level fields whose expiry content is versioned
// with the outer credential. Legacy containers may also carry custom metadata.
func IsCodexExpirationKey(key string) bool {
	for _, candidate := range append(baseauth.CredentialExpirationMetadataKeys(), baseauth.NestedExpirationMetadataKeys()...) {
		if strings.EqualFold(key, candidate) {
			return true
		}
	}
	return false
}

func expirationMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[string]string:
		converted := make(map[string]any, len(typed))
		for key, text := range typed {
			converted[key] = text
		}
		return converted
	default:
		return nil
	}
}

// ExpirationFields extracts only expiry content, including compatible nested
// forms, so a credential patch cannot overwrite unrelated nested settings.
func ExpirationFields(metadata map[string]any) map[string]any {
	fields := credentialFields(metadata, baseauth.CredentialExpirationMetadataKeys())
	for _, key := range baseauth.NestedExpirationMetadataKeys() {
		if nested := expirationFieldsFromValue(metadata[key]); len(nested) != 0 {
			fields[key] = nested
		} else if value, present := metadata[key]; present && expirationMap(value) == nil {
			// Explicitly clearing a legacy container also clears its expiry.
			fields[key] = nil
		}
	}
	return fields
}

func expirationFieldsFromValue(value any) map[string]any {
	if nested := expirationMap(value); nested != nil {
		return ExpirationFields(nested)
	}
	return nil
}

// ReplaceExpirationFields replaces the entire expiry snapshot while retaining
// unrelated data inside legacy token containers.
func ReplaceExpirationFields(target, source map[string]any) {
	fields := ExpirationFields(source)
	for _, key := range baseauth.CredentialExpirationMetadataKeys() {
		delete(target, key)
		if value, exists := fields[key]; exists {
			target[key] = value
		}
	}
	for _, key := range baseauth.NestedExpirationMetadataKeys() {
		nested := cloneStringAnyMap(expirationMap(target[key]))
		sourceNested, _ := fields[key].(map[string]any)
		if nested == nil && len(sourceNested) == 0 {
			continue
		}
		if nested == nil {
			nested = make(map[string]any)
		}
		ReplaceExpirationFields(nested, sourceNested)
		if len(nested) == 0 {
			delete(target, key)
		} else {
			target[key] = nested
		}
	}
}

// MergeNonExpirationFields merges custom legacy container fields without letting
// their embedded expiry bypass the outer credential's version check.
func MergeNonExpirationFields(target, before, source map[string]any) {
	for _, key := range baseauth.NestedExpirationMetadataKeys() {
		incoming := expirationMap(source[key])
		if incoming == nil {
			if value, specified := source[key]; specified && value != nil && expirationMap(target[key]) == nil {
				old, had := before[key]
				current, present := target[key]
				if had == present && reflect.DeepEqual(old, current) && !reflect.DeepEqual(old, value) {
					target[key] = value
				}
			}
			continue
		}
		current := cloneStringAnyMap(expirationMap(target[key]))
		if current == nil {
			current = make(map[string]any)
		}
		base := expirationMap(before[key])
		mergeNonExpirationMap(current, base, incoming)
		if len(current) != 0 {
			target[key] = current
		}
	}
}

func mergeNonExpirationMap(target, before, source map[string]any) {
	for key, value := range source {
		if key == "token" || key == "Token" {
			MergeNonExpirationFields(target, before, map[string]any{key: value})
			continue
		}
		if IsCodexExpirationKey(key) {
			continue
		}
		old, had := before[key]
		current, present := target[key]
		if (!had || !reflect.DeepEqual(old, value)) && (had == present && reflect.DeepEqual(old, current)) {
			target[key] = value
		}
	}
}
