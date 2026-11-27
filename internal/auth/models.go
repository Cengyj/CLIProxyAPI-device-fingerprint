// Package auth provides authentication functionality for various AI service providers.
// It includes interfaces and implementations for token storage and authentication methods.
package auth

// TokenStorage defines the interface for storing authentication tokens.
// Implementations of this interface should provide methods to persist
// authentication tokens to a file system location.
type TokenStorage interface {
	// SaveTokenToFile persists authentication tokens to the specified file path.
	//
	// Parameters:
	//   - authFilePath: The file path where the authentication tokens should be saved
	//
	// Returns:
	//   - error: An error if the save operation fails, nil otherwise
	SaveTokenToFile(authFilePath string) error
}

// ExpirationMetadataKeys returns absolute credential expiry fields in read-precedence order.
func ExpirationMetadataKeys() []string {
	return []string{"expired", "expire", "expires_at", "expiresAt", "expiry", "expires"}
}

// RelativeExpirationMetadataKeys returns supported relative lifetime fields.
func RelativeExpirationMetadataKeys() []string {
	return []string{"expires_in", "expiresIn"}
}

// ExpirationTimestampMetadataKeys returns the issue times used with relative lifetimes.
func ExpirationTimestampMetadataKeys() []string {
	return []string{"timestamp", "issued_at", "issuedAt"}
}

// NestedExpirationMetadataKeys returns legacy containers that can carry expiry fields.
func NestedExpirationMetadataKeys() []string {
	return []string{"token", "Token"}
}

// CredentialExpirationMetadataKeys contains every scalar field in an expiry snapshot.
func CredentialExpirationMetadataKeys() []string {
	keys := append(ExpirationMetadataKeys(), RelativeExpirationMetadataKeys()...)
	return append(keys, ExpirationTimestampMetadataKeys()...)
}
