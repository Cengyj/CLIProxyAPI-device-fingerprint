package helps

import (
	"context"
	"testing"
)

type callbackHomeRefreshClient struct {
	refresh func(context.Context, string, string) ([]byte, error)
}

func (callbackHomeRefreshClient) HeartbeatOK() bool { return true }
func (c callbackHomeRefreshClient) GetRefreshAuth(ctx context.Context, index, digest string) ([]byte, error) {
	return c.refresh(ctx, index, digest)
}

// SetHomeRefreshForTest exposes only the existing test seam to external tests.
func SetHomeRefreshForTest(t testing.TB, refresh func(context.Context, string, string) ([]byte, error)) {
	t.Helper()
	previous := currentHomeRefreshClient
	currentHomeRefreshClient = func() homeRefreshClient { return callbackHomeRefreshClient{refresh: refresh} }
	t.Cleanup(func() { currentHomeRefreshClient = previous })
}
