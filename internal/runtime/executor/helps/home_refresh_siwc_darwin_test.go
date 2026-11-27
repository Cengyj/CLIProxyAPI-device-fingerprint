package helps_test

import (
	"context"
	"os"
	"testing"

	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

func TestMain(m *testing.M) {
	codexauth.ReadSIWCSystemState = func(context.Context) ([]byte, error) {
		return []byte("Current System Capabilities are: CPU Graphics Audio Network\n"), nil
	}
	os.Exit(m.Run())
}
