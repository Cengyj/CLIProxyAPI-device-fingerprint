package helps

import (
	"net/http"
	"strings"
)

// FinalizeCodexWebsocketHeaders keeps the native account-header spelling while
// honoring the final administrator override. Header.Set writes its canonical
// spelling, which otherwise coexists with the built-in native spelling.
// Call after both credential and model header rules, before binding the socket.
func FinalizeCodexWebsocketHeaders(headers http.Header) {
	const accountHeader = "ChatGPT-Account-ID"
	values, overridden := headers[http.CanonicalHeaderKey(accountHeader)]
	if !overridden {
		return
	}
	for key := range headers {
		if strings.EqualFold(key, accountHeader) {
			delete(headers, key)
		}
	}
	headers[accountHeader] = values
}
