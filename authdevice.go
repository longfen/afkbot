package main

import (
	"github.com/sandertv/gophertunnel/minecraft"
	"golang.org/x/oauth2"
)

// ... other imports ...

// If your authdevice.go is in the same package, you don't need to import it.

var (
// ... your other vars ...
)

func main() {
	// ... your setup code ...

	// Use the custom TokenSource for authentication
	var tokenSource oauth2.TokenSource
	token, err := loadToken("token.json")
	if err == nil {
		tokenSource = RefreshTokenSource(token)
	} else {
		tokenSource = TokenSource // will prompt for device code
		// After getting a token, save it:
		tok, _ := tokenSource.Token()
		saveToken(tok, "token.json")
	}

	conn, err := minecraft.Dialer{
		TokenSource: tokenSource,
	}.Dial("raknet", target)
	if err != nil {
		// handle error
	}

	// ... rest of your bot code ...
}
