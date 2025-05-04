package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"

	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

const (
	commandBufferSize = 100
	tokenFile         = "token.json"
)

var (
	connGlobal  *minecraft.Conn
	connMutex   sync.Mutex
	commandChan = make(chan string, commandBufferSize)
)

// =====================
// Device Auth Section
// =====================

// TokenSource holds an oauth2.TokenSource which uses device auth to get a code.
var TokenSource oauth2.TokenSource = &tokenSource{w: os.Stdout}

type tokenSource struct {
	w io.Writer
	t *oauth2.Token
}

func (src *tokenSource) Token() (*oauth2.Token, error) {
	if src.t == nil {
		t, err := RequestLiveTokenWriter(src.w)
		src.t = t
		return t, err
	}
	tok, err := refreshToken(src.t)
	if err != nil {
		return nil, err
	}
	src.t = tok
	return tok, nil
}

func RefreshTokenSource(t *oauth2.Token) oauth2.TokenSource {
	return RefreshTokenSourceWriter(t, os.Stdout)
}

func RefreshTokenSourceWriter(t *oauth2.Token, w io.Writer) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(t, &tokenSource{w: w, t: t})
}

func RequestLiveTokenWriter(w io.Writer) (*oauth2.Token, error) {
	d, err := startDeviceAuth()
	if err != nil {
		return nil, err
	}
	_, _ = w.Write([]byte(fmt.Sprintf("Authenticate at %v using the code %v.\n", d.VerificationURI, d.UserCode)))
	ticker := time.NewTicker(time.Second * time.Duration(d.Interval))
	defer ticker.Stop()

	for range ticker.C {
		t, err := pollDeviceAuth(d.DeviceCode)
		if err != nil {
			return nil, fmt.Errorf("error polling for device auth: %w", err)
		}
		if t != nil {
			_, _ = w.Write([]byte("Authentication successful.\n"))
			return t, nil
		}
	}
	panic("unreachable")
}

func startDeviceAuth() (*deviceAuthConnect, error) {
	resp, err := http.PostForm("https://login.live.com/oauth20_connect.srf", url.Values{
		"client_id":     {"0000000048183522"},
		"scope":         {"service::user.auth.xboxlive.com::MBI_SSL"},
		"response_type": {"device_code"},
	})
	if err != nil {
		return nil, fmt.Errorf("POST https://login.live.com/oauth20_connect.srf: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("POST https://login.live.com/oauth20_connect.srf: %v", resp.Status)
	}
	data := new(deviceAuthConnect)
	return data, json.NewDecoder(resp.Body).Decode(data)
}

func pollDeviceAuth(deviceCode string) (t *oauth2.Token, err error) {
	resp, err := http.PostForm(microsoft.LiveConnectEndpoint.TokenURL, url.Values{
		"client_id":   {"0000000048183522"},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	})
	if err != nil {
		return nil, fmt.Errorf("POST https://login.live.com/oauth20_token.srf: %w", err)
	}
	defer resp.Body.Close()
	poll := new(deviceAuthPoll)
	if err := json.NewDecoder(resp.Body).Decode(poll); err != nil {
		return nil, fmt.Errorf("POST https://login.live.com/oauth20_token.srf: json decode: %w", err)
	}
	if poll.Error == "authorization_pending" {
		return nil, nil
	} else if poll.Error == "" {
		return &oauth2.Token{
			AccessToken:  poll.AccessToken,
			TokenType:    poll.TokenType,
			RefreshToken: poll.RefreshToken,
			Expiry:       time.Now().Add(time.Duration(poll.ExpiresIn) * time.Second),
		}, nil
	}
	return nil, fmt.Errorf("%v: %v", poll.Error, poll.ErrorDescription)
}

func refreshToken(t *oauth2.Token) (*oauth2.Token, error) {
	resp, err := http.PostForm(microsoft.LiveConnectEndpoint.TokenURL, url.Values{
		"client_id":     {"0000000048183522"},
		"scope":         {"service::user.auth.xboxlive.com::MBI_SSL"},
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.RefreshToken},
	})
	if err != nil {
		return nil, fmt.Errorf("POST https://login.live.com/oauth20_token.srf: %w", err)
	}
	defer resp.Body.Close()
	poll := new(deviceAuthPoll)
	if err := json.NewDecoder(resp.Body).Decode(poll); err != nil {
		return nil, fmt.Errorf("POST https://login.live.com/oauth20_token.srf: json decode: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("POST https://login.live.com/oauth20_token.srf: refresh error: %v", poll.Error)
	}
	return &oauth2.Token{
		AccessToken:  poll.AccessToken,
		TokenType:    poll.TokenType,
		RefreshToken: poll.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(poll.ExpiresIn) * time.Second),
	}, nil
}

type deviceAuthConnect struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURI string `json:"verification_uri"`
	Interval        int    `json:"interval"`
	ExpiresIn       int    `json:"expires_in"`
}

type deviceAuthPoll struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	UserID           string `json:"user_id"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
}

// Save token to file
func saveToken(token *oauth2.Token, filename string) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600)
}

// Load token from file
func loadToken(filename string) (*oauth2.Token, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var token oauth2.Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// =====================
// Bot Section
// =====================

func Clean(s string) string {
	// Remove Minecraft color codes (optional, you can remove this function if not needed)
	return s
}

func readConsoleInput() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input != "" {
			if input == "exit" {
				os.Exit(0)
			}
			commandChan <- input
		}
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run afkbot.go <ip> <port>")
		return
	}

	target := os.Args[1] + ":" + os.Args[2]
	rand.Seed(time.Now().UnixNano())

	go readConsoleInput()

	var tokenSource oauth2.TokenSource
	token, err := loadToken(tokenFile)
	if err == nil {
		fmt.Println("Loaded token from file.")
		tokenSource = RefreshTokenSource(token)
	} else {
		fmt.Println("No valid token found, starting device code login...")
		tokenSource = TokenSource
		tok, err := tokenSource.Token()
		if err != nil {
			fmt.Println("Login failed:", err)
			os.Exit(1)
		}
		saveToken(tok, tokenFile)
		fmt.Println("Saved token to file.")
	}

	conn, err := minecraft.Dialer{
		TokenSource: tokenSource,
	}.Dial("raknet", target)
	if err != nil {
		fmt.Println("Connection error:", err)
		time.Sleep(2 * time.Second)
		return
	}

	connMutex.Lock()
	connGlobal = conn
	connMutex.Unlock()

	go func() {
		for cmd := range commandChan {
			connMutex.Lock()
			if connGlobal != nil {
				connGlobal.WritePacket(&packet.Text{
					TextType: packet.TextTypeChat,
					Message:  cmd,
				})
				fmt.Printf("Sent command: %s\n", cmd)
			}
			connMutex.Unlock()
		}
	}()

	go func() {
		for {
			posX := float32(rand.Intn(163) - 8)
			posY := float32(rand.Intn(25))
			posZ := float32(rand.Intn(16321) - 810)

			conn.WritePacket(&packet.SubChunkRequest{
				Dimension: -343,
				Position:  protocol.SubChunkPos{int32(rand.Intn(16310) - 8), int32(rand.Intn(1610) - 81)},
				Offsets:   []protocol.SubChunkOffset{{0, 127, 127}},
			})

			conn.WritePacket(&packet.MovePlayer{
				EntityRuntimeID: 100000000000000,
				Position:        mgl32.Vec3{posX, posY, posZ},
				Pitch:           rand.Float32() * 361,
				Yaw:             rand.Float32() * 31,
				Mode:            packet.MoveModeNormal,
			})

			time.Sleep(2 * time.Second)
		}
	}()

	for {
		pk, err := conn.ReadPacket()
		if err != nil {
			break
		}

		switch p := pk.(type) {
		case *packet.Text:
			cleanMessage := Clean(p.Message)
			fmt.Printf("[CHAT] %s\n", cleanMessage)

		case *packet.ResourcePacksInfo:
			conn.WritePacket(&packet.ResourcePackClientResponse{
				Response: 1,
			})
			conn.WritePacket(&packet.ResourcePackClientResponse{
				Response: 2,
			})
			conn.WritePacket(&packet.ResourcePackClientResponse{
				Response: 3,
			})
		}
	}
}
