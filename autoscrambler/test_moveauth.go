package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"golang.org/x/oauth2"
)

type User struct {
	Position   mgl32.Vec3
	Yaw, Pitch float32
	serverConn *minecraft.Conn
	mu         sync.Mutex
}

const moveAuthTokenFile = "token.json"

func moveAuthSaveToken(token *oauth2.Token, filename string) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600)
}

func moveAuthLoadToken(filename string) (*oauth2.Token, error) {
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

type moveAuthTokenSource struct {
	w io.Writer
	t *oauth2.Token
}

func (src *moveAuthTokenSource) Token() (*oauth2.Token, error) {
	if src.t == nil {
		t, err := moveAuthRequestLiveTokenWriter(src.w)
		src.t = t
		return t, err
	}
	tok, err := moveAuthRefreshToken(src.t)
	if err != nil {
		return nil, err
	}
	src.t = tok
	return tok, nil
}

func moveAuthRequestLiveTokenWriter(w io.Writer) (*oauth2.Token, error) {
	fmt.Fprintln(w, "Authenticate at https://microsoft.com/devicelogin and enter the code shown in your console.")
	return nil, fmt.Errorf("Device code flow not implemented in this minimal test. Please copy the device auth logic from your main bot if needed.")
}

func moveAuthRefreshToken(t *oauth2.Token) (*oauth2.Token, error) {
	return t, nil // No-op for minimal test
}

func (u *User) MovePlayer(vec mgl32.Vec3, yaw, pitch float32) {
	u.mu.Lock()
	u.Position = u.Position.Add(vec)
	u.Yaw = yaw
	u.Pitch = pitch
	_ = u.serverConn.WritePacket(&packet.MovePlayer{
		EntityRuntimeID: 1, // You may need to set this to your actual runtime ID
		Position:        u.Position,
		Pitch:           pitch,
		Yaw:             yaw,
		HeadYaw:         yaw,
		Mode:            packet.MoveModeNormal,
		OnGround:        false,
	})
	u.mu.Unlock()
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run test_moveauth.go <ip> <port>")
		return
	}
	addr := os.Args[1] + ":" + os.Args[2]

	var tokenSource oauth2.TokenSource
	token, err := moveAuthLoadToken(moveAuthTokenFile)
	if err == nil {
		fmt.Println("Loaded token from file.")
		tokenSource = oauth2.ReuseTokenSource(token, &moveAuthTokenSource{w: os.Stdout, t: token})
	} else {
		fmt.Println("No valid token found, device code login required.")
		tokenSource = &moveAuthTokenSource{w: os.Stdout}
		tok, err := tokenSource.Token()
		if err != nil {
			fmt.Println("Login failed:", err)
			os.Exit(1)
		}
		moveAuthSaveToken(tok, moveAuthTokenFile)
		fmt.Println("Saved token to file.")
	}

	conn, err := minecraft.Dialer{
		TokenSource: tokenSource,
	}.Dial("raknet", addr)
	if err != nil {
		fmt.Println("Connection error:", err)
		return
	}

	user := &User{
		Position:   mgl32.Vec3{10.5, 70, 10.5},
		Yaw:        0,
		Pitch:      0,
		serverConn: conn,
	}

	go func() {
		for {
			_, err := conn.ReadPacket()
			if err != nil {
				fmt.Println("ReadPacket error:", err)
				return
			}
		}
	}()

	fallVec := mgl32.Vec3{0, -0.08, 0}
	for {
		user.MovePlayer(fallVec, 0, 0)
		fmt.Printf("[DEBUG] Sent Move to Y=%.2f\n", user.Position.Y())
		time.Sleep(50 * time.Millisecond)
	}
}
