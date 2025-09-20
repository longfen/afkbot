package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

var cleaner = regexp.MustCompile("§[0-9a-v]")

func Clean(s string) string {
	return cleaner.ReplaceAllString(s, "")
}

const (
	ResourcePackResponseSendPacks          = 1
	ResourcePackResponseAllPacksDownloaded = 2
	ResourcePackResponseCompleted          = 3
	tokenFile                              = "token.json"
)

const (
	discordWebhookURL = "https://discord.com/api/webhooks/1368325993949036715/RP5sfExwNoXPyVrAWkZ11RPRlKnHlEE41_n-FjSNrTE8-sWt3FyvbRg1jMxonTayipzN"
	targetPlayer      = "SkilledFaun5806"
)

type DiscordMessage struct {
	Content string `json:"content"`
}

type DiscordWebhookResponse struct {
	ID string `json:"id"`
}

type BotMessageIDs struct {
	StartedID string `json:"started_id"`
	EndedID   string `json:"ended_id"`
}

const botMsgIDFile = "botmsgids.json"

func saveBotMessageIDs(ids BotMessageIDs) {
	data, _ := json.Marshal(ids)
	_ = os.WriteFile(botMsgIDFile, data, 0600)
}

func loadBotMessageIDs() BotMessageIDs {
	var ids BotMessageIDs
	data, err := os.ReadFile(botMsgIDFile)
	if err == nil {
		_ = json.Unmarshal(data, &ids)
	}
	return ids
}

var (
	connGlobal          *minecraft.Conn
	connMutex           sync.Mutex
	wordList            []string
	wordFile            = "wordlist.txt"
	currentScramble     string
	balanceCheckPending bool
	lastPrizeWon        string
	commandChan         = make(chan string)

	playerListMutex sync.Mutex
	playerList      = make(map[string]struct{})
)

// Add player to playerList (thread-safe)
func addPlayer(name string) {
	playerListMutex.Lock()
	defer playerListMutex.Unlock()
	if name != "" && name != "You" && name != "you" {
		playerList[name] = struct{}{}
	}
}

// Get a snapshot of all players (thread-safe)
func getAllPlayers() []string {
	playerListMutex.Lock()
	defer playerListMutex.Unlock()
	names := make([]string, 0, len(playerList))
	for n := range playerList {
		names = append(names, n)
	}
	return names
}

// Try to extract player names from chat lines (very basic, can be improved)
func extractPlayerNamesFromChat(msg string) []string {
	var names []string
	// Pattern: [ + ] Name (Name) or similar
	if idx1 := strings.Index(msg, "] "); idx1 != -1 {
		rest := msg[idx1+2:]
		if idx2 := strings.Index(rest, " ("); idx2 != -1 {
			name := strings.TrimSpace(rest[:idx2])
			if isLikelyPlayerName(name) {
				names = append(names, name)
			}
		}
	}
	// Pattern: (+) Name has logged on!
	if strings.HasPrefix(msg, "(+)") && strings.Contains(msg, "has logged on!") {
		parts := strings.Split(msg, " ")
		if len(parts) > 2 {
			name := parts[1]
			if isLikelyPlayerName(name) {
				names = append(names, name)
			}
		}
	}
	// Pattern: PlayerName: message
	if idx := strings.Index(msg, ":"); idx > 0 {
		name := strings.TrimSpace(msg[:idx])
		if close := strings.LastIndex(name, "]"); close != -1 {
			name = strings.TrimSpace(name[close+1:])
		}
		if isLikelyPlayerName(name) {
			names = append(names, name)
		}
	}
	// Pattern: PlayerName joined the game
	if strings.HasSuffix(msg, "joined the game") {
		parts := strings.Split(msg, " ")
		if len(parts) > 0 {
			name := parts[0]
			if isLikelyPlayerName(name) {
				names = append(names, name)
			}
		}
	}
	return names
}

// Helper: checks if a string is a likely player name
func isLikelyPlayerName(name string) bool {
	if len(name) < 3 || len(name) > 20 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	// Add more exclusions if needed (e.g., keywords)
	switch strings.ToLower(name) {
	case "has", "logged", "on", "the", "and", "for", "you", "msg", "sent", "test", "chat", "vote", "store", "discord", "website", "version", "exp", "from", "charity", "mail", "quest", "reset", "check", "your", "use", "latest", "update", "season", "v", "op", "factions", "divine", "lootbox", "point", "here", "pilotrex6242766":
		return false
	}
	return true
}

func init() {
	loadWordList()
}

func loadWordList() {
	file, err := os.Open(wordFile)
	if err != nil {
		wordList = []string{
			"Loot", "Factions", "Cobblestone", "Factionvault", "Sand",
			"Grinding", "Grinder", "Clxisgay", "Envoys", "SellWands", "Koth",
			"Enderpearl", "Lootboxes", "Griefing",
		}
		saveWordList()
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			wordList = append(wordList, word)
		}
	}
}

func saveWordList() {
	file, err := os.Create(wordFile)
	if err != nil {
		return
	}
	defer file.Close()

	for _, word := range wordList {
		_, _ = file.WriteString(word + "\n")
	}
}

func sendToDiscord(message string) {
	msg := DiscordMessage{
		Content: message,
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		fmt.Println("[DEBUG] Failed to marshal Discord message:", err)
		return
	}

	resp, err := http.Post(discordWebhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("[DEBUG] Failed to send to Discord:", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("[DEBUG] Discord webhook error: %s\n", string(body))
	}
}

func sendToDiscordWithID(message string) (string, error) {
	msg := DiscordMessage{Content: message}
	jsonData, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	resp, err := http.Post(discordWebhookURL+"?wait=true", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("discord webhook error: %s", string(body))
	}
	var webhookResp DiscordWebhookResponse
	if err := json.NewDecoder(resp.Body).Decode(&webhookResp); err != nil {
		return "", err
	}
	return webhookResp.ID, nil
}

func deleteDiscordMessage(messageID string) error {
	req, err := http.NewRequest("DELETE", discordWebhookURL+"/messages/"+messageID, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord delete error: %s", string(body))
	}
	return nil
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

// =====================
// Device Auth Section
// =====================

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

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run afkbot.go <ip> <port>")
		return
	}

	target := os.Args[1] + ":" + os.Args[2]
	rand.Seed(time.Now().UnixNano())

	// Discord message management
	ids := loadBotMessageIDs()
	if ids.EndedID != "" {
		_ = deleteDiscordMessage(ids.EndedID)
		ids.EndedID = ""
		saveBotMessageIDs(ids)
	}
	startedID, err := sendToDiscordWithID("🤖 Bot started!")
	if err == nil {
		ids.StartedID = startedID
		saveBotMessageIDs(ids)
	}

	// Handle Ctrl+C (SIGINT) and SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		// Cleanup on exit
		ids := loadBotMessageIDs()
		if ids.StartedID != "" {
			_ = deleteDiscordMessage(ids.StartedID)
			ids.StartedID = ""
			saveBotMessageIDs(ids)
		}
		endedID, err := sendToDiscordWithID("🛑 Bot ended!")
		if err == nil {
			ids.EndedID = endedID
			saveBotMessageIDs(ids)
		}
		os.Exit(0)
	}()

	go readConsoleInput()

	for {
		// Always try to load a valid token before connecting
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
			// Never delete the token file automatically
			time.Sleep(2 * time.Second)
			continue
		}

		connMutex.Lock()
		connGlobal = conn
		connMutex.Unlock()

		// Send /list to get all online players
		go func() {
			time.Sleep(2 * time.Second) // Wait for connection to be ready
			connMutex.Lock()
			if connGlobal != nil {
				connGlobal.WritePacket(&packet.Text{
					TextType: packet.TextTypeChat,
					Message:  "/list",
				})
				fmt.Println("[DEBUG] Sent /list to server to get online players.")
			}
			connMutex.Unlock()
		}()

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

		// SPAMMER: repeatedly send /msg "playername" LONGFENOWNSYOU to all known players
		go func() {
			// Force a test message to yourself (replace YourName with your in-game name)
			testMsg := "/msg \"ybzaiah\" LONGFENOWNSYOU (test)"
			fmt.Println("[DEBUG] Sending test message to yourself: ", testMsg)
			connMutex.Lock()
			if connGlobal != nil {
				connGlobal.WritePacket(&packet.Text{
					TextType: packet.TextTypeChat,
					Message:  testMsg,
				})
			}
			connMutex.Unlock()
			time.Sleep(2 * time.Second)

			for {
				players := getAllPlayers()
				fmt.Printf("[DEBUG] Player list: %v\n", players)
				for _, name := range players {
					if name != "" {
						msg := "/msg \"" + name + "\" LONGFENOWNSYOU"
						fmt.Printf("[DEBUG] Spamming: %s\n", msg)
						connMutex.Lock()
						if connGlobal != nil {
							connGlobal.WritePacket(&packet.Text{
								TextType: packet.TextTypeChat,
								Message:  msg,
							})
						}
						connMutex.Unlock()
						// Optionally, add a small delay between messages to avoid rate limits
						time.Sleep(200 * time.Millisecond)
					}
				}
				// Wait a bit before next spam round
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

				// Try to extract player names from chat
				for _, n := range extractPlayerNamesFromChat(cleanMessage) {
					addPlayer(n)
				}

			case *packet.ResourcePacksInfo:
				conn.WritePacket(&packet.ResourcePackClientResponse{
					Response: ResourcePackResponseSendPacks,
				})
				conn.WritePacket(&packet.ResourcePackClientResponse{
					Response: ResourcePackResponseAllPacksDownloaded,
				})
				conn.WritePacket(&packet.ResourcePackClientResponse{
					Response: ResourcePackResponseCompleted,
				})
			}
		}
	}
}
