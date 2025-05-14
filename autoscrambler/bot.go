package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
)

type Config struct {
	Token         string `json:"token"`
	ApplicationID string `json:"application_id"`
	AdminID       string `json:"admin_id"`
}

type UserAccess struct {
	TimeoutUntil int64 `json:"timeout_until"`
	CanConfig    bool  `json:"can_config"`
	CanStart     bool  `json:"can_start"`
	CanStop      bool  `json:"can_stop"`
	ConfigTimes  int64 `json:"config_times"`
}

type BotConfig struct {
	IP   string `json:"ip"`
	Port string `json:"port"`
}

type UserConfigs struct {
	Configs map[string]BotConfig `json:"configs"`
	Access  UserAccess           `json:"access"`
}

type AllConfigs map[string]UserConfigs // userID -> UserConfigs

const configFile = "botconfigs.json"

var (
	botProcess  *exec.Cmd
	cfg         *Config
	userScreens = make(map[string]string) // userID -> screenName
)

func loadConfig(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveBotConfig(userID, name, ip, port string) error {
	configs := loadAllConfigs()
	user, ok := configs[userID]
	if !ok {
		user = UserConfigs{Configs: make(map[string]BotConfig)}
	}
	if user.Configs == nil {
		user.Configs = make(map[string]BotConfig)
	}
	user.Configs[name] = BotConfig{IP: ip, Port: port}
	configs[userID] = user
	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0600)
}

func loadAllConfigs() AllConfigs {
	configs := make(AllConfigs)
	data, err := os.ReadFile(configFile)
	if err == nil {
		_ = json.Unmarshal(data, &configs)
	}
	return configs
}

func saveAllConfigs(configs AllConfigs) error {
	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0600)
}

func isHostReachable(host string) bool {
	out, err := exec.Command("ping", "-c", "1", "-W", "2", host).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "1 received") || strings.Contains(string(out), "bytes from")
}

func isValidIPorHostname(host string) bool {
	// Check if it's a valid IP
	if net.ParseIP(host) != nil {
		return true
	}
	// Check if it's a valid hostname (simple check)
	if len(host) > 0 && len(host) <= 253 && !strings.ContainsAny(host, " !@#$%^&*()=+[]{};:'\",<>/?\\|") {
		return true
	}
	return false
}

func main() {
	var err error
	cfg, err = loadConfig("config.json")
	if err != nil {
		fmt.Println("Failed to load config:", err)
		return
	}

	dg, err := discordgo.New("Bot " + cfg.Token)
	if err != nil {
		fmt.Println("error creating Discord session,", err)
		return
	}

	dg.AddHandler(interactionCreate)

	err = dg.Open()
	if err != nil {
		fmt.Println("error opening connection,", err)
		return
	}

	// Register slash commands
	_, err = dg.ApplicationCommandCreate(cfg.ApplicationID, "", &discordgo.ApplicationCommand{
		Name:        "start",
		Description: "Start the Go bot with IP and port",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "ip",
				Description: "Server IP",
				Required:    true,
			},
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "port",
				Description: "Server Port",
				Required:    true,
			},
		},
	})
	if err != nil {
		fmt.Println("Cannot create /start command:", err)
	}

	_, err = dg.ApplicationCommandCreate(cfg.ApplicationID, "", &discordgo.ApplicationCommand{
		Name:        "stop",
		Description: "Stop the Go bot",
	})
	if err != nil {
		fmt.Println("Cannot create /stop command:", err)
	}

	_, err = dg.ApplicationCommandCreate(cfg.ApplicationID, "", &discordgo.ApplicationCommand{
		Name:        "config",
		Description: "Save or use a bot config",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "save",
				Description: "Save a config",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionString,
						Name:        "name",
						Description: "Config name",
						Required:    true,
					},
					{
						Type:        discordgo.ApplicationCommandOptionString,
						Name:        "ip",
						Description: "Server IP",
						Required:    true,
					},
					{
						Type:        discordgo.ApplicationCommandOptionString,
						Name:        "port",
						Description: "Server Port",
						Required:    true,
					},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "use",
				Description: "Use a saved config",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:         discordgo.ApplicationCommandOptionString,
						Name:         "name",
						Description:  "Config name to use",
						Required:     true,
						Autocomplete: true,
					},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "list",
				Description: "List all configs",
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "delete",
				Description: "Delete a config",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionString,
						Name:        "name",
						Description: "Config name to delete",
						Required:    true,
					},
				},
			},
		},
	})
	if err != nil {
		fmt.Println("Cannot create /config command:", err)
	}

	_, err = dg.ApplicationCommandCreate(cfg.ApplicationID, "", &discordgo.ApplicationCommand{
		Name:        "admin",
		Description: "Admin config management",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionSubCommandGroup,
				Name:        "config",
				Description: "Config management actions",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "list",
						Description: "List all users and their configs",
					},
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "delete",
						Description: "Delete a user's config",
						Options: []*discordgo.ApplicationCommandOption{
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "user_id",
								Description: "User ID",
								Required:    true,
							},
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "config_name",
								Description: "Config name",
								Required:    true,
							},
						},
					},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommandGroup,
				Name:        "access",
				Description: "User access management",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "timeout",
						Description: "Timeout a user",
						Options: []*discordgo.ApplicationCommandOption{
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "user_id",
								Description: "User ID",
								Required:    true,
							},
							{
								Type:        discordgo.ApplicationCommandOptionInteger,
								Name:        "duration",
								Description: "Duration amount",
								Required:    true,
							},
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "unit",
								Description: "Unit (seconds, minutes, hours, days, months, years, lifetime)",
								Required:    true,
								Choices: []*discordgo.ApplicationCommandOptionChoice{
									{Name: "seconds", Value: "seconds"},
									{Name: "minutes", Value: "minutes"},
									{Name: "hours", Value: "hours"},
									{Name: "days", Value: "days"},
									{Name: "months", Value: "months"},
									{Name: "years", Value: "years"},
									{Name: "lifetime", Value: "lifetime"},
								},
							},
						},
					},
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "grant",
						Description: "Grant time-based access to create configs",
						Options: []*discordgo.ApplicationCommandOption{
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "user_id",
								Description: "User ID",
								Required:    true,
							},
							{
								Type:        discordgo.ApplicationCommandOptionInteger,
								Name:        "duration",
								Description: "Duration amount",
								Required:    true,
							},
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "unit",
								Description: "Unit (seconds, minutes, hours, days, months, years, lifetime)",
								Required:    true,
								Choices: []*discordgo.ApplicationCommandOptionChoice{
									{Name: "seconds", Value: "seconds"},
									{Name: "minutes", Value: "minutes"},
									{Name: "hours", Value: "hours"},
									{Name: "days", Value: "days"},
									{Name: "months", Value: "months"},
									{Name: "years", Value: "years"},
									{Name: "lifetime", Value: "lifetime"},
								},
							},
						},
					},
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "removeaccess",
						Description: "Remove access to config/start/stop/all",
						Options: []*discordgo.ApplicationCommandOption{
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "user_id",
								Description: "User ID",
								Required:    true,
							},
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "what",
								Description: "What to remove (config, start, stop, all)",
								Required:    true,
								Choices: []*discordgo.ApplicationCommandOptionChoice{
									{Name: "config", Value: "config"},
									{Name: "start", Value: "start"},
									{Name: "stop", Value: "stop"},
									{Name: "all", Value: "all"},
								},
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		fmt.Println("Cannot create /admin command:", err)
	}

	// List and delete old commands (run this once, then remove)
	commands, _ := dg.ApplicationCommands(cfg.ApplicationID, "")
	for _, cmd := range commands {
		if cmd.Name == "adminconfigs" {
			fmt.Println("Deleting old /adminconfigs command...")
			_ = dg.ApplicationCommandDelete(cfg.ApplicationID, "", cmd.ID)
		}
	}

	fmt.Println("Bot is now running. Press CTRL+C to exit.")

	// Wait for a CTRL-C
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-stop

	dg.Close()
}

func interactionCreate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type == discordgo.InteractionApplicationCommandAutocomplete {
		if i.ApplicationCommandData().Name == "config" {
			if len(i.ApplicationCommandData().Options) > 0 && i.ApplicationCommandData().Options[0].Name == "use" {
				userID := i.Member.User.ID
				configs := loadAllConfigs()
				user, ok := configs[userID]
				if !ok {
					user = UserConfigs{Configs: make(map[string]BotConfig)}
				}
				if user.Configs == nil {
					user.Configs = make(map[string]BotConfig)
				}
				var choices []*discordgo.ApplicationCommandOptionChoice
				for name := range user.Configs {
					choices = append(choices, &discordgo.ApplicationCommandOptionChoice{
						Name:  name,
						Value: name,
					})
				}
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionApplicationCommandAutocompleteResult,
					Data: &discordgo.InteractionResponseData{
						Choices: choices,
					},
				})
				return
			}
		}
	}

	// Restrict all commands except /admin
	if i.ApplicationCommandData().Name != "admin" {
		userID := i.Member.User.ID
		configs := loadAllConfigs()
		user, ok := configs[userID]
		if !ok {
			user = UserConfigs{Configs: make(map[string]BotConfig)}
		}
		if user.Configs == nil {
			user.Configs = make(map[string]BotConfig)
		}
		now := time.Now().Unix()
		if user.Access.ConfigTimes == 0 || user.Access.ConfigTimes < now {
			// Optionally, clear their access fields here if you want
			user.Access.CanConfig = false
			user.Access.CanStart = false
			user.Access.CanStop = false
			user.Access.ConfigTimes = 0
			configs[userID] = user
			saveAllConfigs(configs)

			respondEphemeral(s, i, "Your access has expired. Please contact an admin to regain access.")
			return
		}
	}

	switch i.ApplicationCommandData().Name {
	case "start":
		userID := i.Member.User.ID
		ip := i.ApplicationCommandData().Options[0].StringValue()
		port := i.ApplicationCommandData().Options[1].StringValue()

		// Check if user already has a screen running
		if _, exists := userScreens[userID]; exists {
			respondEphemeral(s, i, "You already have a bot running. Use /stop to stop it first.")
			return
		}

		// Check if host is reachable
		if !isHostReachable(ip) {
			respondEphemeral(s, i, "Invalid IP/port: host is not reachable (ping failed).")
			return
		}

		screenName := "discord_" + userID // or whatever unique name you want
		cmd := exec.Command("screen", "-dmS", screenName, "go", "run", "timedmaingo2.go", ip, port)
		cmd.Dir = "/home/longfen/autoscrambler"
		fmt.Printf("Running command: %v (in %s)\n", cmd.Args, cmd.Dir)
		err := cmd.Start()
		if err != nil {
			fmt.Printf("Error starting command: %v\n", err)
			respondEphemeral(s, i, fmt.Sprintf("Failed to start bot in screen: %v", err))
			return
		}
		userScreens[userID] = screenName
		respondEphemeral(s, i, fmt.Sprintf("Bot started in screen session: %s", screenName))
	case "stop":
		if botProcess != nil && botProcess.Process != nil {
			syscall.Kill(-botProcess.Process.Pid, syscall.SIGINT)
			botProcess.Wait()
			botProcess = nil
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "Bot stopped!",
				},
			})
		} else {
			s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Content: "No bot is running.",
				},
			})
		}
	case "config":
		opts := i.ApplicationCommandData().Options
		userID := i.Member.User.ID
		if len(opts) > 0 && opts[0].Type == discordgo.ApplicationCommandOptionSubCommand {
			switch opts[0].Name {
			case "save":
				name := opts[0].Options[0].StringValue()
				ip := opts[0].Options[1].StringValue()
				port := opts[0].Options[2].StringValue()
				if !isHostReachable(ip) {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: "Invalid IP/port: host is not reachable (ping failed).",
							Flags:   1 << 6,
						},
					})
					return
				}
				// Load all configs for this user
				configs := loadAllConfigs()
				user, ok := configs[userID]
				if !ok {
					user = UserConfigs{Configs: make(map[string]BotConfig)}
				}
				if user.Configs == nil {
					user.Configs = make(map[string]BotConfig)
				}
				// Check for duplicate name
				if _, exists := user.Configs[name]; exists {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: fmt.Sprintf("Config name '%s' already exists. Please choose a different name.", name),
							Flags:   1 << 6,
						},
					})
					return
				}
				// Check for duplicate IP/port
				for _, cfg := range user.Configs {
					if cfg.IP == ip && cfg.Port == port {
						s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
							Type: discordgo.InteractionResponseChannelMessageWithSource,
							Data: &discordgo.InteractionResponseData{
								Content: fmt.Sprintf("You already have a config with IP %s and port %s.", ip, port),
								Flags:   1 << 6,
							},
						})
						return
					}
				}

				// Check if IP is reachable
				if !isHostReachable(ip) {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: fmt.Sprintf("IP/host '%s' is not reachable (ping failed).", ip),
							Flags:   1 << 6,
						},
					})
					return
				}

				user.Configs[name] = BotConfig{IP: ip, Port: port}
				configs[userID] = user
				err := saveBotConfig(userID, name, ip, port)
				content := ""
				if err != nil {
					content = fmt.Sprintf("Failed to save config: %v", err)
				} else {
					content = fmt.Sprintf("Config '%s' saved with IP: %s, Port: %s", name, ip, port)
				}
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: content,
						Flags:   1 << 6,
					},
				})
				return
			case "use":
				name := opts[0].Options[0].StringValue()
				configs := loadAllConfigs()
				user, ok := configs[userID]
				if !ok {
					user = UserConfigs{Configs: make(map[string]BotConfig)}
				}
				if user.Configs == nil {
					user.Configs = make(map[string]BotConfig)
				}
				cfg, exists := user.Configs[name]
				if !exists {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: fmt.Sprintf("Config '%s' not found.", name),
							Flags:   1 << 6,
						},
					})
					return
				}
				if !isHostReachable(cfg.IP) {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: fmt.Sprintf("IP/host '%s' is not reachable (ping failed).", cfg.IP),
							Flags:   1 << 6,
						},
					})
					return
				}
				// Start the bot with the config
				if botProcess != nil && botProcess.Process != nil {
					s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
						Type: discordgo.InteractionResponseChannelMessageWithSource,
						Data: &discordgo.InteractionResponseData{
							Content: "Bot is already running!",
							Flags:   1 << 6,
						},
					})
					return
				}
				botProcess = exec.Command("go", "run", "timedmaingo2.go", cfg.IP, cfg.Port)
				botProcess.Stdout = os.Stdout
				botProcess.Stderr = os.Stderr
				fmt.Printf("Running command: %v\n", botProcess.Args)
				err := botProcess.Run()
				content := ""
				if err != nil {
					content = fmt.Sprintf("Failed to start bot: %v", err)
					botProcess = nil
				} else {
					content = fmt.Sprintf("Bot started with config '%s' (IP: %s, Port: %s)", name, cfg.IP, cfg.Port)
				}
				s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
					Type: discordgo.InteractionResponseChannelMessageWithSource,
					Data: &discordgo.InteractionResponseData{
						Content: content,
						Flags:   1 << 6,
					},
				})
			case "list":
				configs := loadAllConfigs()
				user, ok := configs[userID]
				if !ok {
					user = UserConfigs{Configs: make(map[string]BotConfig)}
				}
				if user.Configs == nil {
					user.Configs = make(map[string]BotConfig)
				}
				if len(user.Configs) == 0 {
					respondEphemeral(s, i, "You have no configs.")
					return
				}
				var list strings.Builder
				for name, cfg := range user.Configs {
					list.WriteString(fmt.Sprintf("`%s`: %s:%s\n", name, cfg.IP, cfg.Port))
				}
				respondEphemeral(s, i, "Your configs:\n"+list.String())
			case "delete":
				name := opts[0].Options[0].StringValue()
				configs := loadAllConfigs()
				user, ok := configs[userID]
				if !ok {
					user = UserConfigs{Configs: make(map[string]BotConfig)}
				}
				if user.Configs == nil {
					user.Configs = make(map[string]BotConfig)
				}
				delete(user.Configs, name)
				configs[userID] = user
				err := saveBotConfig(userID, name, "", "")
				content := ""
				if err != nil {
					content = fmt.Sprintf("Failed to delete config: %v", err)
				} else {
					content = fmt.Sprintf("Config '%s' deleted.", name)
				}
				respondEphemeral(s, i, content)
			}
		}
	case "admin":
		if i.Member.User.ID != cfg.AdminID {
			respondEphemeral(s, i, "You are not authorized to use this command.")
			return
		}
		group := i.ApplicationCommandData().Options[0]
		switch group.Name {
		case "config":
			switch group.Options[0].Name {
			case "list":
				configs := loadAllConfigs()
				var out strings.Builder
				for uid, user := range configs {
					out.WriteString(fmt.Sprintf("User: %s\n", uid))
					out.WriteString(fmt.Sprintf("  TimeoutUntil: %v\n", user.Access.TimeoutUntil))
					out.WriteString(fmt.Sprintf("  CanConfig: %v, CanStart: %v, CanStop: %v\n", user.Access.CanConfig, user.Access.CanStart, user.Access.CanStop))
					out.WriteString(fmt.Sprintf("  ConfigTimes: %v\n", user.Access.ConfigTimes))
					for name, cfg := range user.Configs {
						out.WriteString(fmt.Sprintf("    `%s`: %s:%s\n", name, cfg.IP, cfg.Port))
					}
				}
				respondEphemeral(s, i, out.String())
			case "delete":
				userID := group.Options[0].Options[0].StringValue()
				configName := group.Options[0].Options[1].StringValue()
				// Check if user is in the server
				_, err := s.GuildMember(i.GuildID, userID)
				if err != nil {
					respondEphemeral(s, i, fmt.Sprintf("User ID %s is not a member of this server.", userID))
					return
				}
				configs := loadAllConfigs()
				user, ok := configs[userID]
				if !ok {
					user = UserConfigs{Configs: make(map[string]BotConfig)}
				}
				if user.Configs == nil {
					user.Configs = make(map[string]BotConfig)
				}
				if _, exists := user.Configs[configName]; exists {
					delete(user.Configs, configName)
					configs[userID] = user
					saveAllConfigs(configs)
					respondEphemeral(s, i, fmt.Sprintf("Deleted config '%s' for user %s.", configName, userID))
				} else {
					respondEphemeral(s, i, "Config not found.")
				}
			}
		case "access":
			switch group.Options[0].Name {
			case "timeout":
				userID := group.Options[0].Options[0].StringValue()
				duration := group.Options[0].Options[1].IntValue()
				unit := group.Options[0].Options[2].StringValue()
				seconds := durationToSeconds(duration, unit)
				configs := loadAllConfigs()
				user, ok := configs[userID]
				if !ok {
					user = UserConfigs{Configs: make(map[string]BotConfig)}
				}
				if user.Configs == nil {
					user.Configs = make(map[string]BotConfig)
				}
				user.Access.TimeoutUntil = time.Now().Unix() + seconds
				configs[userID] = user
				saveAllConfigs(configs)
				respondEphemeral(s, i, fmt.Sprintf("User %s timed out for %d %s.", userID, duration, unit))
			case "grant":
				userID := group.Options[0].Options[0].StringValue()
				duration := group.Options[0].Options[1].IntValue()
				unit := group.Options[0].Options[2].StringValue()
				seconds := durationToSeconds(duration, unit)
				configs := loadAllConfigs()
				user, ok := configs[userID]
				if !ok {
					user = UserConfigs{Configs: make(map[string]BotConfig)}
				}
				if user.Configs == nil {
					user.Configs = make(map[string]BotConfig)
				}
				user.Access.ConfigTimes = time.Now().Unix() + seconds
				configs[userID] = user
				saveAllConfigs(configs)
				respondEphemeral(s, i, fmt.Sprintf("User %s granted config access for %d %s.", userID, duration, unit))
			case "removeaccess":
				userID := group.Options[0].Options[0].StringValue()
				what := group.Options[0].Options[1].StringValue()
				configs := loadAllConfigs()
				user, ok := configs[userID]
				if !ok {
					user = UserConfigs{Configs: make(map[string]BotConfig)}
				}
				if user.Configs == nil {
					user.Configs = make(map[string]BotConfig)
				}
				switch what {
				case "config":
					user.Access.CanConfig = false
				case "start":
					user.Access.CanStart = false
				case "stop":
					user.Access.CanStop = false
				case "all":
					user.Access.CanConfig = false
					user.Access.CanStart = false
					user.Access.CanStop = false
				}
				configs[userID] = user
				saveAllConfigs(configs)
				respondEphemeral(s, i, fmt.Sprintf("Removed %s access for user %s.", what, userID))
			}
		}
	}
}

func respondEphemeral(s *discordgo.Session, i *discordgo.InteractionCreate, content string) {
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: content,
			Flags:   1 << 6,
		},
	})
}

func durationToSeconds(amount int64, unit string) int64 {
	switch unit {
	case "seconds":
		return amount
	case "minutes":
		return amount * 60
	case "hours":
		return amount * 3600
	case "days":
		return amount * 86400
	case "months":
		return amount * 2592000
	case "years":
		return amount * 31536000
	case "lifetime":
		return 100 * 365 * 24 * 3600 // 100 years
	default:
		return 0
	}
}

func extractUserID(input string) string {
	// If input is a mention like <@1234567890>, extract the ID
	if strings.HasPrefix(input, "<@") && strings.HasSuffix(input, ">") {
		return strings.Trim(input, "<@!>")
	}
	return input
}
