package filter

import "slices"

// Service is a well-known app or site that can be blocked with one switch.
// Domains are blocked with everything under them.
type Service struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Domains  []string `json:"domains"`
}

// Services is DNServe's own catalog, kept short and to the domains each
// service needs to work, so blocking one breaks it cleanly without taking
// unrelated sites with it. Shared domains (Google's, Meta's and Microsoft's
// CDNs) are left out on purpose.
var Services = []Service{
	// Video and streaming
	{"youtube", "YouTube", "Video", []string{"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com", "yt3.ggpht.com", "youtubekids.com"}},
	{"netflix", "Netflix", "Video", []string{"netflix.com", "netflix.net", "nflxext.com", "nflximg.com", "nflximg.net", "nflxvideo.net", "nflxso.net"}},
	{"twitch", "Twitch", "Video", []string{"twitch.tv", "twitchcdn.net", "twitchsvc.net", "jtvnw.net", "ttvnw.net", "twitch.a2z.com"}},
	{"disneyplus", "Disney+", "Video", []string{"disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com", "disneystreaming.com"}},
	{"primevideo", "Prime Video", "Video", []string{"primevideo.com", "aiv-cdn.net", "aiv-delivery.net", "amazonvideo.com", "pv-cdn.net"}},
	{"hulu", "Hulu", "Video", []string{"hulu.com", "hulustream.com", "huluim.com"}},
	{"max", "Max", "Video", []string{"max.com", "hbomax.com", "hbo.com", "hbomaxcdn.com", "hbonow.com"}},
	{"vimeo", "Vimeo", "Video", []string{"vimeo.com", "vimeocdn.com", "player.vimeo.com"}},
	{"dailymotion", "Dailymotion", "Video", []string{"dailymotion.com", "dmcdn.net", "dm-event.net"}},

	// Social
	{"tiktok", "TikTok", "Social", []string{"tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokv.us", "byteoversea.com", "ibytedtos.com", "ibyteimg.com", "muscdn.com", "musical.ly", "tik-tokapi.com"}},
	{"instagram", "Instagram", "Social", []string{"instagram.com", "cdninstagram.com", "ig.me", "instagr.am"}},
	{"facebook", "Facebook", "Social", []string{"facebook.com", "facebook.net", "fbcdn.net", "fb.com", "fb.me", "fbsbx.com", "messenger.com"}},
	{"snapchat", "Snapchat", "Social", []string{"snapchat.com", "snap.com", "snapads.com", "snapkit.com", "sc-cdn.net", "sc-static.net", "snap-dev.net", "feelinsonice-hrd.appspot.com"}},
	{"twitter", "X (Twitter)", "Social", []string{"x.com", "twitter.com", "twimg.com", "t.co", "twttr.com"}},
	{"reddit", "Reddit", "Social", []string{"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "reddituploads.com"}},
	{"pinterest", "Pinterest", "Social", []string{"pinterest.com", "pinimg.com", "pin.it"}},
	{"tumblr", "Tumblr", "Social", []string{"tumblr.com"}},
	{"linkedin", "LinkedIn", "Social", []string{"linkedin.com", "licdn.com", "lnkd.in"}},
	{"bluesky", "Bluesky", "Social", []string{"bsky.app", "bsky.social", "bsky.network"}},
	{"threads", "Threads", "Social", []string{"threads.net", "threads.com"}},

	// Messaging
	{"whatsapp", "WhatsApp", "Messaging", []string{"whatsapp.com", "whatsapp.net", "wa.me"}},
	{"telegram", "Telegram", "Messaging", []string{"telegram.org", "telegram.me", "t.me", "telegra.ph", "telesco.pe", "tdesktop.com"}},
	{"discord", "Discord", "Messaging", []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com", "discord.dev", "discord.new", "discord.gift"}},
	{"signal", "Signal", "Messaging", []string{"signal.org", "whispersystems.org", "signal.art", "signal.group", "signal.me"}},

	// Games
	{"roblox", "Roblox", "Games", []string{"roblox.com", "rbxcdn.com", "rbx.com", "roblox.cn", "robloxlabs.com", "roblox.qq.com"}},
	{"fortnite", "Fortnite", "Games", []string{"fortnite.com", "epicgames.com", "epicgames.dev", "unrealengine.com", "epicgames.net", "ol.epicgames.com"}},
	{"minecraft", "Minecraft", "Games", []string{"minecraft.net", "mojang.com", "minecraftservices.com", "minecraft-services.net"}},
	{"steam", "Steam", "Games", []string{"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steamgames.com", "steamusercontent.com", "valvesoftware.com"}},
	{"xboxlive", "Xbox Live", "Games", []string{"xboxlive.com", "xbox.com", "xboxservices.com", "xboxab.com"}},
	{"playstation", "PlayStation Network", "Games", []string{"playstation.com", "playstation.net", "sonyentertainmentnetwork.com", "psn.com"}},
	{"nintendo", "Nintendo online", "Games", []string{"nintendo.com", "nintendo.net", "nintendo-europe.com", "nintendowifi.net"}},
	{"leagueoflegends", "League of Legends", "Games", []string{"leagueoflegends.com", "riotgames.com", "riotcdn.net", "lolstatic.com", "lolesports.com", "pvp.net"}},

	// Shopping and money
	{"amazon", "Amazon shopping", "Shopping", []string{"amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.com.au", "a.co", "amzn.to", "media-amazon.com", "ssl-images-amazon.com"}},
	{"ebay", "eBay", "Shopping", []string{"ebay.com", "ebay.co.uk", "ebay.ca", "ebay.de", "ebay.com.au", "ebayimg.com", "ebaystatic.com", "ebayrtm.com"}},
	{"temu", "Temu", "Shopping", []string{"temu.com", "kwcdn.com"}},
	{"shein", "Shein", "Shopping", []string{"shein.com", "ltwebstatic.com", "sheingsp.com"}},

	// AI chat
	{"chatgpt", "ChatGPT", "AI", []string{"chatgpt.com", "chat.openai.com", "oaistatic.com", "oaiusercontent.com"}},

	// Dating
	{"tinder", "Tinder", "Dating", []string{"tinder.com", "gotinder.com", "tindersparks.com"}},
	{"bumble", "Bumble", "Dating", []string{"bumble.com", "bumble.app", "bumbcdn.com"}},
}

// ServiceByID returns a service from the catalog.
func ServiceByID(id string) (Service, bool) {
	i := slices.IndexFunc(Services, func(s Service) bool { return s.ID == id })
	if i < 0 {
		return Service{}, false
	}
	return Services[i], true
}

// ServiceRules returns the block rules for a set of service ids, in the
// custom rule syntax. Unknown ids are skipped.
func ServiceRules(ids []string) []string {
	var out []string
	for _, id := range ids {
		if s, ok := ServiceByID(id); ok {
			for _, d := range s.Domains {
				out = append(out, "||"+d+"^")
			}
		}
	}
	return out
}

// AddServices adds one source per blocked service, at the custom-rule tier
// so an allow rule of your own still wins.
func AddServices(b *Builder, ids []string) {
	for _, id := range ids {
		s, ok := ServiceByID(id)
		if !ok {
			continue
		}
		src := b.AddSource("Blocked service: "+s.Name, TierCustom)
		for _, d := range s.Domains {
			b.Add(src, Rule{Domain: d, Kind: Suffix})
		}
	}
}
