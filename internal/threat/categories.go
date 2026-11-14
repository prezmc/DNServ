package threat

import (
	"strings"

	"github.com/prezmc/dnserv/internal/filter"
)

// Categories say what people use a site for, in everyday words, for the
// traffic map: social media, streaming, gaming and so on. They come from
// DNServ's own short table (and its blocked services catalog), then from
// the AdGuard companies database's tracker types and owners. Anything
// else is CatOther.
const (
	CatSocial    = "Social media"
	CatStreaming = "Streaming"
	CatMessaging = "Messaging and calls"
	CatGaming    = "Gaming"
	CatShopping  = "Shopping"
	CatNews      = "News"
	CatSearch    = "Search and AI"
	CatWork      = "Work and email"
	CatMoney     = "Banking and payments"
	CatOS        = "OS and cloud services"
	CatSmartHome = "Smart home and TV"
	CatCDN       = "CDN and hosting"
	CatAds       = "Ads and tracking"
	CatNetwork   = "Network"
	CatDating    = "Dating"
	CatOther     = "Other"
)

// Category is where a domain falls: its category and, when DNServ knows
// it, the app or site it belongs to ("Netflix").
type Category struct {
	Name    string `json:"name"`
	Service string `json:"service,omitempty"`
}

// catDomain is a known domain's category and service name.
type catDomain struct{ cat, service string }

// catDomains maps a domain (and everything under it) to its category.
var catDomains = func() map[string]catDomain {
	m := map[string]catDomain{}
	add := func(cat, service string, domains ...string) {
		for _, d := range domains {
			m[d] = catDomain{cat, service}
		}
	}
	// The blocked services catalog already names the big apps.
	for _, s := range filter.Services {
		cat := map[string]string{"Video": CatStreaming, "Social": CatSocial, "Messaging": CatMessaging, "Games": CatGaming,
			"Shopping": CatShopping, "AI": CatSearch, "Dating": CatDating}[s.Category]
		if cat == "" {
			cat = CatOther
		}
		add(cat, s.Name, s.Domains...)
	}

	add(CatStreaming, "Spotify", "spotify.com", "scdn.co", "spotifycdn.com", "spotifycdn.net", "spoti.fi", "pscdn.co")
	add(CatStreaming, "Apple TV and Music", "tv.apple.com", "music.apple.com", "itunes.apple.com", "hls.itunes.apple.com", "play.itunes.apple.com", "applemusic.com")
	add(CatStreaming, "Plex", "plex.tv", "plex.direct", "plex.bz")
	add(CatStreaming, "Roku", "roku.com", "rokutime.com")
	add(CatStreaming, "Peacock", "peacocktv.com")
	add(CatStreaming, "Paramount+", "paramountplus.com", "cbsivideo.com", "cbsaavideo.com")
	add(CatStreaming, "Crunchyroll", "crunchyroll.com", "vrv.co")
	add(CatStreaming, "Pluto TV", "pluto.tv")
	add(CatStreaming, "Tubi", "tubi.tv", "tubitv.com")
	add(CatStreaming, "SoundCloud", "soundcloud.com", "sndcdn.com")
	add(CatStreaming, "Pandora", "pandora.com", "pandora.net")
	add(CatStreaming, "Deezer", "deezer.com", "dzcdn.net")
	add(CatStreaming, "Tidal", "tidal.com", "tidalhifi.com")
	add(CatStreaming, "Audible", "audible.com", "audible.co.uk")
	add(CatStreaming, "BBC iPlayer", "iplayer.bbc.co.uk")
	add(CatStreaming, "ESPN", "espn.com", "espncdn.com")
	add(CatStreaming, "Sling TV", "sling.com", "movetv.com")
	add(CatStreaming, "Stan", "stan.com.au")
	add(CatStreaming, "Kayo", "kayosports.com.au")
	add(CatStreaming, "Binge", "binge.com.au")

	add(CatMessaging, "Zoom", "zoom.us", "zoom.com", "zoomgov.com")
	add(CatMessaging, "Skype", "skype.com", "skypeassets.com")
	add(CatMessaging, "FaceTime and iMessage", "facetime.apple.com", "ess.apple.com", "ids.apple.com")
	add(CatMessaging, "Viber", "viber.com")
	add(CatMessaging, "WeChat", "wechat.com", "weixin.qq.com")

	add(CatGaming, "EA", "ea.com", "origin.com", "eapcdn.com")
	add(CatGaming, "Battle.net", "battle.net", "blizzard.com", "blzstatic.cn")
	add(CatGaming, "Ubisoft", "ubisoft.com", "ubi.com", "ubisoftconnect.com")
	add(CatGaming, "GOG", "gog.com", "gogalaxy.com")
	add(CatGaming, "Rockstar Games", "rockstargames.com")
	add(CatGaming, "Unity", "unity3d.com", "unity.com")
	add(CatGaming, "Game Center", "gc.apple.com", "gamecenter.apple.com")

	add(CatShopping, "Walmart", "walmart.com", "walmartimages.com")
	add(CatShopping, "Target", "target.com", "targetimg1.com")
	add(CatShopping, "Etsy", "etsy.com", "etsystatic.com")
	add(CatShopping, "Best Buy", "bestbuy.com")
	add(CatShopping, "AliExpress", "aliexpress.com", "aliexpress.us", "alicdn.com")
	add(CatShopping, "IKEA", "ikea.com")
	add(CatShopping, "Costco", "costco.com")
	add(CatShopping, "Shopify", "shopify.com", "myshopify.com", "shopifycdn.com", "shop.app")

	add(CatNews, "", "bbc.com", "bbc.co.uk", "bbci.co.uk", "cnn.com", "nytimes.com", "nyt.com", "theguardian.com", "guim.co.uk",
		"reuters.com", "apnews.com", "foxnews.com", "washingtonpost.com", "wsj.com", "bloomberg.com", "npr.org", "abc.net.au",
		"news.com.au", "smh.com.au", "theage.com.au", "dailymail.co.uk", "independent.co.uk", "ft.com", "theverge.com",
		"arstechnica.com", "techcrunch.com", "wired.com", "engadget.com", "nbcnews.com", "cbsnews.com", "usatoday.com",
		"news.google.com", "news.yahoo.com", "msn.com", "flipboard.com", "apple.news", "news.apple.com", "economist.com",
		"theatlantic.com", "politico.com", "axios.com", "9news.com.au", "sbs.com.au", "stuff.co.nz", "nzherald.co.nz", "cbc.ca")

	add(CatSearch, "Google Search", "google.com", "google.co.uk", "google.com.au", "google.ca", "google.de")
	add(CatSearch, "Bing", "bing.com", "bing.net")
	add(CatSearch, "DuckDuckGo", "duckduckgo.com")
	add(CatSearch, "Brave Search", "search.brave.com")
	add(CatSearch, "Ecosia", "ecosia.org")
	add(CatSearch, "Yahoo", "yahoo.com", "yimg.com")
	add(CatSearch, "OpenAI", "openai.com")
	add(CatSearch, "Claude", "claude.ai", "anthropic.com", "claude.com")
	add(CatSearch, "Gemini", "gemini.google.com", "bard.google.com")
	add(CatSearch, "Perplexity", "perplexity.ai")
	add(CatSearch, "Copilot", "copilot.microsoft.com")

	add(CatWork, "Microsoft 365", "office.com", "office.net", "office365.com", "microsoft365.com", "sharepoint.com", "outlook.com",
		"outlook.office.com", "outlook.office365.com", "teams.microsoft.com", "teams.live.com", "lync.com", "onenote.com")
	add(CatWork, "Gmail and Google Docs", "gmail.com", "mail.google.com", "docs.google.com", "drive.google.com", "meet.google.com", "calendar.google.com")
	add(CatWork, "Slack", "slack.com", "slack-edge.com", "slack-msgs.com")
	add(CatWork, "Notion", "notion.so", "notion.com")
	add(CatWork, "Atlassian", "atlassian.com", "atlassian.net", "jira.com", "trello.com")
	add(CatWork, "GitHub", "github.com", "githubusercontent.com", "githubassets.com", "github.io")
	add(CatWork, "Dropbox", "dropbox.com", "dropboxapi.com", "dropboxstatic.com")
	add(CatWork, "Box", "box.com", "boxcdn.net")
	add(CatWork, "Adobe", "adobe.com", "adobe.io", "adobelogin.com", "typekit.net")
	add(CatWork, "Proton", "proton.me", "protonmail.com")
	add(CatWork, "Fastmail", "fastmail.com")
	add(CatWork, "Webex", "webex.com")
	add(CatWork, "Salesforce", "salesforce.com", "force.com")

	add(CatMoney, "PayPal", "paypal.com", "paypalobjects.com", "venmo.com")
	add(CatMoney, "Stripe", "stripe.com", "stripe.network")
	add(CatMoney, "", "wise.com", "revolut.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "capitalone.com", "citi.com",
		"americanexpress.com", "visa.com", "mastercard.com", "coinbase.com", "binance.com", "commbank.com.au", "anz.com",
		"westpac.com.au", "nab.com.au", "barclays.co.uk", "hsbc.com", "monzo.com", "klarna.com", "afterpay.com")

	add(CatOS, "Apple", "apple.com", "icloud.com", "icloud-content.com", "mzstatic.com", "aaplimg.com", "cdn-apple.com",
		"apple-cloudkit.com", "apple-dns.net", "apple.co", "me.com", "push.apple.com", "itunes.com", "apple-mapkit.com")
	add(CatOS, "Microsoft", "microsoft.com", "windows.com", "windows.net", "windowsupdate.com", "live.com", "live.net",
		"msftconnecttest.com", "msftncsi.com", "msedge.net", "msauth.net", "msftauth.net", "microsoftonline.com",
		"onedrive.com", "onedrive.live.com", "1drv.com", "sfx.ms", "visualstudio.com", "azure.com")
	add(CatOS, "Google", "googleapis.com", "gstatic.com", "gvt1.com", "gvt2.com", "gvt3.com", "android.com", "googlezip.net",
		"ggpht.com", "googleusercontent.com", "google.dev", "withgoogle.com", "googleapis.cn", "android.clients.google.com",
		"play.google.com", "accounts.google.com", "photos.google.com", "chromium.org", "chrome.com")
	add(CatOS, "Samsung", "samsung.com", "samsungcloud.com", "samsungapps.com", "samsungosp.com", "samsungdm.com")
	add(CatOS, "Firefox", "mozilla.com", "mozilla.org", "mozilla.net", "firefox.com")
	add(CatOS, "Ubuntu", "ubuntu.com", "canonical.com", "snapcraft.io")
	add(CatOS, "Debian", "debian.org")
	add(CatOS, "Docker", "docker.com", "docker.io")
	add(CatOS, "Brave", "brave.com", "brave.software", "bravesoftware.com")

	add(CatSmartHome, "Amazon Alexa", "amazonalexa.com", "alexa.com", "alexa.amazon.com", "avs-alexa-na.amazon.com", "device-metrics-us.amazon.com", "amazon-dss.com")
	add(CatSmartHome, "Ring", "ring.com", "ringdevices.com")
	add(CatSmartHome, "Google Nest", "nest.com", "home.nest.com", "dropcam.com", "googlehomefoyer-pa.googleapis.com")
	add(CatSmartHome, "Tuya and Smart Life", "tuya.com", "tuyaus.com", "tuyaeu.com", "tuyacn.com", "tuyain.com")
	add(CatSmartHome, "Philips Hue", "meethue.com", "philips-hue.com")
	add(CatSmartHome, "Sonos", "sonos.com", "sonos.net")
	add(CatSmartHome, "ecobee", "ecobee.com")
	add(CatSmartHome, "SmartThings", "smartthings.com", "samsungiotcloud.com")
	add(CatSmartHome, "Wyze", "wyze.com", "wyzecam.com")
	add(CatSmartHome, "TP-Link and Kasa", "tplinkcloud.com", "tp-link.com", "kasasmart.com", "tplinkra.com", "tplinknbu.com")
	add(CatSmartHome, "Meross", "meross.com")
	add(CatSmartHome, "Anker and eufy", "anker-in.com", "eufylife.com", "eufy.com", "anker.com", "soundcore.com")
	add(CatSmartHome, "Home Assistant", "home-assistant.io", "nabu.casa")
	add(CatSmartHome, "IFTTT", "ifttt.com")
	add(CatSmartHome, "Govee", "govee.com")
	add(CatSmartHome, "LIFX", "lifx.com", "lifx.co")
	add(CatSmartHome, "Arlo", "arlo.com", "arlo.net")
	add(CatSmartHome, "Blink", "immedia-semi.com", "blinkforhome.com")
	add(CatSmartHome, "Shelly", "shelly.cloud")
	add(CatSmartHome, "Netatmo", "netatmo.com", "netatmo.net")
	add(CatSmartHome, "tado", "tado.com")
	add(CatSmartHome, "Roborock and Xiaomi", "roborock.com", "io.mi.com", "mi.com", "xiaomi.com", "xiaomi.net")
	add(CatSmartHome, "Ecovacs", "ecovacs.com", "ecouser.net")
	add(CatSmartHome, "myQ", "myq-cloud.com", "myqdevice.com")
	add(CatSmartHome, "Samsung TV", "samsungcloudsolution.com", "samsungcloudsolution.net", "samsungotn.net", "samsungqbe.com", "samsungacr.com", "samsungtifa.com")
	add(CatSmartHome, "LG TV", "lgtvsdp.com", "lgsmartad.com", "lgappstv.com", "lge.com")
	add(CatSmartHome, "Vizio", "vizio.com", "tvinteractive.tv")
	add(CatSmartHome, "Chromecast", "chromecast.com")
	add(CatSmartHome, "Apple Home", "home.apple.com")
	add(CatSmartHome, "Ubiquiti", "ui.com", "ubnt.com", "svc.ui.com")
	add(CatSmartHome, "Synology", "synology.com", "quickconnect.to")

	add(CatCDN, "Akamai", "akamai.net", "akamaiedge.net", "akamaihd.net", "akamaized.net", "akamaitechnologies.com", "edgekey.net",
		"edgesuite.net", "akadns.net", "akamai.com", "akstat.io")
	add(CatCDN, "Cloudflare", "cloudflare.com", "cloudflare.net", "cdnjs.cloudflare.com", "cloudflareinsights.com", "workers.dev", "pages.dev")
	add(CatCDN, "Fastly", "fastly.net", "fastlylb.net", "fastly.com", "fastly-edge.com")
	add(CatCDN, "Amazon Web Services", "amazonaws.com", "cloudfront.net", "awsstatic.com", "aws.amazon.com", "awsdns-cn.com", "amazontrust.com")
	add(CatCDN, "Microsoft Azure", "azureedge.net", "azurefd.net", "trafficmanager.net", "cloudapp.net", "azurewebsites.net", "azure.net", "msecnd.net", "aspnetcdn.com")
	add(CatCDN, "", "jsdelivr.net", "unpkg.com", "cdn77.org", "b-cdn.net", "bunny.net", "llnwd.net", "edgecastcdn.net",
		"vercel.app", "netlify.app", "herokuapp.com", "digitaloceanspaces.com", "gcore.com", "stackpathdns.com")

	add(CatNetwork, "", "in-addr.arpa", "ip6.arpa", "resolver.arpa", "home.arpa", "pool.ntp.org", "ntp.org", "time.apple.com",
		"time.windows.com", "time.google.com", "time.cloudflare.com", "captive.apple.com", "connectivitycheck.gstatic.com",
		"connectivitycheck.android.com", "detectportal.firefox.com", "nmcheck.gnome.org", "dns.google", "one.one.one.one",
		"cloudflare-dns.com", "quad9.net", "dns.quad9.net", "dns.adguard.com", "nextdns.io", "letsencrypt.org", "lencr.org",
		"digicert.com", "ocsp.apple.com", "ocsp.digicert.com", "sectigo.com", "pki.goog", "globalsign.com", "ipv4only.arpa",
		"ifconfig.me", "ipinfo.io", "speedtest.net", "ookla.com", "fast.com")
	return m
}()

// trackerCats turns the companies database's tracker types into
// categories, for domains DNServ's own table doesn't know.
var trackerCats = map[string]string{
	"Advertising": CatAds, "Adult advertising": CatAds, "Site analytics": CatAds, "Mobile analytics": CatAds, "Telemetry": CatAds,
	"Social media": CatSocial, "Audio video player": CatStreaming, "Content delivery": CatCDN, "Hosting": CatCDN, "Email": CatWork,
}

// companyCats places a domain by the company that runs it, last.
var companyCats = map[string]string{
	"Apple": CatOS, "Microsoft": CatOS, "Google": CatOS, "Samsung": CatOS, "Mozilla": CatOS,
	"Akamai Technologies": CatCDN, "Cloudflare": CatCDN, "Fastly": CatCDN, "Amazon Web Services": CatCDN,
	"Meta Platforms": CatSocial, "Facebook": CatSocial, "ByteDance": CatSocial, "Netflix": CatStreaming, "Spotify": CatStreaming,
}

// CategoryOf says what name is used for. t is its companies database type
// (nil if unknown).
func CategoryOf(name string, t *Type) Category {
	name = filter.Normalize(name)
	var out *catDomain
	parents(name, func(n string) bool {
		if c, ok := catDomains[n]; ok {
			out = &c
			return false
		}
		return true
	})
	if out != nil {
		return Category{Name: out.cat, Service: out.service}
	}
	if t != nil {
		co := ShortCompany(t.Company)
		if c, ok := trackerCats[t.Category]; ok {
			return Category{Name: c, Service: co}
		}
		if c, ok := companyCats[co]; ok {
			return Category{Name: c, Service: co}
		}
	}
	if strings.HasSuffix(name, ".arpa") || strings.HasSuffix(name, ".local") {
		return Category{Name: CatNetwork}
	}
	return Category{Name: CatOther}
}

// ShortCompany trims a company's legal suffix: "Apple Inc." → "Apple",
// "Meta Platforms, Inc." → "Meta Platforms".
func ShortCompany(s string) string {
	for {
		t := strings.TrimSpace(strings.TrimRight(s, ".,"))
		for _, suf := range []string{" Inc", " Corporation", " Corp", " LLC", " Ltd", " Limited", " GmbH", " AG", " S.A", " SA", " plc", " Co"} {
			if strings.HasSuffix(t, suf) && len(t) > len(suf)+1 {
				t = strings.TrimSpace(strings.TrimRight(strings.TrimSuffix(t, suf), ".,"))
			}
		}
		if t == s {
			return s
		}
		s = t
	}
}

// Category says what name is used for, from DNServ's table and the
// companies database.
func (in *Intel) Category(name string) Category {
	var t *Type
	if in != nil {
		t = in.TypeOf(name)
	}
	return CategoryOf(name, t)
}
