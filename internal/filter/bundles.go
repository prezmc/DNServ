package filter

// BundleList is one blocklist inside a category bundle.
type BundleList struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Bundle is a category of blocking (ads, adult sites, gambling, ...) that
// adds a few curated lists in one click. Bundles stack on top of the
// protection level; they only add rows to the normal blocklist settings,
// so the lists can still be renamed, switched off or removed one by one.
type Bundle struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	About string `json:"about"`
	// Warning says what may stop working, if anything usually does.
	Warning string       `json:"warning,omitempty"`
	Lists   []BundleList `json:"lists"`
}

const hagezi = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/"

// Bundles is the catalog, kept to well-maintained lists in a format DNServ
// reads fully (AdBlock-style domain rules or hosts files).
var Bundles = []Bundle{
	{ID: "ads", Name: "Ads and pop-ups", About: "Ad networks and pop-up or pop-under ad domains.",
		Lists: []BundleList{
			{"AdGuard DNS filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
			{"HaGeZi Pop-Up Ads", hagezi + "popupads.txt"},
		}},
	{ID: "malware", Name: "Malware and phishing", About: "Known malware, phishing, scam and crypto-mining domains, updated daily.",
		Lists: []BundleList{
			{"HaGeZi Threat Intelligence", hagezi + "tif.txt"},
			{"Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt"},
			{"URLhaus malicious domains", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt"},
			{"NoCoin crypto mining", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt"},
		}},
	{ID: "scams", Name: "Scams and fake shops", About: "Fake shops, fake streaming sites and other scam sites.",
		Lists: []BundleList{
			{"HaGeZi Fake", hagezi + "fake.txt"},
		}},
	{ID: "smarttv", Name: "Smart TV tracking", About: "What Samsung, LG, Roku and Fire TV sets report about what you watch.",
		Warning: "Some TV app stores or firmware updates may stop working.",
		Lists: []BundleList{
			{"HaGeZi Samsung tracking", hagezi + "native.samsung.txt"},
			{"HaGeZi LG webOS tracking", hagezi + "native.lgwebos.txt"},
			{"HaGeZi Roku tracking", hagezi + "native.roku.txt"},
			{"HaGeZi Amazon tracking", hagezi + "native.amazon.txt"},
			{"Perflyst Smart TV", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt"},
		}},
	{ID: "telemetry", Name: "Phone and computer tracking", About: "Telemetry from Windows and Office, Apple, Xiaomi and TikTok.",
		Warning: "Can slow some Windows or Apple features, such as error reports.",
		Lists: []BundleList{
			{"HaGeZi Windows and Office tracking", hagezi + "native.winoffice.txt"},
			{"HaGeZi Apple tracking", hagezi + "native.apple.txt"},
			{"HaGeZi Xiaomi tracking", hagezi + "native.xiaomi.txt"},
			{"HaGeZi TikTok tracking", hagezi + "native.tiktok.txt"},
		}},
	{ID: "adult", Name: "Adult sites", About: "Pornography and other adult content.",
		Lists: []BundleList{
			{"HaGeZi NSFW", hagezi + "nsfw.txt"},
		}},
	{ID: "gambling", Name: "Gambling", About: "Betting, casino and lottery sites.",
		Lists: []BundleList{
			{"HaGeZi Gambling", hagezi + "gambling.txt"},
		}},
	{ID: "piracy", Name: "Piracy", About: "Illegal streaming, torrent and download sites.",
		Lists: []BundleList{
			{"HaGeZi Anti-Piracy", hagezi + "anti.piracy.txt"},
		}},
	{ID: "bypass", Name: "VPNs, proxies and DNS bypass", About: "Services that let devices get around filtering.",
		Warning: "Blocks VPN apps, including work VPNs.",
		Lists: []BundleList{
			{"HaGeZi DoH, VPN and proxy bypass", hagezi + "doh-vpn-proxy-bypass.txt"},
		}},
}
