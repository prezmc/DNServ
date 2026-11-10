package filter

// BypassDomains are public DNS-over-HTTPS/TLS resolvers and relay services
// that devices and browsers use to skip the local DNS server. With
// filtering.block_bypass on they are blocked, so devices fall back to this
// server. Allow one with a custom "@@||name^" rule if you rely on it.
//
// Blocking the names is only half of it: a device can still reach a
// resolver by IP. Pair this with a router rule that blocks outbound TCP and
// UDP port 853 and redirects port 53 to DNServ (see the README).
var BypassDomains = []string{
	// Google
	"dns.google", "dns.google.com",
	// Cloudflare
	"cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
	"security.cloudflare-dns.com", "family.cloudflare-dns.com",
	"mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
	// Quad9
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
	// OpenDNS / Cisco
	"doh.opendns.com", "dns.opendns.com", "doh.familyshield.opendns.com",
	// AdGuard
	"dns.adguard.com", "dns.adguard-dns.com", "dns-family.adguard.com",
	"unfiltered.adguard-dns.com", "family.adguard-dns.com",
	// NextDNS, Mullvad, Control D, CleanBrowsing, DNS.SB, others
	"dns.nextdns.io", "doh.mullvad.net", "dns.mullvad.net", "adblock.dns.mullvad.net",
	"freedns.controld.com", "dns.controld.com",
	"doh.cleanbrowsing.org", "doh.dns.sb", "doh.libredns.gr",
	"dns.switch.ch", "doh.applied-privacy.net", "dns0.eu", "zero.dns0.eu",
	// Apple iCloud Private Relay (Apple documents NXDOMAIN to disable it).
	"mask.icloud.com", "mask-h2.icloud.com",
}
