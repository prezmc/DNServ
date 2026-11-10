package store

import "github.com/prezmc/dnserve/internal/config"

// Settings are the values changed from the UI or API. A nil field means
// "not set here": the node uses its config file, environment or built-in
// default. Once a value is saved here it wins over those.
type Settings struct {
	UpstreamMode    *string  `json:"upstream_mode,omitempty"`
	UpstreamServers []string `json:"upstream_servers,omitempty"`

	TunnelInterface      *string  `json:"tunnel_interface,omitempty"`
	TunnelExpectedEgress []string `json:"tunnel_expected_egress,omitempty"`
	TunnelOnDown         *string  `json:"tunnel_on_down,omitempty"`

	AllowedNets []string         `json:"allowed_nets,omitempty"`
	LocalDNS    *string          `json:"local_dns,omitempty"`
	TimeZone    *string          `json:"time_zone,omitempty"`
	Records     *[]config.Record `json:"records,omitempty"`

	FilteringEnabled *bool                `json:"filtering_enabled,omitempty"`
	BlockMode        *string              `json:"block_mode,omitempty"`
	BlockBypass      *bool                `json:"block_bypass,omitempty"`
	BlockedServices  *[]string            `json:"blocked_services,omitempty"`
	SafeSearch       *bool                `json:"safe_search,omitempty"`
	Lists            *[]config.ListConfig `json:"lists,omitempty"`
	Allowlists       *[]config.ListConfig `json:"allowlists,omitempty"`
	Rules            *[]string            `json:"rules,omitempty"`

	HistoryDays *int `json:"history_days,omitempty"`
	StatsDays   *int `json:"stats_days,omitempty"`

	ThreatFeeds    *bool     `json:"threat_feeds,omitempty"`
	TrustedDomains *[]string `json:"trusted_domains,omitempty"`
}

// Overlay returns base with every set field replaced.
func (s Settings) Overlay(base config.Config) config.Config {
	c := base
	if s.UpstreamMode != nil {
		c.Upstream.Mode = *s.UpstreamMode
	}
	if s.UpstreamServers != nil {
		c.Upstream.Servers = append([]string(nil), s.UpstreamServers...)
	}
	if s.TunnelInterface != nil {
		c.Upstream.Tunnel.Interface = *s.TunnelInterface
	}
	if s.TunnelExpectedEgress != nil {
		c.Upstream.Tunnel.ExpectedEgress = append([]string(nil), s.TunnelExpectedEgress...)
	}
	if s.TunnelOnDown != nil {
		c.Upstream.Tunnel.OnDown = *s.TunnelOnDown
	}
	if s.AllowedNets != nil {
		c.DNS.AllowedNets = append([]string(nil), s.AllowedNets...)
	}
	if s.LocalDNS != nil {
		c.DNS.LocalDNS = *s.LocalDNS
	}
	if s.TimeZone != nil {
		c.TimeZone = *s.TimeZone
	}
	if s.Records != nil {
		c.DNS.Records = append([]config.Record(nil), (*s.Records)...)
	}
	if s.FilteringEnabled != nil {
		c.Filtering.Enabled = *s.FilteringEnabled
	}
	if s.BlockMode != nil {
		c.Filtering.BlockMode = *s.BlockMode
	}
	if s.BlockBypass != nil {
		c.Filtering.BlockBypass = *s.BlockBypass
	}
	if s.BlockedServices != nil {
		c.Filtering.BlockedServices = append([]string(nil), (*s.BlockedServices)...)
	}
	if s.SafeSearch != nil {
		c.Filtering.SafeSearch = *s.SafeSearch
	}
	if s.Lists != nil {
		c.Filtering.Lists = append([]config.ListConfig(nil), (*s.Lists)...)
	}
	if s.Allowlists != nil {
		c.Filtering.Allowlists = append([]config.ListConfig(nil), (*s.Allowlists)...)
	}
	if s.Rules != nil {
		c.Filtering.Rules = append([]string(nil), (*s.Rules)...)
	}
	if s.HistoryDays != nil {
		c.History.Days = *s.HistoryDays
	}
	if s.StatsDays != nil {
		c.History.StatsDays = *s.StatsDays
	}
	if s.ThreatFeeds != nil {
		c.Analytics.ThreatFeeds = *s.ThreatFeeds
	}
	if s.TrustedDomains != nil {
		c.Analytics.TrustedDomains = append([]string(nil), (*s.TrustedDomains)...)
	}
	return c
}

// Merge copies every field set in p onto s.
func (s *Settings) Merge(p Settings) {
	if p.UpstreamMode != nil {
		s.UpstreamMode = p.UpstreamMode
	}
	if p.UpstreamServers != nil {
		s.UpstreamServers = p.UpstreamServers
	}
	if p.TunnelInterface != nil {
		s.TunnelInterface = p.TunnelInterface
	}
	if p.TunnelExpectedEgress != nil {
		s.TunnelExpectedEgress = p.TunnelExpectedEgress
	}
	if p.TunnelOnDown != nil {
		s.TunnelOnDown = p.TunnelOnDown
	}
	if p.AllowedNets != nil {
		s.AllowedNets = p.AllowedNets
	}
	if p.LocalDNS != nil {
		s.LocalDNS = p.LocalDNS
	}
	if p.TimeZone != nil {
		s.TimeZone = p.TimeZone
	}
	if p.Records != nil {
		s.Records = p.Records
	}
	if p.FilteringEnabled != nil {
		s.FilteringEnabled = p.FilteringEnabled
	}
	if p.BlockMode != nil {
		s.BlockMode = p.BlockMode
	}
	if p.BlockBypass != nil {
		s.BlockBypass = p.BlockBypass
	}
	if p.BlockedServices != nil {
		s.BlockedServices = p.BlockedServices
	}
	if p.SafeSearch != nil {
		s.SafeSearch = p.SafeSearch
	}
	if p.Lists != nil {
		s.Lists = p.Lists
	}
	if p.Allowlists != nil {
		s.Allowlists = p.Allowlists
	}
	if p.Rules != nil {
		s.Rules = p.Rules
	}
	if p.HistoryDays != nil {
		s.HistoryDays = p.HistoryDays
	}
	if p.StatsDays != nil {
		s.StatsDays = p.StatsDays
	}
	if p.ThreatFeeds != nil {
		s.ThreatFeeds = p.ThreatFeeds
	}
	if p.TrustedDomains != nil {
		s.TrustedDomains = p.TrustedDomains
	}
}

// Touches reports which permission areas a patch changes.
func (p Settings) Touches() (upstream, network, lists, rules bool) {
	upstream = p.UpstreamMode != nil || p.UpstreamServers != nil || p.TunnelInterface != nil ||
		p.TunnelExpectedEgress != nil || p.TunnelOnDown != nil
	network = p.AllowedNets != nil || p.LocalDNS != nil || p.TimeZone != nil || p.Records != nil
	lists = p.Lists != nil || p.Allowlists != nil || p.BlockBypass != nil || p.BlockedServices != nil || p.SafeSearch != nil || p.FilteringEnabled != nil || p.BlockMode != nil ||
		p.ThreatFeeds != nil || p.TrustedDomains != nil
	rules = p.Rules != nil
	return
}

// TouchesHistory reports whether a patch changes how long query history is
// kept (an admin decision, since it is about privacy).
func (p Settings) TouchesHistory() bool { return p.HistoryDays != nil || p.StatsDays != nil }
