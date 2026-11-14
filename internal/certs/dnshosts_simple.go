package certs

// SimpleField is one setting shown up front for a popular DNS host, with a
// plain label, instead of lego's full list of variable names.
type SimpleField struct {
	Var      string `json:"var"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret,omitempty"`
	Optional bool   `json:"optional,omitempty"`
	Hint     string `json:"hint,omitempty"` // placeholder
}

type simpleHost struct {
	fields []SimpleField
	help   string
}

// The recommended way to sign in to popular DNS hosts. Other settings
// lego accepts stay available under "Other ways to sign in".
var simpleHosts = map[string]simpleHost{
	"cloudflare": {[]SimpleField{{Var: "CF_DNS_API_TOKEN", Label: "API token", Secret: true}},
		"In Cloudflare, open My Profile, then API Tokens, then Create Token. Use the “Edit zone DNS” template and pick your domain under Zone Resources."},
	"route53": {[]SimpleField{
		{Var: "AWS_ACCESS_KEY_ID", Label: "Access key ID"},
		{Var: "AWS_SECRET_ACCESS_KEY", Label: "Secret access key", Secret: true},
		{Var: "AWS_REGION", Label: "Region", Optional: true, Hint: "us-east-1"},
	}, "Make an IAM user allowed to change records in your hosted zone (route53:ChangeResourceRecordSets, ListHostedZonesByName and GetChange), then create an access key for it."},
	"digitalocean": {[]SimpleField{{Var: "DO_AUTH_TOKEN", Label: "API token", Secret: true}},
		"In DigitalOcean, open API, then Tokens, then Generate New Token with write access."},
	"porkbun": {[]SimpleField{
		{Var: "PORKBUN_API_KEY", Label: "API key"},
		{Var: "PORKBUN_SECRET_API_KEY", Label: "Secret API key", Secret: true},
	}, "In Porkbun, open Account, then API Access, and create a key. Then turn on API Access for your domain on the Domain Management page."},
	"namecheap": {[]SimpleField{
		{Var: "NAMECHEAP_API_USER", Label: "Username"},
		{Var: "NAMECHEAP_API_KEY", Label: "API key", Secret: true},
	}, "In Namecheap, open Profile, then Tools, then Namecheap API Access. Turn it on and add your home’s public IP address to the allowed list."},
	"godaddy": {[]SimpleField{
		{Var: "GODADDY_API_KEY", Label: "API key"},
		{Var: "GODADDY_API_SECRET", Label: "API secret", Secret: true},
	}, "Create a Production key at developer.godaddy.com/keys. GoDaddy only allows its DNS API on some accounts; if it refuses, use the CNAME option instead."},
	"hetzner":  {[]SimpleField{{Var: "HETZNER_API_TOKEN", Label: "API token", Secret: true}}, "In Hetzner DNS Console, open API tokens and create one."},
	"gandiv5":  {[]SimpleField{{Var: "GANDIV5_PERSONAL_ACCESS_TOKEN", Label: "Personal access token", Secret: true}}, "In Gandi, open your account’s Authentication options and create a personal access token that can manage domain technical configurations."},
	"duckdns":  {[]SimpleField{{Var: "DUCKDNS_TOKEN", Label: "Token", Secret: true}}, "The token shown at the top of duckdns.org once you sign in."},
	"linode":   {[]SimpleField{{Var: "LINODE_TOKEN", Label: "API token", Secret: true}}, "In Linode (Akamai) Cloud Manager, create a personal access token with Domains set to Read/Write."},
	"desec":    {[]SimpleField{{Var: "DESEC_TOKEN", Label: "Token", Secret: true}}, "In deSEC, open Token Management and create a token."},
	"ionos":    {[]SimpleField{{Var: "IONOS_API_KEY", Label: "API key", Secret: true, Hint: "prefix.secret"}}, "Create a key at developer.hosting.ionos.com and paste it as prefix.secret."},
	"vultr":    {[]SimpleField{{Var: "VULTR_API_KEY", Label: "API key", Secret: true}}, "In Vultr, open Account, then API, and turn on the API."},
	"dnsimple": {[]SimpleField{{Var: "DNSIMPLE_OAUTH_TOKEN", Label: "API token", Secret: true}}, "In DNSimple, open Account, then Access Tokens, and create an account token."},
}
