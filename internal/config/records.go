package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Record is a local DNS record: Name answers with Value. Value is an IP
// address (an A or AAAA record) or another name (a CNAME, an alias).
// Name may start with "*." to cover every name below it.
type Record struct {
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value" json:"value"`
	Note  string `yaml:"note,omitempty" json:"note,omitempty"`
}

// MaxRecords limits the local records.
const MaxRecords = 5000

// RecordKind is "A", "AAAA" or "CNAME" for a valid record's value.
func (r Record) Kind() string {
	if ip, err := netip.ParseAddr(r.Value); err == nil {
		if ip.Unmap().Is4() {
			return "A"
		}
		return "AAAA"
	}
	return "CNAME"
}

// NormalizeName lower-cases a name and drops a trailing dot.
func NormalizeName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// NormalizeRecords cleans up records (case, trailing dots, IP format) and
// checks them: valid names and values, and an alias is the only record
// for its name.
func NormalizeRecords(in []Record) ([]Record, error) {
	if len(in) > MaxRecords {
		return nil, fmt.Errorf("at most %d local records", MaxRecords)
	}
	out := make([]Record, 0, len(in))
	kinds := map[string]map[string]bool{}
	seen := map[[2]string]bool{}
	for _, r := range in {
		r.Name, r.Note = NormalizeName(r.Name), strings.TrimSpace(r.Note)
		host := strings.TrimPrefix(r.Name, "*.")
		if !validHostname(host) || strings.Contains(host, "*") {
			return nil, fmt.Errorf("%q isn't a valid name (use letters, digits and hyphens, like nas.home or *.lab.home)", r.Name)
		}
		if host == "localhost" || strings.HasSuffix(host, ".localhost") {
			return nil, errors.New("localhost always points to this device and can't be changed")
		}
		if len(r.Note) > 200 {
			return nil, fmt.Errorf("the note for %s is too long", r.Name)
		}
		v := strings.TrimSpace(r.Value)
		if ip, err := netip.ParseAddr(v); err == nil {
			if ip.Zone() != "" {
				return nil, fmt.Errorf("%s: use an address without a zone (%%)", r.Name)
			}
			r.Value = ip.Unmap().String()
		} else {
			r.Value = NormalizeName(v)
			if !validHostname(r.Value) {
				return nil, fmt.Errorf("%s: %q isn't an IP address or a name", r.Name, v)
			}
			if r.Value == r.Name {
				return nil, fmt.Errorf("%s can't be an alias for itself", r.Name)
			}
		}
		key := [2]string{r.Name, r.Value}
		if seen[key] {
			return nil, fmt.Errorf("%s → %s is listed twice", r.Name, r.Value)
		}
		seen[key] = true
		if kinds[r.Name] == nil {
			kinds[r.Name] = map[string]bool{}
		}
		k := r.Kind()
		if k == "CNAME" && len(kinds[r.Name]) > 0 || kinds[r.Name]["CNAME"] {
			return nil, fmt.Errorf("%s is an alias for another name, so it can't have other records too", r.Name)
		}
		kinds[r.Name][k] = true
		out = append(out, r)
	}
	return out, nil
}
