package filter

import (
	"net/url"
	"testing"
)

func TestBundles(t *testing.T) {
	ids := map[string]bool{}
	urls := map[string]string{}
	for _, b := range Bundles {
		if b.ID == "" || b.Name == "" || b.About == "" || len(b.Lists) == 0 {
			t.Errorf("bundle %q is incomplete", b.ID)
		}
		if ids[b.ID] {
			t.Errorf("duplicate bundle id %q", b.ID)
		}
		ids[b.ID] = true
		for _, l := range b.Lists {
			u, err := url.Parse(l.URL)
			if err != nil || u.Scheme != "https" || u.Host == "" || l.Name == "" {
				t.Errorf("bundle %q: bad list %+v", b.ID, l)
			}
			if prev, ok := urls[l.URL]; ok {
				t.Errorf("list %s is in both %q and %q", l.URL, prev, b.ID)
			}
			urls[l.URL] = b.ID
		}
	}
}
