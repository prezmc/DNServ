package filter

import (
	"strings"
	"sync/atomic"
)

// Selection is a group's own choice of the shared sources: which lists
// apply, and whether the household's custom rules, blocked services and
// bypass protection do. Its mask is worked out once per index, on the
// first lookup after a rebuild.
type Selection struct {
	// Lists are the URLs of the lists (blocklists and allowlists) that
	// apply. Nil means the household's lists.
	Lists map[string]bool
	// NoHousehold drops the household's custom rules, blocked services
	// and bypass protection.
	NoHousehold bool

	cache atomic.Pointer[selMask]
}

type selMask struct {
	ix   *Index
	mask []uint64
}

// Empty reports whether the selection uses no shared source at all.
func (s *Selection) Empty() bool { return s.Lists != nil && len(s.Lists) == 0 && s.NoHousehold }

// Mask returns the bit per source id of ix that s uses.
func (s *Selection) Mask(ix *Index) []uint64 {
	if c := s.cache.Load(); c != nil && c.ix == ix {
		return c.mask
	}
	mask := make([]uint64, 1+len(ix.Sources())/64)
	for _, src := range ix.Sources() {
		var on bool
		if url, ok := strings.CutPrefix(src.Key, "list:"); ok {
			if s.Lists == nil {
				on = src.Household
			} else {
				on = s.Lists[url]
			}
		} else {
			on = src.Household && !s.NoHousehold
		}
		if on {
			mask[src.ID/64] |= 1 << (src.ID % 64)
		}
	}
	s.cache.Store(&selMask{ix: ix, mask: mask})
	return mask
}
