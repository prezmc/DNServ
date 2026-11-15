package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

func TestGroupPolicy(t *testing.T) {
	st := &store.State{
		Groups: map[string]*store.Group{
			"kids": {ID: "kids", Name: "Kids", Rules: []string{"||games.example^", "@@||school.example^"},
				Schedules: []store.Schedule{
					{Name: "Bedtime", Days: []int{0, 1, 2, 3, 4}, Start: "21:00", End: "07:00", BlockAll: true},
					{Name: "Homework", Days: []int{1, 2, 3, 4, 5}, Start: "16:00", End: "18:00", Rules: []string{"||video.example^"}},
				}},
			"work": {ID: "work", Name: "Work", SkipBlocklists: true},
		},
		Devices: map[string]*store.Device{
			"tab": {ID: "tab", Name: "Tablet", Addrs: []string{"192.168.1.20", "fd00::20"}, Group: "kids"},
			"lap": {ID: "lap", Name: "Laptop", Addrs: []string{"192.168.1.30"}, Group: "work"},
			"tv":  {ID: "tv", Name: "TV", Addrs: []string{"192.168.1.40"}},
		},
	}
	s := Build(st)
	kids := s.For(netip.MustParseAddr("::ffff:192.168.1.20"))
	if kids == nil || kids.Name != "Kids" || s.For(netip.MustParseAddr("fd00::20")) != kids {
		t.Fatal("tablet not in Kids")
	}
	if s.For(netip.MustParseAddr("192.168.1.40")) != nil || s.For(netip.MustParseAddr("10.0.0.1")) != nil {
		t.Fatal("ungrouped device has a group")
	}
	if w := s.For(netip.MustParseAddr("192.168.1.30")); w.Shared == nil || !w.Shared.Empty() {
		t.Fatal("work group should skip shared lists")
	}

	at := func(day time.Weekday, hhmm string) time.Time {
		c, _ := store.ParseClock(hhmm)
		// 2026-11-08 is a Sunday.
		return time.Date(2026, 11, 8+int(day), c/60, c%60, 0, 0, time.Local)
	}
	cases := []struct {
		name    string
		when    time.Time
		blocked bool
		decided bool
		source  string
	}{
		{"news.example", at(time.Wednesday, "12:00"), false, false, ""},
		{"games.example", at(time.Wednesday, "12:00"), true, true, "Group Kids"},
		{"news.example", at(time.Wednesday, "22:00"), true, true, "Schedule Bedtime"},
		{"news.example", at(time.Thursday, "06:59"), true, true, "Schedule Bedtime"}, // started Wednesday
		{"news.example", at(time.Thursday, "07:00"), false, false, ""},
		{"news.example", at(time.Friday, "22:00"), false, false, ""},               // no bedtime on Friday nights
		{"news.example", at(time.Saturday, "06:00"), false, false, ""},             // nor Saturday morning
		{"news.example", at(time.Monday, "06:00"), true, true, "Schedule Bedtime"}, // Sunday night
		{"school.example", at(time.Wednesday, "22:00"), false, true, "Group Kids"}, // allow beats bedtime
		{"www.video.example", at(time.Friday, "17:00"), true, true, "Schedule Homework"},
		{"www.video.example", at(time.Saturday, "17:00"), false, false, ""},
	}
	for _, c := range cases {
		m, decided := kids.Check(c.name, c.when)
		if m.Blocked != c.blocked || decided != c.decided || m.Source != c.source {
			t.Errorf("%s at %s: blocked=%v decided=%v source=%q", c.name, c.when.Format("Mon 15:04"), m.Blocked, decided, m.Source)
		}
	}
	if got := kids.Active(at(time.Tuesday, "23:00")); len(got) != 1 || got[0] != "Bedtime" {
		t.Errorf("active = %v", got)
	}
	var nilSet *Set
	if nilSet.For(netip.MustParseAddr("192.168.1.20")) != nil {
		t.Fatal("nil set")
	}
}

func TestTargetedRulesAndSelection(t *testing.T) {
	st := &store.State{
		Groups: map[string]*store.Group{
			"kids": {ID: "kids", Name: "Kids", Rules: []string{"||games.example^"}, ListMode: "choose", Lists: []string{"https://adult"}},
			"work": {ID: "work", Name: "Work", HouseholdRules: "off"},
		},
		Devices: map[string]*store.Device{
			"tab": {ID: "tab", Name: "Tablet", Addrs: []string{"192.168.1.20"}, Group: "kids"},
			"pad": {ID: "pad", Name: "iPad", Addrs: []string{"192.168.1.21"}, Group: "kids"},
			"tv":  {ID: "tv", Name: "Living room TV", Addrs: []string{"192.168.1.40"}},
			"lap": {ID: "lap", Name: "Laptop", Addrs: []string{"192.168.1.30"}, Group: "work"},
		},
	}
	rules := []string{"||ads.example^", "||video.example^$client=kids", "||shop.example^$client='Living room TV'|192.168.1.30", "@@||ok.example^$client=Tablet"}
	s := BuildWith(st, rules)
	at := time.Date(2026, 11, 11, 12, 0, 0, 0, time.Local)
	check := func(ip, name string) (bool, bool) {
		g := s.For(netip.MustParseAddr(ip))
		if g == nil {
			return false, false
		}
		m, decided := g.Check(name, at)
		return m.Blocked, decided
	}
	if b, _ := check("192.168.1.20", "video.example"); !b {
		t.Error("$client=kids (any case) should block for the tablet")
	}
	if b, _ := check("192.168.1.21", "games.example"); !b {
		t.Error("group rules lost on a device with targeted rules")
	}
	if b, d := check("192.168.1.20", "ok.example"); b || !d {
		t.Error("device-targeted allow")
	}
	if _, d := check("192.168.1.21", "ok.example"); d {
		t.Error("the allow for Tablet applied to the iPad")
	}
	if b, _ := check("192.168.1.40", "shop.example"); !b {
		t.Error("device name with quotes")
	}
	if b, _ := check("192.168.1.30", "shop.example"); !b {
		t.Error("address target")
	}
	if b, d := check("192.168.1.40", "ads.example"); b || d {
		t.Error("household rules belong to the shared filter, not the policy")
	}
	tv := s.For(netip.MustParseAddr("192.168.1.40"))
	if tv.Shared != nil || tv.HasSchedules() {
		t.Error("a household device with targeted rules should follow the household")
	}
	kids := s.For(netip.MustParseAddr("192.168.1.21"))
	if kids.Shared == nil || !kids.Shared.Lists["https://adult"] || kids.Shared.NoHousehold {
		t.Errorf("kids selection: %+v", kids.Shared)
	}
	if s.For(netip.MustParseAddr("192.168.1.20")).Shared != kids.Shared {
		t.Error("devices of one group should share its selection")
	}
	if w := s.For(netip.MustParseAddr("192.168.1.30")); w.Shared == nil || w.Shared.Lists != nil || !w.Shared.NoHousehold {
		t.Errorf("work selection: %+v", w.Shared)
	}
}
