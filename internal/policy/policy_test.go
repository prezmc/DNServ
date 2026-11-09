package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/prezmc/dnserve/internal/store"
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
	if !s.For(netip.MustParseAddr("192.168.1.30")).SkipShared {
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
