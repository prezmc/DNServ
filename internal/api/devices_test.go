package api

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/prezmc/dnserve/internal/filter"
	"github.com/prezmc/dnserve/internal/querylog"
)

func TestDevicesQueriesAndCheck(t *testing.T) {
	e := newEnv(t)
	ql := querylog.New(100)
	e.api.QueryLog = ql
	e.api.LookupName = func(_ context.Context, a netip.Addr) string {
		if a == netip.MustParseAddr("192.168.1.20") {
			return "kitchen-ipad"
		}
		return ""
	}
	e.api.CheckDomain = func(name string) filter.Match {
		if name == "ads.example.com" {
			return filter.Match{Blocked: true, Rule: filter.Rule{Domain: "ads.example.com", Kind: filter.Exact}, Source: "Test list"}
		}
		return filter.Match{}
	}
	admin, _ := e.setupAdmin()

	now := time.Unix(1_800_000_000, 0)
	tv := netip.MustParseAddr("192.168.1.10")
	ipad := netip.MustParseAddr("192.168.1.20")
	ql.Add(querylog.Entry{Time: now, Client: tv, Name: "ads.example.com", Type: "A", Result: querylog.Blocked})
	ql.Add(querylog.Entry{Time: now.Add(time.Second), Client: tv, Name: "example.com", Type: "A", Result: querylog.Answered})
	ql.Add(querylog.Entry{Time: now.Add(2 * time.Second), Client: ipad, Name: "news.example.org", Type: "AAAA", Result: querylog.Cached})

	// Seen devices, newest first, with router names.
	var devs []deviceView
	admin.want(200, "GET", "/api/v1/devices", nil, &devs)
	if len(devs) != 2 || devs[0].Addrs[0] != "192.168.1.20" || devs[0].Hostname != "kitchen-ipad" || devs[1].Queries != 2 || devs[1].Blocked != 1 {
		t.Fatalf("devices = %+v", devs)
	}

	// Name the TV; bad input is refused.
	admin.want(400, "POST", "/api/v1/devices", map[string]any{"name": "", "addrs": []string{"192.168.1.10"}}, nil)
	admin.want(400, "POST", "/api/v1/devices", map[string]any{"name": "TV", "addrs": []string{"not-an-ip"}}, nil)
	var tvDev struct{ ID string }
	admin.want(201, "POST", "/api/v1/devices", map[string]any{"name": "Living room TV", "addrs": []string{"192.168.1.10"}}, &tvDev)
	admin.want(400, "POST", "/api/v1/devices", map[string]any{"name": "Other", "addrs": []string{"192.168.1.10"}}, nil) // address taken
	admin.want(200, "GET", "/api/v1/devices", nil, &devs)
	if len(devs) != 2 || devs[1].Name != "Living room TV" || devs[1].ID != tvDev.ID || devs[1].Queries != 2 {
		t.Fatalf("after naming: %+v", devs)
	}

	// Queries by device id, by IP, by result, and paging.
	var qr struct {
		Queries     []querylog.Entry
		DeviceNames map[string]string `json:"device_names"`
	}
	admin.want(200, "GET", "/api/v1/queries?client="+tvDev.ID, nil, &qr)
	if len(qr.Queries) != 2 || qr.DeviceNames["192.168.1.10"] != "Living room TV" {
		t.Fatalf("by device: %+v", qr)
	}
	admin.want(200, "GET", "/api/v1/queries?client=192.168.1.20", nil, &qr)
	if len(qr.Queries) != 1 {
		t.Fatalf("by ip: %+v", qr)
	}
	admin.want(200, "GET", "/api/v1/queries?result=blocked", nil, &qr)
	if len(qr.Queries) != 1 || qr.Queries[0].Name != "ads.example.com" {
		t.Fatalf("blocked: %+v", qr)
	}
	admin.want(200, "GET", "/api/v1/queries?limit=1", nil, &qr)
	if len(qr.Queries) != 1 || qr.Queries[0].Name != "news.example.org" {
		t.Fatalf("page 1: %+v", qr)
	}
	admin.want(200, "GET", "/api/v1/queries?limit=5&before="+itoa(qr.Queries[0].ID), nil, &qr)
	if len(qr.Queries) != 2 {
		t.Fatalf("page 2: %+v", qr)
	}
	admin.want(400, "GET", "/api/v1/queries?client=nope", nil, nil)

	// Check a domain.
	var chk struct {
		Blocked bool
		Rule    string
		List    string
	}
	admin.want(200, "GET", "/api/v1/domains/check?name=ADS.example.com.", nil, &chk)
	if !chk.Blocked || chk.List != "Test list" || chk.Rule == "" {
		t.Fatalf("check = %+v", chk)
	}
	admin.want(200, "GET", "/api/v1/domains/check?name=fine.example.com", nil, &chk)
	if chk.Blocked {
		t.Fatalf("fine.example.com blocked")
	}
	admin.want(400, "GET", "/api/v1/domains/check?name=not%20a%20domain", nil, nil)

	// Router address for device names is validated.
	admin.want(400, "PATCH", "/api/v1/settings", map[string]any{"local_dns": "not an address"}, nil)
	admin.want(200, "PATCH", "/api/v1/settings", map[string]any{"local_dns": "192.168.1.1"}, nil)

	// Rename, then forget the device.
	admin.want(200, "PUT", "/api/v1/devices/"+tvDev.ID, map[string]any{"name": "TV", "addrs": []string{"192.168.1.10", "fd00::10"}}, nil)
	admin.want(404, "PUT", "/api/v1/devices/missing", map[string]any{"name": "x", "addrs": []string{"192.168.1.30"}}, nil)
	admin.want(204, "DELETE", "/api/v1/devices/"+tvDev.ID, nil, nil)
	devs = nil
	admin.want(200, "GET", "/api/v1/devices", nil, &devs)
	if len(devs) != 2 || devs[1].ID != "" {
		t.Fatalf("after delete: %+v", devs)
	}
}

func itoa(n uint64) string {
	b := []byte{}
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
		if n == 0 {
			return string(b)
		}
	}
}

func TestGroups(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	var tab, lap struct{ ID string }
	admin.want(201, "POST", "/api/v1/devices", map[string]any{"name": "Tablet", "addrs": []string{"192.168.1.20"}}, &tab)
	admin.want(201, "POST", "/api/v1/devices", map[string]any{"name": "Laptop", "addrs": []string{"192.168.1.30"}}, &lap)

	bedtime := map[string]any{"name": "Bedtime", "days": []int{0, 1, 2, 3, 4}, "start": "21:00", "end": "07:00", "block_all": true}
	admin.want(400, "POST", "/api/v1/groups", map[string]any{"name": ""}, nil)
	admin.want(400, "POST", "/api/v1/groups", map[string]any{"name": "Kids", "rules": []string{"not a rule!"}}, nil)
	admin.want(400, "POST", "/api/v1/groups", map[string]any{"name": "Kids", "schedules": []any{map[string]any{"name": "x", "days": []int{1}, "start": "25:00", "end": "07:00", "block_all": true}}}, nil)
	admin.want(400, "POST", "/api/v1/groups", map[string]any{"name": "Kids", "schedules": []any{map[string]any{"name": "x", "days": []int{}, "start": "21:00", "end": "07:00", "block_all": true}}}, nil)
	admin.want(400, "POST", "/api/v1/groups", map[string]any{"name": "Kids", "devices": []string{"nope"}}, nil)

	var kids struct{ ID string }
	admin.want(201, "POST", "/api/v1/groups", map[string]any{"name": "Kids", "rules": []string{"||games.example^"}, "schedules": []any{bedtime}, "devices": []string{tab.ID}}, &kids)
	admin.want(400, "POST", "/api/v1/groups", map[string]any{"name": "kids"}, nil) // duplicate name

	type gv struct {
		ID        string
		Name      string
		Devices   []string
		Schedules []struct{ Name string }
	}
	var list struct {
		Groups   []gv
		TimeZone string `json:"time_zone"`
	}
	admin.want(200, "GET", "/api/v1/groups", nil, &list)
	if len(list.Groups) != 1 || len(list.Groups[0].Devices) != 1 || list.Groups[0].Devices[0] != tab.ID || len(list.Groups[0].Schedules) != 1 || list.TimeZone == "" {
		t.Fatalf("groups = %+v", list)
	}

	// Renaming a device keeps its group; moving the laptop in via the device.
	admin.want(200, "PUT", "/api/v1/devices/"+tab.ID, map[string]any{"name": "Kid's tablet", "addrs": []string{"192.168.1.20"}}, nil)
	if g := e.api.Store.State().Devices[tab.ID].Group; g != kids.ID {
		t.Fatalf("rename lost group: %q", g)
	}
	admin.want(400, "PUT", "/api/v1/devices/"+lap.ID, map[string]any{"name": "Laptop", "addrs": []string{"192.168.1.30"}, "group": "missing"}, nil)
	admin.want(200, "PUT", "/api/v1/devices/"+lap.ID, map[string]any{"name": "Laptop", "addrs": []string{"192.168.1.30"}, "group": kids.ID}, nil)

	// Saving the group with a new device list moves devices out.
	admin.want(200, "PUT", "/api/v1/groups/"+kids.ID, map[string]any{"name": "Kids", "devices": []string{lap.ID}}, nil)
	st := e.api.Store.State()
	if st.Devices[tab.ID].Group != "" || st.Devices[lap.ID].Group != kids.ID || len(st.Groups[kids.ID].Schedules) != 0 {
		t.Fatalf("after save: tab=%q lap=%q", st.Devices[tab.ID].Group, st.Devices[lap.ID].Group)
	}

	// Deleting the group frees its devices.
	admin.want(204, "DELETE", "/api/v1/groups/"+kids.ID, nil, nil)
	if e.api.Store.State().Devices[lap.ID].Group != "" {
		t.Fatal("device still in deleted group")
	}
	admin.want(404, "DELETE", "/api/v1/groups/"+kids.ID, nil, nil)

	// Time zone setting is validated.
	admin.want(400, "PATCH", "/api/v1/settings", map[string]any{"time_zone": "Mars/Olympus"}, nil)
	admin.want(200, "PATCH", "/api/v1/settings", map[string]any{"time_zone": "Europe/London"}, nil)
	admin.want(200, "GET", "/api/v1/groups", nil, &list)
	if list.TimeZone != "Europe/London" {
		t.Fatalf("time zone = %q", list.TimeZone)
	}
}
