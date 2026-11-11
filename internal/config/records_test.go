package config

import "testing"

func TestFollowNode(t *testing.T) {
	recs := []Record{
		{Name: "dns1.home", Value: "192.168.1.140", Node: "n1"},
		{Name: "other.home", Value: "192.168.1.140"},              // not made for the node
		{Name: "dns1-old.home", Value: "192.168.1.9", Node: "n1"}, // pointed elsewhere by hand
		{Name: "dns2.home", Value: "192.168.1.249", Node: "n2"},
	}
	if !FollowNode(recs, "n1", "192.168.1.140", "192.168.1.150") {
		t.Fatal("nothing changed")
	}
	if recs[0].Value != "192.168.1.150" || recs[1].Value != "192.168.1.140" || recs[2].Value != "192.168.1.9" || recs[3].Value != "192.168.1.249" {
		t.Fatalf("got %+v", recs)
	}
	if FollowNode(recs, "n2", "192.168.1.249", "192.168.1.249") {
		t.Fatal("changed with the same address")
	}
	n, err := NormalizeRecords([]Record{{Name: "DNS1.home", Value: "192.168.1.1", Node: " n1 "}})
	if err != nil || n[0].Node != "n1" {
		t.Fatalf("normalize: %+v %v", n, err)
	}
}
