package backup

import "testing"

func TestBackupNames(t *testing.T) {
	for name, want := range map[string]bool{
		"dnserv-node-20261110-120000" + Ext:  true,
		"dnserve-node-20261110-120000" + Ext: true, // made before the rename
		"other-20261110-120000" + Ext:        false,
		"dnserv-node-20261110-120000.txt":    false,
	} {
		if got := isBackupName(name); got != want {
			t.Errorf("isBackupName(%q) = %v, want %v", name, got, want)
		}
	}
}
