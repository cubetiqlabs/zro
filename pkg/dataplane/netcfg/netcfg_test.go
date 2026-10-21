package netcfg

import "testing"

func TestValidateInterfaceName(t *testing.T) {
	valid := []string{"zro0", "zro-gw", "wg0", "eth0.100", "a"}
	for _, name := range valid {
		if err := ValidateInterfaceName(name); err != nil {
			t.Fatalf("ValidateInterfaceName(%q) returned %v", name, err)
		}
	}

	invalid := []string{"", "has space", "semi;colon", "slash/name", "this-name-is-way-too-long"}
	for _, name := range invalid {
		if err := ValidateInterfaceName(name); err == nil {
			t.Fatalf("ValidateInterfaceName(%q) unexpectedly succeeded", name)
		}
	}
}

func TestConfigureOverlayRejectsBadInput(t *testing.T) {
	if err := ConfigureOverlay("bad name", "100.64.0.1", "", 1420); err == nil {
		t.Fatal("expected invalid interface name to fail")
	}
	if err := ConfigureOverlay("zro0", "not-an-ip", "", 1420); err == nil {
		t.Fatal("expected invalid IPv4 address to fail")
	}
	if err := AddHostRoute("zro0", "999.1.1.1"); err == nil {
		t.Fatal("expected invalid route address to fail")
	}
}
