package core

import (
	"encoding/hex"
	"testing"
)

func TestGenerateNetworkID(t *testing.T) {
	for i := 0; i < 20; i++ {
		netID := GenerateNetworkID()
		if len(netID) != 16 {
			t.Fatalf("expected 16 characters network ID, got %s (len: %d)", netID, len(netID))
		}
		if _, err := hex.DecodeString(netID); err != nil {
			t.Fatalf("network ID %s is not valid hex: %v", netID, err)
		}
	}
}

func TestStringListValuerScanner(t *testing.T) {
	list := StringList{"tag:web", "env:prod"}

	// 1. Value()
	val, err := list.Value()
	if err != nil {
		t.Fatalf("Value() failed: %v", err)
	}
	jsonStr, ok := val.([]byte)
	if !ok {
		t.Fatalf("expected []byte from Value(), got %T", val)
	}
	if string(jsonStr) != `["tag:web","env:prod"]` {
		t.Fatalf("unexpected JSON: %s", string(jsonStr))
	}

	// 2. Scan() from bytes
	var scanned StringList
	if err := scanned.Scan(jsonStr); err != nil {
		t.Fatalf("Scan(bytes) failed: %v", err)
	}
	if len(scanned) != 2 || scanned[0] != "tag:web" || scanned[1] != "env:prod" {
		t.Fatalf("Scan mismatch: %+v", scanned)
	}

	// 3. Scan() from string
	var scannedStr StringList
	if err := scannedStr.Scan(`["tag:db"]`); err != nil {
		t.Fatalf("Scan(string) failed: %v", err)
	}
	if len(scannedStr) != 1 || scannedStr[0] != "tag:db" {
		t.Fatalf("Scan(string) mismatch: %+v", scannedStr)
	}

	// 4. Scan(nil)
	var scannedNil StringList
	if err := scannedNil.Scan(nil); err != nil {
		t.Fatalf("Scan(nil) failed: %v", err)
	}
	if len(scannedNil) != 0 {
		t.Fatalf("expected empty list on Scan(nil)")
	}

	// 5. Value() on nil
	var nilList StringList
	valNil, err := nilList.Value()
	if err != nil || valNil != "[]" {
		t.Fatalf("expected '[]' on nil Value(), got %v", valNil)
	}
}
