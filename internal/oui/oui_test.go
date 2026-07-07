package oui

import "testing"

func TestLookupKnownVendor(t *testing.T) {
	// 00:00:00 is XEROX CORPORATION in the IEEE registry.
	if got := Lookup("00:00:00:12:34:56"); got != "XEROX CORPORATION" {
		t.Errorf("Lookup = %q, want XEROX CORPORATION", got)
	}
}

func TestLookupIgnoresSeparators(t *testing.T) {
	withColons := Lookup("00:00:00:aa:bb:cc")
	withDashes := Lookup("00-00-00-AA-BB-CC")
	bare := Lookup("000000aabbcc")
	if withColons != withDashes || withColons != bare {
		t.Errorf("separator handling differs: %q / %q / %q", withColons, withDashes, bare)
	}
}

func TestLookupLocallyAdministered(t *testing.T) {
	// 0x02 in the first octet sets the U/L bit (randomized MAC).
	if got := Lookup("02:11:22:33:44:55"); got != "(locally administered)" {
		t.Errorf("Lookup = %q, want (locally administered)", got)
	}
}

func TestLookupUnknownAndShort(t *testing.T) {
	if got := Lookup("fc:fc:fc:00:00:00"); got != "" {
		t.Errorf("unknown prefix Lookup = %q, want empty", got)
	}
	if got := Lookup("00:00"); got != "" {
		t.Errorf("short input Lookup = %q, want empty", got)
	}
}
