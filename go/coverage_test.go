package dns

import (
	"encoding/json"

	core "dappco.re/go"
)

// These tests exercise real behaviour for helpers and thin wrappers that the
// generated symbol-existence triplets leave at 0% coverage. They sit beside
// the existing house-convention triplets rather than replacing them.

func TestCoverage_IntActionValue_Good(t *core.T) {
	cases := []struct {
		name string
		raw  any
		want int
	}{
		{"int", int(53), 53},
		{"uint", uint(53), 53},
		{"uint8", uint8(53), 53},
		{"uint16", uint16(53), 53},
		{"uint32", uint32(53), 53},
		{"uint64", uint64(53), 53},
		{"int32", int32(53), 53},
		{"int64", int64(53), 53},
		{"float32-whole", float32(53), 53},
		{"json-number-int", json.Number("53"), 53},
		{"json-number-whole-float", json.Number("53.0"), 53},
		{"int64-negative", int64(-7), -7},
		{"json-number-negative-int", json.Number("-7"), -7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *core.T) {
			got, err := intActionValue(map[string]any{actionArgPort: tc.raw}, actionArgPort)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			if got != tc.want {
				t.Fatalf("%s: expected %d, got %d", tc.name, tc.want, got)
			}
		})
	}
}

func TestCoverage_IntActionValue_Bad(t *core.T) {
	if _, err := intActionValue(nil, actionArgPort); err == nil {
		t.Fatal("expected nil values map to error")
	}
	if _, err := intActionValue(map[string]any{}, actionArgPort); err == nil {
		t.Fatal("expected missing key to error")
	}
	if _, err := intActionValue(map[string]any{actionArgPort: "53"}, actionArgPort); err == nil {
		t.Fatal("expected string value to error")
	}
}

func TestCoverage_IntActionValue_Ugly(t *core.T) {
	uglyCases := []struct {
		name string
		raw  any
	}{
		{"negative-float", float64(-1)},
		{"fractional-float32", float32(53.5)},
		{"non-numeric-json-number", json.Number("not-a-number")},
		{"fractional-json-number", json.Number("53.5")},
	}
	for _, tc := range uglyCases {
		t.Run(tc.name, func(t *core.T) {
			if _, err := intActionValue(map[string]any{actionArgPort: tc.raw}, actionArgPort); err == nil {
				t.Fatalf("%s: expected rejection", tc.name)
			}
		})
	}
}

func TestCoverage_StringActionValueOptional_Good(t *core.T) {
	got, err := stringActionValueOptional(map[string]any{"bind": "  127.0.0.1  "}, "bind")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "127.0.0.1" {
		t.Fatalf("expected trimmed value, got %q", got)
	}
}

func TestCoverage_StringActionValueOptional_Bad(t *core.T) {
	if _, err := stringActionValueOptional(map[string]any{"bind": 53}, "bind"); err == nil {
		t.Fatal("expected non-string value to error")
	}
}

func TestCoverage_StringActionValueOptional_Ugly(t *core.T) {
	got, err := stringActionValueOptional(nil, "bind")
	if err != nil || got != "" {
		t.Fatalf("expected nil map to yield empty string with no error, got %q, %v", got, err)
	}
	got, err = stringActionValueOptional(map[string]any{}, "bind")
	if err != nil || got != "" {
		t.Fatalf("expected missing key to yield empty string with no error, got %q, %v", got, err)
	}
}

func TestCoverage_BetterWildcardMatch_Good(t *core.T) {
	if !betterWildcardMatch("*.charon.lthn", "") {
		t.Fatal("expected any candidate to beat an empty current match")
	}
	if !betterWildcardMatch("*.gateway.charon.lthn", "*.charon.lthn") {
		t.Fatal("expected the more specific (longer) suffix to win")
	}
}

func TestCoverage_BetterWildcardMatch_Bad(t *core.T) {
	if betterWildcardMatch("*.charon.lthn", "*.gateway.charon.lthn") {
		t.Fatal("expected the shorter suffix to lose")
	}
}

func TestCoverage_BetterWildcardMatch_Ugly(t *core.T) {
	// Equal-length suffixes break the tie lexicographically.
	if !betterWildcardMatch("*.a.charon.lthn", "*.b.charon.lthn") {
		t.Fatal("expected lexicographically smaller candidate to win on equal length")
	}
	if betterWildcardMatch("*.b.charon.lthn", "*.a.charon.lthn") {
		t.Fatal("expected lexicographically larger candidate to lose on equal length")
	}
}

func TestCoverage_HSDRPCError_Error_Good(t *core.T) {
	err := &HSDRPCError{Code: -32601, Message: "method not found"}
	if got := err.Error(); got != "hsd rpc error (-32601): method not found" {
		t.Fatalf("unexpected error string: %q", got)
	}
}

func TestCoverage_HSDRPCError_Error_Ugly(t *core.T) {
	var err *HSDRPCError
	if got := err.Error(); got != "" {
		t.Fatalf("expected empty string from nil receiver, got %q", got)
	}
}
