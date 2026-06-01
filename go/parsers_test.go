package dns

import (
	"encoding/json"

	core "dappco.re/go"
	dnsprotocol "github.com/miekg/dns"
)

// Parser-focused tests covering malformed JSON, missing fields and bad
// resource-record encodings — the error edges the symbol-existence triplets
// do not reach.

func TestParsers_ParseHSDBlockchainInfo_Good(t *core.T) {
	info, err := parseHSDBlockchainInfo(json.RawMessage(`{"tree_root":"root-snake"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.TreeRoot != "root-snake" {
		t.Fatalf("expected snake_case tree_root, got %q", info.TreeRoot)
	}

	info, err = parseHSDBlockchainInfo(json.RawMessage(`{"treeRoot":"root-camel"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.TreeRoot != "root-camel" {
		t.Fatalf("expected camelCase treeRoot fallback, got %q", info.TreeRoot)
	}
}

func TestParsers_ParseHSDBlockchainInfo_Bad(t *core.T) {
	if _, err := parseHSDBlockchainInfo(json.RawMessage(`not-json`)); err == nil {
		t.Fatal("expected malformed JSON to error")
	}
	if _, err := parseHSDBlockchainInfo(json.RawMessage(`{"tree_root":123}`)); err == nil {
		t.Fatal("expected non-string tree_root to error")
	}
}

func TestParsers_ParseHSDBlockchainInfo_Ugly(t *core.T) {
	if _, err := parseHSDBlockchainInfo(json.RawMessage(`{"height":42}`)); err == nil {
		t.Fatal("expected a payload with no tree root to error")
	}
}

func TestParsers_ParseDNSSECResourceRecord_Good(t *core.T) {
	rr, err := parseDNSSECResourceRecord("charon.lthn.", dnsprotocol.TypeDS, "60485 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	header := rr.Header()
	if header.Rrtype != dnsprotocol.TypeDS {
		t.Fatalf("expected DS record, got %d", header.Rrtype)
	}
	if header.Name != "charon.lthn." {
		t.Fatalf("expected question name on header, got %q", header.Name)
	}
	if header.Ttl != defaultDNSTTL {
		t.Fatalf("expected default TTL, got %d", header.Ttl)
	}
}

func TestParsers_ParseDNSSECResourceRecord_Bad(t *core.T) {
	if _, err := parseDNSSECResourceRecord("charon.lthn.", dnsprotocol.TypeDS, "   "); err == nil {
		t.Fatal("expected an empty value to error")
	}
}

func TestParsers_ParseDNSSECResourceRecord_Ugly(t *core.T) {
	if _, err := parseDNSSECResourceRecord("charon.lthn.", dnsprotocol.TypeDS, "totally invalid record body"); err == nil {
		t.Fatal("expected an unparseable record body to error")
	}
}

func TestParsers_ParseMainchainAliases_Good(t *core.T) {
	bare, err := parseMainchainAliases(json.RawMessage(`["Gateway.Charon.lthn.","node.charon.lthn"]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bare) != 2 || bare[0] != "gateway.charon.lthn" {
		t.Fatalf("expected normalised alias list, got %#v", bare)
	}

	wrapped, err := parseMainchainAliases(json.RawMessage(`{"aliases":["gateway.charon.lthn"]}`))
	if err != nil {
		t.Fatalf("unexpected error on wrapped aliases: %v", err)
	}
	if len(wrapped) != 1 || wrapped[0] != "gateway.charon.lthn" {
		t.Fatalf("expected wrapped alias list, got %#v", wrapped)
	}

	records, err := parseMainchainAliases(json.RawMessage(`[{"hns":"gateway.charon.lthn"},{"comment":"alias hns=node.charon.lthn"}]`))
	if err != nil {
		t.Fatalf("unexpected error on record list: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected two aliases from records, got %#v", records)
	}
}

func TestParsers_ParseMainchainAliases_Bad(t *core.T) {
	if _, err := parseMainchainAliases(json.RawMessage(`42`)); err == nil {
		t.Fatal("expected a bare number to error")
	}
}

func TestParsers_ParseMainchainAliases_Ugly(t *core.T) {
	// A record list where one record is neither a string nor an object.
	if _, err := parseMainchainAliases(json.RawMessage(`[12345]`)); err == nil {
		t.Fatal("expected a non-string non-object record to error")
	}
}

func TestParsers_ParseActionAliasRecord_Good(t *core.T) {
	cases := []struct {
		name   string
		record map[string]any
		want   string
	}{
		{"hns", map[string]any{"hns": "Gateway.Charon.lthn."}, "gateway.charon.lthn"},
		{"comment", map[string]any{"comment": "alias hns=node.charon.lthn"}, "node.charon.lthn"},
		{"alias", map[string]any{"alias": "edge.charon.lthn"}, "edge.charon.lthn"},
		{"name", map[string]any{"name": "ns.charon.lthn"}, "ns.charon.lthn"},
		{"none", map[string]any{"height": 1}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *core.T) {
			got, err := parseActionAliasRecord(tc.record)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			if got != tc.want {
				t.Fatalf("%s: expected %q, got %q", tc.name, tc.want, got)
			}
		})
	}
}

func TestParsers_ParseActionAliasRecord_Bad(t *core.T) {
	badCases := []map[string]any{
		{"hns": 1},
		{"comment": 2},
		{"alias": 3},
		{"name": 4},
	}
	for _, record := range badCases {
		if _, err := parseActionAliasRecord(record); err == nil {
			t.Fatalf("expected non-string value to error for %#v", record)
		}
	}
}

func TestParsers_ExtractAliasFromComment_Good(t *core.T) {
	cases := []struct {
		name    string
		comment string
		want    string
	}{
		{"equals-inline", "gateway alias HNS=gateway.charon.lthn;", "gateway.charon.lthn"},
		{"spaced-equals", "gateway alias hns = node.charon.lthn", "node.charon.lthn"},
		{"colon-marker", "see hns: edge.charon.lthn for details", "edge.charon.lthn"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *core.T) {
			if got := extractAliasFromComment(tc.comment); got != tc.want {
				t.Fatalf("%s: expected %q, got %q", tc.name, tc.want, got)
			}
		})
	}
}

func TestParsers_ExtractAliasFromComment_Ugly(t *core.T) {
	if got := extractAliasFromComment("no alias marker here"); got != "" {
		t.Fatalf("expected empty string for a comment without an hns marker, got %q", got)
	}
	if got := extractAliasFromComment(""); got != "" {
		t.Fatalf("expected empty string for an empty comment, got %q", got)
	}
}

func TestParsers_ParseHSDNameResource_Good(t *core.T) {
	// records-wrapper form
	wrapped, err := parseHSDNameResource(json.RawMessage(`{"records":{"a":["10.10.10.10"],"txt":"v=lthn1"}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(wrapped.A) != 1 || wrapped.A[0] != "10.10.10.10" {
		t.Fatalf("unexpected A from records wrapper: %#v", wrapped.A)
	}
	if len(wrapped.TXT) != 1 || wrapped.TXT[0] != "v=lthn1" {
		t.Fatalf("unexpected single-string TXT: %#v", wrapped.TXT)
	}

	// top-level fields form (case-insensitive keys)
	topLevel, err := parseHSDNameResource(json.RawMessage(`{"A":["10.0.0.1"],"AAAA":["fe80::1"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(topLevel.A) != 1 || len(topLevel.AAAA) != 1 {
		t.Fatalf("unexpected top-level parse: %#v", topLevel)
	}
}

func TestParsers_ParseHSDNameResource_Bad(t *core.T) {
	if _, err := parseHSDNameResource(json.RawMessage(`not-json`)); err == nil {
		t.Fatal("expected malformed JSON to error")
	}
	if _, err := parseHSDNameResource(json.RawMessage(`{"records":{"a":12345}}`)); err == nil {
		t.Fatal("expected an unparseable record value to error")
	}
}

func TestParsers_ParseHSDNameResource_Ugly(t *core.T) {
	if _, err := parseHSDNameResource(json.RawMessage(`{"height":42}`)); err == nil {
		t.Fatal("expected a payload with no record fields to error")
	}
}

func TestParsers_ParseHSDRecordValue_Good(t *core.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"array", `["a","b"]`, []string{"a", "b"}},
		{"single-string", `"only"`, []string{"only"}},
		{"empty-string", `""`, nil},
		{"null", `null`, nil},
		{"whitespace", "   ", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *core.T) {
			got, err := parseHSDRecordValue(json.RawMessage(tc.raw))
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("%s: expected %#v, got %#v", tc.name, tc.want, got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("%s: index %d expected %q, got %q", tc.name, i, tc.want[i], got[i])
				}
			}
		})
	}
}

func TestParsers_ParseHSDRecordValue_Bad(t *core.T) {
	if _, err := parseHSDRecordValue(json.RawMessage(`12345`)); err == nil {
		t.Fatal("expected a numeric record value to error")
	}
}

func TestParsers_HasHSDNameResourceField_Good(t *core.T) {
	fields := map[string]json.RawMessage{"AAAA": json.RawMessage(`["fe80::1"]`)}
	if !hasHSDNameResourceField(fields) {
		t.Fatal("expected case-insensitive AAAA field to be detected")
	}
}

func TestParsers_HasHSDNameResourceField_Ugly(t *core.T) {
	if hasHSDNameResourceField(nil) {
		t.Fatal("expected nil fields to report no record field")
	}
	if hasHSDNameResourceField(map[string]json.RawMessage{"height": json.RawMessage(`1`)}) {
		t.Fatal("expected a non-record field map to report no record field")
	}
}
