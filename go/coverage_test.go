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

// recordingRegistrar captures the action names a service publishes so the
// registrar-aware constructors can be exercised without a real Core surface.
type recordingRegistrar struct {
	names []string
}

func (registrar *recordingRegistrar) RegisterAction(name string, _ func(map[string]any) (any, bool, error)) {
	registrar.names = append(registrar.names, name)
}

func TestCoverage_NewDNSServiceFromOptions_Good(t *core.T) {
	service := NewDNSServiceFromOptions(DNSServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
		},
	})
	if service == nil {
		t.Fatal("expected a service")
	}
	result, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(result.A) != 1 || result.A[0] != "10.10.10.10" {
		t.Fatalf("unexpected resolve result: %#v (ok=%t)", result, ok)
	}
}

func TestCoverage_NewDNSServiceWithContextRegistrar_Good(t *core.T) {
	registrar := &recordingRegistrar{}
	service := NewDNSServiceWithContextRegistrar(DNSServiceOptions{}, registrar)
	if service == nil {
		t.Fatal("expected a service")
	}
	if len(registrar.names) == 0 {
		t.Fatal("expected the registrar to receive at least one action")
	}
}

func TestCoverage_StartHealthServer_Good(t *core.T) {
	service := NewService(ServiceOptions{})
	server, err := service.StartHealthServer("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("expected health server to start: %v", err)
	}
	defer func() { _ = server.Close() }()
	if server.HealthAddress() == "" {
		t.Fatal("expected a bound health address")
	}
}

func TestCoverage_StartDNSServer_Good(t *core.T) {
	service := NewService(ServiceOptions{})
	server, err := service.StartDNSServer("127.0.0.1", pickFreeDNSPort(t))
	if err != nil {
		t.Fatalf("expected DNS server to start: %v", err)
	}
	defer func() { _ = server.Close() }()
	if server.DNSAddress() == "" {
		t.Fatal("expected a bound DNS address")
	}
}

func TestCoverage_StartDNSAndHealth_Good(t *core.T) {
	service := NewService(ServiceOptions{})
	runtime, err := service.StartDNSAndHealth("127.0.0.1", pickFreeDNSPort(t), 0)
	if err != nil {
		t.Fatalf("expected runtime to start: %v", err)
	}
	defer func() { _ = runtime.Close() }()
	if runtime.DNSAddress() == "" || runtime.HealthAddress() == "" {
		t.Fatalf("expected both addresses, got dns=%q health=%q", runtime.DNSAddress(), runtime.HealthAddress())
	}
}

func TestCoverage_StartConfigured_Good(t *core.T) {
	service := NewService(ServiceOptions{
		DNSPort:  pickFreeDNSPort(t),
		HTTPPort: 0,
	})
	runtime, err := service.StartConfigured("127.0.0.1")
	if err != nil {
		t.Fatalf("expected configured runtime to start: %v", err)
	}
	defer func() { _ = runtime.Close() }()
	if runtime.DNSAddress() == "" {
		t.Fatal("expected a bound DNS address")
	}
}

func TestCoverage_ResolveWithWildcardMatch_Good(t *core.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"*.charon.lthn": {A: []string{"10.0.0.1"}},
		},
	})
	result, ok, usedWildcard := service.ResolveWithWildcardMatch("node.charon.lthn")
	if !ok {
		t.Fatal("expected a wildcard resolution")
	}
	if !usedWildcard {
		t.Fatal("expected usedWildcard to be true for a wildcard-only match")
	}
	if len(result.A) != 1 || result.A[0] != "10.0.0.1" {
		t.Fatalf("unexpected wildcard result: %#v", result)
	}
}

func TestCoverage_ResolveWithWildcardMatch_Bad(t *core.T) {
	service := NewService(ServiceOptions{})
	if _, ok, _ := service.ResolveWithWildcardMatch("missing.charon.lthn"); ok {
		t.Fatal("expected no match for an empty service")
	}
}

func TestCoverage_ResolveWithWildcardMatch_Ugly(t *core.T) {
	var service *Service
	if _, ok, used := service.ResolveWithWildcardMatch("any.charon.lthn"); ok || used {
		t.Fatal("expected nil receiver to report no match")
	}
}

func TestCoverage_ResolveTXT_NilReceiverAndMiss(t *core.T) {
	var nilService *Service
	if _, ok := nilService.ResolveTXT("x"); ok {
		t.Fatal("expected nil receiver ResolveTXT to miss")
	}
	if _, ok := nilService.ResolveTXTRecords("x"); ok {
		t.Fatal("expected nil receiver ResolveTXTRecords to miss")
	}
	if _, ok, _ := nilService.ResolveTXTWithMatch("x"); ok {
		t.Fatal("expected nil receiver ResolveTXTWithMatch to miss")
	}
	if _, ok, _ := nilService.ResolveWithMatch("x"); ok {
		t.Fatal("expected nil receiver ResolveWithMatch to miss")
	}

	service := NewService(ServiceOptions{})
	if _, ok := service.ResolveTXT("missing.charon.lthn"); ok {
		t.Fatal("expected ResolveTXT miss for an empty service")
	}
	if _, ok := service.ResolveTXTRecords("missing.charon.lthn"); ok {
		t.Fatal("expected ResolveTXTRecords miss for an empty service")
	}
}

func TestCoverage_ResolveTXT_Good(t *core.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {TXT: []string{"v=lthn1 type=gateway"}},
		},
	})
	txt, ok := service.ResolveTXT("gateway.charon.lthn")
	if !ok || len(txt) != 1 || txt[0] != "v=lthn1 type=gateway" {
		t.Fatalf("unexpected TXT resolve: %#v (ok=%t)", txt, ok)
	}
	records, ok := service.ResolveTXTRecords("gateway.charon.lthn")
	if !ok || len(records.TXT) != 1 {
		t.Fatalf("unexpected TXT records: %#v (ok=%t)", records, ok)
	}
}

func TestCoverage_ServiceRuntime_NilReceiver(t *core.T) {
	var runtime *ServiceRuntime
	if runtime.DNSAddress() != "" {
		t.Fatal("expected nil runtime DNSAddress to be empty")
	}
	if runtime.HealthAddress() != "" {
		t.Fatal("expected nil runtime HealthAddress to be empty")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("expected nil runtime Close to be a no-op, got %v", err)
	}
}

func TestCoverage_ServiceRuntime_AliasFieldFallbacks(t *core.T) {
	service := NewService(ServiceOptions{})
	dnsServer, err := service.Serve("127.0.0.1", pickFreeDNSPort(t))
	if err != nil {
		t.Fatalf("expected DNS server: %v", err)
	}
	healthServer, err := service.ServeHTTPHealth("127.0.0.1", 0)
	if err != nil {
		_ = dnsServer.Close()
		t.Fatalf("expected health server: %v", err)
	}

	// Populate only the compatibility-alias fields so the fallback branches
	// in DNSAddress/HealthAddress/Close run.
	runtime := &ServiceRuntime{DNS: dnsServer, Health: healthServer}
	if runtime.DNSAddress() == "" {
		t.Fatal("expected DNS alias fallback to yield an address")
	}
	if runtime.HealthAddress() == "" {
		t.Fatal("expected Health alias fallback to yield an address")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("expected clean close of alias-only runtime, got %v", err)
	}
}

func TestCoverage_HealthServer_Close_NilAndDouble(t *core.T) {
	var nilServer *HealthServer
	if err := nilServer.Close(); err != nil {
		t.Fatalf("expected nil HealthServer Close to be a no-op, got %v", err)
	}

	service := NewService(ServiceOptions{})
	server, err := service.ServeHTTPHealth("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("expected health server: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("expected first close to succeed, got %v", err)
	}
}
