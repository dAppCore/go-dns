package dns

import (
	"context"

	core "dappco.re/go"
)

// Coverage for the action dispatch edges and the port-resolver nil-receiver
// guards that the symbol-existence triplets do not run.

func TestActionCoverage_HandleActionContext_Good(t *core.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
		},
	})
	// A nil context must be replaced with context.Background internally.
	payload, ok, err := service.HandleActionContext(nil, ActionResolveAll, map[string]any{
		actionArgName: "gateway.charon.lthn",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected the resolve-all action to find a record")
	}
	if payload == nil {
		t.Fatal("expected a payload from the resolve-all action")
	}
}

func TestActionCoverage_HandleActionContext_Bad(t *core.T) {
	service := NewService(ServiceOptions{})
	if _, _, err := service.HandleActionContext(context.Background(), "dns.does-not-exist", nil); err == nil {
		t.Fatal("expected an unknown action name to error")
	}
}

func TestActionCoverage_HandleActionContext_Ugly(t *core.T) {
	service := NewService(ServiceOptions{})
	// Missing required name argument should surface the helper error.
	if _, _, err := service.HandleActionContext(context.Background(), ActionResolve, map[string]any{}); err == nil {
		t.Fatal("expected a missing name argument to error")
	}
}

func TestActionCoverage_IntActionValueOptionalFromKeys_Good(t *core.T) {
	value, provided, err := intActionValueOptionalFromKeys(map[string]any{
		actionArgHealthPort: 5554,
	}, actionArgPort, actionArgHealthPort)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !provided || value != 5554 {
		t.Fatalf("expected the health_port fallback key to resolve to 5554, got %d (provided=%t)", value, provided)
	}
}

func TestActionCoverage_IntActionValueOptionalFromKeys_Bad(t *core.T) {
	if _, _, err := intActionValueOptionalFromKeys(map[string]any{
		actionArgPort: "not-an-int",
	}, actionArgPort); err == nil {
		t.Fatal("expected a non-integer value to error")
	}
}

func TestActionCoverage_IntActionValueOptionalFromKeys_Ugly(t *core.T) {
	value, provided, err := intActionValueOptionalFromKeys(map[string]any{}, actionArgPort, actionArgHealthPort)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provided || value != 0 {
		t.Fatalf("expected no key present to yield zero and not-provided, got %d (provided=%t)", value, provided)
	}
}

func TestActionCoverage_PortResolvers_NilReceiver(t *core.T) {
	var service *Service
	if got := service.DNSListenPort(); got != DefaultDNSPort {
		t.Fatalf("expected nil DNSListenPort to default to %d, got %d", DefaultDNSPort, got)
	}
	if got := service.DNSPort(); got != DefaultDNSPort {
		t.Fatalf("expected nil DNSPort to default to %d, got %d", DefaultDNSPort, got)
	}
	if got := service.ResolveDNSPort(); got != DefaultDNSPort {
		t.Fatalf("expected nil ResolveDNSPort to default to %d, got %d", DefaultDNSPort, got)
	}
	if got := service.ResolveHealthPort(); got != DefaultHTTPPort {
		t.Fatalf("expected nil ResolveHealthPort to default to %d, got %d", DefaultHTTPPort, got)
	}
	if got := service.ResolveHTTPPort(); got != DefaultHTTPPort {
		t.Fatalf("expected nil ResolveHTTPPort to default to %d, got %d", DefaultHTTPPort, got)
	}
}

func TestActionCoverage_PortResolvers_ConfiguredValues(t *core.T) {
	service := NewService(ServiceOptions{DNSPort: 1053, HTTPPort: 8080})
	if got := service.ResolveDNSPort(); got != 1053 {
		t.Fatalf("expected configured DNS port 1053, got %d", got)
	}
	if got := service.ResolveHealthPort(); got != 8080 {
		t.Fatalf("expected configured health port 8080, got %d", got)
	}
}
