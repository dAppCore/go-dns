package dns

import "testing"

func TestServiceResolveUsesExactNameBeforeWildcard(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"*.charon.lthn": {
				A: []string{"10.69.69.165"},
			},
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	result, ok := service.Resolve("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected exact record to resolve")
	}
	if len(result.A) != 1 || result.A[0] != "10.10.10.10" {
		t.Fatalf("unexpected resolve result: %#v", result.A)
	}
}

func TestServiceResolveUsesMostSpecificWildcard(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"*.lthn": {
				A: []string{"10.0.0.1"},
			},
			"*.charon.lthn": {
				A: []string{"10.0.0.2"},
			},
		},
	})

	result, ok := service.Resolve("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected wildcard record to resolve")
	}
	if len(result.A) != 1 || result.A[0] != "10.0.0.2" {
		t.Fatalf("unexpected wildcard match: %#v", result.A)
	}
}

func TestServiceResolveTXTUsesWildcard(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"*.gateway.charon.lthn": {
				TXT: []string{"v=lthn1 type=gateway"},
			},
		},
	})

	result, ok := service.ResolveTXT("node1.gateway.charon.lthn.")
	if !ok {
		t.Fatal("expected wildcard TXT record")
	}
	if len(result) != 1 || result[0] != "v=lthn1 type=gateway" {
		t.Fatalf("unexpected TXT record: %#v", result)
	}
}

func TestServiceResolveAddressReturnsMergedRecords(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A:    []string{"10.10.10.10", "10.10.10.10"},
				AAAA: []string{"2600:1f1c:7f0:4f01:0000:0000:0000:0001"},
			},
		},
	})

	result, ok := service.ResolveAddress("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected address record to resolve")
	}
	if len(result.Addresses) != 2 {
		t.Fatalf("expected merged unique addresses, got %#v", result.Addresses)
	}
	if result.Addresses[0] != "10.10.10.10" || result.Addresses[1] != "2600:1f1c:7f0:4f01:0000:0000:0000:0001" {
		t.Fatalf("unexpected address order or value: %#v", result.Addresses)
	}
}

func TestServiceResolveAddressFallsBackToFalseWhenMissing(t *testing.T) {
	service := NewService(ServiceOptions{})

	if _, ok := service.ResolveAddress("missing.charon.lthn"); ok {
		t.Fatal("expected missing record to return false")
	}
}

func TestServiceResolveReverseUsesARecords(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	result, ok := service.ResolveReverse("10.10.10.10")
	if !ok {
		t.Fatal("expected reverse record to resolve")
	}
	if len(result) != 1 || result[0] != "gateway.charon.lthn" {
		t.Fatalf("unexpected reverse result: %#v", result)
	}
}

func TestServiceResolveReverseFallsBackToFalseWhenUnknown(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	if _, ok := service.ResolveReverse("10.10.10.11"); ok {
		t.Fatal("expected no reverse match for unknown IP")
	}
}

func TestServiceResolveReverseUsesSetAndRemove(t *testing.T) {
	service := NewService(ServiceOptions{})
	service.SetRecord("gateway.charon.lthn", NameRecords{
		AAAA: []string{"2600:1f1c:7f0:4f01:0000:0000:0000:0001"},
	})

	result, ok := service.ResolveReverse("2600:1f1c:7f0:4f01::1")
	if !ok || len(result) != 1 || result[0] != "gateway.charon.lthn" {
		t.Fatalf("expected newly set reverse record, got %#v", result)
	}

	service.RemoveRecord("gateway.charon.lthn")
	if _, ok := service.ResolveReverse("2600:1f1c:7f0:4f01::1"); ok {
		t.Fatal("expected removed reverse record to disappear")
	}
}
