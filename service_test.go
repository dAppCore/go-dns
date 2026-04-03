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

