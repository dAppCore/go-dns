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

func TestServiceHealthUsesDeterministicTreeRootAndUpdatesOnMutations(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A:  []string{"10.10.10.10", "10.0.0.1"},
				NS: []string{"ns1.example.com"},
			},
		},
	})

	health := service.Health()
	root, ok := health["tree_root"].(string)
	if !ok || root == "" || root == "stubbed" {
		t.Fatalf("expected computed tree root, got %#v", health["tree_root"])
	}

	healthRepeating := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				NS: []string{"ns1.example.com"},
				A:  []string{"10.0.0.1", "10.10.10.10"},
			},
		},
	}).Health()["tree_root"].(string)

	if healthRepeating != root {
		t.Fatalf("expected deterministic tree root, got %s and %s", healthRepeating, root)
	}

	service.SetRecord("gateway.charon.lthn", NameRecords{
		A: []string{"10.10.10.11"},
	})
	updatedRoot, ok := service.Health()["tree_root"].(string)
	if !ok || updatedRoot == root {
		t.Fatalf("expected updated tree root after SetRecord, got %s", updatedRoot)
	}

	service.RemoveRecord("gateway.charon.lthn")
	removedRoot, ok := service.Health()["tree_root"].(string)
	if !ok || removedRoot == updatedRoot {
		t.Fatalf("expected updated tree root after RemoveRecord, got %s", removedRoot)
	}
}

func TestServiceDiscoverReplacesRecordsFromDiscoverer(t *testing.T) {
	records := []map[string]NameRecords{
		{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
			"*.lthn": {
				A: []string{"10.0.0.1"},
			},
		},
	}
	index := 0
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"legacy.charon.lthn": {
				A: []string{"10.11.11.11"},
			},
		},
		Discoverer: func() (map[string]NameRecords, error) {
			next := records[index%len(records)]
			index++
			return next, nil
		},
	})

	if _, ok := service.Resolve("legacy.charon.lthn"); !ok {
		t.Fatal("expected baseline record before discovery")
	}

	if err := service.Discover(); err != nil {
		t.Fatalf("unexpected discover error: %v", err)
	}

	result, ok := service.Resolve("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected discovered exact record")
	}
	if len(result.A) != 1 || result.A[0] != "10.10.10.10" {
		t.Fatalf("unexpected discovered resolve result: %#v", result.A)
	}
	if _, ok := service.Resolve("legacy.unknown"); ok {
		t.Fatal("expected replaced cache not to resolve via old record")
	}
}

func TestServiceDiscoverReturnsNilWithoutDiscoverer(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	if err := service.Discover(); err != nil {
		t.Fatalf("expected no error when discoverer is missing: %v", err)
	}
}
