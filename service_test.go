package dns

import (
	"errors"
	"strings"
	"testing"
	"time"

	dnsprotocol "github.com/miekg/dns"
)

func exchangeWithRetry(t *testing.T, client dnsprotocol.Client, request *dnsprotocol.Msg, address string) *dnsprotocol.Msg {
	t.Helper()

	for attempt := 0; attempt < 80; attempt++ {
		response, _, err := client.Exchange(request, address)
		if err == nil {
			return response
		}
		if !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("dns query failed: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("dns query failed after retrying due to startup timing")
	return nil
}

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

func TestServiceDiscoverFallsBackWhenPrimaryDiscovererFails(t *testing.T) {
	primaryCalled := false
	fallbackCalled := false

	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"legacy.charon.lthn": {
				A: []string{"10.11.11.11"},
			},
		},
		Discoverer: func() (map[string]NameRecords, error) {
			primaryCalled = true
			return nil, errors.New("chain service unavailable")
		},
		FallbackDiscoverer: func() (map[string]NameRecords, error) {
			fallbackCalled = true
			return map[string]NameRecords{
				"gateway.charon.lthn": {
					A: []string{"10.10.10.10"},
				},
			}, nil
		},
	})

	if err := service.Discover(); err != nil {
		t.Fatalf("expected fallback discovery to succeed: %v", err)
	}
	if !primaryCalled {
		t.Fatal("expected primary discoverer to be attempted")
	}
	if !fallbackCalled {
		t.Fatal("expected fallback discoverer to run after primary failure")
	}

	result, ok := service.Resolve("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected fallback record to resolve")
	}
	if len(result.A) != 1 || result.A[0] != "10.10.10.10" {
		t.Fatalf("unexpected fallback resolve result: %#v", result.A)
	}
	if _, ok := service.Resolve("legacy.charon.lthn"); ok {
		t.Fatal("expected legacy record to be replaced by fallback discovery")
	}
}

func TestServiceDiscoverUsesFallbackOnlyWhenPrimaryMissing(t *testing.T) {
	fallbackCalled := false

	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"legacy.charon.lthn": {
				A: []string{"10.11.11.11"},
			},
		},
		FallbackDiscoverer: func() (map[string]NameRecords, error) {
			fallbackCalled = true
			return map[string]NameRecords{
				"gateway.charon.lthn": {
					A: []string{"10.10.10.20"},
				},
			}, nil
		},
	})

	if err := service.Discover(); err != nil {
		t.Fatalf("expected fallback discovery to run: %v", err)
	}
	if !fallbackCalled {
		t.Fatal("expected fallback discoverer to run when primary is missing")
	}

	if _, ok := service.Resolve("gateway.charon.lthn"); !ok {
		t.Fatal("expected fallback record to resolve")
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

func TestServiceServeResolvesAAndAAAARecords(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A:    []string{"10.10.10.10"},
				AAAA: []string{"2600:1f1c:7f0:4f01::1"},
			},
		},
	})

	srv, err := service.Serve("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("expected server to start: %v", err)
	}
	defer func() { _ = srv.Close() }()

	client := dnsprotocol.Client{}
	query := func(qtype uint16) *dnsprotocol.Msg {
		request := new(dnsprotocol.Msg)
		request.SetQuestion("gateway.charon.lthn.", qtype)
		response := exchangeWithRetry(t, client, request, srv.Address())
		if response.Rcode != dnsprotocol.RcodeSuccess {
			t.Fatalf("unexpected rcode for qtype %d: %d", qtype, response.Rcode)
		}
		return response
	}

	aResponse := query(dnsprotocol.TypeA)
	if len(aResponse.Answer) != 1 {
		t.Fatalf("expected one A answer, got %d", len(aResponse.Answer))
	}
	if got, ok := aResponse.Answer[0].(*dnsprotocol.A); !ok || got.A.String() != "10.10.10.10" {
		t.Fatalf("unexpected A answer: %#v", aResponse.Answer[0])
	}

	aaaaResponse := query(dnsprotocol.TypeAAAA)
	if len(aaaaResponse.Answer) != 1 {
		t.Fatalf("expected one AAAA answer, got %d", len(aaaaResponse.Answer))
	}
	if got, ok := aaaaResponse.Answer[0].(*dnsprotocol.AAAA); !ok || got.AAAA.String() != "2600:1f1c:7f0:4f01::1" {
		t.Fatalf("unexpected AAAA answer: %#v", aaaaResponse.Answer[0])
	}
}

func TestServiceServeResolvesWildcardAndPTRRecords(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"*.charon.lthn": {
				A: []string{"10.0.0.1"},
			},
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	srv, err := service.Serve("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("expected server to start: %v", err)
	}
	defer func() { _ = srv.Close() }()

	client := dnsprotocol.Client{}
	request := new(dnsprotocol.Msg)
	request.SetQuestion("node1.charon.lthn.", dnsprotocol.TypeA)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("unexpected rcode: %d", response.Rcode)
	}
	if got, ok := response.Answer[0].(*dnsprotocol.A); !ok || got.A.String() != "10.0.0.1" {
		t.Fatalf("unexpected wildcard A answer: %#v", response.Answer)
	}

	ptrName := "10.10.10.10.in-addr.arpa."
	ptrRequest := new(dnsprotocol.Msg)
	ptrRequest.SetQuestion(ptrName, dnsprotocol.TypePTR)
	ptrResponse := exchangeWithRetry(t, client, ptrRequest, srv.Address())
	if len(ptrResponse.Answer) == 0 {
		t.Fatal("expected PTR answer")
	}
	if got, ok := ptrResponse.Answer[0].(*dnsprotocol.PTR); !ok || got.Ptr != "gateway.charon.lthn." {
		t.Fatalf("unexpected PTR answer: %#v", ptrResponse.Answer)
	}
}

func TestServiceServeReturnsNXDOMAINWhenMissing(t *testing.T) {
	service := NewService(ServiceOptions{})

	srv, err := service.Serve("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("expected server to start: %v", err)
	}
	defer func() { _ = srv.Close() }()

	client := dnsprotocol.Client{}
	request := new(dnsprotocol.Msg)
	request.SetQuestion("missing.charon.lthn.", dnsprotocol.TypeA)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", response.Rcode)
	}
}
