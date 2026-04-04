package dns

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
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

func pickFreeTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("expected free TCP port: %v", err)
	}
	defer func() { _ = listener.Close() }()

	tcpAddress, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected TCP listener address, got %T", listener.Addr())
	}

	return tcpAddress.Port
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

func TestServiceResolveWithMatchIndicatesExactMatch(t *testing.T) {
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

	result, ok, usedWildcard := service.ResolveWithMatch("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected exact record to resolve")
	}
	if usedWildcard {
		t.Fatalf("expected exact match to report usedWildcard=false, got %#v", result.A)
	}
}

func TestServiceResolveWithMatchIndicatesWildcardMatch(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"*.charon.lthn": {
				A: []string{"10.69.69.165"},
			},
		},
	})

	result, ok, usedWildcard := service.ResolveWithMatch("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected wildcard record to resolve")
	}
	if !usedWildcard {
		t.Fatalf("expected wildcard match to report usedWildcard=true, got %#v", result.A)
	}
}

func TestServiceOptionsAliasBuildsService(t *testing.T) {
	service := NewService(Options{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	result, ok := service.ResolveAddress("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected service constructed from Options alias to resolve")
	}
	if len(result.Addresses) != 1 || result.Addresses[0] != "10.10.10.10" {
		t.Fatalf("unexpected resolve result from Options alias: %#v", result.Addresses)
	}
}

func TestNewDNSServiceAliasToExistingConstructor(t *testing.T) {
	service := NewDNSService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	result, ok := service.ResolveAddress("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected service constructed from NewDNSService alias to resolve")
	}
	if len(result.Addresses) != 1 || result.Addresses[0] != "10.10.10.10" {
		t.Fatalf("unexpected resolve result from NewDNSService: %#v", result.Addresses)
	}
}

func TestNewDNSServiceWithRegistrarAliasRegistersActions(t *testing.T) {
	recorder := &actionRecorder{}
	service := NewDNSServiceWithRegistrar(ServiceOptions{}, recorder)
	if service == nil {
		t.Fatal("expected service instance from NewDNSServiceWithRegistrar")
	}

	if len(recorder.names) != len(service.ActionNames()) {
		t.Fatalf("expected %d registered action names, got %d", len(service.ActionNames()), len(recorder.names))
	}

	expected := map[string]struct{}{}
	for _, name := range service.ActionNames() {
		expected[name] = struct{}{}
	}
	for _, name := range recorder.names {
		if _, ok := expected[name]; !ok {
			t.Fatalf("unexpected action name registered by NewDNSServiceWithRegistrar: %q", name)
		}
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

func TestServiceResolveWildcardMatchesOnlyOneLabel(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"*.charon.lthn": {
				A: []string{"10.0.0.2"},
			},
			"*.bar.charon.lthn": {
				A: []string{"10.0.0.3"},
			},
		},
	})

	if _, ok := service.Resolve("foo.bar.charon.lthn"); !ok {
		t.Fatal("expected deeper wildcard match to resolve against the matching depth")
	}

	result, ok := service.Resolve("foo.charon.lthn")
	if !ok {
		t.Fatal("expected single-label wildcard to resolve")
	}
	if len(result.A) != 1 || result.A[0] != "10.0.0.2" {
		t.Fatalf("unexpected wildcard result for single-label match: %#v", result.A)
	}

	if _, ok := service.Resolve("foo.baz.charon.lthn"); ok {
		t.Fatal("expected wildcard to require an exact one-label match")
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

func TestServiceResolveTXTRecordsReturnsNamedField(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				TXT: []string{"v=lthn1 type=gateway"},
			},
		},
	})

	result, ok := service.ResolveTXTRecords("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected named TXT result to resolve")
	}
	if len(result.TXT) != 1 || result.TXT[0] != "v=lthn1 type=gateway" {
		t.Fatalf("unexpected ResolveTXTRecords output: %#v", result.TXT)
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

func TestServiceResolveReverseNamesReturnsNamedField(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	result, ok := service.ResolveReverseNames("10.10.10.10")
	if !ok {
		t.Fatal("expected named reverse result")
	}
	if len(result.Names) != 1 || result.Names[0] != "gateway.charon.lthn" {
		t.Fatalf("unexpected reverse names result: %#v", result)
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

func TestServiceResolveReverseAcceptsInAddrARPAQueryName(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	names, ok := service.ResolveReverse("10.10.10.10.in-addr.arpa.")
	if !ok {
		t.Fatal("expected reverse lookup by PTR name to resolve")
	}
	if len(names) != 1 || names[0] != "gateway.charon.lthn" {
		t.Fatalf("unexpected reverse results for PTR name: %#v", names)
	}
}

func TestServiceResolveReverseAcceptsIPv6ARPAQueryName(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				AAAA: []string{"2001:db8::4f01:0000:0000:0000:0001"},
			},
		},
	})

	names, ok := service.ResolveReverse("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.f.4.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
	if !ok {
		t.Fatal("expected reverse lookup by IPv6 PTR name to resolve")
	}
	if len(names) != 1 || names[0] != "gateway.charon.lthn" {
		t.Fatalf("unexpected reverse results for IPv6 PTR name: %#v", names)
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

func TestServiceRecordTTLExpiresForwardAndReverseLookups(t *testing.T) {
	service := NewService(ServiceOptions{
		RecordTTL: 25 * time.Millisecond,
	})

	service.SetRecord("gateway.charon.lthn", NameRecords{
		A: []string{"10.10.10.10"},
	})

	if _, ok := service.Resolve("gateway.charon.lthn"); !ok {
		t.Fatal("expected record to resolve before expiry")
	}
	if names, ok := service.ResolveReverse("10.10.10.10"); !ok || len(names) != 1 || names[0] != "gateway.charon.lthn" {
		t.Fatalf("expected reverse record before expiry, got %#v (ok=%t)", names, ok)
	}

	time.Sleep(100 * time.Millisecond)

	if _, ok := service.Resolve("gateway.charon.lthn"); ok {
		t.Fatal("expected forward record to expire")
	}
	if _, ok := service.ResolveReverse("10.10.10.10"); ok {
		t.Fatal("expected reverse record to expire with the forward record")
	}
	if health := service.Health(); health.NamesCached != 0 {
		t.Fatalf("expected expired record to be pruned from health, got %#v", health)
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
	root := health.TreeRoot
	if root == "" || root == "stubbed" {
		t.Fatalf("expected computed tree root, got %#v", health.TreeRoot)
	}

	healthRepeating := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				NS: []string{"ns1.example.com"},
				A:  []string{"10.0.0.1", "10.10.10.10"},
			},
		},
	}).Health().TreeRoot

	if healthRepeating != root {
		t.Fatalf("expected deterministic tree root, got %s and %s", healthRepeating, root)
	}

	service.SetRecord("gateway.charon.lthn", NameRecords{
		A: []string{"10.10.10.11"},
	})
	updatedRoot := service.Health().TreeRoot
	if updatedRoot == root {
		t.Fatalf("expected updated tree root after SetRecord, got %s", updatedRoot)
	}

	service.RemoveRecord("gateway.charon.lthn")
	removedRoot := service.Health().TreeRoot
	if removedRoot == updatedRoot {
		t.Fatalf("expected updated tree root after RemoveRecord, got %s", removedRoot)
	}
}

func TestServiceHealthUsesChainTreeRootAfterDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "chain-root-1",
				},
			})
		case "getnameresource":
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"a": []string{"10.10.10.10"},
				},
			})
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{"gateway.charon.lthn"}, nil
		},
		HSDClient: NewHSDClient(HSDClientOptions{URL: server.URL}),
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected discover to run for health chain-root assertions: %v", err)
	}

	health := service.Health()
	root := health.TreeRoot
	if root != "chain-root-1" {
		t.Fatalf("expected health to expose chain tree_root, got %#v", health.TreeRoot)
	}
}

func TestServiceLocalMutationClearsChainTreeRoot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "chain-root-1",
				},
			})
		case "getnameresource":
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"a": []string{"10.10.10.10"},
				},
			})
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{"gateway.charon.lthn"}, nil
		},
		HSDClient: NewHSDClient(HSDClientOptions{URL: server.URL}),
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected discovery to populate chain tree root: %v", err)
	}
	if health := service.Health(); health.TreeRoot != "chain-root-1" {
		t.Fatalf("expected chain tree root before local mutation, got %#v", health.TreeRoot)
	}

	service.SetRecord("gateway.charon.lthn", NameRecords{
		A: []string{"10.10.10.11"},
	})

	health := service.Health()
	if health.TreeRoot == "chain-root-1" {
		t.Fatalf("expected local mutation to clear stale chain tree root, got %#v", health.TreeRoot)
	}
	if health.TreeRoot == "" {
		t.Fatal("expected health to fall back to computed tree root after local mutation")
	}
}

func TestServiceServeHTTPHealthReturnsJSON(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	httpServer, err := service.ServeHTTPHealth("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("expected health HTTP server to start: %v", err)
	}
	defer func() {
		_ = httpServer.Close()
	}()

	if httpServer.HealthAddress() == "" {
		t.Fatal("expected health address from health server")
	}
	if httpServer.Address() != httpServer.HealthAddress() {
		t.Fatalf("expected Address and HealthAddress to match, got %q and %q", httpServer.Address(), httpServer.HealthAddress())
	}

	response, err := http.Get("http://" + httpServer.HealthAddress() + "/health")
	if err != nil {
		t.Fatalf("expected health endpoint to respond: %v", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected health status: %d", response.StatusCode)
	}

	var payload map[string]any
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("expected health payload: %v", err)
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("expected health JSON: %v", err)
	}
	if payload["status"] != "ready" {
		t.Fatalf("expected ready health status, got %#v", payload["status"])
	}
	if payload["names_cached"] != float64(1) {
		t.Fatalf("expected one cached name, got %#v", payload["names_cached"])
	}
}

func TestServiceServeAllStartsDNSAndHTTPTogether(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	runtime, err := service.ServeAll("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatalf("expected combined runtime to start: %v", err)
	}
	defer func() {
		_ = runtime.Close()
	}()

	if runtime.DNSAddress() == "" {
		t.Fatal("expected DNS address from combined runtime")
	}
	if runtime.HealthAddress() == "" {
		t.Fatal("expected health address from combined runtime")
	}
	if runtime.DNS.Address() != runtime.DNSAddress() {
		t.Fatalf("expected DNSAddress and Address to match, got %q and %q", runtime.DNS.DNSAddress(), runtime.DNS.Address())
	}
	if runtime.HTTPAddress() != runtime.HealthAddress() {
		t.Fatalf("expected HTTPAddress and HealthAddress to match, got %q and %q", runtime.HTTPAddress(), runtime.HealthAddress())
	}

	response, err := http.Get("http://" + runtime.HealthAddress() + "/health")
	if err != nil {
		t.Fatalf("expected combined HTTP health endpoint to respond: %v", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected combined health status: %d", response.StatusCode)
	}

	client := dnsprotocol.Client{}
	request := new(dnsprotocol.Msg)
	request.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeA)
	dnsResponse := exchangeWithRetry(t, client, request, runtime.DNSAddress())
	if dnsResponse.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("unexpected combined DNS rcode: %d", dnsResponse.Rcode)
	}
	if len(dnsResponse.Answer) != 1 {
		t.Fatalf("expected one DNS answer from combined runtime, got %d", len(dnsResponse.Answer))
	}
}

func TestServiceServeConfiguredUsesPortsFromServiceOptions(t *testing.T) {
	dnsPort := pickFreeTCPPort(t)
	httpPort := pickFreeTCPPort(t)

	service := NewService(ServiceOptions{
		DNSPort:  dnsPort,
		HTTPPort: httpPort,
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	runtime, err := service.ServeConfigured("127.0.0.1")
	if err != nil {
		t.Fatalf("expected configured runtime to start: %v", err)
	}
	defer func() {
		_ = runtime.Close()
	}()

	_, dnsActualPort, err := net.SplitHostPort(runtime.DNSAddress())
	if err != nil {
		t.Fatalf("expected DNS address to parse: %v", err)
	}
	if dnsActualPort != strconv.Itoa(dnsPort) {
		t.Fatalf("expected configured DNS port %d, got %s", dnsPort, dnsActualPort)
	}

	_, httpActualPort, err := net.SplitHostPort(runtime.HealthAddress())
	if err != nil {
		t.Fatalf("expected HTTP address to parse: %v", err)
	}
	if httpActualPort != strconv.Itoa(httpPort) {
		t.Fatalf("expected configured HTTP port %d, got %s", httpPort, httpActualPort)
	}
}

func TestServiceServeDefaultsPortWhenZero(t *testing.T) {
	const configuredDNSPort = 5353
	service := NewService(ServiceOptions{
		DNSPort: configuredDNSPort,
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	server, err := service.Serve("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("expected Serve to default DNS port: %v", err)
	}
	defer func() {
		_ = server.Close()
	}()

	_, port, err := net.SplitHostPort(server.DNSAddress())
	if err != nil {
		t.Fatalf("expected DNS address to parse: %v", err)
	}
	if port != strconv.Itoa(configuredDNSPort) {
		t.Fatalf("expected zero port to default to configured service DNS port %d, got %s", configuredDNSPort, port)
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
		RecordDiscoverer: func() (map[string]NameRecords, error) {
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

func TestServiceDiscoverAliasesUsesConfiguredAliasDiscovery(t *testing.T) {
	var treeRootCalls int32
	var nameResourceCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "alias-root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			if len(payload.Params) != 1 || payload.Params[0] != "gateway.charon.lthn" {
				t.Fatalf("unexpected alias lookup: %#v", payload.Params)
			}
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"a": []string{"10.10.10.10"},
				},
			})
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{"gateway.charon.lthn"}, nil
		},
		HSDClient: NewHSDClient(HSDClientOptions{URL: server.URL}),
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected DiscoverAliases action to run: %v", err)
	}

	record, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(record.A) != 1 || record.A[0] != "10.10.10.10" {
		t.Fatalf("expected discovered gateway record, got %#v (ok=%t)", record, ok)
	}
	if atomic.LoadInt32(&treeRootCalls) != 1 || atomic.LoadInt32(&nameResourceCalls) != 1 {
		t.Fatalf("expected discovery to perform chain and name-resource calls, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&treeRootCalls), atomic.LoadInt32(&nameResourceCalls))
	}
}

func TestServiceDiscoverAliasesUsesConfiguredActionCaller(t *testing.T) {
	var treeRootCalls int32
	var nameResourceCalls int32
	actionCalled := false
	discovererCalled := false

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "action-caller-root",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			switch payload.Params[0] {
			case "gateway.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"a": []string{"10.10.10.10"},
					},
				})
			case "node.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"aaaa": []string{"2600:1f1c:7f0:4f01::2"},
					},
				})
			default:
				t.Fatalf("unexpected alias lookup: %#v", payload.Params)
			}
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasActionCaller: actionCallerFunc(func(ctx context.Context, name string, values map[string]any) (any, bool, error) {
			actionCalled = true
			if name != "blockchain.chain.aliases" {
				t.Fatalf("unexpected action name: %s", name)
			}
			return map[string]any{
				"aliases": []any{"gateway.charon.lthn", "node.charon.lthn"},
			}, true, nil
		}),
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			discovererCalled = true
			return nil, errors.New("discoverer should not run when action caller succeeds")
		},
		HSDClient: NewHSDClient(HSDClientOptions{URL: server.URL}),
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected DiscoverAliases to complete through action caller: %v", err)
	}
	if !actionCalled {
		t.Fatal("expected action caller to be invoked")
	}
	if discovererCalled {
		t.Fatal("expected chain alias discoverer to be skipped after action caller success")
	}

	gateway, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(gateway.A) != 1 || gateway.A[0] != "10.10.10.10" {
		t.Fatalf("expected gateway A record, got %#v (ok=%t)", gateway, ok)
	}
	node, ok := service.Resolve("node.charon.lthn")
	if !ok || len(node.AAAA) != 1 || node.AAAA[0] != "2600:1f1c:7f0:4f01::2" {
		t.Fatalf("expected node AAAA record, got %#v (ok=%t)", node, ok)
	}

	if atomic.LoadInt32(&treeRootCalls) != 1 || atomic.LoadInt32(&nameResourceCalls) != 2 {
		t.Fatalf("expected discovery to perform chain and name-resource calls, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&treeRootCalls), atomic.LoadInt32(&nameResourceCalls))
	}
}

func TestNewServiceInfersChainAliasActionCallerFromRegistrar(t *testing.T) {
	var actionCalls int32
	var chainAliasCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			atomic.AddInt32(&chainAliasCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "action-registry-root",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&chainAliasCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"a": []string{"10.10.10.10"},
				},
			})
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	registrar := &actionRegistrarAndCaller{
		actionRecorder: actionRecorder{},
	}
	registrar.handlers = map[string]func(map[string]any) (any, bool, error){}
	service := NewService(ServiceOptions{
		ActionRegistrar: registrar,
		HSDClient: NewHSDClient(HSDClientOptions{
			URL: server.URL,
		}),
		RecordTTL: time.Minute,
	})

	registrar.actionCall = func(ctx context.Context, action string, values map[string]any) (any, bool, error) {
		atomic.AddInt32(&actionCalls, 1)
		if action != "blockchain.chain.aliases" {
			t.Fatalf("unexpected action name: %s", action)
		}
		return map[string]any{
			"aliases": []any{"gateway.charon.lthn"},
		}, true, nil
	}

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected discover to use registrar action caller: %v", err)
	}

	record, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(record.A) != 1 || record.A[0] != "10.10.10.10" {
		t.Fatalf("expected discovered gateway record, got %#v (ok=%t)", record, ok)
	}

	if atomic.LoadInt32(&actionCalls) != 1 {
		t.Fatalf("expected one action-caller invocation, got %d", atomic.LoadInt32(&actionCalls))
	}
	if atomic.LoadInt32(&chainAliasCalls) != 2 {
		t.Fatalf("expected two HSD calls (tree root + resource), got %d", atomic.LoadInt32(&chainAliasCalls))
	}
}

func TestServiceDiscoverAliasesTreatsNilActionResponseAsNoAliases(t *testing.T) {
	var actionCalled bool
	var fallbackCallCount int32

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&fallbackCallCount, 1)
		t.Fatalf("expected nil action result to avoid fallback RPC calls, got %s", request.Method)
		_, _ = responseWriter.Write([]byte("{}"))
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
		ChainAliasActionCaller: actionCallerFunc(func(ctx context.Context, name string, values map[string]any) (any, bool, error) {
			actionCalled = true
			if name != "blockchain.chain.aliases" {
				t.Fatalf("unexpected action name: %s", name)
			}
			return nil, true, nil
		}),
		HSDClient:    NewHSDClient(HSDClientOptions{URL: server.URL}),
		MainchainURL: server.URL,
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected DiscoverAliases to treat nil action result as empty aliases: %v", err)
	}
	if !actionCalled {
		t.Fatal("expected action caller to be invoked")
	}
	if atomic.LoadInt32(&fallbackCallCount) != 0 {
		t.Fatalf("expected no fallback RPC calls, got %d", atomic.LoadInt32(&fallbackCallCount))
	}
	if _, ok := service.Resolve("gateway.charon.lthn"); ok {
		t.Fatal("expected existing records to be cleared after nil alias response")
	}
	health := service.Health()
	if health.NamesCached != 0 {
		t.Fatalf("expected empty cache after nil alias response, got %d", health.NamesCached)
	}
}

func TestServiceDiscoverAliasesUsesConfiguredChainAliasAction(t *testing.T) {
	var treeRootCalls int32
	var nameResourceCalls int32
	actionCalled := false
	discovererCalled := false

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "action-root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			if len(payload.Params) != 1 || payload.Params[0] != "gateway.charon.lthn" {
				t.Fatalf("unexpected alias lookup: %#v", payload.Params)
			}
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"a": []string{"10.10.10.10"},
				},
			})
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasAction: func(_ context.Context) ([]string, error) {
			actionCalled = true
			return []string{"gateway.charon.lthn"}, nil
		},
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			discovererCalled = true
			return nil, errors.New("discoverer should not be used when action succeeds")
		},
		HSDClient: NewHSDClient(HSDClientOptions{URL: server.URL}),
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected DiscoverAliases to complete through chain alias action: %v", err)
	}
	if !actionCalled {
		t.Fatal("expected chain alias action to be called")
	}
	if discovererCalled {
		t.Fatal("expected chain alias discoverer to be skipped after action success")
	}

	record, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(record.A) != 1 || record.A[0] != "10.10.10.10" {
		t.Fatalf("expected discovered gateway record, got %#v (ok=%t)", record, ok)
	}
	if atomic.LoadInt32(&treeRootCalls) != 1 || atomic.LoadInt32(&nameResourceCalls) != 1 {
		t.Fatalf("expected one tree-root and one name-resource RPC call, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&treeRootCalls), atomic.LoadInt32(&nameResourceCalls))
	}
}

func TestNewServiceBuildsRPCClientsFromOptions(t *testing.T) {
	var chainCalls int32
	var treeRootCalls int32
	var nameResourceCalls int32
	expectedAuth := "Basic dXNlcjphcGkta2V5"

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "get_all_alias_details":
			atomic.AddInt32(&chainCalls, 1)
			if got := request.Header.Get("Authorization"); got != expectedAuth {
				t.Fatalf("expected hsd-auth header for mainchain request %q, got %q", expectedAuth, got)
			}
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": []any{
					map[string]any{
						"hns": "gateway.charon.lthn",
					},
				},
			})
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			if got := request.Header.Get("Authorization"); got != expectedAuth {
				t.Fatalf("expected hsd auth header %q, got %q", expectedAuth, got)
			}
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "options-root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			if got := request.Header.Get("Authorization"); got != expectedAuth {
				t.Fatalf("expected hsd auth header %q, got %q", expectedAuth, got)
			}
			if len(payload.Params) != 1 || payload.Params[0] != "gateway.charon.lthn" {
				t.Fatalf("unexpected alias lookup: %#v", payload.Params)
			}
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"a": []string{"10.10.10.10"},
				},
			})
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		MainchainURL: server.URL,
		HSDURL:       server.URL,
		HSDUsername:  "user",
		HSDApiKey:    "api-key",
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected configured RPC clients to drive discovery: %v", err)
	}

	record, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(record.A) != 1 || record.A[0] != "10.10.10.10" {
		t.Fatalf("expected discovered record from configured clients, got %#v (ok=%t)", record, ok)
	}

	health := service.Health()
	if health.TreeRoot != "options-root-1" {
		t.Fatalf("expected health to reflect configured HSD client tree root, got %#v", health.TreeRoot)
	}

	if atomic.LoadInt32(&chainCalls) != 1 || atomic.LoadInt32(&treeRootCalls) != 1 || atomic.LoadInt32(&nameResourceCalls) != 1 {
		t.Fatalf(
			"expected chain=1 tree-root=1 name-resource=1, got %d %d %d",
			atomic.LoadInt32(&chainCalls),
			atomic.LoadInt32(&treeRootCalls),
			atomic.LoadInt32(&nameResourceCalls),
		)
	}
}

func TestServiceDiscoverAliasesClearsCacheWhenAliasListBecomesEmpty(t *testing.T) {
	var hsdCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&hsdCalls, 1)
		t.Fatalf("unexpected HSD request while clearing an empty alias list")
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"legacy.charon.lthn": {
				A: []string{"10.11.11.11"},
			},
		},
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{}, nil
		},
		HSDClient: NewHSDClient(HSDClientOptions{URL: server.URL}),
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected empty alias discovery to succeed: %v", err)
	}

	if _, ok := service.Resolve("legacy.charon.lthn"); ok {
		t.Fatal("expected stale records to be cleared when the alias list is empty")
	}

	health := service.Health()
	if health.NamesCached != 0 {
		t.Fatalf("expected empty cache after clearing aliases, got %d", health.NamesCached)
	}

	if atomic.LoadInt32(&hsdCalls) != 0 {
		t.Fatalf("expected no HSD requests when alias discovery returns empty, got %d", atomic.LoadInt32(&hsdCalls))
	}
}

func TestServiceDiscoverAliasesClearsCacheWhenAliasListIsEmptyWithoutHSDClient(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"legacy.charon.lthn": {
				A: []string{"10.11.11.11"},
			},
		},
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{}, nil
		},
	})
	service.hsdClient = nil
	service.mainchainAliasClient = nil

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected empty alias discovery to succeed without HSD client: %v", err)
	}

	if _, ok := service.Resolve("legacy.charon.lthn"); ok {
		t.Fatal("expected stale records to be cleared when the alias list is empty")
	}

	health := service.Health()
	if health.NamesCached != 0 {
		t.Fatalf("expected empty cache after clearing aliases, got %d", health.NamesCached)
	}
}

func TestServiceDiscoverAliasesParsesAliasDetailRecordsFromActionCaller(t *testing.T) {
	var treeRootCalls int32
	var nameResourceCalls int32
	actionCalled := false

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "record-root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			switch payload.Params[0] {
			case "gateway.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"a": []string{"10.10.10.10"},
					},
				})
			case "node.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"aaaa": []string{"2600:1f1c:7f0:4f01::2"},
					},
				})
			default:
				t.Fatalf("unexpected alias lookup: %#v", payload.Params)
			}
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasActionCaller: actionCallerFunc(func(ctx context.Context, name string, values map[string]any) (any, bool, error) {
			actionCalled = true
			if name != "blockchain.chain.aliases" {
				t.Fatalf("unexpected action name: %s", name)
			}
			return map[string]any{
				"aliases": []any{
					map[string]any{
						"name":    "gateway",
						"comment": "gateway alias hns=gateway.charon.lthn",
					},
					map[string]any{
						"name": "node",
						"hns":  "node.charon.lthn",
					},
				},
			}, true, nil
		}),
		HSDClient: NewHSDClient(HSDClientOptions{URL: server.URL}),
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected DiscoverAliases to parse alias detail records: %v", err)
	}
	if !actionCalled {
		t.Fatal("expected action caller to be invoked")
	}
	if atomic.LoadInt32(&treeRootCalls) != 1 || atomic.LoadInt32(&nameResourceCalls) != 2 {
		t.Fatalf("expected one tree-root and two name-resource RPC calls, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&treeRootCalls), atomic.LoadInt32(&nameResourceCalls))
	}

	gateway, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(gateway.A) != 1 || gateway.A[0] != "10.10.10.10" {
		t.Fatalf("expected gateway A record, got %#v (ok=%t)", gateway, ok)
	}
	node, ok := service.Resolve("node.charon.lthn")
	if !ok || len(node.AAAA) != 1 || node.AAAA[0] != "2600:1f1c:7f0:4f01::2" {
		t.Fatalf("expected node AAAA record, got %#v (ok=%t)", node, ok)
	}
}

func TestServiceDiscoverAliasesRefreshesWhenAliasListChangesBeforeTreeRootIntervalExpires(t *testing.T) {
	var treeRootCalls int32
	var nameResourceCalls int32
	aliasListIndex := 0

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "shared-tree-root",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			switch payload.Params[0] {
			case "gateway.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"a": []string{"10.10.10.10"},
					},
				})
			case "node.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"aaaa": []string{"2600:1f1c:7f0:4f01::2"},
					},
				})
			default:
				t.Fatalf("unexpected alias lookup: %#v", payload.Params)
			}
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		TreeRootCheckInterval: time.Hour,
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			defer func() { aliasListIndex++ }()
			if aliasListIndex == 0 {
				return []string{"gateway.charon.lthn"}, nil
			}
			return []string{"gateway.charon.lthn", "node.charon.lthn"}, nil
		},
		HSDClient: NewHSDClient(HSDClientOptions{URL: server.URL}),
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected first DiscoverAliases call to succeed: %v", err)
	}
	if atomic.LoadInt32(&treeRootCalls) != 1 || atomic.LoadInt32(&nameResourceCalls) != 1 {
		t.Fatalf("expected first discovery to query tree root and one alias, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&treeRootCalls), atomic.LoadInt32(&nameResourceCalls))
	}

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected second DiscoverAliases call to refresh changed aliases: %v", err)
	}
	if atomic.LoadInt32(&treeRootCalls) != 2 || atomic.LoadInt32(&nameResourceCalls) != 3 {
		t.Fatalf("expected alias change to force refresh, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&treeRootCalls), atomic.LoadInt32(&nameResourceCalls))
	}

	gateway, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(gateway.A) != 1 || gateway.A[0] != "10.10.10.10" {
		t.Fatalf("expected refreshed gateway record, got %#v (ok=%t)", gateway, ok)
	}
	node, ok := service.Resolve("node.charon.lthn")
	if !ok || len(node.AAAA) != 1 || node.AAAA[0] != "2600:1f1c:7f0:4f01::2" {
		t.Fatalf("expected refreshed node record, got %#v (ok=%t)", node, ok)
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
		RecordDiscoverer: func() (map[string]NameRecords, error) {
			primaryCalled = true
			return nil, errors.New("chain service unavailable")
		},
		FallbackRecordDiscoverer: func() (map[string]NameRecords, error) {
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

func TestServiceDiscoverReturnsNilAfterFallbackDiscoverySucceeds(t *testing.T) {
	service := NewService(ServiceOptions{
		RecordDiscoverer: func() (map[string]NameRecords, error) {
			return nil, errors.New("primary discoverer failed")
		},
		FallbackRecordDiscoverer: func() (map[string]NameRecords, error) {
			return map[string]NameRecords{
				"gateway.charon.lthn": {
					A: []string{"10.10.10.10"},
				},
			}, nil
		},
	})

	if err := service.Discover(); err != nil {
		t.Fatalf("expected fallback discovery success to return nil, got %v", err)
	}

	result, ok := service.Resolve("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected fallback record to resolve after discovery")
	}
	if len(result.A) != 1 || result.A[0] != "10.10.10.10" {
		t.Fatalf("unexpected fallback resolve result: %#v", result.A)
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
		FallbackRecordDiscoverer: func() (map[string]NameRecords, error) {
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

func TestServiceDiscoverFromChainAliasesUsesFallbackWhenPrimaryFails(t *testing.T) {
	primaryCalled := false
	fallbackCalled := false
	var treeRootCalls int32
	var nameResourceCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			switch payload.Params[0] {
			case "gateway.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"a": []string{"10.10.10.10"},
					},
				})
			case "node.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"aaaa": []string{"2600:1f1c:7f0:4f01::2"},
					},
				})
			default:
				t.Fatalf("unexpected alias query: %#v", payload.Params)
			}
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			primaryCalled = true
			return nil, errors.New("blockchain service unavailable")
		},
		FallbackChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			fallbackCalled = true
			return []string{"gateway.charon.lthn", "node.charon.lthn"}, nil
		},
	})

	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})
	if err := service.DiscoverFromChainAliases(context.Background(), client); err != nil {
		t.Fatalf("expected chain alias discovery to complete: %v", err)
	}
	if !primaryCalled {
		t.Fatal("expected primary chain alias discoverer to be attempted")
	}
	if !fallbackCalled {
		t.Fatal("expected fallback chain alias discoverer to run")
	}

	gateway, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(gateway.A) != 1 || gateway.A[0] != "10.10.10.10" {
		t.Fatalf("expected gateway A record, got %#v (ok=%t)", gateway, ok)
	}
	node, ok := service.Resolve("node.charon.lthn")
	if !ok || len(node.AAAA) != 1 || node.AAAA[0] != "2600:1f1c:7f0:4f01::2" {
		t.Fatalf("expected node AAAA record, got %#v (ok=%t)", node, ok)
	}

	if atomic.LoadInt32(&treeRootCalls) != 1 || atomic.LoadInt32(&nameResourceCalls) != 2 {
		t.Fatalf("expected one tree-root and two name-resource RPC calls, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&treeRootCalls), atomic.LoadInt32(&nameResourceCalls))
	}
}

func TestServiceDiscoverFromChainAliasesUsesConfiguredHSDClient(t *testing.T) {
	var treeRootCalls int32
	var nameResourceCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			switch payload.Params[0] {
			case "gateway.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"a": []string{"10.10.10.10"},
					},
				})
			default:
				t.Fatalf("unexpected alias lookup: %#v", payload.Params)
			}
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{"gateway.charon.lthn"}, nil
		},
		HSDClient: NewHSDClient(HSDClientOptions{URL: server.URL}),
	})

	if err := service.DiscoverFromChainAliases(context.Background(), nil); err != nil {
		t.Fatalf("expected chain alias discovery to complete: %v", err)
	}

	if atomic.LoadInt32(&treeRootCalls) != 1 {
		t.Fatalf("expected one tree-root call, got %d", atomic.LoadInt32(&treeRootCalls))
	}
	if atomic.LoadInt32(&nameResourceCalls) != 1 {
		t.Fatalf("expected one name-resource call, got %d", atomic.LoadInt32(&nameResourceCalls))
	}

	gateway, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(gateway.A) != 1 || gateway.A[0] != "10.10.10.10" {
		t.Fatalf("expected gateway A record, got %#v (ok=%t)", gateway, ok)
	}
}

func TestServiceDiscoverFromChainAliasesFallsBackToMainchainClientWhenDiscovererFails(t *testing.T) {
	var chainAliasCalls int32
	var treeRootCalls int32
	var nameResourceCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "get_all_alias_details":
			atomic.AddInt32(&chainAliasCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": []any{
					map[string]any{
						"hns": "gateway.charon.lthn",
					},
					map[string]any{
						"hns": "node.charon.lthn",
					},
				},
			})
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "chain-root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			switch payload.Params[0] {
			case "gateway.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"a": []string{"10.10.10.10"},
					},
				})
			case "node.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"aaaa": []string{"2600:1f1c:7f0:4f01::2"},
					},
				})
			default:
				t.Fatalf("unexpected alias query: %#v", payload.Params)
			}
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return nil, errors.New("blockchain service unavailable")
		},
		MainchainAliasClient: NewMainchainAliasClient(MainchainClientOptions{
			URL: server.URL,
		}),
	})
	hsdClient := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})
	if err := service.DiscoverFromChainAliases(context.Background(), hsdClient); err != nil {
		t.Fatalf("expected chain alias discovery to complete: %v", err)
	}

	gateway, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(gateway.A) != 1 || gateway.A[0] != "10.10.10.10" {
		t.Fatalf("expected gateway A record, got %#v (ok=%t)", gateway, ok)
	}
	node, ok := service.Resolve("node.charon.lthn")
	if !ok || len(node.AAAA) != 1 || node.AAAA[0] != "2600:1f1c:7f0:4f01::2" {
		t.Fatalf("expected node AAAA record, got %#v (ok=%t)", node, ok)
	}

	if atomic.LoadInt32(&chainAliasCalls) != 1 {
		t.Fatalf("expected one chain alias call, got %d", atomic.LoadInt32(&chainAliasCalls))
	}
	if atomic.LoadInt32(&treeRootCalls) != 1 || atomic.LoadInt32(&nameResourceCalls) != 2 {
		t.Fatalf("expected one tree-root and two name-resource calls, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&treeRootCalls), atomic.LoadInt32(&nameResourceCalls))
	}
}

func TestServiceDiscoverFromChainAliasesSkipsRefreshWhenTreeRootUnchanged(t *testing.T) {
	var treeRootCalls int32
	var nameResourceCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "same-root",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			switch payload.Params[0] {
			case "gateway.charon.lthn":
				_ = json.NewEncoder(responseWriter).Encode(map[string]any{
					"result": map[string]any{
						"a": []string{"10.10.10.10"},
					},
				})
			default:
				t.Fatalf("unexpected alias query: %#v", payload.Params)
			}
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		TreeRootCheckInterval: 5 * time.Second,
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{"gateway.charon.lthn"}, nil
		},
	})

	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})
	if err := service.DiscoverFromChainAliases(context.Background(), client); err != nil {
		t.Fatalf("expected first chain alias discovery to run: %v", err)
	}
	if err := service.DiscoverFromChainAliases(context.Background(), client); err != nil {
		t.Fatalf("expected second chain alias discovery to skip refresh: %v", err)
	}

	if atomic.LoadInt32(&treeRootCalls) != 1 {
		t.Fatalf("expected one tree_root check in interval window, got %d", atomic.LoadInt32(&treeRootCalls))
	}
	if atomic.LoadInt32(&nameResourceCalls) != 1 {
		t.Fatalf("expected one name-resource query while refreshing, got %d", atomic.LoadInt32(&nameResourceCalls))
	}
}

func TestServiceDiscoverFromChainAliasesIgnoresMissingDiscoverers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		t.Fatalf("expected no hsd requests when alias discoverers are missing")
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})
	service.mainchainAliasClient = nil
	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	if err := service.DiscoverFromChainAliases(context.Background(), client); err != nil {
		t.Fatalf("expected no-op when no alias discoverer configured and no mainchain client: %v", err)
	}

	result, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(result.A) != 1 || result.A[0] != "10.10.10.10" {
		t.Fatalf("expected baseline record to stay in cache, got %#v (ok=%t)", result, ok)
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

func TestServiceDiscoverAliasesReturnsNilWithoutDiscovererOrHSDClient(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})
	service.mainchainAliasClient = nil

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected discover aliases to no-op without sources or HSD client when no explicit mainchain client: %v", err)
	}

	result, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(result.A) != 1 || result.A[0] != "10.10.10.10" {
		t.Fatalf("expected cached record to remain intact, got %#v (ok=%t)", result, ok)
	}
}

func TestServiceDiscoverFromMainchainAliasesClearsCacheWhenAliasListIsEmptyWithoutHSDClient(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"legacy.charon.lthn": {
				A: []string{"10.11.11.11"},
			},
		},
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{}, nil
		},
	})
	service.mainchainAliasClient = nil
	service.hsdClient = nil

	if err := service.DiscoverFromMainchainAliases(context.Background(), nil, nil); err != nil {
		t.Fatalf("expected empty mainchain alias discovery to succeed without HSD or mainchain client: %v", err)
	}

	if _, ok := service.Resolve("legacy.charon.lthn"); ok {
		t.Fatal("expected stale records to be cleared when the mainchain alias list is empty")
	}

	health := service.Health()
	if health.NamesCached != 0 {
		t.Fatalf("expected empty cache after clearing aliases, got %d", health.NamesCached)
	}
}

func TestServiceCreatesDefaultHSDClientWhenURLNotConfigured(t *testing.T) {
	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{"gateway.charon.lthn"}, nil
		},
	})
	if service.hsdClient == nil {
		t.Fatalf("expected default HSD client to be created when HSDURL is not configured")
	}
	if service.hsdClient.baseURL != "http://127.0.0.1:14037" {
		t.Fatalf("expected default HSD base URL, got %q", service.hsdClient.baseURL)
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

func TestServiceServeAnswersDSRecords(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				DS: []string{"60485 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"},
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
	request.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeDS)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("unexpected DS rcode: %d", response.Rcode)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected one DS answer, got %d", len(response.Answer))
	}
	if _, ok := response.Answer[0].(*dnsprotocol.DS); !ok {
		t.Fatalf("expected DS answer, got %#v", response.Answer[0])
	}
}

func TestServiceServeAnswersDNSKEYRecords(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				DNSKEY: []string{"257 3 13 AA=="},
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
	request.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeDNSKEY)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("unexpected DNSKEY rcode: %d", response.Rcode)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected one DNSKEY answer, got %d", len(response.Answer))
	}
	if _, ok := response.Answer[0].(*dnsprotocol.DNSKEY); !ok {
		t.Fatalf("expected DNSKEY answer, got %#v", response.Answer[0])
	}
}

func TestServiceServeAnswersRRSIGRecords(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				RRSIG: []string{"A 8 2 3600 20260101000000 20250101000000 12345 gateway.charon.lthn. AA=="},
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
	request.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeRRSIG)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("unexpected RRSIG rcode: %d", response.Rcode)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected one RRSIG answer, got %d", len(response.Answer))
	}
	if _, ok := response.Answer[0].(*dnsprotocol.RRSIG); !ok {
		t.Fatalf("expected RRSIG answer, got %#v", response.Answer[0])
	}
}

func TestServiceServeAnswersANYWithAllRecordTypes(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A:    []string{"10.10.10.10"},
				AAAA: []string{"2600:1f1c:7f0:4f01::1"},
				TXT:  []string{"v=lthn1 type=gateway"},
				NS:   []string{"ns.gateway.charon.lthn"},
				DS:   []string{"60485 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"},
			},
			"node.charon.lthn": {
				A: []string{"10.10.10.11"},
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
	request.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeANY)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("unexpected ANY rcode: %d", response.Rcode)
	}

	var sawA, sawAAAA, sawTXT, sawNS, sawDS, sawSOA bool
	for _, answer := range response.Answer {
		switch rr := answer.(type) {
		case *dnsprotocol.A:
			sawA = rr.A.String() == "10.10.10.10"
		case *dnsprotocol.AAAA:
			sawAAAA = rr.AAAA.String() == "2600:1f1c:7f0:4f01::1"
		case *dnsprotocol.TXT:
			sawTXT = len(rr.Txt) == 1 && rr.Txt[0] == "v=lthn1 type=gateway"
		case *dnsprotocol.NS:
			sawNS = rr.Ns == "ns.gateway.charon.lthn."
		case *dnsprotocol.DS:
			sawDS = true
		case *dnsprotocol.SOA:
			sawSOA = true
		}
	}

	if !sawA || !sawAAAA || !sawTXT || !sawNS || !sawDS {
		t.Fatalf("expected ANY answer to include A, AAAA, TXT, NS, and DS records, got %#v", response.Answer)
	}
	if sawSOA {
		t.Fatalf("expected ANY answer for a non-apex name to omit SOA, got %#v", response.Answer)
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

func TestServiceServeAnswersSOAOnlyForZoneApex(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"charon.lthn": {
				NS: []string{"ns1.charon.lthn"},
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
	apexRequest := new(dnsprotocol.Msg)
	apexRequest.SetQuestion("charon.lthn.", dnsprotocol.TypeSOA)
	apexResponse := exchangeWithRetry(t, client, apexRequest, srv.Address())
	if apexResponse.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("expected SOA query for apex to succeed, got %d", apexResponse.Rcode)
	}
	if len(apexResponse.Answer) != 1 {
		t.Fatalf("expected one SOA answer for apex, got %d", len(apexResponse.Answer))
	}
	if _, ok := apexResponse.Answer[0].(*dnsprotocol.SOA); !ok {
		t.Fatalf("expected SOA answer for apex, got %#v", apexResponse.Answer[0])
	}

	subdomainRequest := new(dnsprotocol.Msg)
	subdomainRequest.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeSOA)
	subdomainResponse := exchangeWithRetry(t, client, subdomainRequest, srv.Address())
	if subdomainResponse.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("expected SOA query for non-apex existing name to succeed, got %d", subdomainResponse.Rcode)
	}
	if len(subdomainResponse.Answer) != 0 {
		t.Fatalf("expected no SOA answer for non-apex name, got %#v", subdomainResponse.Answer)
	}
}

func TestServiceServeAnswersSOAForDerivedZoneApexWithoutExactRecord(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
			"node.charon.lthn": {
				A: []string{"10.10.10.11"},
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
	request.SetQuestion("charon.lthn.", dnsprotocol.TypeSOA)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("expected SOA query for derived apex to succeed, got %d", response.Rcode)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected one SOA answer for derived apex, got %d", len(response.Answer))
	}
	if _, ok := response.Answer[0].(*dnsprotocol.SOA); !ok {
		t.Fatalf("expected SOA answer for derived apex, got %#v", response.Answer[0])
	}
}

func TestServiceServeAnswersSOAForWildcardOnlyDerivedZoneApex(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"*.charon.lthn": {
				A: []string{"10.0.0.1"},
			},
		},
	})

	srv, err := service.Serve("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("expected server to start: %v", err)
	}
	defer func() {
		_ = srv.Close()
	}()

	client := dnsprotocol.Client{}
	request := new(dnsprotocol.Msg)
	request.SetQuestion("charon.lthn.", dnsprotocol.TypeSOA)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("expected SOA query for wildcard-derived apex to succeed, got %d", response.Rcode)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected one SOA answer for wildcard-derived apex, got %d", len(response.Answer))
	}
	if _, ok := response.Answer[0].(*dnsprotocol.SOA); !ok {
		t.Fatalf("expected SOA answer for wildcard-derived apex, got %#v", response.Answer[0])
	}
}

func TestServiceServeAnswersNSForDerivedZoneApexWithoutExactRecord(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
			"node.charon.lthn": {
				A: []string{"10.10.10.11"},
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
	request.SetQuestion("charon.lthn.", dnsprotocol.TypeNS)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("expected NS query for derived apex to succeed, got %d", response.Rcode)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected one NS answer for derived apex, got %d", len(response.Answer))
	}
	ns, ok := response.Answer[0].(*dnsprotocol.NS)
	if !ok {
		t.Fatalf("expected NS answer for derived apex, got %#v", response.Answer[0])
	}
	if ns.Ns != "ns.charon.lthn." {
		t.Fatalf("expected synthesized apex NS, got %q", ns.Ns)
	}
}

func TestServiceServeAnswersNSForWildcardOnlyDerivedZoneApex(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"*.gateway.charon.lthn": {
				A: []string{"10.0.0.1"},
			},
		},
	})

	srv, err := service.Serve("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("expected server to start: %v", err)
	}
	defer func() {
		_ = srv.Close()
	}()

	client := dnsprotocol.Client{}
	request := new(dnsprotocol.Msg)
	request.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeNS)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("expected NS query for wildcard-derived apex to succeed, got %d", response.Rcode)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("expected one NS answer for wildcard-derived apex, got %d", len(response.Answer))
	}
	ns, ok := response.Answer[0].(*dnsprotocol.NS)
	if !ok {
		t.Fatalf("expected NS answer for wildcard-derived apex, got %#v", response.Answer[0])
	}
	if ns.Ns != "ns.gateway.charon.lthn." {
		t.Fatalf("expected synthesized wildcard-derived apex NS, got %q", ns.Ns)
	}
}

func TestServiceResolveAllSynthesizesNSForDerivedZoneApex(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
			"node.charon.lthn": {
				AAAA: []string{"2600:1f1c:7f0:4f01::2"},
			},
		},
	})

	result, ok := service.ResolveAll("charon.lthn")
	if !ok {
		t.Fatal("expected derived zone apex to resolve")
	}
	if len(result.NS) != 1 || result.NS[0] != "ns.charon.lthn" {
		t.Fatalf("expected synthesized apex NS, got %#v", result.NS)
	}
}

func TestServiceResolveAllSynthesizesNSForWildcardOnlyDerivedZoneApex(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"*.charon.lthn": {
				A: []string{"10.0.0.1"},
			},
		},
	})

	result, ok := service.ResolveAll("charon.lthn")
	if !ok {
		t.Fatal("expected wildcard-derived zone apex to resolve")
	}
	if len(result.A) != 0 || len(result.AAAA) != 0 || len(result.TXT) != 0 {
		t.Fatalf("expected no A/AAAA/TXT values for derived wildcard apex, got %#v", result)
	}
	if len(result.NS) != 1 || result.NS[0] != "ns.charon.lthn" {
		t.Fatalf("expected synthesized NS from wildcard-derived apex, got %#v", result.NS)
	}
}

func TestServiceResolveAllReturnsStableShapeForDerivedZoneApex(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
			"node.charon.lthn": {
				AAAA: []string{"2600:1f1c:7f0:4f01::2"},
			},
		},
	})

	result, ok := service.ResolveAll("charon.lthn")
	if !ok {
		t.Fatal("expected derived zone apex to resolve")
	}
	if result.A == nil || result.AAAA == nil || result.TXT == nil || result.NS == nil {
		t.Fatalf("expected stable slice fields for derived apex, got %#v", result)
	}
	if len(result.A) != 0 || len(result.AAAA) != 0 || len(result.TXT) != 0 {
		t.Fatalf("expected empty value arrays for derived apex, got %#v", result)
	}
	if len(result.NS) != 1 || result.NS[0] != "ns.charon.lthn" {
		t.Fatalf("expected synthesized apex NS, got %#v", result.NS)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("expected derived apex payload to marshal: %v", err)
	}
	if string(raw) != `{"a":[],"aaaa":[],"txt":[],"ns":["ns.charon.lthn"]}` {
		t.Fatalf("expected stable JSON shape for derived apex, got %s", raw)
	}
}

func TestServiceResolveAllReturnsEmptyArraysForMissingRecordValues(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
			"node.charon.lthn": {
				AAAA: []string{"2600:1f1c:7f0:4f01::2"},
			},
		},
	})

	result, ok := service.ResolveAll("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected record to resolve")
	}
	if result.AAAA == nil || len(result.AAAA) != 0 {
		t.Fatalf("expected empty AAAA slice, got %#v", result.AAAA)
	}
	if result.TXT == nil || len(result.TXT) != 0 {
		t.Fatalf("expected empty TXT slice, got %#v", result.TXT)
	}
	if result.NS == nil || len(result.NS) != 0 {
		t.Fatalf("expected empty NS slice, got %#v", result.NS)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("expected result to marshal: %v", err)
	}
	if string(raw) != `{"a":["10.10.10.10"],"aaaa":[],"txt":[],"ns":[]}` {
		t.Fatalf("expected empty arrays in JSON, got %s", raw)
	}
}

func TestServiceResolveAllReturnsEmptyArraysForMissingName(t *testing.T) {
	service := NewService(ServiceOptions{})

	result, ok := service.ResolveAll("missing.charon.lthn")
	if !ok {
		t.Fatal("expected missing name to still return the array-shaped payload")
	}
	if len(result.A) != 0 || len(result.AAAA) != 0 || len(result.TXT) != 0 || len(result.NS) != 0 {
		t.Fatalf("expected empty arrays for missing name, got %#v", result)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("expected result to marshal: %v", err)
	}
	if string(raw) != `{"a":[],"aaaa":[],"txt":[],"ns":[]}` {
		t.Fatalf("expected empty arrays in JSON, got %s", raw)
	}
}

func TestServiceResolveAllIncludesDNSSECRecords(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A:      []string{"10.10.10.10"},
				DS:     []string{"60485 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"},
				DNSKEY: []string{"257 3 13 AA=="},
				RRSIG:  []string{"A 8 2 3600 20260101000000 20250101000000 12345 gateway.charon.lthn. AA=="},
			},
		},
	})

	result, ok := service.ResolveAll("gateway.charon.lthn")
	if !ok {
		t.Fatal("expected dnssec record to resolve")
	}
	if len(result.A) != 1 || result.A[0] != "10.10.10.10" {
		t.Fatalf("unexpected A records in dns.resolve.all payload: %#v", result.A)
	}
	if len(result.DS) != 1 || result.DS[0] != "60485 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Fatalf("expected DS payload in resolve.all, got %#v", result.DS)
	}
	if len(result.DNSKEY) != 1 || result.DNSKEY[0] != "257 3 13 AA==" {
		t.Fatalf("expected DNSKEY payload in resolve.all, got %#v", result.DNSKEY)
	}
	if len(result.RRSIG) != 1 || result.RRSIG[0] != "A 8 2 3600 20260101000000 20250101000000 12345 gateway.charon.lthn. AA==" {
		t.Fatalf("expected RRSIG payload in resolve.all, got %#v", result.RRSIG)
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

func TestServiceServeReturnsNoErrorWhenTypeIsMissing(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
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
	request.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeTXT)
	response := exchangeWithRetry(t, client, request, srv.Address())
	if response.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("expected NOERROR for existing name without TXT records, got %d", response.Rcode)
	}
	if len(response.Answer) != 0 {
		t.Fatalf("expected empty answer for missing TXT record, got %#v", response.Answer)
	}
}

func TestServiceHandleActionResolveAndTXTAndAll(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A:    []string{"10.10.10.10"},
				AAAA: []string{"2600:1f1c:7f0:4f01::1"},
				TXT:  []string{"v=lthn1 type=gateway"},
				NS:   []string{"ns.charon.lthn"},
			},
		},
	})

	addresses, ok, err := service.HandleAction(ActionResolve, map[string]any{
		"name": "gateway.charon.lthn",
	})
	if err != nil {
		t.Fatalf("unexpected resolve action error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolve action to return a record")
	}
	payload, ok := addresses.(ResolveAddressResult)
	if !ok {
		t.Fatalf("expected ResolveAddressResult payload, got %T", addresses)
	}
	if len(payload.Addresses) != 2 || payload.Addresses[0] != "10.10.10.10" || payload.Addresses[1] != "2600:1f1c:7f0:4f01::1" {
		t.Fatalf("unexpected resolve result: %#v", payload.Addresses)
	}

	txtPayload, ok, err := service.HandleAction(ActionResolveTXT, map[string]any{
		"name": "gateway.charon.lthn",
	})
	if err != nil {
		t.Fatalf("unexpected txt action error: %v", err)
	}
	if !ok {
		t.Fatal("expected txt action to return a record")
	}
	txts, ok := txtPayload.(ResolveTXTResult)
	if !ok {
		t.Fatalf("expected ResolveTXTResult payload, got %T", txtPayload)
	}
	if len(txts.TXT) != 1 || txts.TXT[0] != "v=lthn1 type=gateway" {
		t.Fatalf("unexpected txt result: %#v", txts.TXT)
	}

	allPayload, ok, err := service.HandleAction(ActionResolveAll, map[string]any{
		"name": "gateway.charon.lthn",
	})
	if err != nil {
		t.Fatalf("unexpected resolve.all action error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolve.all action to return a record")
	}
	all, ok := allPayload.(ResolveAllResult)
	if !ok {
		t.Fatalf("expected ResolveAllResult payload, got %T", allPayload)
	}
	if len(all.NS) != 1 || all.NS[0] != "ns.charon.lthn" {
		t.Fatalf("unexpected resolve.all result: %#v", all)
	}
}

func TestServiceHandleActionServeDefaultsPortFromServiceConfiguration(t *testing.T) {
	desiredPort := pickFreeTCPPort(t)
	service := NewService(ServiceOptions{
		DNSPort: desiredPort,
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	payload, ok, err := service.HandleAction(ActionServe, map[string]any{
		"bind": "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("expected serve action to default port when omitted: %v", err)
	}
	if !ok {
		t.Fatal("expected serve action to succeed with omitted port")
	}
	dnsServer, ok := payload.(*DNSServer)
	if !ok {
		t.Fatalf("expected DNSServer payload, got %T", payload)
	}
	if dnsServer == nil {
		t.Fatal("expected dns server from serve action")
	}

	_, port, err := net.SplitHostPort(dnsServer.DNSAddress())
	if err != nil {
		t.Fatalf("expected service address to include port: %v", err)
	}
	if port != strconv.Itoa(desiredPort) {
		t.Fatalf("expected configured DNS port %d, got %q", desiredPort, port)
	}

	_ = dnsServer.Close()
}

func TestServiceHandleActionServeHealthPortStartsRuntime(t *testing.T) {
	desiredHealthPort := pickFreeTCPPort(t)
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	payload, ok, err := service.HandleAction(ActionServe, map[string]any{
		"bind":        "127.0.0.1",
		"health_port": desiredHealthPort,
	})
	if err != nil {
		t.Fatalf("expected serve action with health port to start: %v", err)
	}
	if !ok {
		t.Fatal("expected serve action to succeed with health port")
	}
	runtime, ok := payload.(*ServiceRuntime)
	if !ok {
		t.Fatalf("expected ServiceRuntime payload, got %T", payload)
	}
	if runtime == nil {
		t.Fatal("expected service runtime from serve action")
	}
	defer func() {
		_ = runtime.Close()
	}()

	if runtime.DNSAddress() == "" {
		t.Fatal("expected dns address from runtime")
	}
	if runtime.HealthAddress() == "" {
		t.Fatal("expected health address from runtime")
	}

	_, runtimeHealthPort, err := net.SplitHostPort(runtime.HealthAddress())
	if err != nil {
		t.Fatalf("expected health address to include port: %v", err)
	}
	if runtimeHealthPort != strconv.Itoa(desiredHealthPort) {
		t.Fatalf("expected requested health port %d, got %q", desiredHealthPort, runtimeHealthPort)
	}
	_, _, err = net.SplitHostPort(runtime.DNSAddress())
	if err != nil {
		t.Fatalf("expected dns address to include port: %v", err)
	}

	response, err := http.Get("http://" + runtime.HealthAddress() + "/health")
	if err != nil {
		t.Fatalf("expected health endpoint to respond: %v", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected health status: %d", response.StatusCode)
	}
}

func TestServiceHandleActionServeDefaultsToConfiguredHTTPPort(t *testing.T) {
	httpPort := pickFreeTCPPort(t)
	dnsPort := pickFreeTCPPort(t)
	service := NewService(ServiceOptions{
		DNSPort:  dnsPort,
		HTTPPort: httpPort,
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	payload, ok, err := service.HandleAction(ActionServe, map[string]any{
		"bind": "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("expected serve action to start runtime with default http port: %v", err)
	}
	if !ok {
		t.Fatal("expected serve action to succeed")
	}
	runtime, ok := payload.(*ServiceRuntime)
	if !ok {
		t.Fatalf("expected ServiceRuntime payload, got %T", payload)
	}
	if runtime == nil {
		t.Fatal("expected runtime from serve action")
	}
	defer func() {
		_ = runtime.Close()
	}()

	_, dnsPortStr, err := net.SplitHostPort(runtime.DNSAddress())
	if err != nil {
		t.Fatalf("expected dns address to include port: %v", err)
	}
	if dnsPortStr != strconv.Itoa(dnsPort) {
		t.Fatalf("expected configured DNS port %d, got %q", dnsPort, dnsPortStr)
	}
	_, healthPortStr, err := net.SplitHostPort(runtime.HealthAddress())
	if err != nil {
		t.Fatalf("expected health address to include port: %v", err)
	}
	if healthPortStr != strconv.Itoa(httpPort) {
		t.Fatalf("expected configured health port %d, got %q", httpPort, healthPortStr)
	}
}

func TestServiceHandleActionServeCamelCaseAliases(t *testing.T) {
	dnsPort := pickFreeTCPPort(t)
	healthPort := pickFreeTCPPort(t)
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	payload, ok, err := service.HandleAction(ActionServe, map[string]any{
		"bindAddress": "127.0.0.1",
		"dnsPort":     dnsPort,
		"healthPort":  healthPort,
	})
	if err != nil {
		t.Fatalf("expected serve action to start runtime with camelCase args: %v", err)
	}
	if !ok {
		t.Fatal("expected serve action to succeed with camelCase args")
	}

	runtime, ok := payload.(*ServiceRuntime)
	if !ok {
		t.Fatalf("expected ServiceRuntime payload, got %T", payload)
	}
	if runtime == nil {
		t.Fatal("expected service runtime from serve action")
	}
	defer func() {
		_ = runtime.Close()
	}()

	_, runtimeDNSPort, err := net.SplitHostPort(runtime.DNSAddress())
	if err != nil {
		t.Fatalf("expected dns address to include port: %v", err)
	}
	if runtimeDNSPort != strconv.Itoa(dnsPort) {
		t.Fatalf("expected dns port %d, got %q", dnsPort, runtimeDNSPort)
	}

	_, runtimeHealthPort, err := net.SplitHostPort(runtime.HealthAddress())
	if err != nil {
		t.Fatalf("expected health address to include port: %v", err)
	}
	if runtimeHealthPort != strconv.Itoa(healthPort) {
		t.Fatalf("expected health port %d, got %q", healthPort, runtimeHealthPort)
	}
}

func TestServiceHandleActionServeSnakeCaseAliases(t *testing.T) {
	dnsPort := pickFreeTCPPort(t)
	healthPort := pickFreeTCPPort(t)
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	payload, ok, err := service.HandleAction(ActionServe, map[string]any{
		"bind":       "127.0.0.1",
		"dns_port":   dnsPort,
		"healthPort": healthPort,
	})
	if err != nil {
		t.Fatalf("expected serve action to start runtime with snake_case dns port: %v", err)
	}
	if !ok {
		t.Fatal("expected serve action to succeed with snake_case dns port")
	}

	runtime, ok := payload.(*ServiceRuntime)
	if !ok {
		t.Fatalf("expected ServiceRuntime payload, got %T", payload)
	}
	if runtime == nil {
		t.Fatal("expected service runtime from serve action")
	}
	defer func() {
		_ = runtime.Close()
	}()

	_, runtimeDNSPort, err := net.SplitHostPort(runtime.DNSAddress())
	if err != nil {
		t.Fatalf("expected dns address to include port: %v", err)
	}
	if runtimeDNSPort != strconv.Itoa(dnsPort) {
		t.Fatalf("expected dns port %d, got %q", dnsPort, runtimeDNSPort)
	}
}

func TestServiceResolveServePortDefaultsToStandardDNSPort(t *testing.T) {
	service := NewService(ServiceOptions{})
	if service.ResolveDNSPort() != DefaultDNSPort {
		t.Fatalf("expected ResolveDNSPort to default to standard DNS port %d, got %d", DefaultDNSPort, service.ResolveDNSPort())
	}
	if service.DNSPort() != DefaultDNSPort {
		t.Fatalf("expected DNSPort alias to return the standard DNS port %d, got %d", DefaultDNSPort, service.DNSPort())
	}
	if service.DNSListenPort() != DefaultDNSPort {
		t.Fatalf("expected DNSListenPort to return the standard DNS port %d, got %d", DefaultDNSPort, service.DNSListenPort())
	}
	if service.resolveServePort() != DefaultDNSPort {
		t.Fatalf("expected internal resolveServePort helper to return the standard DNS port %d, got %d", DefaultDNSPort, service.resolveServePort())
	}
	if service.resolveDNSListenPort() != DefaultDNSPort {
		t.Fatalf("expected internal resolveDNSListenPort helper to return the standard DNS port %d, got %d", DefaultDNSPort, service.resolveDNSListenPort())
	}

	customPort := 1053
	customService := NewService(ServiceOptions{
		DNSPort: customPort,
	})
	if customService.ResolveDNSPort() != customPort {
		t.Fatalf("expected ResolveDNSPort to honor configured DNSPort, got %d", customService.ResolveDNSPort())
	}
	if customService.DNSPort() != customPort {
		t.Fatalf("expected DNSPort alias to honor configured DNSPort, got %d", customService.DNSPort())
	}
	if customService.DNSListenPort() != customPort {
		t.Fatalf("expected DNSListenPort to honor configured DNSPort, got %d", customService.DNSListenPort())
	}
	if customService.resolveServePort() != customPort {
		t.Fatalf("expected resolveServePort helper to honor configured DNSPort, got %d", customService.resolveServePort())
	}
	if customService.resolveDNSListenPort() != customPort {
		t.Fatalf("expected resolveDNSListenPort helper to honor configured DNSPort, got %d", customService.resolveDNSListenPort())
	}
}

func TestServiceResolveHTTPPortDefaultsToStandardHTTPPort(t *testing.T) {
	service := NewService(ServiceOptions{})
	if service.ResolveHTTPPort() != DefaultHTTPPort {
		t.Fatalf("expected ResolveHTTPPort to default to %d, got %d", DefaultHTTPPort, service.ResolveHTTPPort())
	}
	if service.HTTPPort() != DefaultHTTPPort {
		t.Fatalf("expected HTTPPort alias to return default %d, got %d", DefaultHTTPPort, service.HTTPPort())
	}
	if service.HTTPListenPort() != DefaultHTTPPort {
		t.Fatalf("expected HTTPListenPort to return default %d, got %d", DefaultHTTPPort, service.HTTPListenPort())
	}
	if service.resolveHTTPPort() != DefaultHTTPPort {
		t.Fatalf("expected resolveHTTPPort helper to return default %d, got %d", DefaultHTTPPort, service.resolveHTTPPort())
	}
	if service.resolveHTTPListenPort() != DefaultHTTPPort {
		t.Fatalf("expected resolveHTTPListenPort helper to return default %d, got %d", DefaultHTTPPort, service.resolveHTTPListenPort())
	}

	customPort := 5555
	customService := NewService(ServiceOptions{
		HTTPPort: customPort,
	})
	if customService.ResolveHTTPPort() != customPort {
		t.Fatalf("expected ResolveHTTPPort to honor configured HTTPPort, got %d", customService.ResolveHTTPPort())
	}
	if customService.HTTPPort() != customPort {
		t.Fatalf("expected HTTPPort alias to honor configured HTTPPort, got %d", customService.HTTPPort())
	}
	if customService.HTTPListenPort() != customPort {
		t.Fatalf("expected HTTPListenPort to honor configured HTTPPort, got %d", customService.HTTPListenPort())
	}
	if customService.resolveHTTPPort() != customPort {
		t.Fatalf("expected resolveHTTPPort helper to honor configured HTTPPort, got %d", customService.resolveHTTPPort())
	}
	if customService.resolveHTTPListenPort() != customPort {
		t.Fatalf("expected resolveHTTPListenPort helper to honor configured HTTPPort, got %d", customService.resolveHTTPListenPort())
	}
}

func TestServiceActionNamesExposeAllRFCActions(t *testing.T) {
	service := NewService(ServiceOptions{})

	names := service.ActionNames()
	expected := []string{
		ActionResolve,
		ActionResolveTXT,
		ActionResolveAll,
		ActionReverse,
		ActionServe,
		ActionHealth,
		ActionDiscover,
	}

	if len(names) != len(expected) {
		t.Fatalf("expected %d action names, got %d: %#v", len(expected), len(names), names)
	}
	for i, name := range expected {
		if names[i] != name {
			t.Fatalf("unexpected action name at %d: got %q want %q", i, names[i], name)
		}
	}
}

func TestServiceRegisterActionsPublishesAllActionsInOrder(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	registrar := &actionRecorder{}
	service.RegisterActions(registrar)

	expected := service.ActionNames()
	if len(registrar.names) != len(expected) {
		t.Fatalf("expected %d registered actions, got %d: %#v", len(expected), len(registrar.names), registrar.names)
	}
	for index, name := range expected {
		if registrar.names[index] != name {
			t.Fatalf("unexpected registered action at %d: got %q want %q", index, registrar.names[index], name)
		}
	}

	payload, ok, err := registrar.handlers[ActionResolve](map[string]any{"name": "gateway.charon.lthn"})
	if err != nil {
		t.Fatalf("unexpected registered handler error: %v", err)
	}
	if !ok {
		t.Fatal("expected registered handler to resolve")
	}
	result, ok := payload.(ResolveAddressResult)
	if !ok || len(result.Addresses) != 1 || result.Addresses[0] != "10.10.10.10" {
		t.Fatalf("unexpected registered handler payload: %#v", payload)
	}
}

func TestServiceRegisterActionsUsesContextAwareRegistrarWhenAvailable(t *testing.T) {
	type ctxKey string

	registrar := &actionContextRecorder{}
	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(ctx context.Context) ([]string, error) {
			value, ok := ctx.Value(ctxKey("discover-token")).(string)
			if !ok {
				t.Fatal("expected discover context to be preserved")
			}
			if value != "preserved" {
				t.Fatalf("unexpected discover context value: %q", value)
			}
			return []string{"gateway.charon.lthn"}, nil
		},
		HSDClient: NewHSDClient(HSDClientOptions{
			URL: "http://127.0.0.1:1",
		}),
	})

	service.RegisterActions(registrar)

	invoke, ok := registrar.contextHandlers[ActionDiscover]
	if !ok {
		t.Fatal("expected context-aware registrar to receive discover action")
	}

	ctx := context.WithValue(context.Background(), ctxKey("discover-token"), "preserved")
	payload, succeeded, err := invoke(ctx, nil)
	if err == nil {
		t.Fatal("expected discover action to fail without an HSD endpoint")
	}
	if succeeded {
		t.Fatal("expected discover action to report failure")
	}
	if payload != nil {
		t.Fatalf("expected no payload on failure, got %#v", payload)
	}
	if !strings.Contains(err.Error(), "connection refused") && !strings.Contains(err.Error(), "hsd rpc request failed") {
		t.Fatalf("expected discover action to propagate the HSD client error, got %v", err)
	}
}

func TestNewServiceWithRegistrarBuildsAndRegistersInOneStep(t *testing.T) {
	registrar := &actionRecorder{}
	service := NewServiceWithRegistrar(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	}, registrar)

	if service == nil {
		t.Fatal("expected service to be built")
	}

	if len(registrar.names) != len(service.ActionNames()) {
		t.Fatalf("expected helper to register all actions, got %#v", registrar.names)
	}

	payload, ok, err := registrar.handlers[ActionResolve](map[string]any{"name": "gateway.charon.lthn"})
	if err != nil {
		t.Fatalf("unexpected registered handler error: %v", err)
	}
	if !ok {
		t.Fatal("expected registered handler to resolve")
	}
	result, ok := payload.(ResolveAddressResult)
	if !ok || len(result.Addresses) != 1 || result.Addresses[0] != "10.10.10.10" {
		t.Fatalf("unexpected registered handler payload: %#v", payload)
	}
}

func TestNewServiceAutoRegistersActionsWhenRegistrarIsConfigured(t *testing.T) {
	registrar := &actionRecorder{}
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
		ActionRegistrar: registrar,
	})

	if service == nil {
		t.Fatal("expected service to be built")
	}

	expected := service.ActionNames()
	if len(registrar.names) != len(expected) {
		t.Fatalf("expected constructor to auto-register %d actions, got %d: %#v", len(expected), len(registrar.names), registrar.names)
	}
	for index, name := range expected {
		if registrar.names[index] != name {
			t.Fatalf("unexpected auto-registered action at %d: got %q want %q", index, registrar.names[index], name)
		}
	}
}

func TestServiceActionDefinitionsHaveInvokers(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.10"},
			},
		},
	})

	definitions := service.ActionDefinitions()
	if len(definitions) == 0 {
		t.Fatal("expected action definitions")
	}

	for _, definition := range definitions {
		if definition.Name == "" {
			t.Fatal("expected action definition name")
		}
		if definition.Invoke == nil {
			t.Fatalf("expected action invoke for %s", definition.Name)
		}
	}

	resolveDefinition := definitions[0]
	if resolveDefinition.Name != ActionResolve {
		t.Fatalf("expected first action definition to be %s, got %s", ActionResolve, resolveDefinition.Name)
	}
	payload, ok, err := resolveDefinition.Invoke(map[string]any{
		"name": "gateway.charon.lthn",
	})
	if err != nil {
		t.Fatalf("unexpected action invoke error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolve action definition to return a record")
	}
	result, ok := payload.(ResolveAddressResult)
	if !ok || len(result.Addresses) != 1 || result.Addresses[0] != "10.10.10.10" {
		t.Fatalf("unexpected resolve payload: %#v", payload)
	}

	handlePayload, handleOK, handleErr := service.HandleAction(ActionResolve, map[string]any{
		"name": "gateway.charon.lthn",
	})
	if handleErr != nil || !handleOK {
		t.Fatalf("unexpected handle action result: ok=%t err=%v", handleOK, handleErr)
	}
	if handleResult, ok := handlePayload.(ResolveAddressResult); !ok || len(handleResult.Addresses) != 1 || handleResult.Addresses[0] != "10.10.10.10" {
		t.Fatalf("unexpected handle action payload: %#v", handlePayload)
	}
}

func TestServiceHandleActionReverseHealthServeAndDiscover(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}
		switch payload.Method {
		case "getblockchaininfo":
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "discover-root",
				},
			})
		case "getnameresource":
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"a": []string{"10.10.10.10"},
				},
			})
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{"gateway.charon.lthn"}, nil
		},
		HSDClient: NewHSDClient(HSDClientOptions{
			URL: server.URL,
		}),
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				A: []string{"10.10.10.20"},
			},
		},
	})

	reversePayload, ok, err := service.HandleAction(ActionReverse, map[string]any{
		"ip": "10.10.10.20",
	})
	if err != nil {
		t.Fatalf("unexpected reverse action error: %v", err)
	}
	if !ok {
		t.Fatal("expected reverse action to return a record")
	}
	reverse, ok := reversePayload.(ReverseLookupResult)
	if !ok {
		t.Fatalf("expected ReverseLookupResult payload, got %T", reversePayload)
	}
	if len(reverse.Names) != 1 || reverse.Names[0] != "gateway.charon.lthn" {
		t.Fatalf("unexpected reverse result: %#v", reverse.Names)
	}

	healthPayload, ok, err := service.HandleAction(ActionHealth, nil)
	if err != nil {
		t.Fatalf("unexpected health action error: %v", err)
	}
	if !ok {
		t.Fatal("expected health action payload")
	}
	health, ok := healthPayload.(HealthResult)
	if !ok {
		t.Fatalf("expected HealthResult payload, got %T", healthPayload)
	}
	if health.Status != "ready" {
		t.Fatalf("unexpected health payload: %#v", health)
	}

	srvPayload, ok, err := service.HandleAction(ActionServe, map[string]any{
		"bind": "127.0.0.1",
		"port": 0,
	})
	if err != nil {
		t.Fatalf("unexpected serve action error: %v", err)
	}
	if !ok {
		t.Fatal("expected serve action to start server")
	}
	dnsServer, ok := srvPayload.(*DNSServer)
	if !ok {
		t.Fatalf("expected DNSServer payload, got %T", srvPayload)
	}
	if dnsServer.DNSAddress() == "" {
		t.Fatal("expected server address from serve action")
	}
	if dnsServer.Address() != dnsServer.DNSAddress() {
		t.Fatalf("expected Address and DNSAddress to match, got %q and %q", dnsServer.Address(), dnsServer.DNSAddress())
	}
	_ = dnsServer.Close()

	discoverPayload, ok, err := service.HandleAction(ActionDiscover, nil)
	if err != nil {
		t.Fatalf("unexpected discover action error: %v", err)
	}
	if discoverPayload == nil || !ok {
		t.Fatal("expected discover action payload")
	}
	if !ok {
		t.Fatal("expected discover action to succeed")
	}
	discoverHealth, ok := discoverPayload.(HealthResult)
	if !ok {
		t.Fatalf("expected discover action payload HealthResult, got %T", discoverPayload)
	}
	if discoverHealth.TreeRoot != "discover-root" {
		t.Fatalf("expected discover to refresh tree root, got %#v", discoverHealth.TreeRoot)
	}
}

func TestServiceHandleActionContextPassesThroughToDiscover(t *testing.T) {
	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(ctx context.Context) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		HSDClient: NewHSDClient(HSDClientOptions{
			URL: "http://127.0.0.1:1",
		}),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	payload, ok, err := service.HandleActionContext(ctx, ActionDiscover, nil)
	if err == nil {
		t.Fatal("expected discover action to fail for a canceled context")
	}
	if ok {
		t.Fatal("expected discover action to report failure")
	}
	if payload != nil {
		t.Fatalf("expected no payload on context cancellation, got %#v", payload)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation error, got %v", err)
	}
}

func TestServiceDiscoverAliasesFallsBackToMainchainAliasRPCUsingHSDURL(t *testing.T) {
	var chainAliasCalls int32
	var treeRootCalls int32
	var nameResourceCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}

		switch payload.Method {
		case "get_all_alias_details":
			atomic.AddInt32(&chainAliasCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": []any{
					map[string]any{
						"hns": "gateway.charon.lthn",
					},
				},
			})
		case "getblockchaininfo":
			atomic.AddInt32(&treeRootCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "inferred-mainchain-root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&nameResourceCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"a": []string{"10.10.10.10"},
				},
			})
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		HSDURL:  server.URL,
		Records: map[string]NameRecords{},
	})

	if err := service.DiscoverAliases(context.Background()); err != nil {
		t.Fatalf("expected discover to use inferred mainchain URL: %v", err)
	}

	record, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(record.A) != 1 || record.A[0] != "10.10.10.10" {
		t.Fatalf("expected discovered gateway A record, got %#v (ok=%t)", record, ok)
	}

	if atomic.LoadInt32(&chainAliasCalls) != 1 {
		t.Fatalf("expected one mainchain alias call, got %d", atomic.LoadInt32(&chainAliasCalls))
	}
	if atomic.LoadInt32(&treeRootCalls) != 1 {
		t.Fatalf("expected one tree-root call, got %d", atomic.LoadInt32(&treeRootCalls))
	}
	if atomic.LoadInt32(&nameResourceCalls) != 1 {
		t.Fatalf("expected one name-resource call, got %d", atomic.LoadInt32(&nameResourceCalls))
	}
}

func TestNewServiceBuildsMainchainAliasClientByDefault(t *testing.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{},
	})

	if service.mainchainAliasClient == nil {
		t.Fatal("expected default mainchain alias client when none is provided")
	}
	if got := service.mainchainAliasClient.baseURL; got != "http://127.0.0.1:14037" {
		t.Fatalf("expected fallback mainchain alias client URL %q, got %q", "http://127.0.0.1:14037", got)
	}
}

func TestStringActionValueTrimsWhitespaceForRequiredArgument(t *testing.T) {
	value, err := stringActionValue(map[string]any{
		actionArgName: "  gateway.charon.lthn  ",
	}, actionArgName)
	if err != nil {
		t.Fatalf("expected trimmed string value, got error: %v", err)
	}
	if value != "gateway.charon.lthn" {
		t.Fatalf("expected trimmed value, got %q", value)
	}
}

func TestStringActionValueRejectsWhitespaceOnlyArgument(t *testing.T) {
	_, err := stringActionValue(map[string]any{
		actionArgName: "   ",
	}, actionArgName)
	if err == nil {
		t.Fatal("expected whitespace-only argument to be rejected")
	}
}

func TestParseActionAliasListAcceptsMapSliceTypedAny(t *testing.T) {
	aliases, err := parseActionAliasList([]map[string]any{
		{
			"hns": "gateway.charon.lthn",
		},
		{
			"name":    "node",
			"comment": "node alias hns=node.charon.lthn",
		},
	})
	if err != nil {
		t.Fatalf("unexpected typed map slice parse error: %v", err)
	}
	if len(aliases) != 2 {
		t.Fatalf("expected two aliases, got %#v", aliases)
	}
	if aliases[0] != "gateway.charon.lthn" || aliases[1] != "node.charon.lthn" {
		t.Fatalf("unexpected alias parsing result: %#v", aliases)
	}
}

func TestParseActionAliasListAcceptsStringMapSlice(t *testing.T) {
	aliases, err := parseActionAliasList([]map[string]string{
		{
			"hns": "gateway.charon.lthn",
		},
		{
			"name":    "node",
			"comment": "node alias hns=node.charon.lthn",
		},
	})
	if err != nil {
		t.Fatalf("unexpected typed string map slice parse error: %v", err)
	}
	if len(aliases) != 2 {
		t.Fatalf("expected two aliases, got %#v", aliases)
	}
	if aliases[0] != "gateway.charon.lthn" || aliases[1] != "node.charon.lthn" {
		t.Fatalf("unexpected alias parsing result: %#v", aliases)
	}
}

func TestParseActionAliasListAcceptsAliasMap(t *testing.T) {
	aliases, err := parseActionAliasList(map[string]any{
		"gateway": "gateway.charon.lthn",
		"node":    "node.charon.lthn",
	})
	if err != nil {
		t.Fatalf("unexpected alias map parse error: %v", err)
	}
	if len(aliases) != 2 {
		t.Fatalf("expected two aliases, got %#v", aliases)
	}
	if aliases[0] != "gateway.charon.lthn" || aliases[1] != "node.charon.lthn" {
		t.Fatalf("unexpected alias map parsing result: %#v", aliases)
	}
}

func TestNormalizeNameAndNormalizeIPArePublicWrappers(t *testing.T) {
	normalizedName := NormalizeName(" Gateway.Charon.lthn. ")
	if normalizedName != "gateway.charon.lthn" {
		t.Fatalf("expected normalized DNS name, got %q", normalizedName)
	}

	normalizedIP := NormalizeIP(" 2001:0DB8::0001 ")
	if normalizedIP != "2001:db8::1" {
		t.Fatalf("expected normalized IP, got %q", normalizedIP)
	}

	if NormalizeIP("invalid") != "" {
		t.Fatal("expected invalid IP to normalize to empty string")
	}
}

func TestIntActionValueRejectsNonIntegerFloat(t *testing.T) {
	_, err := intActionValue(map[string]any{
		actionArgPort: 53.9,
	}, actionArgPort)
	if err == nil {
		t.Fatal("expected non-integer float value to be rejected")
	}
}

func TestIntActionValueAcceptsWholeFloat(t *testing.T) {
	value, err := intActionValue(map[string]any{
		actionArgPort: float64(53),
	}, actionArgPort)
	if err != nil {
		t.Fatalf("expected whole float to be accepted: %v", err)
	}
	if value != 53 {
		t.Fatalf("expected value 53, got %d", value)
	}
}

func TestServiceMethodsHandleNilReceiverWithoutPanicking(t *testing.T) {
	var service *Service

	if _, ok := service.Resolve("gateway.charon.lthn"); ok {
		t.Fatal("expected nil service Resolve to return not found")
	}
	if _, _, ok := service.ResolveWithMatch("gateway.charon.lthn"); ok {
		t.Fatal("expected nil service ResolveWithMatch to return not found")
	}
	if _, ok := service.ResolveReverse("10.10.10.10"); ok {
		t.Fatal("expected nil service ResolveReverse to return not found")
	}
	if _, ok := service.ResolveReverseNames("10.10.10.10"); ok {
		t.Fatal("expected nil service ResolveReverseNames to return not found")
	}
	if got := service.ResolveDNSPort(); got != DefaultDNSPort {
		t.Fatalf("expected default DNS port from nil service, got %d", got)
	}
	if got := service.ResolveHTTPPort(); got != DefaultHTTPPort {
		t.Fatalf("expected default HTTP port from nil service, got %d", got)
	}
	if got := service.Health().Status; got != "not_ready" {
		t.Fatalf("expected nil service health status \"not_ready\", got %q", got)
	}
}

func TestServiceServeReturnsErrorOnNilReceiver(t *testing.T) {
	var service *Service
	if _, err := service.Serve("127.0.0.1", 0); err == nil {
		t.Fatal("expected Serve to fail for nil service receiver")
	}
	if _, err := service.ServeAll("127.0.0.1", 0, 0); err == nil {
		t.Fatal("expected ServeAll to fail for nil service receiver")
	}
	if _, err := service.ServeConfigured("127.0.0.1"); err == nil {
		t.Fatal("expected ServeConfigured to fail for nil service receiver")
	}
}

type actionRecorder struct {
	names    []string
	handlers map[string]func(map[string]any) (any, bool, error)
}

func (recorder *actionRecorder) RegisterAction(name string, invoke func(map[string]any) (any, bool, error)) {
	if recorder.handlers == nil {
		recorder.handlers = map[string]func(map[string]any) (any, bool, error){}
	}
	recorder.names = append(recorder.names, name)
	recorder.handlers[name] = invoke
}

type actionContextRecorder struct {
	names           []string
	contextHandlers map[string]func(context.Context, map[string]any) (any, bool, error)
}

func (recorder *actionContextRecorder) RegisterAction(name string, invoke func(map[string]any) (any, bool, error)) {
	if recorder.contextHandlers == nil {
		recorder.contextHandlers = map[string]func(context.Context, map[string]any) (any, bool, error){}
	}
	recorder.names = append(recorder.names, name)
	recorder.contextHandlers[name] = func(ctx context.Context, values map[string]any) (any, bool, error) {
		return invoke(values)
	}
}

func (recorder *actionContextRecorder) RegisterActionContext(name string, invoke func(context.Context, map[string]any) (any, bool, error)) {
	if recorder.contextHandlers == nil {
		recorder.contextHandlers = map[string]func(context.Context, map[string]any) (any, bool, error){}
	}
	recorder.names = append(recorder.names, name)
	recorder.contextHandlers[name] = invoke
}

type actionCallerFunc func(context.Context, string, map[string]any) (any, bool, error)

func (caller actionCallerFunc) CallAction(ctx context.Context, name string, values map[string]any) (any, bool, error) {
	return caller(ctx, name, values)
}

type actionRegistrarAndCaller struct {
	actionRecorder
	actionCall func(context.Context, string, map[string]any) (any, bool, error)
}

func (registrar *actionRegistrarAndCaller) CallAction(ctx context.Context, name string, values map[string]any) (any, bool, error) {
	if registrar.actionCall == nil {
		return nil, false, nil
	}
	return registrar.actionCall(ctx, name, values)
}
