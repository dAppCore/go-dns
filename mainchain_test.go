package dns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestMainchainClientGetsAliasDetailsAndParsesHNSComments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}
		if payload.Method != "get_all_alias_details" {
			t.Fatalf("expected method get_all_alias_details, got %s", payload.Method)
		}

		responseWriter.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(responseWriter).Encode(map[string]any{
			"result": []any{
				map[string]any{
					"name":    "gateway",
					"comment": "gateway alias hns=gateway.charon.lthn",
				},
				map[string]any{
					"hns":  "node.charon.lthn",
					"name": "node",
				},
			},
		})
	}))
	defer server.Close()

	client := NewMainchainAliasClient(MainchainClientOptions{
		URL: server.URL,
	})

	aliases, err := client.GetAllAliasDetails(context.Background())
	if err != nil {
		t.Fatalf("unexpected get_all_alias_details error: %v", err)
	}
	if len(aliases) != 2 {
		t.Fatalf("expected 2 aliases, got %d", len(aliases))
	}
	if aliases[0] != "gateway.charon.lthn" || aliases[1] != "node.charon.lthn" {
		t.Fatalf("unexpected aliases: %#v", aliases)
	}
}

func TestServiceDiscoverFromMainchainAliasesUsesMainchainThenHSD(t *testing.T) {
	var chainCalls int32
	var hsdTreeRootCalls int32
	var hsdAliasCalls int32

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
			atomic.AddInt32(&hsdTreeRootCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "chain-root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&hsdAliasCalls, 1)
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

	service := NewService(ServiceOptions{})
	chainClient := NewMainchainAliasClient(MainchainClientOptions{
		URL: server.URL,
	})
	hsdClient := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	if err := service.DiscoverFromMainchainAliases(context.Background(), chainClient, hsdClient); err != nil {
		t.Fatalf("expected discover from mainchain aliases: %v", err)
	}

	gateway, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(gateway.A) != 1 || gateway.A[0] != "10.10.10.10" {
		t.Fatalf("expected gateway A record, got %#v (ok=%t)", gateway, ok)
	}
	node, ok := service.Resolve("node.charon.lthn")
	if !ok || len(node.AAAA) != 1 || node.AAAA[0] != "2600:1f1c:7f0:4f01::2" {
		t.Fatalf("expected node AAAA record, got %#v (ok=%t)", node, ok)
	}

	if chainCalls != 1 || hsdTreeRootCalls != 1 || hsdAliasCalls != 2 {
		t.Fatalf("expected chain=1 tree-root=1 name-resource=2, got %d %d %d", chainCalls, hsdTreeRootCalls, hsdAliasCalls)
	}
}

func TestServiceDiscoverFromMainchainAliasesFallsBackToConfiguredMainchainClient(t *testing.T) {
	var chainCalls int32
	var hsdTreeRootCalls int32
	var hsdAliasCalls int32

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
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": []any{
					map[string]any{
						"hns": "gateway.charon.lthn",
					},
				},
			})
		case "getblockchaininfo":
			atomic.AddInt32(&hsdTreeRootCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "chain-root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&hsdAliasCalls, 1)
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
		MainchainAliasClient: NewMainchainAliasClient(MainchainClientOptions{
			URL: server.URL,
		}),
	})
	hsdClient := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	if err := service.DiscoverFromMainchainAliases(context.Background(), nil, hsdClient); err != nil {
		t.Fatalf("expected discover from configured mainchain client: %v", err)
	}

	record, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(record.A) != 1 || record.A[0] != "10.10.10.10" {
		t.Fatalf("expected gateway A record from configured client, got %#v (ok=%t)", record, ok)
	}

	if atomic.LoadInt32(&chainCalls) != 1 || atomic.LoadInt32(&hsdTreeRootCalls) != 1 || atomic.LoadInt32(&hsdAliasCalls) != 1 {
		t.Fatalf(
			"expected chain=1 tree-root=1 name-resource=1, got %d %d %d",
			atomic.LoadInt32(&chainCalls),
			atomic.LoadInt32(&hsdTreeRootCalls),
			atomic.LoadInt32(&hsdAliasCalls),
		)
	}
}

func TestServiceDiscoverFromMainchainAliasesUsesActionDiscoverer(t *testing.T) {
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
				t.Fatalf("unexpected alias lookup: %#v", payload.Params)
			}
		default:
			t.Fatalf("unexpected method: %s", payload.Method)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{"gateway.charon.lthn", "node.charon.lthn"}, nil
		},
	})
	hsdClient := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	if err := service.DiscoverFromMainchainAliases(context.Background(), nil, hsdClient); err != nil {
		t.Fatalf("expected discover from chain alias discoverer: %v", err)
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
		t.Fatalf("expected tree-root and name-resource calls, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&treeRootCalls), atomic.LoadInt32(&nameResourceCalls))
	}
}

func TestServiceDiscoverFromMainchainAliasesFallsBackToFallbackChainAliasDiscoverer(t *testing.T) {
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
				t.Fatalf("unexpected alias lookup: %#v", payload.Params)
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
		FallbackChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return []string{"gateway.charon.lthn", "node.charon.lthn"}, nil
		},
	})
	hsdClient := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	if err := service.DiscoverFromMainchainAliases(context.Background(), nil, hsdClient); err != nil {
		t.Fatalf("expected fallback discover from chain alias discoverer: %v", err)
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
		t.Fatalf("expected fallback discovery to still trigger RPC calls, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&treeRootCalls), atomic.LoadInt32(&nameResourceCalls))
	}
}

func TestServiceDiscoverFromMainchainAliasesFallsBackToChainClientWhenFallbackChainAliasDiscovererFails(t *testing.T) {
	var chainAliasCalls int32
	var fallbackChainAliasCalls int32
	var hsdTreeRootCalls int32
	var hsdAliasCalls int32

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
			atomic.AddInt32(&hsdTreeRootCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "chain-root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&hsdAliasCalls, 1)
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

	chainClient := NewMainchainAliasClient(MainchainClientOptions{
		URL: server.URL,
	})
	hsdClient := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})
	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return nil, errors.New("blockchain service unavailable")
		},
		FallbackChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			atomic.AddInt32(&fallbackChainAliasCalls, 1)
			return nil, errors.New("fallback chain alias unavailable")
		},
	})

	if err := service.DiscoverFromMainchainAliases(context.Background(), chainClient, hsdClient); err != nil {
		t.Fatalf("expected fallback chain alias discoverer to fail over to chain client: %v", err)
	}

	gateway, ok := service.Resolve("gateway.charon.lthn")
	if !ok || len(gateway.A) != 1 || gateway.A[0] != "10.10.10.10" {
		t.Fatalf("expected gateway A record, got %#v (ok=%t)", gateway, ok)
	}
	node, ok := service.Resolve("node.charon.lthn")
	if !ok || len(node.AAAA) != 1 || node.AAAA[0] != "2600:1f1c:7f0:4f01::2" {
		t.Fatalf("expected node AAAA record, got %#v (ok=%t)", node, ok)
	}

	if atomic.LoadInt32(&fallbackChainAliasCalls) != 1 {
		t.Fatalf("expected fallback chain alias discoverer to run and fail, got %d", atomic.LoadInt32(&fallbackChainAliasCalls))
	}
	if atomic.LoadInt32(&chainAliasCalls) != 1 {
		t.Fatalf("expected chain alias client fallback to be used, got %d", atomic.LoadInt32(&chainAliasCalls))
	}
	if atomic.LoadInt32(&hsdTreeRootCalls) != 1 || atomic.LoadInt32(&hsdAliasCalls) != 2 {
		t.Fatalf("expected fallback to still trigger RPC calls, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&hsdTreeRootCalls), atomic.LoadInt32(&hsdAliasCalls))
	}
}

func TestServiceDiscoverFromMainchainAliasesFallsBackToChainClientWhenPrimaryDiscovererFails(t *testing.T) {
	var chainAliasCalls int32
	var hsdTreeRootCalls int32
	var hsdAliasCalls int32

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
			atomic.AddInt32(&hsdTreeRootCalls, 1)
			responseWriter.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"tree_root": "chain-root-1",
				},
			})
		case "getnameresource":
			atomic.AddInt32(&hsdAliasCalls, 1)
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

	chainClient := NewMainchainAliasClient(MainchainClientOptions{
		URL: server.URL,
	})
	hsdClient := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})
	service := NewService(ServiceOptions{
		ChainAliasDiscoverer: func(_ context.Context) ([]string, error) {
			return nil, errors.New("blockchain service unavailable")
		},
	})

	if err := service.DiscoverFromMainchainAliases(context.Background(), chainClient, hsdClient); err != nil {
		t.Fatalf("expected chain alias discover fallback to chain client: %v", err)
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
		t.Fatalf("expected chain alias to be queried once, got %d", atomic.LoadInt32(&chainAliasCalls))
	}
	if atomic.LoadInt32(&hsdTreeRootCalls) != 1 || atomic.LoadInt32(&hsdAliasCalls) != 2 {
		t.Fatalf("expected one tree-root and two name-resource RPC calls, got treeRoot=%d nameResource=%d", atomic.LoadInt32(&hsdTreeRootCalls), atomic.LoadInt32(&hsdAliasCalls))
	}
}

func TestExtractAliasFromCommentParsesCaseInsensitiveHNSPrefix(t *testing.T) {
	got := extractAliasFromComment("gateway alias HNS=gateway.charon.lthn")
	if got != "gateway.charon.lthn" {
		t.Fatalf("expected gateway.charon.lthn, got %s", got)
	}
}
