package dns

import (
	"context"
	"encoding/json"
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

