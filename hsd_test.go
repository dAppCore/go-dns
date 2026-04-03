package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHSDClientGetNameResourceCallsRPCAndParsesResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}
		if payload.Method != "getnameresource" {
			t.Fatalf("expected method getnameresource, got %s", payload.Method)
		}
		if len(payload.Params) != 1 || payload.Params[0] != "gateway.lthn" {
			t.Fatalf("expected single name param gateway.lthn, got %#v", payload.Params)
		}

		responseWriter.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(responseWriter).Encode(map[string]any{
			"result": map[string]any{
				"a":    []string{"10.10.10.10"},
				"aaaa": []string{"2600:1f1c:7f0:4f01::1"},
				"txt":  []string{"v=lthn1 type=gateway"},
				"ns":   []string{"ns.gateway.lthn"},
			},
		})
	}))
	defer server.Close()

	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	record, err := client.GetNameResource(context.Background(), "gateway.lthn")
	if err != nil {
		t.Fatalf("unexpected getnameresource error: %v", err)
	}
	if len(record.A) != 1 || record.A[0] != "10.10.10.10" {
		t.Fatalf("unexpected A result: %#v", record.A)
	}
	if len(record.AAAA) != 1 || record.AAAA[0] != "2600:1f1c:7f0:4f01::1" {
		t.Fatalf("unexpected AAAA result: %#v", record.AAAA)
	}
}

func TestHSDClientGetNameResourceParsesWrappedRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}
		if payload.Method != "getnameresource" {
			t.Fatalf("expected method getnameresource, got %s", payload.Method)
		}

		responseWriter.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(responseWriter).Encode(map[string]any{
			"result": map[string]any{
				"records": map[string]any{
					"a":   []string{"10.11.11.11"},
					"txt": []string{"v=lthn1 type=node"},
				},
			},
		})
	}))
	defer server.Close()

	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	record, err := client.GetNameResource(context.Background(), "node.lthn")
	if err != nil {
		t.Fatalf("unexpected getnameresource error: %v", err)
	}
	if len(record.A) != 1 || record.A[0] != "10.11.11.11" {
		t.Fatalf("unexpected wrapped A result: %#v", record.A)
	}
	if len(record.TXT) != 1 || record.TXT[0] != "v=lthn1 type=node" {
		t.Fatalf("unexpected wrapped TXT result: %#v", record.TXT)
	}
}

func TestHSDClientGetBlockchainInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}
		if payload.Method != "getblockchaininfo" {
			t.Fatalf("expected method getblockchaininfo, got %s", payload.Method)
		}

		responseWriter.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(responseWriter).Encode(map[string]any{
			"result": map[string]any{
				"tree_root": "f00dc0de",
			},
		})
	}))
	defer server.Close()

	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	info, err := client.GetBlockchainInfo(context.Background())
	if err != nil {
		t.Fatalf("unexpected getblockchaininfo error: %v", err)
	}
	if info.TreeRoot != "f00dc0de" {
		t.Fatalf("unexpected tree root: %q", info.TreeRoot)
	}
}

func TestServiceDiscoverWithHSDRefreshesRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		var payload struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("unexpected request payload: %v", err)
		}
		switch payload.Params[0] {
		case "gateway.lthn":
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"a": []string{"10.10.10.10"},
				},
			})
		case "node.lthn":
			_ = json.NewEncoder(responseWriter).Encode(map[string]any{
				"result": map[string]any{
					"aaaa": []string{"2600:1f1c:7f0:4f01::2"},
				},
			})
		default:
			t.Fatalf("unexpected alias query: %#v", payload.Params)
			responseWriter.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	service := NewService(ServiceOptions{})
	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	if err := service.DiscoverWithHSD(context.Background(), []string{"gateway.lthn", "node.lthn"}, client); err != nil {
		t.Fatalf("expected discovery via hsd to succeed: %v", err)
	}

	if resolved, ok := service.Resolve("gateway.lthn"); !ok || len(resolved.A) != 1 || resolved.A[0] != "10.10.10.10" {
		t.Fatalf("expected refreshed A record, got %#v (ok=%t)", resolved, ok)
	}
	if resolved, ok := service.Resolve("node.lthn"); !ok || len(resolved.AAAA) != 1 || resolved.AAAA[0] != "2600:1f1c:7f0:4f01::2" {
		t.Fatalf("expected refreshed AAAA record, got %#v (ok=%t)", resolved, ok)
	}
}
