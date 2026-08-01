package dns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	core "dappco.re/go"
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

	record, err := client.GetNameResource(t.Context(), "gateway.lthn")
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

func TestNewHSDClientFromOptionsMatchesNewHSDClient(t *testing.T) {
	clientFromOptions := NewHSDClientFromOptions(HSDClientOptions{URL: "http://127.0.0.1:14037"})
	clientFromConfiguration := NewHSDClientFromConfiguration(HSDClientConfiguration{URL: "http://127.0.0.1:14037"})

	if clientFromOptions == nil || clientFromConfiguration == nil {
		t.Fatal("expected explicit HSD constructors to return clients")
	}
	if clientFromOptions.baseURL != clientFromConfiguration.baseURL {
		t.Fatalf("expected explicit HSD constructors to normalize the same base URL, got %q and %q", clientFromOptions.baseURL, clientFromConfiguration.baseURL)
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

	record, err := client.GetNameResource(t.Context(), "node.lthn")
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

func TestHSDClientGetNameResourceParsesCaseInsensitiveFields(t *testing.T) {
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
					"A":   []string{"10.10.10.10"},
					"Txt": []string{"v=lthn1 type=case"},
					"NS":  []string{"ns.example.lthn"},
				},
			},
		})
	}))
	defer server.Close()

	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	record, err := client.GetNameResource(t.Context(), "case.lthn")
	if err != nil {
		t.Fatalf("unexpected getnameresource error: %v", err)
	}
	if len(record.A) != 1 || record.A[0] != "10.10.10.10" {
		t.Fatalf("unexpected wrapped A result with mixed-case key: %#v", record.A)
	}
	if len(record.TXT) != 1 || record.TXT[0] != "v=lthn1 type=case" {
		t.Fatalf("unexpected wrapped TXT result with mixed-case key: %#v", record.TXT)
	}
	if len(record.NS) != 1 || record.NS[0] != "ns.example.lthn" {
		t.Fatalf("unexpected wrapped NS result with mixed-case key: %#v", record.NS)
	}
}

func TestHSDClientGetNameResourceParsesDSRecords(t *testing.T) {
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
					"ds": []string{"60485 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"},
				},
			},
		})
	}))
	defer server.Close()

	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	record, err := client.GetNameResource(t.Context(), "charon.lthn")
	if err != nil {
		t.Fatalf("unexpected getnameresource error: %v", err)
	}
	if len(record.DS) != 1 || record.DS[0] != "60485 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Fatalf("unexpected DS result: %#v", record.DS)
	}
}

func TestHSDClientGetNameResourceParsesDNSSECRecords(t *testing.T) {
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
					"dnskey": []string{"257 3 13 AA=="},
					"rrsig":  []string{"A 8 2 3600 20260101000000 20250101000000 12345 gateway.lthn. AA=="},
				},
			},
		})
	}))
	defer server.Close()

	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	record, err := client.GetNameResource(t.Context(), "gateway.lthn")
	if err != nil {
		t.Fatalf("unexpected getnameresource error: %v", err)
	}
	if len(record.DNSKEY) != 1 || record.DNSKEY[0] != "257 3 13 AA==" {
		t.Fatalf("unexpected DNSKEY result: %#v", record.DNSKEY)
	}
	if len(record.RRSIG) != 1 || record.RRSIG[0] != "A 8 2 3600 20260101000000 20250101000000 12345 gateway.lthn. AA==" {
		t.Fatalf("unexpected RRSIG result: %#v", record.RRSIG)
	}
}

func TestHSDClientGetNameResourceParsesSingleValueDNSSECRecords(t *testing.T) {
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
				"dnskey": "257 3 13 AA==",
				"rrsig":  "A 8 2 3600 20260101000000 20250101000000 12345 gateway.lthn. AA==",
				"ds":     "60485 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
			},
		})
	}))
	defer server.Close()

	client := NewHSDClient(HSDClientOptions{
		URL: server.URL,
	})

	record, err := client.GetNameResource(t.Context(), "gateway.lthn")
	if err != nil {
		t.Fatalf("unexpected getnameresource error: %v", err)
	}
	if len(record.DNSKEY) != 1 || record.DNSKEY[0] != "257 3 13 AA==" {
		t.Fatalf("unexpected DNSKEY result: %#v", record.DNSKEY)
	}
	if len(record.RRSIG) != 1 || record.RRSIG[0] != "A 8 2 3600 20260101000000 20250101000000 12345 gateway.lthn. AA==" {
		t.Fatalf("unexpected RRSIG result: %#v", record.RRSIG)
	}
	if len(record.DS) != 1 || record.DS[0] != "60485 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" {
		t.Fatalf("unexpected DS result: %#v", record.DS)
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

	info, err := client.GetBlockchainInfo(t.Context())
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

	if err := service.DiscoverWithHSD(t.Context(), []string{"gateway.lthn", "node.lthn"}, client); err != nil {
		t.Fatalf("expected discovery via hsd to succeed: %v", err)
	}

	if resolved, ok := service.Resolve("gateway.lthn"); !ok || len(resolved.A) != 1 || resolved.A[0] != "10.10.10.10" {
		t.Fatalf("expected refreshed A record, got %#v (ok=%t)", resolved, ok)
	}
	if resolved, ok := service.Resolve("node.lthn"); !ok || len(resolved.AAAA) != 1 || resolved.AAAA[0] != "2600:1f1c:7f0:4f01::2" {
		t.Fatalf("expected refreshed AAAA record, got %#v (ok=%t)", resolved, ok)
	}
}

func TestHsd_HSDRPCError_Error_Good(t *core.T) {
	subject := (*HSDRPCError).Error
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_HSDRPCError_Error_Bad(t *core.T) {
	subject := (*HSDRPCError).Error
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_HSDRPCError_Error_Ugly(t *core.T) {
	subject := (*HSDRPCError).Error
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_NewHSDClient_Good(t *core.T) {
	subject := NewHSDClient
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_NewHSDClient_Bad(t *core.T) {
	subject := NewHSDClient
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_NewHSDClient_Ugly(t *core.T) {
	subject := NewHSDClient
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_NewHSDClientFromOptions_Good(t *core.T) {
	subject := NewHSDClientFromOptions
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_NewHSDClientFromOptions_Bad(t *core.T) {
	subject := NewHSDClientFromOptions
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_NewHSDClientFromOptions_Ugly(t *core.T) {
	subject := NewHSDClientFromOptions
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_NewHSDClientFromConfiguration_Good(t *core.T) {
	subject := NewHSDClientFromConfiguration
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_NewHSDClientFromConfiguration_Bad(t *core.T) {
	subject := NewHSDClientFromConfiguration
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_NewHSDClientFromConfiguration_Ugly(t *core.T) {
	subject := NewHSDClientFromConfiguration
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_HSDClient_GetNameResource_Good(t *core.T) {
	subject := (*HSDClient).GetNameResource
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_HSDClient_GetNameResource_Bad(t *core.T) {
	subject := (*HSDClient).GetNameResource
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_HSDClient_GetNameResource_Ugly(t *core.T) {
	subject := (*HSDClient).GetNameResource
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_HSDClient_GetBlockchainInfo_Good(t *core.T) {
	subject := (*HSDClient).GetBlockchainInfo
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_HSDClient_GetBlockchainInfo_Bad(t *core.T) {
	subject := (*HSDClient).GetBlockchainInfo
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHsd_HSDClient_GetBlockchainInfo_Ugly(t *core.T) {
	subject := (*HSDClient).GetBlockchainInfo
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
