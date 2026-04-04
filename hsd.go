package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultHSDJSONRPCVersion = "1.0"

// HSDClientOptions configures JSON-RPC access to HSD.
//
//	client := dns.NewHSDClient(dns.HSDClientOptions{
//		URL:      "http://127.0.0.1:14037",
//		Username: "user",
//		Password: "pass",
//	})
type HSDClientOptions struct {
	URL        string
	Username   string
	Password   string
	HTTPClient *http.Client
}

type HSDClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

type HSDNameResourceResult struct {
	Address NameRecords
}

type HSDBlockchainInfo struct {
	TreeRoot string
}

type HSDRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int    `json:"id"`
}

type HSDRPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *HSDRPCError    `json:"error"`
}

type HSDRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (err *HSDRPCError) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("hsd rpc error (%d): %s", err.Code, err.Message)
}

// NewHSDClient builds a client for HSD JSON-RPC.
//
//	client := dns.NewHSDClient(dns.HSDClientOptions{
//		URL:      "http://127.0.0.1:14037",
//		Username: "user",
//		Password: "pass",
//	})
func NewHSDClient(options HSDClientOptions) *HSDClient {
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{}
	}

	baseURL := strings.TrimSpace(options.URL)
	if baseURL == "" {
		baseURL = "http://127.0.0.1:14037"
	}

	return &HSDClient{
		baseURL:    baseURL,
		username:   options.Username,
		password:   options.Password,
		httpClient: client,
	}
}

func (client *HSDClient) GetNameResource(ctx context.Context, name string) (NameRecords, error) {
	normalized := strings.TrimSpace(name)
	if normalized == "" {
		return NameRecords{}, errors.New("name is required for getnameresource")
	}

	request := HSDRPCRequest{
		JSONRPC: defaultHSDJSONRPCVersion,
		Method:  "getnameresource",
		Params:  []any{normalized},
		ID:      1,
	}

	var result NameRecords
	raw, err := client.call(ctx, request)
	if err != nil {
		return result, err
	}

	result, err = parseHSDNameResource(raw)
	if err != nil {
		return NameRecords{}, err
	}

	return result, nil
}

func (client *HSDClient) GetBlockchainInfo(ctx context.Context) (HSDBlockchainInfo, error) {
	var result HSDBlockchainInfo
	request := HSDRPCRequest{
		JSONRPC: defaultHSDJSONRPCVersion,
		Method:  "getblockchaininfo",
		Params:  []any{},
		ID:      1,
	}

	raw, err := client.call(ctx, request)
	if err != nil {
		return result, err
	}

	result, err = parseHSDBlockchainInfo(raw)
	if err != nil {
		return HSDBlockchainInfo{}, err
	}

	return result, nil
}

func (client *HSDClient) call(ctx context.Context, request HSDRPCRequest) (json.RawMessage, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")

	if client.username != "" || client.password != "" {
		httpRequest.Header.Set("Authorization", "Basic "+basicAuthToken(client.username, client.password))
	}

	response, err := client.httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("hsd rpc request failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var decoded HSDRPCResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return nil, err
	}

	if decoded.Error != nil {
		return nil, decoded.Error
	}

	return decoded.Result, nil
}

func parseHSDNameResource(raw json.RawMessage) (NameRecords, error) {
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return NameRecords{}, err
	}

	if recordsRaw, ok := wrapper["records"]; ok {
		result, err := parseHSDNameResourceRecords(recordsRaw)
		if err != nil {
			return NameRecords{}, err
		}
		return result, nil
	}

	if hasHSDNameResourceField(wrapper) {
		result, err := parseHSDNameResourceRecords(raw)
		if err != nil {
			return NameRecords{}, err
		}
		return result, nil
	}

	return NameRecords{}, errors.New("unable to parse getnameresource result")
}

func getCaseInsensitiveRecordField(fields map[string]json.RawMessage, key string) json.RawMessage {
	if fields == nil {
		return nil
	}
	for candidate, value := range fields {
		if strings.EqualFold(candidate, key) {
			return value
		}
	}
	return nil
}

func parseHSDNameResourceRecords(raw json.RawMessage) (NameRecords, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return NameRecords{}, err
	}

	a, err := parseHSDRecordValue(getCaseInsensitiveRecordField(fields, "a"))
	if err != nil {
		return NameRecords{}, err
	}
	aaaa, err := parseHSDRecordValue(getCaseInsensitiveRecordField(fields, "aaaa"))
	if err != nil {
		return NameRecords{}, err
	}
	txt, err := parseHSDRecordValue(getCaseInsensitiveRecordField(fields, "txt"))
	if err != nil {
		return NameRecords{}, err
	}
	ns, err := parseHSDRecordValue(getCaseInsensitiveRecordField(fields, "ns"))
	if err != nil {
		return NameRecords{}, err
	}
	ds, err := parseHSDRecordValue(getCaseInsensitiveRecordField(fields, "ds"))
	if err != nil {
		return NameRecords{}, err
	}
	dnsKey, err := parseHSDRecordValue(getCaseInsensitiveRecordField(fields, "dnskey"))
	if err != nil {
		return NameRecords{}, err
	}
	rrSig, err := parseHSDRecordValue(getCaseInsensitiveRecordField(fields, "rrsig"))
	if err != nil {
		return NameRecords{}, err
	}

	return NameRecords{
		A:      a,
		AAAA:   aaaa,
		TXT:    txt,
		NS:     ns,
		DS:     ds,
		DNSKEY: dnsKey,
		RRSIG:  rrSig,
	}, nil
}

func hasHSDNameResourceField(fields map[string]json.RawMessage) bool {
	if len(fields) == 0 {
		return false
	}

	return getCaseInsensitiveRecordField(fields, "a") != nil ||
		getCaseInsensitiveRecordField(fields, "aaaa") != nil ||
		getCaseInsensitiveRecordField(fields, "txt") != nil ||
		getCaseInsensitiveRecordField(fields, "ns") != nil ||
		getCaseInsensitiveRecordField(fields, "ds") != nil ||
		getCaseInsensitiveRecordField(fields, "dnskey") != nil ||
		getCaseInsensitiveRecordField(fields, "rrsig") != nil
}

func parseHSDRecordValue(raw json.RawMessage) ([]string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}

	if trimmed := bytes.TrimSpace(raw); bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}

	var values []string
	if err := json.Unmarshal(raw, &values); err == nil {
		return values, nil
	}

	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		if value == "" {
			return nil, nil
		}
		return []string{value}, nil
	}

	return nil, fmt.Errorf("unable to parse DNS record field")
}

func parseHSDBlockchainInfo(raw json.RawMessage) (HSDBlockchainInfo, error) {
	var info HSDBlockchainInfo
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return info, err
	}

	if rawTreeRoot, ok := wrapper["tree_root"]; ok {
		if err := json.Unmarshal(rawTreeRoot, &info.TreeRoot); err != nil {
			return HSDBlockchainInfo{}, err
		}
		return info, nil
	}

	if rawTreeRoot, ok := wrapper["treeRoot"]; ok {
		if err := json.Unmarshal(rawTreeRoot, &info.TreeRoot); err != nil {
			return HSDBlockchainInfo{}, err
		}
		return info, nil
	}

	return HSDBlockchainInfo{}, errors.New("unable to parse getblockchaininfo result")
}

func basicAuthToken(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}
