package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// MainchainClientOptions configures JSON-RPC access to the main chain alias source.
//
//	client := dns.NewMainchainAliasClient(dns.MainchainClientOptions{
//		URL:      "http://127.0.0.1:14037",
//		Username: "user",
//		Password: "pass",
//	})
type MainchainClientOptions struct {
	URL        string
	Username   string
	Password   string
	HTTPClient *http.Client
}

// MainchainAliasClientConfiguration is the explicit long-form alias for MainchainClientOptions.
//
//	client := dns.NewMainchainAliasClientFromConfiguration(dns.MainchainAliasClientConfiguration{
//		URL:      "http://127.0.0.1:14037",
//		Username: "user",
//		Password: "pass",
//	})
type MainchainAliasClientConfiguration = MainchainClientOptions

// MainchainAliasClientConfig is kept for compatibility with older call sites.
//
// Deprecated: use MainchainAliasClientConfiguration instead.
type MainchainAliasClientConfig = MainchainClientOptions

type MainchainAliasClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

type MainchainRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int    `json:"id"`
}

type MainchainRPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *HSDRPCError    `json:"error"`
}

// NewMainchainAliasClient builds a client for alias discovery on the main chain.
//
//	client := dns.NewMainchainAliasClient(dns.MainchainClientOptions{
//		URL:      "http://127.0.0.1:14037",
//		Username: "user",
//		Password: "pass",
//	})
func NewMainchainAliasClient(options MainchainClientOptions) *MainchainAliasClient {
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{}
	}

	baseURL := strings.TrimSpace(options.URL)
	if baseURL == "" {
		baseURL = "http://127.0.0.1:14037"
	}

	return &MainchainAliasClient{
		baseURL:    baseURL,
		username:   options.Username,
		password:   options.Password,
		httpClient: client,
	}
}

// NewMainchainAliasClientFromOptions is the explicit long-form constructor name.
//
//	client := dns.NewMainchainAliasClientFromOptions(dns.MainchainClientOptions{
//		URL:      "http://127.0.0.1:14037",
//		Username: "user",
//		Password: "pass",
//	})
func NewMainchainAliasClientFromOptions(options MainchainClientOptions) *MainchainAliasClient {
	return NewMainchainAliasClient(options)
}

// NewMainchainAliasClientFromConfiguration is the explicit constructor name for the main-chain configuration alias.
//
//	client := dns.NewMainchainAliasClientFromConfiguration(dns.MainchainAliasClientConfiguration{
//		URL:      "http://127.0.0.1:14037",
//		Username: "user",
//		Password: "pass",
//	})
func NewMainchainAliasClientFromConfiguration(options MainchainAliasClientConfiguration) *MainchainAliasClient {
	return NewMainchainAliasClient(options)
}

// GetAllAliasDetails returns alias names mapped to HNS DNS names.
//
//	client := dns.NewMainchainAliasClient(dns.MainchainClientOptions{
//		URL:      "http://127.0.0.1:14037",
//		Username: "user",
//		Password: "pass",
//	})
//	aliases, err := client.GetAllAliasDetails(context.Background())
func (client *MainchainAliasClient) GetAllAliasDetails(ctx context.Context) ([]string, error) {
	request := MainchainRPCRequest{
		JSONRPC: defaultHSDJSONRPCVersion,
		Method:  "get_all_alias_details",
		Params:  []any{},
		ID:      1,
	}

	raw, err := client.call(ctx, request)
	if err != nil {
		return nil, err
	}

	aliases, err := parseMainchainAliases(raw)
	if err != nil {
		return nil, err
	}
	return aliases, nil
}

func (client *MainchainAliasClient) call(ctx context.Context, request MainchainRPCRequest) (json.RawMessage, error) {
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
		return nil, fmt.Errorf("mainchain rpc request failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var decoded MainchainRPCResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return nil, err
	}

	if decoded.Error != nil {
		return nil, decoded.Error
	}

	return decoded.Result, nil
}

func parseMainchainAliases(raw json.RawMessage) ([]string, error) {
	var result []string
	if err := json.Unmarshal(raw, &result); err == nil {
		return normalizeAliasList(result), nil
	}

	var wrappedResult map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrappedResult); err == nil {
		if aliasesRaw, ok := wrappedResult["aliases"]; ok {
			return parseMainchainAliases(aliasesRaw)
		}
		if resultRaw, ok := wrappedResult["result"]; ok {
			return parseMainchainAliases(resultRaw)
		}
	}

	var rawRecords []json.RawMessage
	if err := json.Unmarshal(raw, &rawRecords); err != nil {
		return nil, errors.New("unable to parse get_all_alias_details result")
	}

	parsed := make([]string, 0, len(rawRecords))
	for _, rawRecord := range rawRecords {
		next, err := parseMainchainAliasRecord(rawRecord)
		if err != nil {
			return nil, err
		}
		if next != "" {
			parsed = append(parsed, next)
		}
	}
	return normalizeAliasList(parsed), nil
}

func parseMainchainAliasRecord(raw json.RawMessage) (string, error) {
	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		return normalizeName(name), nil
	}

	var record map[string]json.RawMessage
	if err := json.Unmarshal(raw, &record); err != nil {
		return "", err
	}

	var candidate string
	if value, ok := record["hns"]; ok {
		if hns, ok := decodeString(value); ok {
			candidate = normalizeName(hns)
		}
	}
	if candidate == "" && record["comment"] != nil {
		if comment, ok := decodeString(record["comment"]); ok {
			candidate = extractAliasFromComment(comment)
		}
	}
	if candidate == "" && record["alias"] != nil {
		if alias, ok := decodeString(record["alias"]); ok {
			candidate = normalizeName(alias)
		}
	}
	if candidate == "" && record["name"] != nil {
		if alias, ok := decodeString(record["name"]); ok {
			candidate = normalizeName(alias)
		}
	}
	return candidate, nil
}

func decodeString(raw json.RawMessage) (string, bool) {
	var value string
	if len(raw) == 0 {
		return "", false
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func extractAliasFromComment(comment string) string {
	for _, token := range strings.Fields(comment) {
		switch normalizedToken := strings.ToLower(token); {
		case strings.HasPrefix(normalizedToken, "hns="):
			alias := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(normalizedToken, "hns="), ";"))
			if alias != "" {
				return normalizeName(alias)
			}
		}
	}

	commentLower := strings.ToLower(comment)
	if marker := strings.Index(commentLower, "hns="); marker >= 0 {
		alias := comment[marker+4:]
		if trim := strings.IndexAny(alias, " ;,"); trim >= 0 {
			alias = alias[:trim]
		}
		alias = strings.TrimSpace(alias)
		alias = strings.TrimSuffix(alias, ";")
		return normalizeName(alias)
	}

	return ""
}

func normalizeAliasList(raw []string) []string {
	seen := map[string]bool{}
	normalized := make([]string, 0, len(raw))
	for _, name := range raw {
		next := normalizeName(name)
		if next == "" {
			continue
		}
		if seen[next] {
			continue
		}
		seen[next] = true
		normalized = append(normalized, next)
	}
	slices.Sort(normalized)
	return normalized
}
