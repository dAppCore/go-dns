package dns

import (
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

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL, io.NopCloser(io.Reader(strings.NewReader(string(body)))))
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
	var result NameRecords
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return result, err
	}

	if recordsRaw, ok := wrapper["records"]; ok {
		if err := json.Unmarshal(recordsRaw, &result); err != nil {
			return NameRecords{}, err
		}
		return result, nil
	}

	if _, ok := wrapper["a"]; ok {
		if err := json.Unmarshal(raw, &result); err != nil {
			return NameRecords{}, err
		}
		return result, nil
	}

	var wrapped struct {
		A    []string `json:"a"`
		AAAA []string `json:"aaaa"`
		TXT  []string `json:"txt"`
		NS   []string `json:"ns"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		result = NameRecords{
			A:    wrapped.A,
			AAAA: wrapped.AAAA,
			TXT:  wrapped.TXT,
			NS:   wrapped.NS,
		}
		return result, nil
	}

	return NameRecords{}, errors.New("unable to parse getnameresource result")
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
