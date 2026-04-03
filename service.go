package dns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

const defaultTreeRootCheckInterval = 15 * time.Second

type NameRecords struct {
	A    []string `json:"a"`
	AAAA []string `json:"aaaa"`
	TXT  []string `json:"txt"`
	NS   []string `json:"ns"`
}

type ResolveAllResult struct {
	A    []string `json:"a"`
	AAAA []string `json:"aaaa"`
	TXT  []string `json:"txt"`
	NS   []string `json:"ns"`
}

type ResolveAddressResult struct {
	Addresses []string `json:"addresses"`
}

type ResolveTXTResult struct {
	TXT []string `json:"txt"`
}

type ReverseLookupResult struct {
	Names []string `json:"names"`
}

type Service struct {
	mu                           sync.RWMutex
	records                      map[string]NameRecords
	reverseIndex                 map[string][]string
	treeRoot                     string
	hsdClient                    *HSDClient
	mainchainAliasClient         *MainchainAliasClient
	discoverer                   func() (map[string]NameRecords, error)
	fallbackDiscoverer           func() (map[string]NameRecords, error)
	chainAliasDiscoverer         func(context.Context) ([]string, error)
	fallbackChainAliasDiscoverer func(context.Context) ([]string, error)
	lastTreeRootCheck            time.Time
	chainTreeRoot                string
	treeRootCheckInterval        time.Duration
}

type ServiceOptions struct {
	Records                      map[string]NameRecords
	Discoverer                   func() (map[string]NameRecords, error)
	FallbackDiscoverer           func() (map[string]NameRecords, error)
	MainchainAliasClient          *MainchainAliasClient
	HSDClient                    *HSDClient
	ChainAliasDiscoverer         func(context.Context) ([]string, error)
	FallbackChainAliasDiscoverer func(context.Context) ([]string, error)
	TreeRootCheckInterval        time.Duration
}

func NewService(options ServiceOptions) *Service {
	checkInterval := options.TreeRootCheckInterval
	if checkInterval <= 0 {
		checkInterval = defaultTreeRootCheckInterval
	}

	cached := make(map[string]NameRecords, len(options.Records))
	for name, record := range options.Records {
		cached[normalizeName(name)] = record
	}
	treeRoot := computeTreeRoot(cached)
	return &Service{
		records:                      cached,
		reverseIndex:                 buildReverseIndex(cached),
		treeRoot:                     treeRoot,
		hsdClient:                    options.HSDClient,
		mainchainAliasClient:         options.MainchainAliasClient,
		discoverer:                   options.Discoverer,
		fallbackDiscoverer:           options.FallbackDiscoverer,
		chainAliasDiscoverer:         options.ChainAliasDiscoverer,
		fallbackChainAliasDiscoverer: options.FallbackChainAliasDiscoverer,
		treeRootCheckInterval:        checkInterval,
	}
}

func (service *Service) resolveHSDClient(client *HSDClient) (*HSDClient, error) {
	if client != nil {
		return client, nil
	}
	if service.hsdClient == nil {
		return nil, fmt.Errorf("hsd client is required")
	}
	return service.hsdClient, nil
}

func (service *Service) DiscoverFromChainAliases(ctx context.Context, client *HSDClient) error {
	resolved, err := service.resolveHSDClient(client)
	if err != nil {
		return err
	}

	aliases, err := discoverAliasesWithFallback(
		ctx,
		service.chainAliasDiscoverer,
		service.fallbackChainAliasDiscoverer,
		service.mainchainAliasClient,
	)
	if err != nil {
		return err
	}
	if aliases == nil {
		return nil
	}
	return service.discoverFromChainAliasesUsingTreeRoot(ctx, aliases, resolved)
}

func discoverAliasesWithFallback(
	ctx context.Context,
	discoverer func(context.Context) ([]string, error),
	fallback func(context.Context) ([]string, error),
	mainchainClient *MainchainAliasClient,
) ([]string, error) {
	if discoverer == nil {
		if fallback != nil {
			aliases, err := fallback(ctx)
			if err == nil {
				return aliases, nil
			}
			if mainchainClient == nil {
				return nil, err
			}
			return mainchainClient.GetAllAliasDetails(ctx)
		}
		if mainchainClient == nil {
			return nil, nil
		}
		return mainchainClient.GetAllAliasDetails(ctx)
	}

	aliases, err := discoverer(ctx)
	if err == nil {
		return aliases, nil
	}
	if fallback == nil {
		if mainchainClient == nil {
			return nil, err
		}
		return mainchainClient.GetAllAliasDetails(ctx)
	}

	fallbackAliases, fallbackErr := fallback(ctx)
	if fallbackErr == nil {
		return fallbackAliases, nil
	}
	if mainchainClient == nil {
		return nil, fallbackErr
	}
	return mainchainClient.GetAllAliasDetails(ctx)
}

// DiscoverFromMainchainAliases updates records from main-chain aliases resolved through HSD.
//
//	service.DiscoverFromMainchainAliases(context.Background(), dns.NewMainchainAliasClient(dns.MainchainClientOptions{
//		URL: "http://127.0.0.1:14037",
//	}), dns.NewHSDClient(dns.HSDClientOptions{
//		URL: "http://127.0.0.1:14037",
//	}))
func (service *Service) DiscoverFromMainchainAliases(ctx context.Context, chainClient *MainchainAliasClient, hsdClient *HSDClient) error {
	resolvedHSDClient, err := service.resolveHSDClient(hsdClient)
	if err != nil {
		return err
	}

	aliases, err := discoverAliases(
		ctx,
		func(ctx context.Context) ([]string, error) {
			if service.chainAliasDiscoverer != nil {
				return service.chainAliasDiscoverer(ctx)
			}
			if chainClient != nil {
				return chainClient.GetAllAliasDetails(ctx)
			}
			return nil, nil
		},
		func(ctx context.Context) ([]string, error) {
			if service.fallbackChainAliasDiscoverer != nil {
				return service.fallbackChainAliasDiscoverer(ctx)
			}
			if chainClient != nil && service.chainAliasDiscoverer != nil {
				return chainClient.GetAllAliasDetails(ctx)
			}
			return nil, nil
		},
	)
	if err != nil {
		return err
	}
	if len(aliases) == 0 {
		return nil
	}
	return service.discoverFromChainAliasesUsingTreeRoot(ctx, aliases, resolvedHSDClient)
}

func (service *Service) discoverFromChainAliasesUsingTreeRoot(ctx context.Context, aliases []string, client *HSDClient) error {
	if len(aliases) == 0 {
		return nil
	}

	now := time.Now()
	if service.shouldUseCachedTreeRoot(now) {
		return nil
	}

	info, err := client.GetBlockchainInfo(ctx)
	if err != nil {
		return err
	}

	cachedRoot := service.getChainTreeRoot()
	if cachedRoot != "" && cachedRoot == info.TreeRoot {
		service.recordTreeRootCheck(now)
		return nil
	}

	if err := service.DiscoverWithHSD(ctx, aliases, client); err != nil {
		return err
	}

	service.recordTreeRootState(now, info.TreeRoot)
	return nil
}

func (service *Service) shouldUseCachedTreeRoot(now time.Time) bool {
	service.mu.RLock()
	defer service.mu.RUnlock()
	if service.lastTreeRootCheck.IsZero() {
		return false
	}
	if service.treeRootCheckInterval <= 0 {
		return false
	}
	return now.Sub(service.lastTreeRootCheck) < service.treeRootCheckInterval
}

func (service *Service) getChainTreeRoot() string {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.chainTreeRoot
}

func (service *Service) recordTreeRootCheck(now time.Time) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.lastTreeRootCheck = now
}

func (service *Service) recordTreeRootState(now time.Time, treeRoot string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.lastTreeRootCheck = now
	service.chainTreeRoot = treeRoot
}

func discoverAliases(ctx context.Context, discoverer func(context.Context) ([]string, error), fallback func(context.Context) ([]string, error)) ([]string, error) {
	if discoverer == nil {
		if fallback == nil {
			return nil, nil
		}
		aliases, err := fallback(ctx)
		if err != nil {
			return nil, err
		}
		return aliases, nil
	}

	aliases, err := discoverer(ctx)
	if err != nil {
		if fallback == nil {
			return nil, err
		}
		aliases, err = fallback(ctx)
		if err != nil {
			return nil, err
		}
	}
	return aliases, nil
}

func (service *Service) Discover() error {
	discoverer := service.discoverer
	fallback := service.fallbackDiscoverer
	if discoverer == nil {
		if fallback == nil {
			return nil
		}
		discovered, err := fallback()
		if err != nil {
			return err
		}
		service.replaceRecords(discovered)
		return nil
	}

	discovered, err := discoverer()
	if err != nil {
		if fallback == nil {
			return err
		}
		discovered, err = fallback()
		if err != nil {
			return err
		}
		service.replaceRecords(discovered)
		return err
	}
	service.replaceRecords(discovered)
	return nil
}

func (service *Service) replaceRecords(discovered map[string]NameRecords) {
	cached := make(map[string]NameRecords, len(discovered))
	for name, record := range discovered {
		normalizedName := normalizeName(name)
		if normalizedName == "" {
			continue
		}
		cached[normalizedName] = record
	}

	service.mu.Lock()
	defer service.mu.Unlock()
	service.records = cached
	service.reverseIndex = buildReverseIndex(service.records)
	service.treeRoot = computeTreeRoot(service.records)
}

func (service *Service) SetRecord(name string, record NameRecords) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.records[normalizeName(name)] = record
	service.reverseIndex = buildReverseIndex(service.records)
	service.treeRoot = computeTreeRoot(service.records)
}

func (service *Service) RemoveRecord(name string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	delete(service.records, normalizeName(name))
	service.reverseIndex = buildReverseIndex(service.records)
	service.treeRoot = computeTreeRoot(service.records)
}

func (service *Service) Resolve(name string) (ResolveAllResult, bool) {
	record, ok := service.findRecord(name)
	if !ok {
		return ResolveAllResult{}, false
	}
	return resolveResult(record), true
}

func (service *Service) ResolveTXT(name string) ([]string, bool) {
	result, ok := service.ResolveTXTRecords(name)
	if !ok {
		return nil, false
	}
	return result.TXT, true
}

// ResolveTXTRecords returns TXT records wrapped with the RFC field name for action payloads.
//
//	service.ResolveTXTRecords("gateway.charon.lthn")
func (service *Service) ResolveTXTRecords(name string) (ResolveTXTResult, bool) {
	record, ok := service.findRecord(name)
	if !ok {
		return ResolveTXTResult{}, false
	}
	return ResolveTXTResult{
		TXT: append([]string(nil), record.TXT...),
	}, true
}

// DiscoverWithHSD refreshes DNS records for each alias by calling HSD.
// Example:
//
//	err := service.DiscoverWithHSD(context.Background(), []string{"gateway.lthn"}, dns.NewHSDClient(dns.HSDClientOptions{
//		URL:      "http://127.0.0.1:14037",
//		Username: "user",
//		Password: "pass",
//	}))
func (service *Service) DiscoverWithHSD(ctx context.Context, aliases []string, client *HSDClient) error {
	if client == nil {
		return fmt.Errorf("hsd client is required")
	}

	resolved := make(map[string]NameRecords, len(aliases))
	for _, alias := range aliases {
		normalized := normalizeName(alias)
		if normalized == "" {
			continue
		}

		record, err := client.GetNameResource(ctx, normalized)
		if err != nil {
			return err
		}
		resolved[normalized] = record
	}

	service.replaceRecords(resolved)
	return nil
}

func (service *Service) ResolveAddress(name string) (ResolveAddressResult, bool) {
	record, ok := service.findRecord(name)
	if !ok {
		return ResolveAddressResult{}, false
	}
	return ResolveAddressResult{
		Addresses: MergeRecords(record.A, record.AAAA),
	}, true
}

func (service *Service) ResolveReverse(ip string) ([]string, bool) {
	service.mu.RLock()
	defer service.mu.RUnlock()

	normalizedIP := normalizeIP(ip)
	if normalizedIP == "" {
		return nil, false
	}

	names, ok := service.reverseIndex[normalizedIP]
	if !ok {
		return nil, false
	}
	return append([]string(nil), names...), true
}

func (service *Service) ResolveAll(name string) (ResolveAllResult, bool) {
	record, ok := service.findRecord(name)
	if !ok {
		return ResolveAllResult{}, false
	}
	return resolveResult(record), true
}

func (service *Service) Health() map[string]any {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return map[string]any{
		"status":       "ready",
		"names_cached": len(service.records),
		"tree_root":    service.treeRoot,
	}
}

func (service *Service) ResolveReverseNames(ip string) (ReverseLookupResult, bool) {
	names, ok := service.ResolveReverse(ip)
	if !ok {
		return ReverseLookupResult{}, false
	}
	return ReverseLookupResult{Names: names}, true
}

func (service *Service) findRecord(name string) (NameRecords, bool) {
	service.mu.RLock()
	defer service.mu.RUnlock()

	normalized := normalizeName(name)
	if record, ok := service.records[normalized]; ok {
		return record, true
	}

	match, ok := findWildcardMatch(normalized, service.records)
	return match, ok
}

func resolveResult(record NameRecords) ResolveAllResult {
	return ResolveAllResult{
		A:    append([]string(nil), record.A...),
		AAAA: append([]string(nil), record.AAAA...),
		TXT:  append([]string(nil), record.TXT...),
		NS:   append([]string(nil), record.NS...),
	}
}

func buildReverseIndex(records map[string]NameRecords) map[string][]string {
	raw := map[string]map[string]struct{}{}
	for name, record := range records {
		for _, ip := range record.A {
			normalized := normalizeIP(ip)
			if normalized == "" {
				continue
			}
			index := raw[normalized]
			if index == nil {
				index = map[string]struct{}{}
				raw[normalized] = index
			}
			index[name] = struct{}{}
		}
		for _, ip := range record.AAAA {
			normalized := normalizeIP(ip)
			if normalized == "" {
				continue
			}
			index := raw[normalized]
			if index == nil {
				index = map[string]struct{}{}
				raw[normalized] = index
			}
			index[name] = struct{}{}
		}
	}

	reverseIndex := make(map[string][]string, len(raw))
	for ip, names := range raw {
		unique := make([]string, 0, len(names))
		for name := range names {
			unique = append(unique, name)
		}
		slices.Sort(unique)
		reverseIndex[ip] = unique
	}
	return reverseIndex
}

func normalizeIP(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func computeTreeRoot(records map[string]NameRecords) string {
	names := make([]string, 0, len(records))
	for name := range records {
		names = append(names, name)
	}
	slices.Sort(names)

	var builder strings.Builder
	for _, name := range names {
		record := records[name]
		builder.WriteString(name)
		builder.WriteByte('\n')
		builder.WriteString("A=")
		builder.WriteString(serializeRecordValues(record.A))
		builder.WriteByte('\n')
		builder.WriteString("AAAA=")
		builder.WriteString(serializeRecordValues(record.AAAA))
		builder.WriteByte('\n')
		builder.WriteString("TXT=")
		builder.WriteString(serializeRecordValues(record.TXT))
		builder.WriteByte('\n')
		builder.WriteString("NS=")
		builder.WriteString(serializeRecordValues(record.NS))
		builder.WriteByte('\n')
	}

	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func serializeRecordValues(values []string) string {
	copied := append([]string(nil), values...)
	slices.Sort(copied)
	return strings.Join(copied, ",")
}

func findWildcardMatch(name string, records map[string]NameRecords) (NameRecords, bool) {
	bestMatch := ""
	for candidate := range records {
		if !strings.HasPrefix(candidate, "*.") {
			continue
		}
		suffix := strings.TrimPrefix(candidate, "*.")
		if wildcardMatches(suffix, name) {
			if betterWildcardMatch(candidate, bestMatch) {
				bestMatch = candidate
			}
		}
	}
	if bestMatch == "" {
		return NameRecords{}, false
	}
	return records[bestMatch], true
}

func wildcardMatches(suffix, name string) bool {
	parts := strings.Split(suffix, ".")
	if len(parts) == 0 || len(name) <= len(suffix)+1 {
		return false
	}
	if !strings.HasSuffix(name, "."+suffix) {
		return false
	}
	return strings.Count(name[:len(name)-len(suffix)], ".") >= 1
}

func betterWildcardMatch(candidate, current string) bool {
	if current == "" {
		return true
	}
	remainingCandidate := strings.TrimPrefix(candidate, "*.")
	remainingCurrent := strings.TrimPrefix(current, "*.")
	if len(remainingCandidate) > len(remainingCurrent) {
		return true
	}
	if len(remainingCandidate) == len(remainingCurrent) {
		return candidate < current
	}
	return false
}

func normalizeName(name string) string {
	trimmed := strings.TrimSpace(strings.ToLower(name))
	if trimmed == "" {
		return ""
	}
	if strings.HasSuffix(trimmed, ".") {
		trimmed = strings.TrimSuffix(trimmed, ".")
	}
	return trimmed
}

func (service *Service) String() string {
	return fmt.Sprintf("dns.Service{records=%d}", len(service.records))
}

func MergeRecords(values ...[]string) []string {
	unique := []string{}
	seen := map[string]bool{}
	for _, batch := range values {
		for _, value := range batch {
			if seen[value] {
				continue
			}
			seen[value] = true
			unique = append(unique, value)
		}
	}
	slices.Sort(unique)
	return unique
}
