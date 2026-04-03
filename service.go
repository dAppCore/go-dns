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

	cache "github.com/patrickmn/go-cache"
)

// DefaultTreeRootCheckInterval is the cadence used to re-check the HSD tree root
// when ServiceOptions.TreeRootCheckInterval is not set.
//
//	service := dns.NewService(dns.ServiceOptions{})
//	fmt.Println(dns.DefaultTreeRootCheckInterval)
const DefaultTreeRootCheckInterval = 15 * time.Second

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

// HealthResult is the typed payload returned by Health and dns.health.
//
//	health := service.Health()
//	fmt.Println(health.Status, health.NamesCached, health.TreeRoot)
type HealthResult struct {
	Status      string `json:"status"`
	NamesCached int    `json:"names_cached"`
	TreeRoot    string `json:"tree_root"`
}

type Service struct {
	mu                           sync.RWMutex
	records                      map[string]NameRecords
	reverseIndex                 *cache.Cache
	treeRoot                     string
	zoneApex                     string
	lastAliasFingerprint         string
	hsdClient                    *HSDClient
	mainchainAliasClient         *MainchainAliasClient
	chainAliasActionCaller       ActionCaller
	chainAliasAction             func(context.Context) ([]string, error)
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
	MainchainAliasClient         *MainchainAliasClient
	HSDClient                    *HSDClient
	ChainAliasActionCaller       ActionCaller
	ChainAliasAction             func(context.Context) ([]string, error)
	ChainAliasDiscoverer         func(context.Context) ([]string, error)
	FallbackChainAliasDiscoverer func(context.Context) ([]string, error)
	TreeRootCheckInterval        time.Duration
}

// Options is the documented constructor shape for NewService.
//
//	service := dns.NewService(dns.Options{
//		Records: map[string]dns.NameRecords{
//			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//		},
//	})
type Options = ServiceOptions

// NewService builds a DNS service from cached records and optional discovery hooks.
//
//	service := dns.NewService(dns.Options{
//		Records: map[string]dns.NameRecords{
//			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//		},
//	})
func NewService(options ServiceOptions) *Service {
	checkInterval := options.TreeRootCheckInterval
	if checkInterval <= 0 {
		checkInterval = DefaultTreeRootCheckInterval
	}

	cached := make(map[string]NameRecords, len(options.Records))
	for name, record := range options.Records {
		cached[normalizeName(name)] = record
	}
	treeRoot := computeTreeRoot(cached)
	return &Service{
		records:                      cached,
		reverseIndex:                 buildReverseIndexCache(cached),
		treeRoot:                     treeRoot,
		zoneApex:                     computeZoneApex(cached),
		hsdClient:                    options.HSDClient,
		mainchainAliasClient:         options.MainchainAliasClient,
		chainAliasActionCaller:       options.ChainAliasActionCaller,
		chainAliasAction:             options.ChainAliasAction,
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

	aliases, err := service.discoverAliasesFromSources(
		ctx,
		service.chainAliasActionCaller,
		service.chainAliasAction,
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

func aliasFingerprint(aliases []string) string {
	normalized := normalizeAliasList(aliases)
	builder := strings.Builder{}
	for index, alias := range normalized {
		if index > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(alias)
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func (service *Service) discoverAliasesFromSources(
	ctx context.Context,
	actionCaller ActionCaller,
	action func(context.Context) ([]string, error),
	discoverer func(context.Context) ([]string, error),
	fallback func(context.Context) ([]string, error),
	mainchainClient *MainchainAliasClient,
) ([]string, error) {
	if aliases, ok := service.discoverAliasesFromActionCaller(ctx, actionCaller); ok {
		return aliases, nil
	}

	if action != nil {
		aliases, err := action(ctx)
		if err == nil {
			return aliases, nil
		}
	}

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

func (service *Service) discoverAliasesFromActionCaller(ctx context.Context, actionCaller ActionCaller) ([]string, bool) {
	if actionCaller == nil {
		return nil, false
	}

	result, ok, err := actionCaller.CallAction(ctx, "blockchain.chain.aliases", map[string]any{})
	if err != nil || !ok {
		return nil, false
	}

	aliases, err := parseActionAliasList(result)
	if err != nil {
		return nil, false
	}
	return aliases, true
}

func parseActionAliasList(value any) ([]string, error) {
	switch aliases := value.(type) {
	case nil:
		return nil, fmt.Errorf("blockchain.chain.aliases action returned no value")
	case string:
		return normalizeAliasList([]string{aliases}), nil
	case []string:
		return normalizeAliasList(aliases), nil
	case []any:
		parsed := make([]string, 0, len(aliases))
		for _, item := range aliases {
			name, err := parseActionAliasValue(item)
			if err != nil {
				return nil, err
			}
			if name != "" {
				parsed = append(parsed, name)
			}
		}
		return normalizeAliasList(parsed), nil
	case map[string]any:
		if rawAliases, ok := aliases["aliases"]; ok {
			return parseActionAliasList(rawAliases)
		}
		if rawResult, ok := aliases["result"]; ok {
			return parseActionAliasList(rawResult)
		}
		name, err := parseActionAliasRecord(aliases)
		if err != nil {
			return nil, err
		}
		if name != "" {
			return []string{name}, nil
		}
	}

	return nil, fmt.Errorf("blockchain.chain.aliases action returned unsupported result type %T", value)
}

func parseActionAliasValue(value any) (string, error) {
	switch alias := value.(type) {
	case string:
		return normalizeName(alias), nil
	case map[string]any:
		return parseActionAliasRecord(alias)
	default:
		return "", fmt.Errorf("blockchain.chain.aliases action returned unsupported alias item type %T", value)
	}
}

func parseActionAliasRecord(record map[string]any) (string, error) {
	if hns, ok := record["hns"]; ok {
		if name, ok := hns.(string); ok {
			return normalizeName(name), nil
		}
		return "", fmt.Errorf("blockchain.chain.aliases action returned non-string hns value")
	}
	if comment, ok := record["comment"]; ok {
		if text, ok := comment.(string); ok {
			return extractAliasFromComment(text), nil
		}
		return "", fmt.Errorf("blockchain.chain.aliases action returned non-string comment value")
	}
	if alias, ok := record["alias"]; ok {
		if name, ok := alias.(string); ok {
			return normalizeName(name), nil
		}
		return "", fmt.Errorf("blockchain.chain.aliases action returned non-string alias value")
	}
	if name, ok := record["name"]; ok {
		if text, ok := name.(string); ok {
			return normalizeName(text), nil
		}
		return "", fmt.Errorf("blockchain.chain.aliases action returned non-string name value")
	}
	return "", nil
}

// DiscoverFromMainchainAliases refreshes the cache from the main-chain alias list.
//
//	err := service.DiscoverFromMainchainAliases(
//		context.Background(),
//		dns.NewMainchainAliasClient(dns.MainchainClientOptions{URL: "http://127.0.0.1:14037"}),
//		dns.NewHSDClient(dns.HSDClientOptions{URL: "http://127.0.0.1:14037"}),
//	)
func (service *Service) DiscoverFromMainchainAliases(ctx context.Context, chainClient *MainchainAliasClient, hsdClient *HSDClient) error {
	resolvedHSDClient, err := service.resolveHSDClient(hsdClient)
	if err != nil {
		return err
	}

	effectiveChainClient := chainClient
	if effectiveChainClient == nil {
		effectiveChainClient = service.mainchainAliasClient
	}

	aliases, err := service.discoverAliasesFromSources(
		ctx,
		service.chainAliasActionCaller,
		nil,
		func(ctx context.Context) ([]string, error) {
			if service.chainAliasDiscoverer != nil {
				return service.chainAliasDiscoverer(ctx)
			}
			if effectiveChainClient != nil {
				return effectiveChainClient.GetAllAliasDetails(ctx)
			}
			return nil, nil
		},
		func(ctx context.Context) ([]string, error) {
			if service.fallbackChainAliasDiscoverer != nil {
				return service.fallbackChainAliasDiscoverer(ctx)
			}
			if effectiveChainClient != nil && service.chainAliasDiscoverer != nil {
				return effectiveChainClient.GetAllAliasDetails(ctx)
			}
			return nil, nil
		},
		effectiveChainClient,
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
	fingerprint := aliasFingerprint(aliases)
	if service.shouldUseCachedTreeRoot(now, fingerprint) {
		return nil
	}

	info, err := client.GetBlockchainInfo(ctx)
	if err != nil {
		return err
	}

	cachedRoot := service.getChainTreeRoot()
	if cachedRoot != "" && cachedRoot == info.TreeRoot && service.getLastAliasFingerprint() == fingerprint {
		service.recordTreeRootCheck(now, fingerprint)
		return nil
	}

	if err := service.DiscoverWithHSD(ctx, aliases, client); err != nil {
		return err
	}

	service.recordTreeRootState(now, info.TreeRoot, fingerprint)
	return nil
}

func (service *Service) shouldUseCachedTreeRoot(now time.Time, aliasFingerprint string) bool {
	service.mu.RLock()
	defer service.mu.RUnlock()
	if service.lastAliasFingerprint != aliasFingerprint {
		return false
	}
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

func (service *Service) getLastAliasFingerprint() string {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.lastAliasFingerprint
}

func (service *Service) recordAliasFingerprint(aliasFingerprint string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.lastAliasFingerprint = aliasFingerprint
}

func (service *Service) recordTreeRootCheck(now time.Time, aliasFingerprint string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.lastTreeRootCheck = now
	service.lastAliasFingerprint = aliasFingerprint
}

func (service *Service) recordTreeRootState(now time.Time, treeRoot string, aliasFingerprint string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.lastTreeRootCheck = now
	service.chainTreeRoot = treeRoot
	service.lastAliasFingerprint = aliasFingerprint
}

// Discover refreshes the cache from the configured discoverer or fallback.
//
//	err := service.Discover()
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

// DiscoverAliases refreshes DNS records from the configured chain alias source.
//
//	err := service.DiscoverAliases(context.Background())
func (service *Service) DiscoverAliases(ctx context.Context) error {
	return service.DiscoverFromChainAliases(ctx, service.hsdClient)
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
	service.reverseIndex = buildReverseIndexCache(service.records)
	service.treeRoot = computeTreeRoot(service.records)
	service.zoneApex = computeZoneApex(service.records)
}

// SetRecord inserts or replaces one cached name.
//
//	service.SetRecord("gateway.charon.lthn", dns.NameRecords{A: []string{"10.10.10.10"}})
func (service *Service) SetRecord(name string, record NameRecords) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.records[normalizeName(name)] = record
	service.reverseIndex = buildReverseIndexCache(service.records)
	service.treeRoot = computeTreeRoot(service.records)
	service.zoneApex = computeZoneApex(service.records)
}

// RemoveRecord deletes one cached name.
//
//	service.RemoveRecord("gateway.charon.lthn")
func (service *Service) RemoveRecord(name string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	delete(service.records, normalizeName(name))
	service.reverseIndex = buildReverseIndexCache(service.records)
	service.treeRoot = computeTreeRoot(service.records)
	service.zoneApex = computeZoneApex(service.records)
}

// Resolve returns all record types for a name when an exact or wildcard match exists.
//
//	result, ok := service.Resolve("gateway.charon.lthn")
func (service *Service) Resolve(name string) (ResolveAllResult, bool) {
	record, ok := service.findRecord(name)
	if !ok {
		return ResolveAllResult{}, false
	}
	return resolveResult(record), true
}

// ResolveTXT returns only TXT values for a name.
//
//	txt, ok := service.ResolveTXT("gateway.charon.lthn")
func (service *Service) ResolveTXT(name string) ([]string, bool) {
	result, ok := service.ResolveTXTRecords(name)
	if !ok {
		return nil, false
	}
	return result.TXT, true
}

// ResolveTXTRecords returns TXT records wrapped with the RFC field name for action payloads.
//
//	result, ok := service.ResolveTXTRecords("gateway.charon.lthn")
func (service *Service) ResolveTXTRecords(name string) (ResolveTXTResult, bool) {
	record, ok := service.findRecord(name)
	if !ok {
		return ResolveTXTResult{}, false
	}
	return ResolveTXTResult{
		TXT: cloneStrings(record.TXT),
	}, true
}

// DiscoverWithHSD refreshes DNS records for each alias by calling HSD.
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

	fingerprint := aliasFingerprint(aliases)
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
	service.recordAliasFingerprint(fingerprint)
	return nil
}

// ResolveAddress returns A and AAAA values merged into one address list.
//
//	addresses, ok := service.ResolveAddress("gateway.charon.lthn")
func (service *Service) ResolveAddress(name string) (ResolveAddressResult, bool) {
	record, ok := service.findRecord(name)
	if !ok {
		return ResolveAddressResult{}, false
	}
	return ResolveAddressResult{
		Addresses: MergeRecords(record.A, record.AAAA),
	}, true
}

// ResolveReverse returns the names that map back to an IP address.
//
//	names, ok := service.ResolveReverse("10.10.10.10")
func (service *Service) ResolveReverse(ip string) ([]string, bool) {
	normalizedIP := normalizeIP(ip)
	if normalizedIP == "" {
		return nil, false
	}

	service.mu.RLock()
	reverseIndex := service.reverseIndex
	service.mu.RUnlock()

	if reverseIndex == nil {
		return nil, false
	}

	rawNames, found := reverseIndex.Get(normalizedIP)
	if !found {
		return nil, false
	}

	names, ok := rawNames.([]string)
	if !ok || len(names) == 0 {
		return nil, false
	}
	return append([]string(nil), names...), true
}

// ResolveAll returns the full record set for a name, including synthesized apex NS data.
// Missing names still return empty arrays so the action payload stays stable.
//
//	result, ok := service.ResolveAll("charon.lthn")
func (service *Service) ResolveAll(name string) (ResolveAllResult, bool) {
	record, ok := service.findRecord(name)
	if !ok {
		if normalizeName(name) == service.ZoneApex() && service.ZoneApex() != "" {
			return ResolveAllResult{
				NS: []string{"ns." + service.ZoneApex()},
			}, true
		}
		return ResolveAllResult{
			A:    []string{},
			AAAA: []string{},
			TXT:  []string{},
			NS:   []string{},
		}, true
	}
	result := resolveResult(record)
	if normalizeName(name) == service.ZoneApex() && service.ZoneApex() != "" && len(result.NS) == 0 {
		result.NS = []string{"ns." + service.ZoneApex()}
	}
	return result, true
}

// Health reports the live cache size and tree root.
//
//	health := service.Health()
//	fmt.Println(health.TreeRoot)
func (service *Service) Health() HealthResult {
	service.mu.RLock()
	defer service.mu.RUnlock()

	treeRoot := service.treeRoot
	if service.chainTreeRoot != "" {
		treeRoot = service.chainTreeRoot
	}

	return HealthResult{
		Status:      "ready",
		NamesCached: len(service.records),
		TreeRoot:    treeRoot,
	}
}

// ZoneApex returns the computed apex for the current record set.
//
//	apex := service.ZoneApex()
func (service *Service) ZoneApex() string {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.zoneApex
}

// ResolveReverseNames wraps ResolveReverse for action payloads.
//
//	result, ok := service.ResolveReverseNames("10.10.10.10")
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
		A:    cloneStrings(record.A),
		AAAA: cloneStrings(record.AAAA),
		TXT:  cloneStrings(record.TXT),
		NS:   cloneStrings(record.NS),
	}
}

func buildReverseIndexCache(records map[string]NameRecords) *cache.Cache {
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
	reverseIndexCache := cache.New(cache.NoExpiration, cache.NoExpiration)
	for ip, names := range reverseIndex {
		reverseIndexCache.Set(ip, names, cache.NoExpiration)
	}
	return reverseIndexCache
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

func computeZoneApex(records map[string]NameRecords) string {
	names := make([]string, 0, len(records))
	for name := range records {
		if strings.HasPrefix(name, "*.") {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return ""
	}

	commonLabels := strings.Split(names[0], ".")
	for _, name := range names[1:] {
		labels := strings.Split(name, ".")
		commonSuffixLength := 0
		for commonSuffixLength < len(commonLabels) && commonSuffixLength < len(labels) {
			if commonLabels[len(commonLabels)-1-commonSuffixLength] != labels[len(labels)-1-commonSuffixLength] {
				break
			}
			commonSuffixLength++
		}
		if commonSuffixLength == 0 {
			return ""
		}
		commonLabels = commonLabels[len(commonLabels)-commonSuffixLength:]
	}
	return strings.Join(commonLabels, ".")
}

func serializeRecordValues(values []string) string {
	copied := append([]string(nil), values...)
	slices.Sort(copied)
	return strings.Join(copied, ",")
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
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

// String returns a compact debug representation of the service.
//
//	fmt.Println(service)
func (service *Service) String() string {
	return fmt.Sprintf("dns.Service{records=%d}", len(service.records))
}

// MergeRecords deduplicates and sorts record values before returning them.
//
//	values := MergeRecords([]string{"10.10.10.10"}, []string{"10.0.0.1", "10.10.10.10"})
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
