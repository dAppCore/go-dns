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
const DefaultDNSPort = 53
const DefaultHTTPPort = 5554

// NameRecords stores the cached DNS records for one name.
//
//	record := dns.NameRecords{
//		A:   []string{"10.10.10.10"},
//		TXT: []string{"v=lthn1 type=gateway"},
//	}
type NameRecords struct {
	A      []string `json:"a"`
	AAAA   []string `json:"aaaa"`
	TXT    []string `json:"txt"`
	NS     []string `json:"ns"`
	DS     []string `json:"ds"`
	DNSKEY []string `json:"dnskey"`
	RRSIG  []string `json:"rrsig"`
}

// ResolveAllResult returns the full record shape for `dns.resolve.all`.
//
//	result, ok := service.ResolveAll("gateway.charon.lthn")
//	// result = dns.ResolveAllResult{
//	//   A: []string{"10.10.10.10"},
//	//   AAAA: []string{},
//	//   TXT: []string{"v=lthn1 type=gateway"},
//	//   NS: []string{"ns.charon.lthn"},
//	//   DS: []string{},
//	//   DNSKEY: []string{},
//	//   RRSIG: []string{},
//	// }
type ResolveAllResult struct {
	A      []string `json:"a"`
	AAAA   []string `json:"aaaa"`
	TXT    []string `json:"txt"`
	NS     []string `json:"ns"`
	DS     []string `json:"ds"`
	DNSKEY []string `json:"dnskey"`
	RRSIG  []string `json:"rrsig"`
}

// ResolveAddressResult returns the merged address list for `dns.resolve`.
//
//	addresses, ok := service.ResolveAddresses("gateway.charon.lthn")
//	// addresses = dns.ResolveAddressResult{Addresses: []string{"10.10.10.10", "2600:1f1c:7f0:4f01::1"}}
type ResolveAddressResult struct {
	Addresses []string `json:"addresses"`
}

// ResolveTXTResult returns the TXT payload for `dns.resolve.txt`.
//
//	txt, ok := service.ResolveTXTRecords("gateway.charon.lthn")
//	// txt = dns.ResolveTXTResult{TXT: []string{"v=lthn1 type=gateway"}}
type ResolveTXTResult struct {
	TXT []string `json:"txt"`
}

// ReverseLookupResult returns the names resolved by `dns.reverse`.
//
//	names, ok := service.ResolveReverseNames("10.10.10.10")
//	// names = dns.ReverseLookupResult{Names: []string{"gateway.charon.lthn"}}
type ReverseLookupResult struct {
	Names []string `json:"names"`
}

// ReverseIndex stores one IP to the names that point at it in a TTL-backed cache.
//
//	index := buildReverseIndex(records, 15*time.Second)
//	names, ok := index.Lookup("10.10.10.10")
type ReverseIndex struct {
	namesByIP *cache.Cache
}

func (index *ReverseIndex) Lookup(ip string) ([]string, bool) {
	if index == nil || index.namesByIP == nil {
		return nil, false
	}

	normalizedIP := normalizeIP(ip)
	if normalizedIP == "" {
		return nil, false
	}

	names, found := index.namesByIP.Get(normalizedIP)
	if !found {
		return nil, false
	}

	typedNames, ok := names.([]string)
	if !ok || len(typedNames) == 0 {
		return nil, false
	}

	return append([]string(nil), typedNames...), true
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

// ServiceDescription is a semantic snapshot of the service state.
//
//	snapshot := service.Describe()
//	fmt.Println(snapshot.Status, snapshot.ZoneApex, snapshot.TreeRoot)
type ServiceDescription struct {
	Status    string `json:"status"`
	Records   int    `json:"records"`
	ZoneApex  string `json:"zone_apex"`
	TreeRoot  string `json:"tree_root"`
	DNSPort   int    `json:"dns_port"`
	HTTPPort  int    `json:"http_port"`
	RecordTTL string `json:"record_ttl"`
}

type Service struct {
	mutex                        sync.RWMutex
	records                      map[string]NameRecords
	recordExpiry                 map[string]time.Time
	reverseIndex                 *ReverseIndex
	treeRoot                     string
	zoneApex                     string
	dnsPort                      int
	httpPort                     int
	recordTTL                    time.Duration
	lastAliasFingerprint         string
	hsdClient                    *HSDClient
	mainchainAliasClient         *MainchainAliasClient
	chainAliasActionCaller       ActionCaller
	chainAliasActionFunc         func(context.Context) ([]string, error)
	recordDiscoverer             func() (map[string]NameRecords, error)
	fallbackRecordDiscoverer     func() (map[string]NameRecords, error)
	chainAliasDiscoverer         func(context.Context) ([]string, error)
	fallbackChainAliasDiscoverer func(context.Context) ([]string, error)
	lastTreeRootCheck            time.Time
	chainTreeRoot                string
	treeRootCheckInterval        time.Duration
}

// ServiceOptions wires cached DNS records plus the discovery clients and hooks.
//
//	service := dns.NewService(dns.ServiceOptions{
//		Records: map[string]dns.NameRecords{
//			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//		},
//		RecordTTL:    15 * time.Second,
//		HSDURL:       "http://127.0.0.1:14037",
//		MainchainURL: "http://127.0.0.1:14037",
//	})
type ServiceOptions struct {
	Records                  map[string]NameRecords
	RecordDiscoverer         func() (map[string]NameRecords, error)
	FallbackRecordDiscoverer func() (map[string]NameRecords, error)
	// RecordTTL keeps forward records and the reverse index alive for the same duration.
	RecordTTL   time.Duration
	DNSPort     int
	HTTPPort    int
	HSDURL      string
	HSDUsername string
	HSDPassword string
	// HSDApiKey is a compatibility alias for HSDPassword when only a token is available.
	HSDApiKey                    string
	MainchainURL                 string
	MainchainUsername            string
	MainchainPassword            string
	MainchainAliasClient         *MainchainAliasClient
	HSDClient                    *HSDClient
	ChainAliasActionCaller       ActionCaller
	ChainAliasAction             func(context.Context) ([]string, error)
	ChainAliasDiscoverer         func(context.Context) ([]string, error)
	FallbackChainAliasDiscoverer func(context.Context) ([]string, error)
	TreeRootCheckInterval        time.Duration
	ActionRegistrar              ActionRegistrar
}

// ServiceConfiguration is the preferred constructor shape for NewService.
//
//	service := dns.NewService(dns.ServiceConfiguration{
//		Records: map[string]dns.NameRecords{
//			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//		},
//	})
type ServiceConfiguration = ServiceOptions

// DNSServiceConfiguration is the explicit DNS-prefixed configuration alias.
//
//	service := dns.NewDNSServiceFromConfiguration(dns.DNSServiceConfiguration{
//		Records: map[string]dns.NameRecords{
//			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//		},
//	})
type DNSServiceConfiguration = ServiceOptions

// ServiceConfig is kept for compatibility with older call sites.
//
// Deprecated: use ServiceConfiguration instead.
type ServiceConfig = ServiceOptions

// DNSServiceConfig is kept for compatibility with older call sites.
//
// Deprecated: use DNSServiceConfiguration instead.
type DNSServiceConfig = ServiceOptions

// DNSServiceOptions is the preferred long-form type name for service configuration.
//
//	service := dns.NewDNSServiceFromOptions(dns.DNSServiceOptions{
//		Records: map[string]dns.NameRecords{
//			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//		},
//	})
type DNSServiceOptions = ServiceOptions

// Options is kept for compatibility with older call sites.
//
// Deprecated: use ServiceConfiguration instead.
type Options = ServiceOptions

// NewService builds a DNS service from cached records and optional discovery hooks.
//
// Deprecated: use NewDNSService for a more explicit constructor name.
//
//	service := dns.NewService(dns.ServiceConfig{
//		Records: map[string]dns.NameRecords{
//			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//		},
//	})
func NewService(options ServiceOptions) *Service {
	checkInterval := options.TreeRootCheckInterval
	if checkInterval <= 0 {
		checkInterval = DefaultTreeRootCheckInterval
	}

	chainAliasActionCaller := options.ChainAliasActionCaller
	if chainAliasActionCaller == nil {
		if actionCaller, ok := options.ActionRegistrar.(ActionCaller); ok {
			chainAliasActionCaller = actionCaller
		}
	}

	hsdClient := options.HSDClient
	if hsdClient == nil {
		hsdPassword := options.HSDPassword
		if hsdPassword == "" {
			hsdPassword = options.HSDApiKey
		}
		hsdClient = NewHSDClient(HSDClientOptions{
			URL:      options.HSDURL,
			Username: options.HSDUsername,
			Password: hsdPassword,
		})
	}

	mainchainClient := options.MainchainAliasClient
	if mainchainClient == nil {
		mainchainURL := strings.TrimSpace(options.MainchainURL)
		if mainchainURL == "" {
			mainchainURL = strings.TrimSpace(options.HSDURL)
		}
		mainchainPassword := options.MainchainPassword
		mainchainUsername := options.MainchainUsername
		if mainchainPassword == "" {
			mainchainPassword = options.HSDPassword
			if mainchainPassword == "" {
				mainchainPassword = options.HSDApiKey
			}
		}
		if mainchainUsername == "" {
			mainchainUsername = options.HSDUsername
		}
		mainchainClient = NewMainchainAliasClient(MainchainClientOptions{
			URL:      mainchainURL,
			Username: mainchainUsername,
			Password: mainchainPassword,
		})
	}

	cached := make(map[string]NameRecords, len(options.Records))
	for name, record := range options.Records {
		cached[normalizeName(name)] = record
	}
	treeRoot := computeTreeRoot(cached)
	service := &Service{
		records:                      cached,
		recordExpiry:                 make(map[string]time.Time, len(cached)),
		reverseIndex:                 buildReverseIndex(cached, options.RecordTTL),
		treeRoot:                     treeRoot,
		zoneApex:                     computeZoneApex(cached),
		dnsPort:                      options.DNSPort,
		httpPort:                     options.HTTPPort,
		recordTTL:                    options.RecordTTL,
		hsdClient:                    hsdClient,
		mainchainAliasClient:         mainchainClient,
		chainAliasActionCaller:       chainAliasActionCaller,
		chainAliasActionFunc:         options.ChainAliasAction,
		recordDiscoverer:             options.RecordDiscoverer,
		fallbackRecordDiscoverer:     options.FallbackRecordDiscoverer,
		chainAliasDiscoverer:         options.ChainAliasDiscoverer,
		fallbackChainAliasDiscoverer: options.FallbackChainAliasDiscoverer,
		treeRootCheckInterval:        checkInterval,
	}

	if options.ActionRegistrar != nil {
		service.RegisterActions(options.ActionRegistrar)
	}

	if options.RecordTTL > 0 {
		expiresAt := time.Now().Add(options.RecordTTL)
		for name := range cached {
			service.recordExpiry[name] = expiresAt
		}
	}

	return service
}

// NewDNSService builds a DNS service from cached records and optional discovery hooks.
//
//	service := dns.NewDNSService(dns.ServiceConfiguration{
//		Records: map[string]dns.NameRecords{
//			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//		},
//	})
func NewDNSService(options ServiceOptions) *Service {
	return NewService(options)
}

// NewDNSServiceFromOptions is the explicit long-form constructor name.
//
//	service := dns.NewDNSServiceFromOptions(dns.DNSServiceOptions{
//		Records: map[string]dns.NameRecords{
//			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//		},
//	})
func NewDNSServiceFromOptions(options DNSServiceOptions) *Service {
	return NewDNSService(options)
}

// NewDNSServiceFromConfiguration is the explicit constructor name for the DNS configuration alias.
//
//	service := dns.NewDNSServiceFromConfiguration(dns.DNSServiceConfiguration{
//		Records: map[string]dns.NameRecords{
//			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//		},
//	})
func NewDNSServiceFromConfiguration(options DNSServiceConfiguration) *Service {
	return NewDNSService(options)
}

// NewDNSServiceWithContextRegistrar is an explicit constructor name for action wiring.
//
//	service := dns.NewDNSServiceWithContextRegistrar(dns.DNSServiceOptions{}, actionRegistrar)
func NewDNSServiceWithContextRegistrar(options DNSServiceOptions, registrar ActionRegistrar) *Service {
	return NewDNSServiceWithRegistrar(options, registrar)
}

func (service *Service) requireHSDClient(client *HSDClient) (*HSDClient, error) {
	if client != nil {
		return client, nil
	}
	if service.hsdClient == nil {
		return nil, fmt.Errorf("hsd client is required")
	}
	return service.hsdClient, nil
}

func (service *Service) DiscoverFromChainAliases(ctx context.Context, client *HSDClient) error {
	aliases, found, err := service.discoverAliasesFromSources(
		ctx,
		service.chainAliasActionCaller,
		service.chainAliasActionFunc,
		service.chainAliasDiscoverer,
		service.fallbackChainAliasDiscoverer,
		service.mainchainAliasClient,
	)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if len(aliases) == 0 {
		now := time.Now()
		fingerprint := aliasFingerprint(aliases)
		service.replaceRecords(map[string]NameRecords{})
		service.recordTreeRootState(now, "", fingerprint)
		return nil
	}
	effectiveHSDClient, err := service.requireHSDClient(client)
	if err != nil {
		return err
	}
	return service.discoverFromChainAliasesUsingTreeRoot(ctx, aliases, effectiveHSDClient)
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
	chainAliasActionCaller ActionCaller,
	chainAliasAction func(context.Context) ([]string, error),
	chainAliasDiscoverer func(context.Context) ([]string, error),
	fallbackChainAliasDiscoverer func(context.Context) ([]string, error),
	mainchainAliasClient *MainchainAliasClient,
) ([]string, bool, error) {
	if aliases, ok := service.discoverAliasesFromActionCaller(ctx, chainAliasActionCaller); ok {
		return aliases, true, nil
	}

	if chainAliasAction != nil {
		aliases, err := chainAliasAction(ctx)
		if err == nil {
			return aliases, true, nil
		}
	}

	if chainAliasDiscoverer == nil {
		if fallbackChainAliasDiscoverer != nil {
			aliases, err := fallbackChainAliasDiscoverer(ctx)
			if err == nil {
				return aliases, true, nil
			}
			if mainchainAliasClient == nil {
				return nil, false, err
			}
			aliases, err = mainchainAliasClient.GetAllAliasDetails(ctx)
			return aliases, true, err
		}
		if mainchainAliasClient == nil {
			return nil, false, nil
		}
		aliases, err := mainchainAliasClient.GetAllAliasDetails(ctx)
		return aliases, true, err
	}

	aliases, err := chainAliasDiscoverer(ctx)
	if err == nil {
		return aliases, true, nil
	}
	if fallbackChainAliasDiscoverer == nil {
		if mainchainAliasClient == nil {
			return nil, false, err
		}
		aliases, err = mainchainAliasClient.GetAllAliasDetails(ctx)
		return aliases, true, err
	}

	fallbackAliases, fallbackErr := fallbackChainAliasDiscoverer(ctx)
	if fallbackErr == nil {
		return fallbackAliases, true, nil
	}
	if mainchainAliasClient == nil {
		return nil, false, fallbackErr
	}
	aliases, err = mainchainAliasClient.GetAllAliasDetails(ctx)
	return aliases, true, err
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
		return []string{}, nil
	case string:
		return normalizeAliasList([]string{aliases}), nil
	case []string:
		return normalizeAliasList(aliases), nil
	case []map[string]any:
		parsed := make([]string, 0, len(aliases))
		for _, alias := range aliases {
			name, err := parseActionAliasRecord(alias)
			if err != nil {
				return nil, err
			}
			if name != "" {
				parsed = append(parsed, name)
			}
		}
		return normalizeAliasList(parsed), nil
	case []map[string]string:
		parsed := make([]string, 0, len(aliases))
		for _, alias := range aliases {
			normalized := map[string]any{}
			for key, value := range alias {
				normalized[key] = value
			}
			name, err := parseActionAliasRecord(normalized)
			if err != nil {
				return nil, err
			}
			if name != "" {
				parsed = append(parsed, name)
			}
		}
		return normalizeAliasList(parsed), nil
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
		if len(aliases) > 0 {
			parsed := make([]string, 0, len(aliases))
			for _, rawAlias := range aliases {
				alias, err := parseActionAliasValue(rawAlias)
				if err != nil {
					continue
				}
				if alias != "" {
					parsed = append(parsed, alias)
				}
			}
			return normalizeAliasList(parsed), nil
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
//
//	record, ok := service.Resolve("gateway.charon.lthn")
//
//	// The cache now reflects the aliases returned by get_all_alias_details
//	// plus the DNS records fetched from getnameresource.
func (service *Service) DiscoverFromMainchainAliases(ctx context.Context, chainClient *MainchainAliasClient, hsdClient *HSDClient) error {
	effectiveChainClient := chainClient
	if effectiveChainClient == nil {
		effectiveChainClient = service.mainchainAliasClient
	}

	aliases, found, err := service.discoverAliasesFromSources(
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
			if effectiveChainClient != nil {
				return effectiveChainClient.GetAllAliasDetails(ctx)
			}
			return nil, nil
		},
		effectiveChainClient,
	)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if len(aliases) == 0 {
		now := time.Now()
		fingerprint := aliasFingerprint(aliases)
		service.replaceRecords(map[string]NameRecords{})
		service.recordTreeRootState(now, "", fingerprint)
		return nil
	}
	effectiveHSDClient, err := service.requireHSDClient(hsdClient)
	if err != nil {
		return err
	}
	return service.discoverFromChainAliasesUsingTreeRoot(ctx, aliases, effectiveHSDClient)
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
	service.mutex.RLock()
	defer service.mutex.RUnlock()
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
	service.mutex.RLock()
	defer service.mutex.RUnlock()
	return service.chainTreeRoot
}

func (service *Service) getLastAliasFingerprint() string {
	service.mutex.RLock()
	defer service.mutex.RUnlock()
	return service.lastAliasFingerprint
}

func (service *Service) recordAliasFingerprint(aliasFingerprint string) {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	service.lastAliasFingerprint = aliasFingerprint
}

func (service *Service) recordTreeRootCheck(now time.Time, aliasFingerprint string) {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	service.lastTreeRootCheck = now
	service.lastAliasFingerprint = aliasFingerprint
}

func (service *Service) recordTreeRootState(now time.Time, treeRoot string, aliasFingerprint string) {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	service.lastTreeRootCheck = now
	service.chainTreeRoot = treeRoot
	service.lastAliasFingerprint = aliasFingerprint
}

// Discover refreshes the cache from the configured record discoverer or fallback.
//
//	service := dns.NewService(dns.ServiceOptions{
//		RecordDiscoverer: func() (map[string]dns.NameRecords, error) {
//			return map[string]dns.NameRecords{
//				"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
//			}, nil
//		},
//	})
//	err := service.Discover()
func (service *Service) Discover() error {
	discoverer := service.recordDiscoverer
	fallback := service.fallbackRecordDiscoverer
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
		return nil
	}
	service.replaceRecords(discovered)
	return nil
}

// DiscoverAliases refreshes DNS records from the configured chain alias source.
//
//	service := dns.NewService(dns.ServiceOptions{
//		HSDClient: dns.NewHSDClient(dns.HSDClientOptions{URL: "http://127.0.0.1:14037"}),
//		ChainAliasDiscoverer: func(context.Context) ([]string, error) {
//			return []string{"gateway.charon.lthn"}, nil
//		},
//	})
//	_ = service.DiscoverAliases(context.Background())
//	record, ok := service.Resolve("gateway.charon.lthn")
//
//	// The service will call blockchain.chain.aliases first, then fall back to
//	// the configured discoverers or main-chain RPC if needed.
func (service *Service) DiscoverAliases(ctx context.Context) error {
	return service.DiscoverFromChainAliases(ctx, service.hsdClient)
}

func (service *Service) replaceRecords(discovered map[string]NameRecords) {
	cached := make(map[string]NameRecords, len(discovered))
	expiry := make(map[string]time.Time, len(discovered))
	now := time.Now()
	for name, record := range discovered {
		normalizedName := normalizeName(name)
		if normalizedName == "" {
			continue
		}
		cached[normalizedName] = record
		if service.recordTTL > 0 {
			expiry[normalizedName] = now.Add(service.recordTTL)
		}
	}

	service.mutex.Lock()
	defer service.mutex.Unlock()
	service.records = cached
	service.recordExpiry = expiry
	service.chainTreeRoot = ""
	service.lastTreeRootCheck = time.Time{}
	service.lastAliasFingerprint = ""
	service.refreshDerivedStateLocked()
}

// SetRecord inserts or replaces one cached name.
//
//	service.SetRecord("gateway.charon.lthn", dns.NameRecords{A: []string{"10.10.10.10"}})
func (service *Service) SetRecord(name string, record NameRecords) {
	normalizedName := normalizeName(name)
	now := time.Now()
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if normalizedName == "" {
		return
	}
	service.records[normalizedName] = record
	if service.recordTTL > 0 {
		if service.recordExpiry == nil {
			service.recordExpiry = make(map[string]time.Time)
		}
		service.recordExpiry[normalizedName] = now.Add(service.recordTTL)
	} else if service.recordExpiry != nil {
		delete(service.recordExpiry, normalizedName)
	}
	service.chainTreeRoot = ""
	service.lastTreeRootCheck = time.Time{}
	service.lastAliasFingerprint = ""
	service.refreshDerivedStateLocked()
}

// RemoveRecord deletes one cached name.
//
//	service.RemoveRecord("gateway.charon.lthn")
func (service *Service) RemoveRecord(name string) {
	normalizedName := normalizeName(name)
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if normalizedName == "" {
		return
	}
	delete(service.records, normalizedName)
	if service.recordExpiry != nil {
		delete(service.recordExpiry, normalizedName)
	}
	service.chainTreeRoot = ""
	service.lastTreeRootCheck = time.Time{}
	service.lastAliasFingerprint = ""
	service.refreshDerivedStateLocked()
}

// Resolve returns all record types for a name when an exact or wildcard match exists.
//
//	result, ok := service.Resolve("gateway.charon.lthn")
func (service *Service) Resolve(name string) (ResolveAllResult, bool) {
	if service == nil {
		return ResolveAllResult{}, false
	}
	record, ok := service.findRecord(name)
	if !ok {
		return ResolveAllResult{}, false
	}
	return resolveResult(record), true
}

// ResolveRecords is the explicit alias for Resolve.
//
//	result, ok := service.ResolveRecords("gateway.charon.lthn")
func (service *Service) ResolveRecords(name string) (ResolveAllResult, bool) {
	return service.Resolve(name)
}

// ResolveWithWildcardMatch returns all record types and whether the match used a wildcard.
//
//	result, ok, usedWildcard := service.ResolveWithWildcardMatch("node.charon.lthn")
func (service *Service) ResolveWithWildcardMatch(name string) (ResolveAllResult, bool, bool) {
	if service == nil {
		return ResolveAllResult{}, false, false
	}
	record, ok, usedWildcard := service.findRecordWithMatch(name)
	if !ok {
		return ResolveAllResult{}, false, false
	}
	return resolveResult(record), true, usedWildcard
}

// ResolveWithMatch returns matching records and whether the match used a wildcard.
//
//	result, found, usedWildcard := service.ResolveWithMatch("node.charon.lthn")
func (service *Service) ResolveWithMatch(name string) (ResolveAllResult, bool, bool) {
	if service == nil {
		return ResolveAllResult{}, false, false
	}
	record, ok, usedWildcard := service.findRecordWithMatch(name)
	if !ok {
		return ResolveAllResult{}, false, false
	}
	return resolveResult(record), true, usedWildcard
}

// ResolveTXT returns only TXT values for a name.
//
//	txt, ok := service.ResolveTXT("gateway.charon.lthn")
func (service *Service) ResolveTXT(name string) ([]string, bool) {
	if service == nil {
		return nil, false
	}
	result, ok, _ := service.ResolveTXTWithMatch(name)
	if !ok {
		return nil, false
	}
	return result.TXT, true
}

// ResolveTXTRecords returns TXT records wrapped with the RFC field name for action payloads.
//
//	result, ok := service.ResolveTXTRecords("gateway.charon.lthn")
func (service *Service) ResolveTXTRecords(name string) (ResolveTXTResult, bool) {
	if service == nil {
		return ResolveTXTResult{}, false
	}
	result, ok, _ := service.ResolveTXTWithMatch(name)
	if !ok {
		return ResolveTXTResult{}, false
	}
	return result, true
}

// ResolveTXTWithMatch returns TXT values and whether the match used a wildcard.
//
//	result, ok, usedWildcard := service.ResolveTXTWithMatch("node1.gateway.charon.lthn")
func (service *Service) ResolveTXTWithMatch(name string) (ResolveTXTResult, bool, bool) {
	if service == nil {
		return ResolveTXTResult{}, false, false
	}
	record, ok, usedWildcard := service.findRecordWithMatch(name)
	if !ok {
		return ResolveTXTResult{}, false, false
	}
	return ResolveTXTResult{
		TXT: cloneStrings(record.TXT),
	}, true, usedWildcard
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

func (service *Service) pruneExpiredRecords() {
	if service.recordTTL <= 0 {
		return
	}

	now := time.Now()
	service.mutex.Lock()
	defer service.mutex.Unlock()

	if len(service.recordExpiry) == 0 {
		return
	}

	changed := false
	for name, expiresAt := range service.recordExpiry {
		if expiresAt.IsZero() || now.Before(expiresAt) {
			continue
		}
		delete(service.recordExpiry, name)
		delete(service.records, name)
		changed = true
	}

	if changed {
		service.chainTreeRoot = ""
		service.lastTreeRootCheck = time.Time{}
		service.lastAliasFingerprint = ""
		service.refreshDerivedStateLocked()
	}
}

func (service *Service) refreshDerivedStateLocked() {
	service.reverseIndex = buildReverseIndex(service.records, service.recordTTL)
	service.treeRoot = computeTreeRoot(service.records)
	service.zoneApex = computeZoneApex(service.records)
}

// ResolveAddresses returns A and AAAA values merged into one address list.
//
//	addresses, ok := service.ResolveAddresses("gateway.charon.lthn")
func (service *Service) ResolveAddresses(name string) (ResolveAddressResult, bool) {
	if service == nil {
		return ResolveAddressResult{}, false
	}
	record, ok := service.findRecord(name)
	if !ok {
		return ResolveAddressResult{}, false
	}
	return ResolveAddressResult{
		Addresses: MergeRecords(record.A, record.AAAA),
	}, true
}

// ResolveAddress is a compatibility alias for ResolveAddresses.
//
//	addresses, ok := service.ResolveAddress("gateway.charon.lthn")
func (service *Service) ResolveAddress(name string) (ResolveAddressResult, bool) {
	return service.ResolveAddresses(name)
}

// ResolveReverse returns the names that map back to an IP address.
//
//	names, ok := service.ResolveReverse("10.10.10.10")
func (service *Service) ResolveReverse(ip string) ([]string, bool) {
	if service == nil {
		return nil, false
	}
	normalizedIP, ok := normalizeReverseLookupInput(ip)
	if !ok {
		return nil, false
	}
	service.pruneExpiredRecords()
	service.mutex.RLock()
	reverseIndex := service.reverseIndex
	service.mutex.RUnlock()

	if reverseIndex == nil {
		return nil, false
	}

	return reverseIndex.Lookup(normalizedIP)
}

func normalizeReverseLookupInput(value string) (string, bool) {
	normalized := strings.TrimSpace(strings.ToLower(value))
	if normalized == "" {
		return "", false
	}

	if strings.HasSuffix(normalized, ".in-addr.arpa.") || strings.HasSuffix(normalized, ".in-addr.arpa") {
		parsed, ok := parsePTRIP(normalized)
		return parsed, ok
	}
	if strings.HasSuffix(normalized, ".ip6.arpa.") || strings.HasSuffix(normalized, ".ip6.arpa") {
		parsed, ok := parsePTRIP(normalized)
		return parsed, ok
	}

	parsed := normalizeIP(normalized)
	if parsed == "" {
		return "", false
	}
	return parsed, true
}

// ResolveAll returns the full record set for a name, including synthesized apex NS data.
//
//	result, ok := service.ResolveAll("charon.lthn")
//	// result = dns.ResolveAllResult{A: nil, AAAA: nil, TXT: nil, NS: []string{"ns.charon.lthn"}}
//	// ok = true
//
// Missing names still return empty arrays so the action payload stays stable.
//
//	result, ok := service.ResolveAll("missing.charon.lthn")
//	// result = dns.ResolveAllResult{A: []string{}, AAAA: []string{}, TXT: []string{}, NS: []string{}, DS: []string{}, DNSKEY: []string{}, RRSIG: []string{}}
func (service *Service) ResolveAll(name string) (ResolveAllResult, bool) {
	if service == nil {
		return ResolveAllResult{}, false
	}
	record, ok := service.findRecord(name)
	if !ok {
		empty := emptyResolveAllResult()
		if normalizeName(name) == service.ZoneApex() && service.ZoneApex() != "" {
			empty.NS = []string{"ns." + service.ZoneApex()}
			return empty, true
		}
		return empty, true
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
//	fmt.Println(health.Status, health.NamesCached, health.TreeRoot)
func (service *Service) Health() HealthResult {
	if service == nil {
		return HealthResult{
			Status: "not_ready",
		}
	}
	service.pruneExpiredRecords()

	service.mutex.RLock()
	defer service.mutex.RUnlock()

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

// Snapshot returns a structured view of the service state.
//
//	snapshot := service.Snapshot()
//	fmt.Printf("%+v\n", snapshot)
func (service *Service) Snapshot() ServiceDescription {
	if service == nil {
		return ServiceDescription{
			Status: "not_ready",
		}
	}

	service.pruneExpiredRecords()

	service.mutex.RLock()
	defer service.mutex.RUnlock()

	treeRoot := service.treeRoot
	if service.chainTreeRoot != "" {
		treeRoot = service.chainTreeRoot
	}

	dnsPort := service.dnsPort
	if dnsPort <= 0 {
		dnsPort = DefaultDNSPort
	}

	httpPort := service.httpPort
	if httpPort <= 0 {
		httpPort = DefaultHTTPPort
	}

	return ServiceDescription{
		Status:    "ready",
		Records:   len(service.records),
		ZoneApex:  service.zoneApex,
		TreeRoot:  treeRoot,
		DNSPort:   dnsPort,
		HTTPPort:  httpPort,
		RecordTTL: service.recordTTL.String(),
	}
}

// Describe is the compatibility alias for Snapshot.
//
//	snapshot := service.Describe()
//	fmt.Printf("%+v\n", snapshot)
func (service *Service) Describe() ServiceDescription {
	return service.Snapshot()
}

// ZoneApex returns the computed apex for the current record set.
//
//	apex := service.ZoneApex()
//	// "charon.lthn"
func (service *Service) ZoneApex() string {
	if service == nil {
		return ""
	}
	service.pruneExpiredRecords()

	service.mutex.RLock()
	defer service.mutex.RUnlock()
	return service.zoneApex
}

// ResolveReverseNames wraps ResolveReverse for action payloads.
//
//	result, ok := service.ResolveReverseNames("10.10.10.10")
func (service *Service) ResolveReverseNames(ip string) (ReverseLookupResult, bool) {
	if service == nil {
		return ReverseLookupResult{}, false
	}
	names, ok := service.ResolveReverse(ip)
	if !ok {
		return ReverseLookupResult{}, false
	}
	return ReverseLookupResult{Names: names}, true
}

// ResolvePTRNames is the explicit PTR-oriented alias for ResolveReverseNames.
//
//	names, ok := service.ResolvePTRNames("10.10.10.10")
func (service *Service) ResolvePTRNames(ip string) (ReverseLookupResult, bool) {
	return service.ResolveReverseNames(ip)
}

// ResolvePTR is the explicit PTR-oriented alias for ResolveReverse.
//
//	names, ok := service.ResolvePTR("10.10.10.10")
func (service *Service) ResolvePTR(ip string) ([]string, bool) {
	return service.ResolveReverse(ip)
}

func (service *Service) findRecord(name string) (NameRecords, bool) {
	service.pruneExpiredRecords()
	record, ok, _ := service.findRecordWithMatch(name)
	return record, ok
}

func (service *Service) findRecordWithMatch(name string) (NameRecords, bool, bool) {
	service.pruneExpiredRecords()

	service.mutex.RLock()
	defer service.mutex.RUnlock()

	normalized := normalizeName(name)
	if record, ok := service.records[normalized]; ok {
		return record, true, false
	}

	match, ok := findWildcardMatch(normalized, service.records)
	if !ok {
		return NameRecords{}, false, false
	}
	return match, true, true
}

func resolveResult(record NameRecords) ResolveAllResult {
	return ResolveAllResult{
		A:      normalizeRecordValues(record.A),
		AAAA:   normalizeRecordValues(record.AAAA),
		TXT:    normalizeRecordValues(record.TXT),
		NS:     normalizeRecordValues(record.NS),
		DS:     normalizeRecordValues(record.DS),
		DNSKEY: normalizeRecordValues(record.DNSKEY),
		RRSIG:  normalizeRecordValues(record.RRSIG),
	}
}

func emptyResolveAllResult() ResolveAllResult {
	return ResolveAllResult{
		A:      []string{},
		AAAA:   []string{},
		TXT:    []string{},
		NS:     []string{},
		DS:     []string{},
		DNSKEY: []string{},
		RRSIG:  []string{},
	}
}

func buildReverseIndex(records map[string]NameRecords, ttl time.Duration) *ReverseIndex {
	expiration := cache.NoExpiration
	if ttl > 0 {
		expiration = ttl
	}

	namesByIP := cache.New(expiration, ttl)
	for name, record := range records {
		collectReverseName(namesByIP, name, record.A, expiration)
		collectReverseName(namesByIP, name, record.AAAA, expiration)
	}

	for ip, item := range namesByIP.Items() {
		typedNames, ok := item.Object.([]string)
		if !ok {
			namesByIP.Delete(ip)
			continue
		}
		namesByIP.Set(ip, normalizeRecordValues(typedNames), expiration)
	}

	return &ReverseIndex{namesByIP: namesByIP}
}

func collectReverseName(namesByIP *cache.Cache, name string, ips []string, expiration time.Duration) {
	if namesByIP == nil || len(ips) == 0 {
		return
	}

	for _, ip := range ips {
		normalized := normalizeIP(ip)
		if normalized == "" {
			continue
		}

		current, found := namesByIP.Get(normalized)
		if !found {
			namesByIP.Set(normalized, []string{name}, expiration)
			continue
		}

		typedNames, ok := current.([]string)
		if !ok {
			namesByIP.Set(normalized, []string{name}, expiration)
			continue
		}

		namesByIP.Set(normalized, append(typedNames, name), expiration)
	}
}

func normalizeIP(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

// NormalizeIP normalizes a raw IP string into its canonical textual form.
//
//	normalized := dns.NormalizeIP("010.000.000.001")
//	// normalized == "10.0.0.1"
func NormalizeIP(ip string) string {
	return normalizeIP(ip)
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
		builder.WriteString("DS=")
		builder.WriteString(serializeRecordValues(record.DS))
		builder.WriteByte('\n')
		builder.WriteString("DNSKEY=")
		builder.WriteString(serializeRecordValues(record.DNSKEY))
		builder.WriteByte('\n')
		builder.WriteString("RRSIG=")
		builder.WriteString(serializeRecordValues(record.RRSIG))
		builder.WriteByte('\n')
	}

	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func computeZoneApex(records map[string]NameRecords) string {
	names := make([]string, 0, len(records))
	for name := range records {
		if strings.HasPrefix(name, "*.") {
			suffix := strings.TrimPrefix(name, "*.")
			if suffix == "" {
				continue
			}
			names = append(names, suffix)
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
	normalized := normalizeRecordValues(values)
	return strings.Join(normalized, ",")
}

func normalizeRecordValues(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}

	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}

	slices.Sort(normalized)
	return normalized
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
	if suffix == "" || name == suffix {
		return false
	}
	if !strings.HasSuffix(name, "."+suffix) {
		return false
	}
	prefix := strings.TrimSuffix(name, "."+suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
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

// NormalizeName normalizes a raw DNS name for cache lookups and action handling.
//
//	normalized := dns.NormalizeName("Gateway.Charon.lthn.")
//	// normalized == "gateway.charon.lthn"
func NormalizeName(name string) string {
	return normalizeName(name)
}

// String returns a compact debug representation of the service.
//
//	fmt.Println(service)
func (service *Service) String() string {
	snapshot := service.Describe()
	return fmt.Sprintf(
		"dns.Service{status=%q records=%d zone_apex=%q tree_root=%q dns_port=%d http_port=%d record_ttl=%q}",
		snapshot.Status,
		snapshot.Records,
		snapshot.ZoneApex,
		snapshot.TreeRoot,
		snapshot.DNSPort,
		snapshot.HTTPPort,
		snapshot.RecordTTL,
	)
}

// MergeRecords deduplicates and sorts record values before returning them.
//
//	values := MergeRecords([]string{"10.10.10.10"}, []string{"10.0.0.1", "10.10.10.10"})
func MergeRecords(values ...[]string) []string {
	merged := []string{}
	for _, batch := range values {
		merged = append(merged, batch...)
	}
	return normalizeRecordValues(merged)
}
