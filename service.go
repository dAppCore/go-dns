package dns

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

type NameRecords struct {
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	TXT   []string `json:"txt"`
	NS    []string `json:"ns"`
}

type ResolveAllResult struct {
	A    []string `json:"a"`
	AAAA []string `json:"aaaa"`
	TXT  []string `json:"txt"`
	NS   []string `json:"ns"`
}

type Service struct {
	mu       sync.RWMutex
	records  map[string]NameRecords
}

type ServiceOptions struct {
	Records map[string]NameRecords
}

func NewService(options ServiceOptions) *Service {
	cached := make(map[string]NameRecords, len(options.Records))
	for name, record := range options.Records {
		cached[normalizeName(name)] = record
	}
	return &Service{
		records: cached,
	}
}

func (service *Service) SetRecord(name string, record NameRecords) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.records[normalizeName(name)] = record
}

func (service *Service) RemoveRecord(name string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	delete(service.records, normalizeName(name))
}

func (service *Service) Resolve(name string) (ResolveAllResult, bool) {
	record, ok := service.findRecord(name)
	if !ok {
		return ResolveAllResult{}, false
	}
	return resolveResult(record), true
}

func (service *Service) ResolveTXT(name string) ([]string, bool) {
	record, ok := service.findRecord(name)
	if !ok {
		return nil, false
	}
	return append([]string(nil), record.TXT...), true
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
		"tree_root":    "stubbed",
	}
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

