---
module: dappco.re/go/dns
repo: core/go-dns
lang: go
tier: lib
depends:
  - code/core/go
tags:
  - dns
  - resolution
  - networking
  - query
---
# go-dns — .lthn DNS Resolution as a Core Primitive

> Any CoreApp calls `c.Action("dns.resolve", opts)` to resolve .lthn names.
> Backed by chain aliases + HSD sidechain. No dig/nslookup needed.

## Actions

| Action | Params | Returns |
|--------|--------|---------|
| `dns.resolve` | `name` (e.g. "charon.lthn") | `{addresses: ["10.69.69.165"]}` |
| `dns.resolve.txt` | `name` | `{txt: ["v=lthn1 type=gateway..."]}` |
| `dns.resolve.all` | `name` | `{a: [], aaaa: [], txt: [], ns: []}` |
| `dns.reverse` | `ip` | `{names: ["charon.lthn"]}` |
| `dns.serve` | `port`, `bind` | starts DNS server |
| `dns.health` | — | `{status, names_cached, tree_root}` |
| `dns.discover` | — | re-scan chain for aliases → HNS names |

## Resolution Chain

```
1. Query main chain: get_all_alias_details
   → Find aliases, parse hns= from comments
2. Query HSD sidechain: getnameresource for each
   → Get A, AAAA, TXT, NS records
3. Cache with tree-root invalidation
   → Only regenerate when HSD tree root changes (15s check)
4. Serve via DNS protocol (UDP+TCP port 53)
   → Standard dig queries work
```

## Non-Obvious Needs

### 1. Chain Action Dependency
dns.discover calls `blockchain.chain.aliases` to get alias list. Need Core action cross-service calls:
```go
// Inside dns service:
aliases := c.Action("blockchain.chain.aliases").Run(ctx, core.NewOptions())
// Then for each alias, query HSD
```

If blockchain service isn't running, fall back to direct RPC to C++ daemon.

### 2. HSD Sidechain Client
The DNS service needs an HSD JSON-RPC client for `getnameresource` and `getblockchaininfo`. This is different from the main chain RPC — different port (14037), different auth (Basic), different methods.

**Ask:** Should this be in go-dns or a separate `go-hsd` package? The sidechain is also used by:
- LNS (current implementation at ~/Code/lthn/lns/)
- Zone cache daemon (alias-dns-bridge)
- Bob Wallet (lthnDNS)

A shared `go-hsd` client would prevent 4 implementations of the same RPC calls.

### 3. DNS Protocol Server
The current LNS uses `github.com/miekg/dns` for the UDP+TCP server. For go-dns as a Core package:

**Option A:** Keep miekg/dns as dependency (battle-tested, full RFC compliance)
**Option B:** Minimal DNS wire encoder in pure Go (only A/AAAA/TXT/NS/SOA/PTR — the 6 types we serve)

Recommend Option A — DNS protocol edge cases (EDNS0, TCP fallback, compression) are not worth reimplementing.

### 4. Reverse Index
PTR records need an IP→name reverse index. Currently built by scanning the forward cache. For efficiency:
```go
type ReverseIndex struct {
    ipToNames map[string][]string // "10.69.69.165" → ["charon.lthn", "gateway.lthn", ...]
}
```
Rebuilt atomically when tree root changes. Stored in go-cache with same TTL as forward records.

### 5. Wildcard Support
Name owners can set `*.name.lthn` records. The DNS server needs wildcard matching:
```
Query: foo.charon.lthn → no exact match → check *.charon.lthn → match → return wildcard A record
```

### 6. DNSSEC (Future)
HSD supports DS records. Full DNSSEC chain:
```
ITNS sidechain (tree root = trust anchor)
  → DS record per name
    → DNSKEY in zone
      → RRSIG on records
```

Not blocking beta.1. The current implementation serves unsigned records which is fine for internal resolution. DNSSEC is a beta.2 feature.

## Existing Implementation

The LNS at `~/Code/lthn/lns/` (672 lines Go, `dappco.re/go/core@v0.8.0-alpha.1`) already implements:
- DNS over UDP+TCP (A, AAAA, TXT, NS, SOA, PTR)
- Chain-based discovery via `get_all_alias_details`
- Tree-root invalidation via `getblockchaininfo`
- `hns=` alias comment override
- Zone apex SOA
- Reverse DNS (PTR)
- Health endpoint
- 14/14 names resolving on testnet

This code moves into go-dns with Core service registration.

## Service Registration

```go
dnsSvc := dns.NewService(c, dns.Options{
    HSDUrl:    "http://127.0.0.1:14037",
    HSDApiKey: "testkey",
    DNSPort:   53,
    HTTPPort:  5554,
})
// Auto-registers: dns.resolve, dns.resolve.txt, dns.reverse, dns.serve, dns.health, dns.discover
```
