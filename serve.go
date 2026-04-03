package dns

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	dnsprotocol "github.com/miekg/dns"
)

const defaultDNSTTL = 300

// DNSServer owns the UDP+TCP DNS listeners returned by Serve.
//
//	srv, err := service.Serve("127.0.0.1", 53)
//	defer func() { _ = srv.Close() }()
//	fmt.Println("dns at", srv.DNSAddress())
type DNSServer struct {
	udpListener net.PacketConn
	tcpListener net.Listener
	udpServer   *dnsprotocol.Server
	tcpServer   *dnsprotocol.Server
}

// ServiceRuntime wraps the DNS and health listeners returned by ServeAll.
//
//	runtime, err := service.ServeAll("127.0.0.1", 53, 5554)
//	defer func() { _ = runtime.Close() }()
//	fmt.Println(runtime.DNSAddress(), runtime.HealthAddress())
type ServiceRuntime struct {
	DNS    *DNSServer
	Health *HealthServer
	// HTTP is retained for compatibility with older call sites.
	HTTP *HealthServer
}

func (runtime *ServiceRuntime) DNSAddress() string {
	if runtime == nil || runtime.DNS == nil {
		return ""
	}
	return runtime.DNS.DNSAddress()
}

func (runtime *ServiceRuntime) HealthAddress() string {
	if runtime == nil {
		return ""
	}
	if runtime.Health != nil {
		return runtime.Health.HealthAddress()
	}
	if runtime.HTTP != nil {
		return runtime.HTTP.HealthAddress()
	}
	return ""
}

// HTTPAddress is retained for compatibility with older call sites.
func (runtime *ServiceRuntime) HTTPAddress() string {
	return runtime.HealthAddress()
}

func (runtime *ServiceRuntime) Close() error {
	if runtime == nil {
		return nil
	}

	var firstError error
	if runtime.DNS != nil {
		if err := runtime.DNS.Close(); err != nil && firstError == nil {
			firstError = err
		}
	}
	if runtime.Health != nil {
		if err := runtime.Health.Close(); err != nil && firstError == nil {
			firstError = err
		}
	}
	if runtime.HTTP != nil && runtime.HTTP != runtime.Health {
		if err := runtime.HTTP.Close(); err != nil && firstError == nil {
			firstError = err
		}
	}
	return firstError
}

func (server *DNSServer) DNSAddress() string {
	if server.udpListener == nil {
		return ""
	}
	return server.udpListener.LocalAddr().String()
}

// Address is retained for compatibility with older call sites.
func (server *DNSServer) Address() string {
	return server.DNSAddress()
}

func (server *DNSServer) Close() error {
	if server.udpListener != nil {
		_ = server.udpListener.Close()
	}
	if server.tcpListener != nil {
		_ = server.tcpListener.Close()
	}
	var err error
	if server.udpServer != nil {
		err = server.udpServer.Shutdown()
	}
	if server.tcpServer != nil {
		err = server.tcpServer.Shutdown()
	}
	return err
}

// ResolveDNSPort returns the DNS port used for `dns.serve` and `Serve`.
//
//	port := service.ResolveDNSPort()
//	server, err := service.Serve("127.0.0.1", port)
func (service *Service) ResolveDNSPort() int {
	if service == nil || service.dnsPort <= 0 {
		return DefaultDNSPort
	}
	return service.dnsPort
}

// DNSListenPort resolves the configured DNS listen port for `dns.serve`.
//
//	port := service.DNSListenPort()
//	server, err := service.Serve("127.0.0.1", port)
func (service *Service) DNSListenPort() int {
	return service.ResolveDNSPort()
}

// DNSPort is an explicit alias for ResolveDNSPort.
//
//	port := service.DNSPort()
//	server, err := service.Serve("127.0.0.1", port)
func (service *Service) DNSPort() int {
	return service.ResolveDNSPort()
}

// resolveDNSListenPort keeps internal callers aligned with explicit naming.
func (service *Service) resolveDNSListenPort() int {
	return service.DNSListenPort()
}

// resolveServePort is a legacy compatibility helper.
func (service *Service) resolveServePort() int {
	return service.ResolveDNSPort()
}

// ResolveHTTPPort returns the HTTP health port used by `ServeHTTPHealth`.
//
//	port := service.ResolveHTTPPort()
//	healthServer, err := service.ServeHTTPHealth("127.0.0.1", port)
func (service *Service) ResolveHTTPPort() int {
	if service == nil || service.httpPort <= 0 {
		return DefaultHTTPPort
	}
	return service.httpPort
}

// HTTPListenPort resolves the configured health/listener port for `dns.serve`.
//
//	port := service.HTTPListenPort()
//	server, err := service.ServeHTTPHealth("127.0.0.1", port)
func (service *Service) HTTPListenPort() int {
	return service.ResolveHTTPPort()
}

// HTTPPort is an explicit alias for ResolveHTTPPort.
//
//	port := service.HTTPPort()
//	healthServer, err := service.ServeHTTPHealth("127.0.0.1", port)
func (service *Service) HTTPPort() int {
	return service.ResolveHTTPPort()
}

// resolveHTTPListenPort keeps internal callers aligned with explicit naming.
func (service *Service) resolveHTTPListenPort() int {
	return service.HTTPListenPort()
}

// resolveHTTPPort is a legacy compatibility helper.
func (service *Service) resolveHTTPPort() int {
	return service.ResolveHTTPPort()
}

// Serve starts DNS over UDP and TCP.
//
//	srv, err := service.Serve("0.0.0.0", 53)
//	defer func() { _ = srv.Close() }()
//	lookup := new(dnsprotocol.Msg)
//	lookup.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeA)
func (service *Service) Serve(bind string, port int) (*DNSServer, error) {
	if bind == "" {
		bind = "127.0.0.1"
	}
	if port <= 0 {
		port = service.ResolveDNSPort()
	}
	addr := net.JoinHostPort(bind, strconv.Itoa(port))

	udpListener, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		_ = udpListener.Close()
		return nil, err
	}

	requestHandler := &dnsRequestHandler{service: service}
	serveMux := dnsprotocol.NewServeMux()
	serveMux.HandleFunc(".", requestHandler.ServeDNS)

	udpServer := &dnsprotocol.Server{Net: "udp", PacketConn: udpListener, Handler: serveMux}
	tcpServer := &dnsprotocol.Server{Net: "tcp", Listener: tcpListener, Handler: serveMux}

	dnsServer := &DNSServer{
		udpListener: udpListener,
		tcpListener: tcpListener,
		udpServer:   udpServer,
		tcpServer:   tcpServer,
	}

	go func() {
		_ = udpServer.ActivateAndServe()
	}()
	go func() {
		_ = tcpServer.ActivateAndServe()
	}()

	return dnsServer, nil
}

// ServeAll starts DNS and health together.
//
//	runtime, err := service.ServeAll("127.0.0.1", 53, 5554)
//	defer func() { _ = runtime.Close() }()
//	fmt.Println("dns:", runtime.DNSAddress(), "health:", runtime.HealthAddress())
func (service *Service) ServeAll(bind string, dnsPort int, httpPort int) (*ServiceRuntime, error) {
	if dnsPort <= 0 {
		dnsPort = service.resolveDNSListenPort()
	}
	if httpPort <= 0 {
		httpPort = service.resolveHTTPListenPort()
	}

	dnsServer, err := service.Serve(bind, dnsPort)
	if err != nil {
		return nil, err
	}

	httpServer, err := service.ServeHTTPHealth(bind, httpPort)
	if err != nil {
		_ = dnsServer.Close()
		return nil, err
	}

	return &ServiceRuntime{
		DNS:    dnsServer,
		Health: httpServer,
		HTTP:   httpServer,
	}, nil
}

// ServeConfigured starts DNS and health using the ports stored on the service.
//
//	service := dns.NewService(dns.ServiceOptions{
//		DNSPort:  1053,
//		HTTPPort: 5554,
//	})
//	runtime, err := service.ServeConfigured("127.0.0.1")
func (service *Service) ServeConfigured(bind string) (*ServiceRuntime, error) {
	return service.ServeAll(bind, service.dnsPort, service.httpPort)
}

type dnsRequestHandler struct {
	service *Service
}

func (handler *dnsRequestHandler) ServeDNS(responseWriter dnsprotocol.ResponseWriter, request *dnsprotocol.Msg) {
	reply := new(dnsprotocol.Msg)
	reply.Compress = true

	if request == nil {
		reply.SetRcode(reply, dnsprotocol.RcodeNotImplemented)
		_ = responseWriter.WriteMsg(reply)
		return
	}

	reply.SetReply(request)
	if request.Opcode != dnsprotocol.OpcodeQuery {
		reply.SetRcode(request, dnsprotocol.RcodeNotImplemented)
		_ = responseWriter.WriteMsg(reply)
		return
	}

	if len(request.Question) == 0 {
		reply.SetRcode(request, dnsprotocol.RcodeFormatError)
		_ = responseWriter.WriteMsg(reply)
		return
	}

	question := request.Question[0]
	lookupName := strings.TrimSuffix(strings.ToLower(question.Name), ".")
	record, found := handler.service.findRecord(lookupName)

	switch question.Qtype {
	case dnsprotocol.TypeA:
		if !found {
			goto noRecord
		}
		for _, value := range normalizeRecordValues(record.A) {
			parsedIP := net.ParseIP(value)
			if parsedIP == nil || parsedIP.To4() == nil {
				continue
			}
			reply.Answer = append(reply.Answer, &dnsprotocol.A{
				Hdr: dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeA, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
				A:   parsedIP.To4(),
			})
		}
	case dnsprotocol.TypeAAAA:
		if !found {
			goto noRecord
		}
		for _, value := range normalizeRecordValues(record.AAAA) {
			parsedIP := net.ParseIP(value)
			if parsedIP == nil || parsedIP.To4() != nil {
				continue
			}
			reply.Answer = append(reply.Answer, &dnsprotocol.AAAA{
				Hdr:  dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeAAAA, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
				AAAA: parsedIP.To16(),
			})
		}
	case dnsprotocol.TypeTXT:
		if !found {
			goto noRecord
		}
		for _, value := range normalizeRecordValues(record.TXT) {
			reply.Answer = append(reply.Answer, &dnsprotocol.TXT{
				Hdr: dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeTXT, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
				Txt: []string{value},
			})
		}
	case dnsprotocol.TypeNS:
		if found {
			for _, value := range normalizeRecordValues(record.NS) {
				reply.Answer = append(reply.Answer, &dnsprotocol.NS{
					Hdr: dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeNS, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
					Ns:  normalizeName(value) + ".",
				})
			}
		}
		if len(reply.Answer) == 0 && normalizeName(lookupName) == handler.service.ZoneApex() && handler.service.ZoneApex() != "" {
			reply.Answer = append(reply.Answer, &dnsprotocol.NS{
				Hdr: dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeNS, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
				Ns:  normalizeName("ns."+lookupName) + ".",
			})
		}
		if len(reply.Answer) == 0 && !found {
			goto noRecord
		}
	case dnsprotocol.TypePTR:
		ip, ok := parsePTRIP(lookupName)
		if !ok {
			reply.SetRcode(request, dnsprotocol.RcodeFormatError)
			_ = responseWriter.WriteMsg(reply)
			return
		}
		values, ok := handler.service.ResolveReverse(ip)
		if !ok {
			goto noRecord
		}
		for _, value := range values {
			reply.Answer = append(reply.Answer, &dnsprotocol.PTR{
				Hdr: dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypePTR, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
				Ptr: normalizeName(value) + ".",
			})
		}
	case dnsprotocol.TypeSOA:
		if normalizeName(lookupName) == handler.service.ZoneApex() && handler.service.ZoneApex() != "" {
			reply.Answer = append(reply.Answer, &dnsprotocol.SOA{
				Hdr:     dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeSOA, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
				Ns:      normalizeName("ns."+lookupName) + ".",
				Mbox:    "hostmaster." + lookupName + ".",
				Serial:  uint32(time.Now().Unix()),
				Refresh: 86400,
				Retry:   3600,
				Expire:  3600,
				Minttl:  300,
			})
			break
		}
		if !found {
			goto noRecord
		}
	case dnsprotocol.TypeANY:
		if found {
			appendAnyAnswers(reply, question.Name, lookupName, record, handler.service.ZoneApex())
		} else if normalizeName(lookupName) == handler.service.ZoneApex() && handler.service.ZoneApex() != "" {
			appendAnyAnswers(reply, question.Name, lookupName, NameRecords{}, handler.service.ZoneApex())
		} else {
			goto noRecord
		}
	case dnsprotocol.TypeDS:
		if !found {
			goto noRecord
		}
		appendDNSSECResourceRecords(reply, question.Name, dnsprotocol.TypeDS, normalizeRecordValues(record.DS))
	case dnsprotocol.TypeDNSKEY:
		if !found {
			goto noRecord
		}
		appendDNSSECResourceRecords(reply, question.Name, dnsprotocol.TypeDNSKEY, normalizeRecordValues(record.DNSKEY))
	case dnsprotocol.TypeRRSIG:
		if !found {
			goto noRecord
		}
		appendDNSSECResourceRecords(reply, question.Name, dnsprotocol.TypeRRSIG, normalizeRecordValues(record.RRSIG))
	default:
		reply.SetRcode(request, dnsprotocol.RcodeNotImplemented)
		_ = responseWriter.WriteMsg(reply)
		return
	}

	_ = responseWriter.WriteMsg(reply)
	return

noRecord:
	reply.SetRcode(request, dnsprotocol.RcodeNameError)
	_ = responseWriter.WriteMsg(reply)
}

func parsePTRIP(name string) (string, bool) {
	lookup := strings.TrimSuffix(strings.ToLower(name), ".")
	if strings.HasSuffix(lookup, ".in-addr.arpa") {
		base := strings.TrimSuffix(strings.TrimSuffix(lookup, ".in-addr.arpa"), ".")
		labels := strings.Split(base, ".")
		if len(labels) != 4 {
			return "", false
		}
		for _, label := range labels {
			if label == "" {
				return "", false
			}
		}
		reversed := make([]string, 4)
		for i := 0; i < 4; i++ {
			reversed[i] = labels[3-i]
		}
		candidate := strings.Join(reversed, ".")
		parsed := net.ParseIP(candidate)
		if parsed == nil || parsed.To4() == nil {
			return "", false
		}
		return parsed.String(), true
	}
	if strings.HasSuffix(lookup, ".ip6.arpa") {
		base := strings.TrimSuffix(strings.TrimSuffix(lookup, ".ip6.arpa"), ".")
		labels := strings.Split(base, ".")
		if len(labels) != 32 {
			return "", false
		}
		for _, label := range labels {
			if len(label) != 1 {
				return "", false
			}
		}
		reversed := make([]string, 32)
		for i := 0; i < 32; i++ {
			reversed[i] = labels[31-i]
		}
		blocks := make([]string, 8)
		for i := 0; i < 8; i++ {
			block := strings.Join(reversed[i*4:(i+1)*4], "")
			if len(block) != 4 {
				return "", false
			}
			blocks[i] = block
		}
		candidate := strings.Join(blocks, ":")
		parsed := net.ParseIP(candidate)
		if parsed == nil {
			return "", false
		}
		return parsed.String(), true
	}
	return "", false
}

func appendAnyAnswers(reply *dnsprotocol.Msg, questionName string, lookupName string, record NameRecords, zoneApex string) {
	for _, value := range normalizeRecordValues(record.A) {
		parsedIP := net.ParseIP(value)
		if parsedIP == nil || parsedIP.To4() == nil {
			continue
		}
		reply.Answer = append(reply.Answer, &dnsprotocol.A{
			Hdr: dnsprotocol.RR_Header{Name: questionName, Rrtype: dnsprotocol.TypeA, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
			A:   parsedIP.To4(),
		})
	}

	for _, value := range normalizeRecordValues(record.AAAA) {
		parsedIP := net.ParseIP(value)
		if parsedIP == nil || parsedIP.To4() != nil {
			continue
		}
		reply.Answer = append(reply.Answer, &dnsprotocol.AAAA{
			Hdr:  dnsprotocol.RR_Header{Name: questionName, Rrtype: dnsprotocol.TypeAAAA, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
			AAAA: parsedIP.To16(),
		})
	}

	for _, value := range normalizeRecordValues(record.TXT) {
		reply.Answer = append(reply.Answer, &dnsprotocol.TXT{
			Hdr: dnsprotocol.RR_Header{Name: questionName, Rrtype: dnsprotocol.TypeTXT, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
			Txt: []string{value},
		})
	}

	if len(record.NS) > 0 {
		for _, value := range normalizeRecordValues(record.NS) {
			reply.Answer = append(reply.Answer, &dnsprotocol.NS{
				Hdr: dnsprotocol.RR_Header{Name: questionName, Rrtype: dnsprotocol.TypeNS, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
				Ns:  normalizeName(value) + ".",
			})
		}
	}

	for _, value := range normalizeRecordValues(record.DNSKEY) {
		appendDNSSECResourceRecords(reply, questionName, dnsprotocol.TypeDNSKEY, []string{value})
	}

	for _, value := range normalizeRecordValues(record.DS) {
		appendDNSSECResourceRecords(reply, questionName, dnsprotocol.TypeDS, []string{value})
	}

	for _, value := range normalizeRecordValues(record.RRSIG) {
		appendDNSSECResourceRecords(reply, questionName, dnsprotocol.TypeRRSIG, []string{value})
	}

	if normalizeName(lookupName) == normalizeName(zoneApex) && normalizeName(zoneApex) != "" {
		if len(record.NS) == 0 {
			reply.Answer = append(reply.Answer, &dnsprotocol.NS{
				Hdr: dnsprotocol.RR_Header{Name: questionName, Rrtype: dnsprotocol.TypeNS, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
				Ns:  normalizeName("ns."+lookupName) + ".",
			})
		}
		reply.Answer = append(reply.Answer, &dnsprotocol.SOA{
			Hdr:     dnsprotocol.RR_Header{Name: questionName, Rrtype: dnsprotocol.TypeSOA, Class: dnsprotocol.ClassINET, Ttl: defaultDNSTTL},
			Ns:      normalizeName("ns."+lookupName) + ".",
			Mbox:    "hostmaster." + lookupName + ".",
			Serial:  uint32(time.Now().Unix()),
			Refresh: 86400,
			Retry:   3600,
			Expire:  3600,
			Minttl:  300,
		})
	}
}

func appendDNSSECResourceRecords(reply *dnsprotocol.Msg, questionName string, recordType uint16, values []string) {
	for _, value := range values {
		rr, err := parseDNSSECResourceRecord(questionName, recordType, value)
		if err != nil {
			continue
		}
		reply.Answer = append(reply.Answer, rr)
	}
}

func parseDNSSECResourceRecord(questionName string, recordType uint16, raw string) (dnsprotocol.RR, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty dnssec resource value")
	}

	fallback := fmt.Sprintf("%s %d IN %s %s", questionName, defaultDNSTTL, dnsprotocol.TypeToString[recordType], trimmed)
	rr, err := dnsprotocol.NewRR(fallback)
	if err == nil {
		header := rr.Header()
		if header.Rrtype != recordType {
			return nil, fmt.Errorf("dnsprotocol record type mismatch")
		}
		header.Name = questionName
		header.Class = dnsprotocol.ClassINET
		header.Ttl = defaultDNSTTL
		return rr, nil
	}

	if rr, err := dnsprotocol.NewRR(trimmed); err == nil {
		header := rr.Header()
		if header.Rrtype != recordType {
			return nil, fmt.Errorf("dnsprotocol record type mismatch")
		}
		header.Name = questionName
		header.Class = dnsprotocol.ClassINET
		header.Ttl = defaultDNSTTL
		return rr, nil
	}

	return nil, err
}
