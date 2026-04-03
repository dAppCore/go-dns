package dns

import (
	"net"
	"strconv"
	"strings"
	"time"

	dnsprotocol "github.com/miekg/dns"
)

const dnsTTL = 300

// DNSServer handles a live UDP+TCP DNS endpoint and owns listener resources.
type DNSServer struct {
	udpListener net.PacketConn
	tcpListener net.Listener
	udpServer   *dnsprotocol.Server
	tcpServer   *dnsprotocol.Server
}

func (server *DNSServer) Address() string {
	if server.udpListener == nil {
		return ""
	}
	return server.udpListener.LocalAddr().String()
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

// Serve starts DNS over UDP and TCP at bind:port and returns a running server handle.
//
//	srv, err := service.Serve("127.0.0.1", 53)
func (service *Service) Serve(bind string, port int) (*DNSServer, error) {
	if bind == "" {
		bind = "127.0.0.1"
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

	handler := &dnsRequestHandler{service: service}
	mux := dnsprotocol.NewServeMux()
	mux.HandleFunc(".", handler.ServeDNS)

	udpServer := &dnsprotocol.Server{Net: "udp", PacketConn: udpListener, Handler: mux}
	tcpServer := &dnsprotocol.Server{Net: "tcp", Listener: tcpListener, Handler: mux}

	run := &DNSServer{
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

	return run, nil
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
	name := strings.TrimSuffix(strings.ToLower(question.Name), ".")
	record, found := handler.service.findRecord(name)

	switch question.Qtype {
	case dnsprotocol.TypeA:
		if !found {
			goto noRecord
		}
		for _, value := range record.A {
			parsedIP := net.ParseIP(value)
			if parsedIP == nil || parsedIP.To4() == nil {
				continue
			}
			reply.Answer = append(reply.Answer, &dnsprotocol.A{
				Hdr: dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeA, Class: dnsprotocol.ClassINET, Ttl: dnsTTL},
				A:   parsedIP.To4(),
			})
		}
	case dnsprotocol.TypeAAAA:
		if !found {
			goto noRecord
		}
		for _, value := range record.AAAA {
			parsedIP := net.ParseIP(value)
			if parsedIP == nil || parsedIP.To4() != nil {
				continue
			}
			reply.Answer = append(reply.Answer, &dnsprotocol.AAAA{
				Hdr:  dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeAAAA, Class: dnsprotocol.ClassINET, Ttl: dnsTTL},
				AAAA: parsedIP.To16(),
			})
		}
	case dnsprotocol.TypeTXT:
		if !found {
			goto noRecord
		}
		for _, value := range record.TXT {
			reply.Answer = append(reply.Answer, &dnsprotocol.TXT{
				Hdr: dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeTXT, Class: dnsprotocol.ClassINET, Ttl: dnsTTL},
				Txt: []string{value},
			})
		}
	case dnsprotocol.TypeNS:
		if !found {
			goto noRecord
		}
		for _, value := range record.NS {
			reply.Answer = append(reply.Answer, &dnsprotocol.NS{
				Hdr: dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeNS, Class: dnsprotocol.ClassINET, Ttl: dnsTTL},
				Ns:  normalizeName(value) + ".",
			})
		}
	case dnsprotocol.TypePTR:
		ip, ok := parsePTRIP(name)
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
				Hdr: dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypePTR, Class: dnsprotocol.ClassINET, Ttl: dnsTTL},
				Ptr: normalizeName(value) + ".",
			})
		}
	case dnsprotocol.TypeSOA:
		if !found {
			goto noRecord
		}
		if normalizeName(name) == handler.service.ZoneApex() {
			reply.Answer = append(reply.Answer, &dnsprotocol.SOA{
				Hdr:     dnsprotocol.RR_Header{Name: question.Name, Rrtype: dnsprotocol.TypeSOA, Class: dnsprotocol.ClassINET, Ttl: dnsTTL},
				Ns:      normalizeName("ns."+name) + ".",
				Mbox:    "hostmaster." + name + ".",
				Serial:  uint32(time.Now().Unix()),
				Refresh: 86400,
				Retry:   3600,
				Expire:  3600,
				Minttl:  300,
			})
		}
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
