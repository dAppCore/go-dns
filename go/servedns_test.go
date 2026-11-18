package dns

import (
	"net"

	core "github.com/dappcore/go"
	dnsprotocol "github.com/miekg/dns"
)

// captureResponseWriter records the reply a handler writes so ServeDNS edge
// branches can be exercised without binding a UDP/TCP listener.
type captureResponseWriter struct {
	written *dnsprotocol.Msg
}

func (writer *captureResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
}
func (writer *captureResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
}
func (writer *captureResponseWriter) WriteMsg(msg *dnsprotocol.Msg) error {
	writer.written = msg
	return nil
}
func (writer *captureResponseWriter) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (writer *captureResponseWriter) Close() error                     { return nil }
func (writer *captureResponseWriter) TsigStatus() error                { return nil }
func (writer *captureResponseWriter) TsigTimersOnly(bool)              {}
func (writer *captureResponseWriter) Hijack()                          {}

func newTestRequestHandler() *dnsRequestHandler {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {A: []string{"10.10.10.10"}},
		},
	})
	return &dnsRequestHandler{service: service}
}

func TestServeDNS_Good(t *core.T) {
	handler := newTestRequestHandler()
	writer := &captureResponseWriter{}

	request := new(dnsprotocol.Msg)
	request.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeA)
	handler.ServeDNS(writer, request)

	if writer.written == nil {
		t.Fatal("expected a reply to be written")
	}
	if writer.written.Rcode != dnsprotocol.RcodeSuccess {
		t.Fatalf("expected success rcode, got %d", writer.written.Rcode)
	}
	if len(writer.written.Answer) != 1 {
		t.Fatalf("expected one answer, got %d", len(writer.written.Answer))
	}
}

func TestServeDNS_Bad(t *core.T) {
	handler := newTestRequestHandler()

	// nil request -> NotImplemented
	nilWriter := &captureResponseWriter{}
	handler.ServeDNS(nilWriter, nil)
	if nilWriter.written == nil || nilWriter.written.Rcode != dnsprotocol.RcodeNotImplemented {
		t.Fatalf("expected NotImplemented for a nil request, got %#v", nilWriter.written)
	}

	// non-query opcode -> NotImplemented
	opcodeWriter := &captureResponseWriter{}
	statusRequest := new(dnsprotocol.Msg)
	statusRequest.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeA)
	statusRequest.Opcode = dnsprotocol.OpcodeStatus
	handler.ServeDNS(opcodeWriter, statusRequest)
	if opcodeWriter.written == nil || opcodeWriter.written.Rcode != dnsprotocol.RcodeNotImplemented {
		t.Fatalf("expected NotImplemented for a non-query opcode, got %#v", opcodeWriter.written)
	}
}

func TestServeDNS_Ugly(t *core.T) {
	handler := newTestRequestHandler()

	// query with no question section -> FormatError
	emptyWriter := &captureResponseWriter{}
	emptyRequest := new(dnsprotocol.Msg)
	emptyRequest.Opcode = dnsprotocol.OpcodeQuery
	handler.ServeDNS(emptyWriter, emptyRequest)
	if emptyWriter.written == nil || emptyWriter.written.Rcode != dnsprotocol.RcodeFormatError {
		t.Fatalf("expected FormatError for an empty question section, got %#v", emptyWriter.written)
	}

	// query for an unknown name -> NXDOMAIN, no answers
	missingWriter := &captureResponseWriter{}
	missingRequest := new(dnsprotocol.Msg)
	missingRequest.SetQuestion("nope.charon.lthn.", dnsprotocol.TypeA)
	handler.ServeDNS(missingWriter, missingRequest)
	if missingWriter.written == nil {
		t.Fatal("expected a reply for a missing name")
	}
	if len(missingWriter.written.Answer) != 0 {
		t.Fatalf("expected no answers for a missing name, got %d", len(missingWriter.written.Answer))
	}
}

func TestServeDNS_UnsupportedTypeNotImplemented(t *core.T) {
	handler := newTestRequestHandler()
	writer := &captureResponseWriter{}

	request := new(dnsprotocol.Msg)
	// HINFO is not handled by the switch and must hit the default branch.
	request.SetQuestion("gateway.charon.lthn.", dnsprotocol.TypeHINFO)
	handler.ServeDNS(writer, request)

	if writer.written == nil || writer.written.Rcode != dnsprotocol.RcodeNotImplemented {
		t.Fatalf("expected NotImplemented for an unsupported qtype, got %#v", writer.written)
	}
}

func TestServeDNS_PTRFormatError(t *core.T) {
	handler := newTestRequestHandler()
	writer := &captureResponseWriter{}

	request := new(dnsprotocol.Msg)
	// A PTR query whose name is not a valid in-addr.arpa reversal.
	request.SetQuestion("not-a-reverse-name.", dnsprotocol.TypePTR)
	handler.ServeDNS(writer, request)

	if writer.written == nil || writer.written.Rcode != dnsprotocol.RcodeFormatError {
		t.Fatalf("expected FormatError for a malformed PTR name, got %#v", writer.written)
	}
}

func TestServeDNS_RecordTypeHits(t *core.T) {
	service := NewService(ServiceOptions{
		Records: map[string]NameRecords{
			"gateway.charon.lthn": {
				AAAA:   []string{"fe80::1"},
				TXT:    []string{"v=lthn1 type=gateway"},
				DS:     []string{"60485 8 2 A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"},
				DNSKEY: []string{"257 3 13 AA=="},
			},
		},
	})
	handler := &dnsRequestHandler{service: service}

	cases := []struct {
		name  string
		qtype uint16
	}{
		{"AAAA", dnsprotocol.TypeAAAA},
		{"TXT", dnsprotocol.TypeTXT},
		{"DS", dnsprotocol.TypeDS},
		{"DNSKEY", dnsprotocol.TypeDNSKEY},
		{"ANY", dnsprotocol.TypeANY},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *core.T) {
			writer := &captureResponseWriter{}
			request := new(dnsprotocol.Msg)
			request.SetQuestion("gateway.charon.lthn.", tc.qtype)
			handler.ServeDNS(writer, request)
			if writer.written == nil {
				t.Fatalf("%s: expected a reply", tc.name)
			}
			if writer.written.Rcode != dnsprotocol.RcodeSuccess {
				t.Fatalf("%s: expected success rcode, got %d", tc.name, writer.written.Rcode)
			}
			if len(writer.written.Answer) == 0 {
				t.Fatalf("%s: expected at least one answer", tc.name)
			}
		})
	}
}
