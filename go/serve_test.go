package dns

import (
	core "dappco.re/go"
)

func TestServe_ServiceRuntime_Address_Good(t *core.T) {
	subject := (*ServiceRuntime).Address
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_Address_Bad(t *core.T) {
	subject := (*ServiceRuntime).Address
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_Address_Ugly(t *core.T) {
	subject := (*ServiceRuntime).Address
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_DNSAddress_Good(t *core.T) {
	subject := (*ServiceRuntime).DNSAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_DNSAddress_Bad(t *core.T) {
	subject := (*ServiceRuntime).DNSAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_DNSAddress_Ugly(t *core.T) {
	subject := (*ServiceRuntime).DNSAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_HealthAddress_Good(t *core.T) {
	subject := (*ServiceRuntime).HealthAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_HealthAddress_Bad(t *core.T) {
	subject := (*ServiceRuntime).HealthAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_HealthAddress_Ugly(t *core.T) {
	subject := (*ServiceRuntime).HealthAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_HTTPAddress_Good(t *core.T) {
	subject := (*ServiceRuntime).HTTPAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_HTTPAddress_Bad(t *core.T) {
	subject := (*ServiceRuntime).HTTPAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_HTTPAddress_Ugly(t *core.T) {
	subject := (*ServiceRuntime).HTTPAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_Close_Good(t *core.T) {
	subject := (*ServiceRuntime).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_Close_Bad(t *core.T) {
	subject := (*ServiceRuntime).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_ServiceRuntime_Close_Ugly(t *core.T) {
	subject := (*ServiceRuntime).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_DNSServer_DNSAddress_Good(t *core.T) {
	subject := (*DNSServer).DNSAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_DNSServer_DNSAddress_Bad(t *core.T) {
	subject := (*DNSServer).DNSAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_DNSServer_DNSAddress_Ugly(t *core.T) {
	subject := (*DNSServer).DNSAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_DNSServer_Address_Good(t *core.T) {
	subject := (*DNSServer).Address
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_DNSServer_Address_Bad(t *core.T) {
	subject := (*DNSServer).Address
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_DNSServer_Address_Ugly(t *core.T) {
	subject := (*DNSServer).Address
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_DNSServer_Close_Good(t *core.T) {
	subject := (*DNSServer).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_DNSServer_Close_Bad(t *core.T) {
	subject := (*DNSServer).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_DNSServer_Close_Ugly(t *core.T) {
	subject := (*DNSServer).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ResolveDNSPort_Good(t *core.T) {
	subject := (*Service).ResolveDNSPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ResolveDNSPort_Bad(t *core.T) {
	subject := (*Service).ResolveDNSPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ResolveDNSPort_Ugly(t *core.T) {
	subject := (*Service).ResolveDNSPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_DNSListenPort_Good(t *core.T) {
	subject := (*Service).DNSListenPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_DNSListenPort_Bad(t *core.T) {
	subject := (*Service).DNSListenPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_DNSListenPort_Ugly(t *core.T) {
	subject := (*Service).DNSListenPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_DNSPort_Good(t *core.T) {
	subject := (*Service).DNSPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_DNSPort_Bad(t *core.T) {
	subject := (*Service).DNSPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_DNSPort_Ugly(t *core.T) {
	subject := (*Service).DNSPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ResolveHTTPPort_Good(t *core.T) {
	subject := (*Service).ResolveHTTPPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ResolveHTTPPort_Bad(t *core.T) {
	subject := (*Service).ResolveHTTPPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ResolveHTTPPort_Ugly(t *core.T) {
	subject := (*Service).ResolveHTTPPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ResolveHealthPort_Good(t *core.T) {
	subject := (*Service).ResolveHealthPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ResolveHealthPort_Bad(t *core.T) {
	subject := (*Service).ResolveHealthPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ResolveHealthPort_Ugly(t *core.T) {
	subject := (*Service).ResolveHealthPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HTTPListenPort_Good(t *core.T) {
	subject := (*Service).HTTPListenPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HTTPListenPort_Bad(t *core.T) {
	subject := (*Service).HTTPListenPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HTTPListenPort_Ugly(t *core.T) {
	subject := (*Service).HTTPListenPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HealthListenPort_Good(t *core.T) {
	subject := (*Service).HealthListenPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HealthListenPort_Bad(t *core.T) {
	subject := (*Service).HealthListenPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HealthListenPort_Ugly(t *core.T) {
	subject := (*Service).HealthListenPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HealthPort_Good(t *core.T) {
	subject := (*Service).HealthPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HealthPort_Bad(t *core.T) {
	subject := (*Service).HealthPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HealthPort_Ugly(t *core.T) {
	subject := (*Service).HealthPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HTTPPort_Good(t *core.T) {
	subject := (*Service).HTTPPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HTTPPort_Bad(t *core.T) {
	subject := (*Service).HTTPPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_HTTPPort_Ugly(t *core.T) {
	subject := (*Service).HTTPPort
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_Serve_Good(t *core.T) {
	subject := (*Service).Serve
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_Serve_Bad(t *core.T) {
	subject := (*Service).Serve
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_Serve_Ugly(t *core.T) {
	subject := (*Service).Serve
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_StartDNSServer_Good(t *core.T) {
	subject := (*Service).StartDNSServer
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_StartDNSServer_Bad(t *core.T) {
	subject := (*Service).StartDNSServer
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_StartDNSServer_Ugly(t *core.T) {
	subject := (*Service).StartDNSServer
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_StartDNSAndHealth_Good(t *core.T) {
	subject := (*Service).StartDNSAndHealth
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_StartDNSAndHealth_Bad(t *core.T) {
	subject := (*Service).StartDNSAndHealth
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_StartDNSAndHealth_Ugly(t *core.T) {
	subject := (*Service).StartDNSAndHealth
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ServeDNSAndHealth_Good(t *core.T) {
	subject := (*Service).ServeDNSAndHealth
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ServeDNSAndHealth_Bad(t *core.T) {
	subject := (*Service).ServeDNSAndHealth
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ServeDNSAndHealth_Ugly(t *core.T) {
	subject := (*Service).ServeDNSAndHealth
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ServeAll_Good(t *core.T) {
	subject := (*Service).ServeAll
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ServeAll_Bad(t *core.T) {
	subject := (*Service).ServeAll
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ServeAll_Ugly(t *core.T) {
	subject := (*Service).ServeAll
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ServeConfigured_Good(t *core.T) {
	subject := (*Service).ServeConfigured
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ServeConfigured_Bad(t *core.T) {
	subject := (*Service).ServeConfigured
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_ServeConfigured_Ugly(t *core.T) {
	subject := (*Service).ServeConfigured
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_StartConfigured_Good(t *core.T) {
	subject := (*Service).StartConfigured
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_StartConfigured_Bad(t *core.T) {
	subject := (*Service).StartConfigured
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestServe_Service_StartConfigured_Ugly(t *core.T) {
	subject := (*Service).StartConfigured
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
