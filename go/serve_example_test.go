package dns

func ExampleServiceRuntime_Address() {
	_ = (*ServiceRuntime).Address
}

func ExampleServiceRuntime_DNSAddress() {
	_ = (*ServiceRuntime).DNSAddress
}

func ExampleServiceRuntime_HealthAddress() {
	_ = (*ServiceRuntime).HealthAddress
}

func ExampleServiceRuntime_HTTPAddress() {
	_ = (*ServiceRuntime).HTTPAddress
}

func ExampleServiceRuntime_Close() {
	_ = (*ServiceRuntime).Close
}

func ExampleDNSServer_DNSAddress() {
	_ = (*DNSServer).DNSAddress
}

func ExampleDNSServer_Address() {
	_ = (*DNSServer).Address
}

func ExampleDNSServer_Close() {
	_ = (*DNSServer).Close
}

func ExampleService_ResolveDNSPort() {
	_ = (*Service).ResolveDNSPort
}

func ExampleService_DNSListenPort() {
	_ = (*Service).DNSListenPort
}

func ExampleService_DNSPort() {
	_ = (*Service).DNSPort
}

func ExampleService_ResolveHTTPPort() {
	_ = (*Service).ResolveHTTPPort
}

func ExampleService_ResolveHealthPort() {
	_ = (*Service).ResolveHealthPort
}

func ExampleService_HTTPListenPort() {
	_ = (*Service).HTTPListenPort
}

func ExampleService_HealthListenPort() {
	_ = (*Service).HealthListenPort
}

func ExampleService_HealthPort() {
	_ = (*Service).HealthPort
}

func ExampleService_HTTPPort() {
	_ = (*Service).HTTPPort
}

func ExampleService_Serve() {
	_ = (*Service).Serve
}

func ExampleService_StartDNSServer() {
	_ = (*Service).StartDNSServer
}

func ExampleService_StartDNSAndHealth() {
	_ = (*Service).StartDNSAndHealth
}

func ExampleService_ServeDNSAndHealth() {
	_ = (*Service).ServeDNSAndHealth
}

func ExampleService_ServeAll() {
	_ = (*Service).ServeAll
}

func ExampleService_ServeConfigured() {
	_ = (*Service).ServeConfigured
}

func ExampleService_StartConfigured() {
	_ = (*Service).StartConfigured
}
