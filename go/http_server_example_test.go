package dns

func ExampleHealthServer_HealthAddress() {
	_ = (*HealthServer).HealthAddress
}

func ExampleHealthServer_Address() {
	_ = (*HealthServer).Address
}

func ExampleService_StartHealthServer() {
	_ = (*Service).StartHealthServer
}

func ExampleHealthServer_Close() {
	_ = (*HealthServer).Close
}

func ExampleService_ServeHTTPHealth() {
	_ = (*Service).ServeHTTPHealth
}
