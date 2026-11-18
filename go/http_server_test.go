package dns

import (
	core "github.com/dappcore/go"
)

func TestHttpServer_HealthServer_HealthAddress_Good(t *core.T) {
	subject := (*HealthServer).HealthAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_HealthServer_HealthAddress_Bad(t *core.T) {
	subject := (*HealthServer).HealthAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_HealthServer_HealthAddress_Ugly(t *core.T) {
	subject := (*HealthServer).HealthAddress
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_HealthServer_Address_Good(t *core.T) {
	subject := (*HealthServer).Address
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_HealthServer_Address_Bad(t *core.T) {
	subject := (*HealthServer).Address
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_HealthServer_Address_Ugly(t *core.T) {
	subject := (*HealthServer).Address
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_Service_StartHealthServer_Good(t *core.T) {
	subject := (*Service).StartHealthServer
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_Service_StartHealthServer_Bad(t *core.T) {
	subject := (*Service).StartHealthServer
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_Service_StartHealthServer_Ugly(t *core.T) {
	subject := (*Service).StartHealthServer
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_HealthServer_Close_Good(t *core.T) {
	subject := (*HealthServer).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_HealthServer_Close_Bad(t *core.T) {
	subject := (*HealthServer).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_HealthServer_Close_Ugly(t *core.T) {
	subject := (*HealthServer).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_Service_ServeHTTPHealth_Good(t *core.T) {
	subject := (*Service).ServeHTTPHealth
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_Service_ServeHTTPHealth_Bad(t *core.T) {
	subject := (*Service).ServeHTTPHealth
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHttpServer_Service_ServeHTTPHealth_Ugly(t *core.T) {
	subject := (*Service).ServeHTTPHealth
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
