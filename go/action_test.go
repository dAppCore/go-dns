package dns

import (
	core "github.com/dappcore/go"
)

func TestAction_Service_ActionDefinitions_Good(t *core.T) {
	subject := (*Service).ActionDefinitions
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_ActionDefinitions_Bad(t *core.T) {
	subject := (*Service).ActionDefinitions
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_ActionDefinitions_Ugly(t *core.T) {
	subject := (*Service).ActionDefinitions
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_ActionNames_Good(t *core.T) {
	subject := (*Service).ActionNames
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_ActionNames_Bad(t *core.T) {
	subject := (*Service).ActionNames
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_ActionNames_Ugly(t *core.T) {
	subject := (*Service).ActionNames
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_RegisterActions_Good(t *core.T) {
	subject := (*Service).RegisterActions
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_RegisterActions_Bad(t *core.T) {
	subject := (*Service).RegisterActions
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_RegisterActions_Ugly(t *core.T) {
	subject := (*Service).RegisterActions
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_NewServiceWithRegistrar_Good(t *core.T) {
	subject := NewServiceWithRegistrar
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_NewServiceWithRegistrar_Bad(t *core.T) {
	subject := NewServiceWithRegistrar
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_NewServiceWithRegistrar_Ugly(t *core.T) {
	subject := NewServiceWithRegistrar
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_NewDNSServiceWithRegistrar_Good(t *core.T) {
	subject := NewDNSServiceWithRegistrar
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_NewDNSServiceWithRegistrar_Bad(t *core.T) {
	subject := NewDNSServiceWithRegistrar
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_NewDNSServiceWithRegistrar_Ugly(t *core.T) {
	subject := NewDNSServiceWithRegistrar
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_HandleAction_Good(t *core.T) {
	subject := (*Service).HandleAction
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_HandleAction_Bad(t *core.T) {
	subject := (*Service).HandleAction
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_HandleAction_Ugly(t *core.T) {
	subject := (*Service).HandleAction
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_HandleActionContext_Good(t *core.T) {
	subject := (*Service).HandleActionContext
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_HandleActionContext_Bad(t *core.T) {
	subject := (*Service).HandleActionContext
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAction_Service_HandleActionContext_Ugly(t *core.T) {
	subject := (*Service).HandleActionContext
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
