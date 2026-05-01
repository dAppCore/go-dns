package dns

func ExampleService_ActionDefinitions() {
	_ = (*Service).ActionDefinitions
}

func ExampleService_ActionNames() {
	_ = (*Service).ActionNames
}

func ExampleService_RegisterActions() {
	_ = (*Service).RegisterActions
}

func ExampleNewServiceWithRegistrar() {
	_ = NewServiceWithRegistrar
}

func ExampleNewDNSServiceWithRegistrar() {
	_ = NewDNSServiceWithRegistrar
}

func ExampleService_HandleAction() {
	_ = (*Service).HandleAction
}

func ExampleService_HandleActionContext() {
	_ = (*Service).HandleActionContext
}
