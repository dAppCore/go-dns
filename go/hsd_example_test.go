package dns

func ExampleHSDRPCError_Error() {
	_ = (*HSDRPCError).Error
}

func ExampleNewHSDClient() {
	_ = NewHSDClient
}

func ExampleNewHSDClientFromOptions() {
	_ = NewHSDClientFromOptions
}

func ExampleNewHSDClientFromConfiguration() {
	_ = NewHSDClientFromConfiguration
}

func ExampleHSDClient_GetNameResource() {
	_ = (*HSDClient).GetNameResource
}

func ExampleHSDClient_GetBlockchainInfo() {
	_ = (*HSDClient).GetBlockchainInfo
}
