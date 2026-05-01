package dns

func ExampleReverseIndex_Lookup() {
	_ = (*ReverseIndex).Lookup
}

func ExampleNewService() {
	_ = NewService
}

func ExampleNewDNSService() {
	_ = NewDNSService
}

func ExampleNewDNSServiceFromOptions() {
	_ = NewDNSServiceFromOptions
}

func ExampleNewDNSServiceFromConfiguration() {
	_ = NewDNSServiceFromConfiguration
}

func ExampleNewDNSServiceWithContextRegistrar() {
	_ = NewDNSServiceWithContextRegistrar
}

func ExampleService_DiscoverFromChainAliases() {
	_ = (*Service).DiscoverFromChainAliases
}

func ExampleService_DiscoverFromMainchainAliases() {
	_ = (*Service).DiscoverFromMainchainAliases
}

func ExampleService_Discover() {
	_ = (*Service).Discover
}

func ExampleService_DiscoverAliases() {
	_ = (*Service).DiscoverAliases
}

func ExampleService_SetRecord() {
	_ = (*Service).SetRecord
}

func ExampleService_RemoveRecord() {
	_ = (*Service).RemoveRecord
}

func ExampleService_Resolve() {
	_ = (*Service).Resolve
}

func ExampleService_ResolveRecords() {
	_ = (*Service).ResolveRecords
}

func ExampleService_ResolveWithWildcardMatch() {
	_ = (*Service).ResolveWithWildcardMatch
}

func ExampleService_ResolveWithMatch() {
	_ = (*Service).ResolveWithMatch
}

func ExampleService_ResolveTXT() {
	_ = (*Service).ResolveTXT
}

func ExampleService_ResolveTXTRecords() {
	_ = (*Service).ResolveTXTRecords
}

func ExampleService_ResolveTXTWithMatch() {
	_ = (*Service).ResolveTXTWithMatch
}

func ExampleService_DiscoverWithHSD() {
	_ = (*Service).DiscoverWithHSD
}

func ExampleService_ResolveAddresses() {
	_ = (*Service).ResolveAddresses
}

func ExampleService_ResolveAddress() {
	_ = (*Service).ResolveAddress
}

func ExampleService_ResolveReverse() {
	_ = (*Service).ResolveReverse
}

func ExampleService_ResolveAll() {
	_ = (*Service).ResolveAll
}

func ExampleService_Health() {
	_ = (*Service).Health
}

func ExampleService_CurrentTreeRoot() {
	_ = (*Service).CurrentTreeRoot
}

func ExampleService_Snapshot() {
	_ = (*Service).Snapshot
}

func ExampleService_Describe() {
	_ = (*Service).Describe
}

func ExampleService_ZoneApex() {
	_ = (*Service).ZoneApex
}

func ExampleService_ResolveReverseNames() {
	_ = (*Service).ResolveReverseNames
}

func ExampleService_ResolvePTRNames() {
	_ = (*Service).ResolvePTRNames
}

func ExampleService_ResolvePTR() {
	_ = (*Service).ResolvePTR
}

func ExampleNormalizeIP() {
	_ = NormalizeIP
}

func ExampleNormalizeName() {
	_ = NormalizeName
}

func ExampleService_String() {
	_ = (*Service).String
}

func ExampleMergeRecords() {
	_ = MergeRecords
}
