package dns

import (
	"context"
	"errors"
	"fmt"
)

const (
	ActionResolve    = "dns.resolve"
	ActionResolveTXT = "dns.resolve.txt"
	ActionResolveAll = "dns.resolve.all"
	ActionReverse    = "dns.reverse"
	ActionServe      = "dns.serve"
	ActionHealth     = "dns.health"
	ActionDiscover   = "dns.discover"
)

var (
	errActionNotFound     = errors.New("dns action not found")
	errActionMissingValue = errors.New("dns action missing required value")
)

type ActionDefinition struct {
	Name          string
	Invoke        func(map[string]any) (any, bool, error)
	InvokeContext func(context.Context, map[string]any) (any, bool, error)
}

// ActionRegistrar publishes DNS actions into another Core surface.
//
//	registrar.RegisterAction(ActionHealth, func(map[string]any) (any, bool, error) {
//		return service.Health(), true, nil
//	})
type ActionRegistrar interface {
	RegisterAction(name string, invoke func(map[string]any) (any, bool, error))
}

// ActionCaller resolves named actions from another Core surface.
//
//	aliases, ok, err := caller.CallAction(context.Background(), "blockchain.chain.aliases", map[string]any{})
type ActionCaller interface {
	CallAction(ctx context.Context, name string, values map[string]any) (any, bool, error)
}

// ActionDefinitions returns the complete DNS action surface in registration order.
//
//	definitions := service.ActionDefinitions()
//	for _, definition := range definitions {
//		fmt.Println(definition.Name)
//	}
func (service *Service) ActionDefinitions() []ActionDefinition {
	return []ActionDefinition{
		{
			Name: ActionResolve,
			Invoke: func(values map[string]any) (any, bool, error) {
				return service.handleResolveAddress(context.Background(), values)
			},
			InvokeContext: func(ctx context.Context, values map[string]any) (any, bool, error) {
				return service.handleResolveAddress(ctx, values)
			},
		},
		{
			Name: ActionResolveTXT,
			Invoke: func(values map[string]any) (any, bool, error) {
				return service.handleResolveTXTRecords(context.Background(), values)
			},
			InvokeContext: func(ctx context.Context, values map[string]any) (any, bool, error) {
				return service.handleResolveTXTRecords(ctx, values)
			},
		},
		{
			Name: ActionResolveAll,
			Invoke: func(values map[string]any) (any, bool, error) {
				return service.handleResolveAll(context.Background(), values)
			},
			InvokeContext: func(ctx context.Context, values map[string]any) (any, bool, error) {
				return service.handleResolveAll(ctx, values)
			},
		},
		{
			Name: ActionReverse,
			Invoke: func(values map[string]any) (any, bool, error) {
				return service.handleReverseLookup(context.Background(), values)
			},
			InvokeContext: func(ctx context.Context, values map[string]any) (any, bool, error) {
				return service.handleReverseLookup(ctx, values)
			},
		},
		{
			Name: ActionServe,
			Invoke: func(values map[string]any) (any, bool, error) {
				return service.handleServe(context.Background(), values)
			},
			InvokeContext: func(ctx context.Context, values map[string]any) (any, bool, error) {
				return service.handleServe(ctx, values)
			},
		},
		{
			Name: ActionHealth,
			Invoke: func(map[string]any) (any, bool, error) {
				return service.Health(), true, nil
			},
			InvokeContext: func(_ context.Context, _ map[string]any) (any, bool, error) {
				return service.Health(), true, nil
			},
		},
		{
			Name: ActionDiscover,
			Invoke: func(map[string]any) (any, bool, error) {
				if err := service.DiscoverAliases(context.Background()); err != nil {
					return nil, false, err
				}
				return service.Health(), true, nil
			},
			InvokeContext: func(ctx context.Context, _ map[string]any) (any, bool, error) {
				if err := service.DiscoverAliases(ctx); err != nil {
					return nil, false, err
				}
				return service.Health(), true, nil
			},
		},
	}
}

// ActionNames returns the names of the registered DNS actions.
//
//	names := service.ActionNames()
//	// []string{"dns.resolve", "dns.resolve.txt", "dns.resolve.all", "dns.reverse", "dns.serve", "dns.health", "dns.discover"}
func (service *Service) ActionNames() []string {
	definitions := service.ActionDefinitions()
	names := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		names = append(names, definition.Name)
	}
	return names
}

// RegisterActions publishes the DNS action surface to a registrar in definition order.
//
//	service.RegisterActions(registrar)
//	// registrar.RegisterAction("dns.health", ...)
func (service *Service) RegisterActions(registrar ActionRegistrar) {
	if registrar == nil {
		return
	}
	for _, definition := range service.ActionDefinitions() {
		registrar.RegisterAction(definition.Name, definition.Invoke)
	}
}

// NewServiceWithRegistrar builds a DNS service and registers its actions in one step.
//
//	service := dns.NewServiceWithRegistrar(dns.ServiceOptions{}, registrar)
//	// registrar now exposes dns.resolve, dns.resolve.txt, dns.resolve.all, dns.reverse, dns.serve, dns.health, dns.discover
func NewServiceWithRegistrar(options ServiceOptions, registrar ActionRegistrar) *Service {
	if registrar != nil {
		options.ActionRegistrar = registrar
	}
	return NewService(options)
}

// HandleAction executes a DNS action by name.
//
//	payload, ok, err := service.HandleAction(ActionResolve, map[string]any{
//		"name": "gateway.charon.lthn",
//	})
func (service *Service) HandleAction(name string, values map[string]any) (any, bool, error) {
	return service.HandleActionContext(context.Background(), name, values)
}

// HandleActionContext executes a DNS action with the supplied context.
//
//	payload, ok, err := service.HandleActionContext(ctx, ActionResolve, map[string]any{
//		"name": "gateway.charon.lthn",
//	})
func (service *Service) HandleActionContext(ctx context.Context, name string, values map[string]any) (any, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for _, definition := range service.ActionDefinitions() {
		if definition.Name == name {
			if definition.InvokeContext != nil {
				return definition.InvokeContext(ctx, values)
			}
			return definition.Invoke(values)
		}
	}
	return nil, false, errActionNotFound
}

func (service *Service) handleResolveAddress(ctx context.Context, values map[string]any) (any, bool, error) {
	_ = ctx
	host, err := stringActionValue(values, "name")
	if err != nil {
		return nil, false, err
	}
	result, ok := service.ResolveAddress(host)
	if !ok {
		return nil, false, nil
	}
	return result, true, nil
}

func (service *Service) handleResolveTXTRecords(ctx context.Context, values map[string]any) (any, bool, error) {
	_ = ctx
	host, err := stringActionValue(values, "name")
	if err != nil {
		return nil, false, err
	}
	result, ok := service.ResolveTXTRecords(host)
	if !ok {
		return nil, false, nil
	}
	return result, true, nil
}

func (service *Service) handleResolveAll(ctx context.Context, values map[string]any) (any, bool, error) {
	_ = ctx
	host, err := stringActionValue(values, "name")
	if err != nil {
		return nil, false, err
	}
	result, ok := service.ResolveAll(host)
	if !ok {
		return nil, false, nil
	}
	return result, true, nil
}

func (service *Service) handleReverseLookup(ctx context.Context, values map[string]any) (any, bool, error) {
	_ = ctx
	ip, err := stringActionValue(values, "ip")
	if err != nil {
		return nil, false, err
	}
	result, ok := service.ResolveReverseNames(ip)
	if !ok {
		return nil, false, nil
	}
	return result, true, nil
}

func (service *Service) handleServe(ctx context.Context, values map[string]any) (any, bool, error) {
	_ = ctx
	bind, _ := stringActionValueOptional(values, "bind")
	port, err := intActionValue(values, "port")
	if err != nil {
		return nil, false, err
	}
	result, err := service.Serve(bind, port)
	if err != nil {
		return nil, false, err
	}
	return result, true, nil
}

func stringActionValue(values map[string]any, key string) (string, error) {
	if values == nil {
		return "", errActionMissingValue
	}
	raw, exists := values[key]
	if !exists {
		return "", errActionMissingValue
	}
	if value, ok := raw.(string); ok {
		return value, nil
	}
	return "", errActionMissingValue
}

func stringActionValueOptional(values map[string]any, key string) (string, error) {
	if values == nil {
		return "", nil
	}
	raw, exists := values[key]
	if !exists {
		return "", nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s", errActionMissingValue, key)
	}
	return value, nil
}

func intActionValue(values map[string]any, key string) (int, error) {
	if values == nil {
		return 0, errActionMissingValue
	}
	raw, exists := values[key]
	if !exists {
		return 0, errActionMissingValue
	}
	switch value := raw.(type) {
	case int:
		return value, nil
	case int32:
		return int(value), nil
	case int64:
		return int(value), nil
	case float64:
		return int(value), nil
	case float32:
		return int(value), nil
	default:
		return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
	}
}
