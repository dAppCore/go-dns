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
	Name   string
	Invoke func(map[string]any) (any, bool, error)
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
//	payload, ok, err := caller.CallAction(context.Background(), "blockchain.chain.aliases", nil)
type ActionCaller interface {
	CallAction(ctx context.Context, name string, values map[string]any) (any, bool, error)
}

// ActionDefinitions returns the complete DNS action surface in registration order.
//
//	definitions := service.ActionDefinitions()
//	for _, definition := range definitions {
//		registrar.RegisterAction(definition.Name, definition.Invoke)
//	}
func (service *Service) ActionDefinitions() []ActionDefinition {
	return []ActionDefinition{
		{
			Name: ActionResolve,
			Invoke: func(values map[string]any) (any, bool, error) {
				host, err := stringActionValue(values, "name")
				if err != nil {
					return nil, false, err
				}
				result, ok := service.ResolveAddress(host)
				if !ok {
					return nil, false, nil
				}
				return result, true, nil
			},
		},
		{
			Name: ActionResolveTXT,
			Invoke: func(values map[string]any) (any, bool, error) {
				host, err := stringActionValue(values, "name")
				if err != nil {
					return nil, false, err
				}
				result, ok := service.ResolveTXTRecords(host)
				if !ok {
					return nil, false, nil
				}
				return result, true, nil
			},
		},
		{
			Name: ActionResolveAll,
			Invoke: func(values map[string]any) (any, bool, error) {
				host, err := stringActionValue(values, "name")
				if err != nil {
					return nil, false, err
				}
				result, ok := service.ResolveAll(host)
				if !ok {
					return nil, false, nil
				}
				return result, true, nil
			},
		},
		{
			Name: ActionReverse,
			Invoke: func(values map[string]any) (any, bool, error) {
				ip, err := stringActionValue(values, "ip")
				if err != nil {
					return nil, false, err
				}
				result, ok := service.ResolveReverseNames(ip)
				if !ok {
					return nil, false, nil
				}
				return result, true, nil
			},
		},
		{
			Name: ActionServe,
			Invoke: func(values map[string]any) (any, bool, error) {
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
			},
		},
		{
			Name: ActionHealth,
			Invoke: func(map[string]any) (any, bool, error) {
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
//	// registrar now knows how to handle dns.health and the rest of the DNS actions.
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
	service := NewService(options)
	service.RegisterActions(registrar)
	return service
}

// HandleAction executes a DNS action by name.
//
//	payload, ok, err := service.HandleAction(ActionResolve, map[string]any{
//		"name": "gateway.charon.lthn",
//	})
func (service *Service) HandleAction(name string, values map[string]any) (any, bool, error) {
	for _, definition := range service.ActionDefinitions() {
		if definition.Name == name {
			return definition.Invoke(values)
		}
	}
	return nil, false, errActionNotFound
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
