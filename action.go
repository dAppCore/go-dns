package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
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

const (
	actionArgBind             = "bind"
	actionArgBindAddress      = "bindAddress"
	actionArgBindAddressSnake = "bind_address"
	actionArgIP               = "ip"
	actionArgAddress          = "address"
	actionArgName             = "name"
	actionArgHost             = "host"
	actionArgHostName         = "hostname"
	actionArgPort             = "port"
	actionArgDNSPort          = "dnsPort"
	actionArgDNSPortSnake     = "dns_port"
	actionArgHealthPort       = "health_port"
	actionArgHealthPortCamel  = "healthPort"
)

type ActionDefinition struct {
	Name          string
	Invoke        func(map[string]any) (any, bool, error)
	InvokeContext func(context.Context, map[string]any) (any, bool, error)
}

// ActionRegistrar publishes DNS actions into another Core surface.
//
//	registrar.RegisterAction(ActionResolve, func(values map[string]any) (any, bool, error) {
//		return service.ResolveAddress("gateway.charon.lthn")
//	})
type ActionRegistrar interface {
	RegisterAction(name string, invoke func(map[string]any) (any, bool, error))
}

// ActionContextRegistrar publishes DNS actions while preserving caller context.
//
//	registrar.RegisterActionContext(
//		ActionDiscover,
//		func(ctx context.Context, values map[string]any) (any, bool, error) {
//			return service.HandleActionContext(ctx, ActionDiscover, values)
//		},
//	)
type ActionContextRegistrar interface {
	RegisterActionContext(name string, invoke func(context.Context, map[string]any) (any, bool, error))
}

// ActionCaller resolves named actions from another Core surface.
//
//	aliases, ok, err := caller.CallAction(
//		context.Background(),
//		"blockchain.chain.aliases",
//		map[string]any{},
//	)
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

	if contextRegistrar, ok := registrar.(ActionContextRegistrar); ok {
		for _, definition := range service.ActionDefinitions() {
			invoke := definition.InvokeContext
			if invoke == nil {
				invoke = func(ctx context.Context, values map[string]any) (any, bool, error) {
					return definition.Invoke(values)
				}
			}
			contextRegistrar.RegisterActionContext(definition.Name, invoke)
		}
		return
	}

	for _, definition := range service.ActionDefinitions() {
		registrar.RegisterAction(definition.Name, definition.Invoke)
	}
}

// NewServiceWithRegistrar builds a DNS service and registers its actions in one step.
//
// Deprecated: use NewDNSServiceWithRegistrar for a more explicit constructor name.
//
//	service := dns.NewServiceWithRegistrar(dns.ServiceConfiguration{}, registrar)
//	// registrar now exposes dns.resolve, dns.resolve.txt, dns.resolve.all, dns.reverse, dns.serve, dns.health, dns.discover
func NewServiceWithRegistrar(options ServiceOptions, registrar ActionRegistrar) *Service {
	if registrar != nil {
		options.ActionRegistrar = registrar
	}
	return NewService(options)
}

// NewDNSServiceWithRegistrar builds a DNS service and registers its actions in one step.
//
//	service := dns.NewDNSServiceWithRegistrar(dns.ServiceConfiguration{}, registrar)
//	// registrar now exposes dns.resolve, dns.resolve.txt, dns.resolve.all, dns.reverse, dns.serve, dns.health, dns.discover
func NewDNSServiceWithRegistrar(options ServiceOptions, registrar ActionRegistrar) *Service {
	return NewServiceWithRegistrar(options, registrar)
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
	host, err := stringActionValueFromKeys(values, actionArgName, actionArgHost, actionArgHostName)
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
	host, err := stringActionValueFromKeys(values, actionArgName, actionArgHost, actionArgHostName)
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
	host, err := stringActionValueFromKeys(values, actionArgName, actionArgHost, actionArgHostName)
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
	ip, err := stringActionValueFromKeys(values, actionArgIP, actionArgAddress)
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
	bind, _, err := stringActionValueOptionalFromKeys(values, actionArgBind, actionArgBindAddress, actionArgBindAddressSnake)
	if err != nil {
		return nil, false, err
	}
	port, portProvided, err := intActionValueOptionalFromKeys(values, actionArgPort, actionArgDNSPort, actionArgDNSPortSnake)
	if err != nil {
		return nil, false, err
	}
	if !portProvided {
		port = service.ResolveDNSPort()
	}

	healthPort, healthPortProvided, err := intActionValueOptionalFromKeys(values, actionArgHealthPort, actionArgHealthPortCamel)
	if err != nil {
		return nil, false, err
	}
	if !healthPortProvided && service.httpPort > 0 {
		runtime, err := service.ServeAll(bind, port, service.httpPort)
		if err != nil {
			return nil, false, err
		}
		return runtime, true, nil
	}
	if healthPortProvided {
		runtime, err := service.ServeAll(bind, port, healthPort)
		if err != nil {
			return nil, false, err
		}
		return runtime, true, nil
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
		value = strings.TrimSpace(value)
		if value == "" {
			return "", errActionMissingValue
		}
		return value, nil
	}
	return "", errActionMissingValue
}

func lookupActionValue(values map[string]any, keys ...string) (any, string, bool) {
	if values == nil {
		return nil, "", false
	}

	for _, key := range keys {
		if value, exists := values[key]; exists {
			return value, key, true
		}
	}

	for _, key := range keys {
		for alias, value := range values {
			if strings.EqualFold(alias, key) {
				return value, alias, true
			}
		}
	}

	return nil, "", false
}

func stringActionValueFromKeys(values map[string]any, keys ...string) (string, error) {
	value, key, found := lookupActionValue(values, keys...)
	if !found {
		return "", errActionMissingValue
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s", errActionMissingValue, key)
	}

	text = strings.TrimSpace(text)
	if text == "" {
		return "", errActionMissingValue
	}

	return text, nil
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
	return strings.TrimSpace(value), nil
}

func stringActionValueOptionalFromKeys(values map[string]any, keys ...string) (string, bool, error) {
	value, key, found := lookupActionValue(values, keys...)
	if !found {
		return "", false, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", false, fmt.Errorf("%w: %s", errActionMissingValue, key)
	}
	return strings.TrimSpace(text), true, nil
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
	case uint:
		return int(value), nil
	case uint8:
		return int(value), nil
	case uint16:
		return int(value), nil
	case uint32:
		return int(value), nil
	case uint64:
		if value > uint64(^uint(0)>>1) {
			return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
		}
		return int(value), nil
	case int32:
		return int(value), nil
	case int64:
		if value > int64(int(^uint(0)>>1)) || value < int64(^uint(0)>>1)*-1-1 {
			return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
		}
		return int(value), nil
	case float64:
		if math.Trunc(value) != value {
			return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
		}
		if value < 0 || value > float64(int(^uint(0)>>1)) {
			return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
		}
		return int(value), nil
	case float32:
		floating := float64(value)
		if math.Trunc(floating) != floating {
			return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
		}
		if floating < 0 || floating > float64(int(^uint(0)>>1)) {
			return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
		}
		return int(floating), nil
	case json.Number:
		parsed, err := value.Int64()
		if err == nil {
			if parsed > int64(int(^uint(0)>>1)) || parsed < int64(^uint(0)>>1)*-1-1 {
				return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
			}
			return int(parsed), nil
		}
		floating, parseErr := value.Float64()
		if parseErr != nil {
			return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
		}
		if math.Trunc(floating) != floating {
			return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
		}
		if floating < 0 || floating > float64(int(^uint(0)>>1)) {
			return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
		}
		return int(floating), nil
	default:
		return 0, fmt.Errorf("%w: %s", errActionMissingValue, key)
	}
}

func intActionValueOptional(values map[string]any, key string) (int, bool, error) {
	if values == nil {
		return 0, false, nil
	}
	_, exists := values[key]
	if !exists {
		return 0, false, nil
	}
	value, err := intActionValue(values, key)
	if err != nil {
		return 0, false, err
	}
	return value, true, nil
}

func intActionValueOptionalFromKeys(values map[string]any, keys ...string) (int, bool, error) {
	for _, key := range keys {
		value, valueProvided, err := intActionValueOptional(values, key)
		if err != nil {
			return 0, false, err
		}
		if valueProvided {
			return value, true, nil
		}
	}

	value, key, found := lookupActionValue(values, keys...)
	if !found {
		return 0, false, nil
	}
	intValue, err := intActionValue(map[string]any{key: value}, key)
	if err != nil {
		return 0, false, err
	}

	return intValue, true, nil
}
