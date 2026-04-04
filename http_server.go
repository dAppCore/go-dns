package dns

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"
)

// HealthServer wraps the `/health` listener returned by ServeHTTPHealth.
//
//	server, err := service.ServeHTTPHealth("127.0.0.1", 5554)
//	defer func() { _ = server.Close() }()
//	fmt.Println("health at", server.Address())
type HealthServer struct {
	listener net.Listener
	server   *http.Server
}

// HTTPServer is kept as a compatibility alias for HealthServer.
type HTTPServer = HealthServer

func (server *HealthServer) HealthAddress() string {
	if server == nil || server.listener == nil {
		return ""
	}
	return server.listener.Addr().String()
}

// Address is retained for compatibility with older call sites.
func (server *HealthServer) Address() string {
	return server.HealthAddress()
}

// StartHealthServer is an explicit convenience wrapper around ServeHTTPHealth.
//
//	health, err := service.StartHealthServer("127.0.0.1", 5554)
func (service *Service) StartHealthServer(bind string, port int) (*HealthServer, error) {
	return service.ServeHTTPHealth(bind, port)
}

func (server *HealthServer) Close() error {
	if server == nil {
		return nil
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if server.server != nil {
		if err := server.server.Shutdown(shutdownContext); err != nil {
			_ = server.server.Close()
			return err
		}
		return nil
	}

	if server.listener != nil {
		return server.listener.Close()
	}
	return nil
}

// ServeHTTPHealth starts the health endpoint.
//
//	server, err := service.ServeHTTPHealth("127.0.0.1", 5554)
//	defer func() { _ = server.Close() }()
//	resp, _ := http.Get("http://" + server.HealthAddress() + "/health")
func (service *Service) ServeHTTPHealth(bind string, port int) (*HealthServer, error) {
	if bind == "" {
		bind = "127.0.0.1"
	}
	if port <= 0 {
		port = service.resolveHTTPPort()
	}

	address := net.JoinHostPort(bind, strconv.Itoa(port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			responseWriter.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		responseWriter.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(responseWriter).Encode(service.Health())
	})

	server := &http.Server{
		Handler: mux,
	}

	httpServer := &HealthServer{
		listener: listener,
		server:   server,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	return httpServer, nil
}
