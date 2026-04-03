package dns

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"
)

// HTTPServer owns the health endpoint listener and server.
//
//	server, err := service.ServeHTTPHealth("127.0.0.1", 5554)
//	defer func() { _ = server.Close() }()
type HTTPServer struct {
	listener net.Listener
	server   *http.Server
}

func (server *HTTPServer) Address() string {
	if server == nil || server.listener == nil {
		return ""
	}
	return server.listener.Addr().String()
}

func (server *HTTPServer) Close() error {
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
func (service *Service) ServeHTTPHealth(bind string, port int) (*HTTPServer, error) {
	if bind == "" {
		bind = "127.0.0.1"
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

	httpServer := &HTTPServer{
		listener: listener,
		server:   server,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	return httpServer, nil
}
