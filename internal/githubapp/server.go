package githubapp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const maxBodySize = 10 * 1024 * 1024 // 10 MB

// Server is the GitHub App webhook server.
type Server struct {
	handler *Handler
	secret  []byte
	mux     *http.ServeMux
	srv     *http.Server
}

// NewServer creates a new webhook server.
func NewServer(cfg *Config, handler *Handler) *Server {
	s := &Server{
		handler: handler,
		secret:  []byte(cfg.WebhookSecret),
		mux:     http.NewServeMux(),
	}

	s.mux.HandleFunc("POST /webhook", s.handleWebhook)
	s.mux.HandleFunc("GET /health", s.handleHealth)

	s.srv = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      s.mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	slog.Info("starting webhook server", "addr", s.srv.Addr)
	return s.srv.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Validate HMAC-SHA256 signature
	sig := r.Header.Get("X-Hub-Signature-256")
	if !s.verifySignature(body, sig) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	event := r.Header.Get("X-GitHub-Event")
	delivery := r.Header.Get("X-GitHub-Delivery")

	slog.Info("received webhook", "event", event, "delivery", delivery)

	switch event {
	case "ping":
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"message":"pong"}`)

	case "pull_request":
		// Process async — respond 202 immediately
		go s.handler.HandlePullRequest(body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"message":"accepted"}`)

	default:
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"message":"ignored"}`)
	}
}

func (s *Server) verifySignature(payload []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}

	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(strings.TrimPrefix(signature, "sha256=")))
}
