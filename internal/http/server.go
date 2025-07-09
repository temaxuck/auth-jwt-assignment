package http

import (
	"encoding/json"
	"log"
	"net/http"

	c "auth-jwt-assignment/config"
	mw "auth-jwt-assignment/internal/http/middleware"
	"auth-jwt-assignment/internal/http/routes"
	"auth-jwt-assignment/internal/repo"
	"auth-jwt-assignment/pkg/jwt"
	"auth-jwt-assignment/pkg/rm"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TODO: Put Handler logic into separate file, e.g. `internal/http/routes/auth.go`
// TODO: Do not store db in the Handler, instead store TokenRepo
type Server struct {
	addr string
	cfg  *c.Config
	db   *pgxpool.Pool
}

func NewServer(addr string, cfg *c.Config, db *pgxpool.Pool) *Server {
	return &Server{
		addr: addr,
		cfg:  cfg,
		db:   db,
	}
}

func (s *Server) RunServer() error {
	j := jwt.New(s.cfg.Auth.Secret, s.cfg.Auth.AccessTokenTTL)
	tr := repo.NewTokenRepo(s.db, s.cfg.Auth.RefreshTokenTTL)

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", routes.NewAuthRouter(j, tr, s.cfg.Auth.WebhookURL)))
	mux.Handle("/security/refresh-new-ip", rm.MethodMapper{Post: securityDummyWebhook})
	mux.Handle("/whoami", rm.MethodMapper{Get: mw.Protected(j, tr, whoami)})

	log.Println("Starting server on:", s.addr)
	return http.ListenAndServe(s.addr, mux)
}

func whoami(w http.ResponseWriter, r *http.Request) {
	atp, ok := r.Context().Value("access-token-payload").(*jwt.AccessTokenPayload)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	data := map[string]string{"GUID": atp.Subject}
	response, err := json.Marshal(data)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	w.Write(response)
}

func securityDummyWebhook(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		UserGUID  string `json:"user_guid"`
		NewIP     string `json:"new_ip"`
		OldIP     string `json:"old_ip"`
		UserAgent string `json:"user_agent"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	log.Printf("INFO: [UserID: %s; UserAgent: %s] Client refreshed token from a new IP address: %s => %s", payload.UserGUID, payload.UserAgent, payload.OldIP, payload.NewIP)

}
