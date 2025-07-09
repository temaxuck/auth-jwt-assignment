package http

import (
	"log"
	"net/http"

	c "auth-jwt-assignment/config"
	"auth-jwt-assignment/internal/http/routes"
	"auth-jwt-assignment/internal/repo"
	"auth-jwt-assignment/pkg/jwt"

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
	mux.Handle("/security/", http.StripPrefix("/security", routes.NewSecurityRouter()))
	mux.Handle("/", routes.NewBaseRouter(j, tr))

	log.Println("Starting server on:", s.addr)
	return http.ListenAndServe(s.addr, mux)
}
