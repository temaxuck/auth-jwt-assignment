package http

import (
	"log"
	"net/http"

	c "auth-jwt-assignment/config"
	_ "auth-jwt-assignment/docs"
	"auth-jwt-assignment/internal/auth"
	"auth-jwt-assignment/internal/http/routes"
	"auth-jwt-assignment/internal/repo"
	"auth-jwt-assignment/pkg/jwt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/swaggo/http-swagger"
)

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
	tr := repo.NewTokenRepo(s.db)
	as := auth.NewAuthService(j, tr, s.cfg)

	mux := http.NewServeMux()
	mux.Handle("/", routes.NewBaseRouter(as))
	mux.Handle("/auth/", http.StripPrefix("/auth", routes.NewAuthRouter(as, s.cfg.Auth.WebhookURL)))
	mux.Handle("/security/", http.StripPrefix("/security", routes.NewSecurityRouter()))
	mux.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	log.Println("INFO: Starting server on:", s.addr)
	return http.ListenAndServe(s.addr, mux)
}
