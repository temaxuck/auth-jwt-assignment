package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Handler struct {
	cfg *Config
	db  *pgxpool.Pool
}

func runServer(addr string, cfg *Config, db *pgxpool.Pool) error {
	h := &Handler{
		cfg: cfg,
		db:  db,
	}

	router := http.NewServeMux()
	router.Handle("/auth/{guid}/login", MethodMapper{Post: h.login})
	router.Handle("/auth/{guid}/logout", MethodMapper{Post: h.logout})
	router.Handle("/auth/{guid}/refresh", MethodMapper{Post: h.refresh})
	router.Handle("/whoami", MethodMapper{Get: h.protected(h.whoami)})

	log.Println("Starting server on:", addr)
	return http.ListenAndServe(addr, router)

}

func (h *Handler) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("access-token")
		if err != nil {
			switch err {
			case http.ErrNoCookie:
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			default:
				log.Printf("ERROR: Couldn't get access token: %v", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
			}
			return
		}

		payload, err := ValidateAccessToken(h.cfg, cookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "access-token-payload", payload)
		r = r.WithContext(ctx)

		next(w, r)
	}
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	GUID := r.PathValue("guid")
	accessToken, expires, err := IssueAccessToken(h.cfg, GUID)
	if err != nil {
		log.Printf("ERROR: Couldn't issue access token: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	SetTokenCookie(w, "access-token", accessToken, expires)

	refreshToken, expires, err := IssueRefreshToken(h.cfg, h.db, GUID, accessToken, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		log.Printf("ERROR: Couldn't issue refresh token: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	SetTokenCookie(w, "refresh-token", refreshToken, expires)
}

func (_ *Handler) logout(w http.ResponseWriter, r *http.Request) {
	log.Println("logout handler")
}

func (_ *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	log.Println("refresh handler")
}

func (h *Handler) whoami(w http.ResponseWriter, r *http.Request) {
	tp, ok := r.Context().Value("access-token-payload").(*AccessTokenPayload)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	data := map[string]string{"GUID": tp.UserGUID}
	response, err := json.Marshal(data)
	if err != nil {
		log.Printf("Couldn't marshal data: %w", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	w.Write(response)
}
