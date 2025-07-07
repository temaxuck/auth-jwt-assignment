package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
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
	router.Handle("/auth/{guid}/refresh", MethodMapper{Post: h.protected(h.refresh)})
	router.Handle("/auth/security/refresh-new-ip", MethodMapper{Post: securityDummyWebhook})
	router.Handle("/whoami", MethodMapper{Get: h.protected(h.whoami)})

	log.Println("Starting server on:", addr)
	return http.ListenAndServe(addr, router)

}

func (h *Handler) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atCookie, err := r.Cookie("access-token")
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

		payload, err := ValidateAccessToken(h.cfg, atCookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		rtCookie, err := r.Cookie("refresh-token")
		ctx := r.Context()
		ctx = context.WithValue(ctx, "access-token", atCookie.Value)
		ctx = context.WithValue(ctx, "refresh-token", rtCookie.Value)
		ctx = context.WithValue(ctx, "access-token-payload", payload)
		r = r.WithContext(ctx)

		next(w, r)
	}
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	guid := r.PathValue("guid")
	accessToken, expires, err := IssueAccessToken(guid, h.cfg.Auth.AccessTokenLifetime, h.cfg.Auth.Secret)
	if err != nil {
		log.Printf("ERROR: Couldn't issue access token: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	SetTokenCookie(w, "access-token", accessToken, expires)

	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	refreshToken, expires, err := IssueRefreshToken(h.db, guid, accessToken, r.UserAgent(), ip, h.cfg.Auth.RefreshTokenLifetime)
	if err != nil {
		log.Printf("ERROR: Couldn't issue refresh token: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	SetTokenCookie(w, "refresh-token", refreshToken, expires)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	guid := r.PathValue("guid")
	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	err := RevokeRefreshTokensForClient(h.db, guid, ip, r.UserAgent())
	if err != nil {
		log.Printf("ERROR: Couldn't revoke refresh token: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	ResetTokenCookie(w, "access-token")
	ResetTokenCookie(w, "refresh-token")
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	guid := r.PathValue("guid")
	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	userAgent := r.UserAgent()
	atRaw, _ := r.Context().Value("access-token").(string)
	rtRaw, _ := r.Context().Value("refresh-token").(string)

	rt, err := FetchRefreshTokenByRawToken(h.db, guid, rtRaw)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if rt.Revoked {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	defer func() {
		err := RevokeRefreshToken(h.db, rt)
		if err != nil {
			log.Printf("ERROR: Couldn't revoke refresh token: %w", err)
		}
	}()

	if rt.AccessToken != atRaw {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if rt.UserAgent != userAgent {
		ResetTokenCookie(w, "access-token")
		ResetTokenCookie(w, "refresh-token")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if rt.IP != ip {
		go func() {
			err := NotifyRefreshFromNewIP(h.cfg.Auth.WebhookURL, guid, ip, rt.IP, userAgent)
			if err != nil {
				log.Printf("ERROR: Failed to notify security service: %v", err)
			}
		}()
	}

	atNew, expires, err := IssueAccessToken(guid, h.cfg.Auth.AccessTokenLifetime, h.cfg.Auth.Secret)
	if err != nil {
		log.Printf("ERROR: Couldn't issue access token: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	SetTokenCookie(w, "access-token", atNew, expires)

	rtNew, expires, err := IssueRefreshToken(h.db, guid, atNew, r.UserAgent(), ip, h.cfg.Auth.RefreshTokenLifetime)
	if err != nil {
		log.Printf("ERROR: Couldn't issue refresh token: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	SetTokenCookie(w, "refresh-token", rtNew, expires)
}

func (h *Handler) whoami(w http.ResponseWriter, r *http.Request) {
	atp, ok := r.Context().Value("access-token-payload").(*AccessTokenPayload)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	data := map[string]string{"GUID": atp.UserGUID}
	response, err := json.Marshal(data)
	if err != nil {
		log.Printf("Couldn't marshal data: %w", err)
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
		log.Printf("ERROR: Failed to unmarshal request body: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	log.Printf("INFO: [UserID: %s; UserAgent: %s] Client refreshed token from a new IP address: %s => %s", payload.UserGUID, payload.UserAgent, payload.OldIP, payload.NewIP)

}
