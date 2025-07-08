package http

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"

	c "auth-jwt-assignment/config"
	"auth-jwt-assignment/internal/auth"
	rm "auth-jwt-assignment/pkg/rm"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Handler struct {
	cfg *c.Config
	db  *pgxpool.Pool
}

func RunServer(addr string, cfg *c.Config, db *pgxpool.Pool) error {
	h := &Handler{
		cfg: cfg,
		db:  db,
	}

	router := http.NewServeMux()
	router.Handle("/auth/{guid}/login", rm.MethodMapper{Post: h.login})
	router.Handle("/auth/{guid}/logout", rm.MethodMapper{Post: h.logout})
	router.Handle("/auth/{guid}/refresh", rm.MethodMapper{Post: h.protected(h.refresh)})
	router.Handle("/auth/security/refresh-new-ip", rm.MethodMapper{Post: securityDummyWebhook})
	router.Handle("/whoami", rm.MethodMapper{Get: h.protected(h.whoami)})

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
				log.Printf("ERROR: %v", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
			}
			return
		}

		payload, err := auth.ValidateAccessToken(h.cfg, atCookie.Value)
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
	accessToken, expires, err := auth.IssueAccessToken(guid, h.cfg.Auth.AccessTokenLifetime, h.cfg.Auth.Secret)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	auth.SetTokenCookie(w, "access-token", accessToken, expires)

	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	refreshToken, expires, err := auth.IssueRefreshToken(h.db, guid, accessToken, r.UserAgent(), ip, h.cfg.Auth.RefreshTokenLifetime)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	auth.SetTokenCookie(w, "refresh-token", refreshToken, expires)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	guid := r.PathValue("guid")
	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	err := auth.RevokeRefreshTokensForClient(h.db, guid, ip, r.UserAgent())
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	auth.ResetTokenCookie(w, "access-token")
	auth.ResetTokenCookie(w, "refresh-token")
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	guid := r.PathValue("guid")
	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	userAgent := r.UserAgent()
	atRaw, _ := r.Context().Value("access-token").(string)
	rtRaw, _ := r.Context().Value("refresh-token").(string)

	rt, err := auth.FetchRefreshTokenByRawToken(h.db, guid, rtRaw)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !auth.ValidateRefreshToken(rt) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	defer func() {
		err := auth.RevokeRefreshToken(h.db, rt)
		if err != nil {
			log.Printf("ERROR: %v", err)
		}
	}()

	if rt.AccessToken != atRaw {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if rt.UserAgent != userAgent {
		auth.ResetTokenCookie(w, "access-token")
		auth.ResetTokenCookie(w, "refresh-token")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if rt.IP != ip {
		go func() {
			err := auth.NotifyRefreshFromNewIP(h.cfg.Auth.WebhookURL, guid, ip, rt.IP, userAgent)
			if err != nil {
				log.Printf("ERROR: Failed to notify security service: %v", err)
			}
		}()
	}

	atNew, expires, err := auth.IssueAccessToken(guid, h.cfg.Auth.AccessTokenLifetime, h.cfg.Auth.Secret)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	auth.SetTokenCookie(w, "access-token", atNew, expires)

	rtNew, expires, err := auth.IssueRefreshToken(h.db, guid, atNew, r.UserAgent(), ip, h.cfg.Auth.RefreshTokenLifetime)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	auth.SetTokenCookie(w, "refresh-token", rtNew, expires)
}

func (h *Handler) whoami(w http.ResponseWriter, r *http.Request) {
	atp, ok := r.Context().Value("access-token-payload").(*auth.AccessTokenPayload)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	data := map[string]string{"GUID": atp.UserGUID}
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
