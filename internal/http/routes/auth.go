package routes

import (
	"log"
	"net"
	"net/http"
	"time"

	"auth-jwt-assignment/internal/auth"
	mw "auth-jwt-assignment/internal/http/middleware"
	m "auth-jwt-assignment/internal/models"
	"auth-jwt-assignment/pkg/rm"
)

type AuthRouter struct {
	service                *auth.AuthService
	notificationWebhookURL string
}

func NewAuthRouter(service *auth.AuthService, webhookURL string) *http.ServeMux {
	h := AuthRouter{service, webhookURL}

	mux := http.NewServeMux()
	mux.Handle("/{guid}/login", rm.MethodMapper{Post: h.login})
	mux.Handle("/{guid}/logout", rm.MethodMapper{Post: h.logout})
	mux.Handle("/{guid}/refresh", rm.MethodMapper{Post: mw.Protected(h.service, h.refresh)})

	return mux
}

func (h *AuthRouter) login(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("guid")
	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	at, rt, err := h.service.IssueTokenPair(userID, r.UserAgent(), ip)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	setTokenPairCookies(w, at.WebToken, at.ExpiresAt, rt.WebToken, rt.ExpiresAt)
}

func (h *AuthRouter) logout(w http.ResponseWriter, r *http.Request) {
	defer resetTokenPairCookies(w)

	atCookie, _ := r.Cookie("access-token")
	atPayload, _ := h.service.ValidateAccessToken(atCookie.Value)
	rtRaw := ""
	if rtCookie, err := r.Cookie("refresh-token"); err == nil {
		rtRaw = rtCookie.Value
	}
	rt, _ := h.service.ExtractRefreshToken(rtRaw)

	err := h.service.Deauthorize(atPayload, rt)
	if err != nil {
		log.Printf("ERROR: %v", err)
	}
}

func (h *AuthRouter) refresh(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("guid")
	at, _ := r.Context().Value("access-token-payload").(*m.AccessToken)
	rtRaw, _ := r.Context().Value("refresh-token").(string)
	rt, err := h.service.ExtractRefreshToken(rtRaw)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !h.service.ValidateRefreshToken(rt, at) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	defer func() {
		err := h.service.RevokeRefreshToken(rt)
		if err != nil {
			log.Printf("ERROR: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
	}()

	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	userAgent := r.UserAgent()
	if rt.UserAgent != userAgent {
		err := h.service.Deauthorize(at, rt)
		if err != nil {
			log.Printf("ERROR: failed to deauthorize: %v", err)
		}
		err = h.service.RevokeRefreshTokensForUserIP(userID, ip)
		if err != nil {
			log.Printf("ERROR: failed to revoke tokens for user [%s; %s]: %v", userID, ip, err)
		}

		resetTokenPairCookies(w)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if rt.IP != ip {
		go func() {
			err := h.service.NotifyRefreshFromNewIP(h.notificationWebhookURL, userID, ip, rt.IP, userAgent)
			if err != nil {
				log.Printf("ERROR: failed to notify security service: %v", err)
			}
		}()
	}

	at, rt, err = h.service.IssueTokenPair(userID, r.UserAgent(), ip)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	setTokenPairCookies(w, at.WebToken, at.ExpiresAt, rt.WebToken, rt.ExpiresAt)
}

func setTokenPairCookies(w http.ResponseWriter, at string, atExpiresAt time.Time, rt string, rtExpiresAt time.Time) {
	setTokenCookie(w, "access-token", at, atExpiresAt)
	setTokenCookie(w, "refresh-token", rt, rtExpiresAt)
}

func resetTokenPairCookies(w http.ResponseWriter) {
	resetCookie(w, "access-token")
	resetCookie(w, "refresh-token")
}
