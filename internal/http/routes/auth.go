package routes

import (
	"log"
	"net"
	"net/http"
	"time"

	"auth-jwt-assignment/internal/auth"
	mw "auth-jwt-assignment/internal/http/middleware"
	"auth-jwt-assignment/internal/repo"
	"auth-jwt-assignment/pkg/jwt"
	"auth-jwt-assignment/pkg/rm"
)

type AuthRouter struct {
	jwt                    *jwt.JWT
	r                      *repo.TokenRepo
	notificationWebhookURL string
}

func NewAuthRouter(jwt *jwt.JWT, r *repo.TokenRepo, webhookURL string) *http.ServeMux {
	h := AuthRouter{jwt, r, webhookURL}

	mux := http.NewServeMux()
	mux.Handle("/{guid}/login", rm.MethodMapper{Post: h.login})
	mux.Handle("/{guid}/logout", rm.MethodMapper{Post: h.logout})
	mux.Handle("/{guid}/refresh", rm.MethodMapper{Post: mw.Protected(jwt, r, h.refresh)})

	return mux
}

func (h *AuthRouter) login(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("guid")
	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	at, atString, rt, rtString, err := auth.IssueTokenPair(h.r, h.jwt, userID, r.UserAgent(), ip)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	setTokenPairCookies(w, atString, at.GetExpiresAt(), rtString, rt.ExpiresAt)
}

func (h *AuthRouter) logout(w http.ResponseWriter, r *http.Request) {
	defer resetTokenPairCookies(w)

	atCookie, _ := r.Cookie("access-token")
	atPayload, _ := h.jwt.ValidateToken(atCookie.Value)
	rtRaw := ""
	if rtCookie, err := r.Cookie("refresh-token"); err == nil {
		rtRaw = rtCookie.Value
	}
	rt, _ := auth.ExtractRefreshToken(h.r, rtRaw)

	err := auth.Deauthorize(h.r, atPayload, rt)
	if err != nil {
		log.Printf("ERROR: %v", err)
	}
}

// TODO: Move issuing a pair of tokens into a separate function in `auth`
func (h *AuthRouter) refresh(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("guid")
	atPayload, _ := r.Context().Value("access-token-payload").(*jwt.AccessTokenPayload)
	rtRaw, _ := r.Context().Value("refresh-token").(string)
	rt, err := auth.ExtractRefreshToken(h.r, rtRaw)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !auth.ValidateRefreshToken(rt, atPayload) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	defer func() {
		err := h.r.RevokeRefreshToken(rt)
		if err != nil {
			log.Printf("ERROR: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
	}()

	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	userAgent := r.UserAgent()
	if rt.UserAgent != userAgent {
		err := auth.Deauthorize(h.r, atPayload, rt)
		if err != nil {
			log.Printf("ERROR: failed to deauthorize: %v", err)
		}
		err = h.r.RevokeRefreshTokensForUserIP(userID, ip)
		if err != nil {
			log.Printf("ERROR: failed to revoke tokens for user [%s; %s]: %v", userID, ip, err)
		}

		resetTokenPairCookies(w)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if rt.IP != ip {
		go func() {
			err := auth.NotifyRefreshFromNewIP(h.notificationWebhookURL, userID, ip, rt.IP, userAgent)
			if err != nil {
				log.Printf("ERROR: failed to notify security service: %v", err)
			}
		}()
	}

	at, atString, rt, rtString, err := auth.IssueTokenPair(h.r, h.jwt, userID, r.UserAgent(), ip)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	setTokenPairCookies(w, atString, at.GetExpiresAt(), rtString, rt.ExpiresAt)
}

func setTokenPairCookies(w http.ResponseWriter, at string, atExpiresAt time.Time, rt string, rtExpiresAt time.Time) {
	setTokenCookie(w, "access-token", at, atExpiresAt)
	setTokenCookie(w, "refresh-token", rt, rtExpiresAt)
}

func resetTokenPairCookies(w http.ResponseWriter) {
	resetCookie(w, "access-token")
	resetCookie(w, "refresh-token")
}
