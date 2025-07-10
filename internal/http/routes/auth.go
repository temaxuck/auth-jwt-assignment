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

	"github.com/google/uuid"
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

// login godoc
// @Summary Login user
// @Description Issues JWT token pair and sets them as cookies
// @Tags auth
// @Param guid path string true "User GUID"
// @Success 200
// @Failure 500
// @Router /auth/{guid}/login [post]
func (h *AuthRouter) login(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("guid")
	if !validateGUID(userID) {
		http.Error(w, "Invalid GUID", http.StatusBadRequest)
		return
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr) // Assuming http.Request.RemoteAddr is always valid
	at, rt, err := h.service.IssueTokenPair(userID, r.UserAgent(), ip)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	setTokenPairCookies(w, at.WebToken, at.ExpiresAt, rt.WebToken, rt.ExpiresAt)
}

// logout godoc
// @Summary Logout user
// @Description Deauthorizes user
// @Tags auth
// @Param guid path string true "User GUID"
// @Success 200
// @Failure 500
// @Router /auth/{guid}/logout [post]
func (h *AuthRouter) logout(w http.ResponseWriter, r *http.Request) {
	defer resetTokenPairCookies(w)

	var at *m.AccessToken
	var rt *m.RefreshToken

	if atCookie, err := r.Cookie("access-token"); err == nil {
		at, _ = h.service.ValidateAccessToken(atCookie.Value)
	}

	if rtCookie, err := r.Cookie("refresh-token"); err == nil {
		rt, _ = h.service.ExtractRefreshToken(rtCookie.Value)
	}

	err := h.service.Deauthorize(at, rt)
	if err != nil {
		log.Printf("ERROR: %v", err)
	}
}

// refresh godoc
// @Summary Refresh tokens
// @Description Refreshes access and refresh tokens if the refresh token is valid. Deauthorizes user if the user agent does not match.
// @Tags auth
// @Param guid path string true "User GUID"
// @Success 200
// @Failure 401
// @Failure 500
// @Router /auth/{guid}/refresh [post]
func (h *AuthRouter) refresh(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("guid")
	if !validateGUID(userID) {
		http.Error(w, "Invalid GUID", http.StatusBadRequest)
		return
	}
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
		// ALERT: This doesn't make sure that server will actually notify the security service.
		//        For this specific assignment I didn't implement graceful shutdown of this app
		//        which would make sure that all of the background tasks either completed or failed
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

func validateGUID(userGUID string) bool {
	_, err := uuid.Parse(userGUID)
	return err == nil
}

func setTokenPairCookies(w http.ResponseWriter, at string, atExpiresAt time.Time, rt string, rtExpiresAt time.Time) {
	setTokenCookie(w, "access-token", at, atExpiresAt)
	setTokenCookie(w, "refresh-token", rt, rtExpiresAt)
}

func resetTokenPairCookies(w http.ResponseWriter) {
	resetCookie(w, "access-token")
	resetCookie(w, "refresh-token")
}
