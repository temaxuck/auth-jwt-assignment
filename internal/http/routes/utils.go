package routes

import (
	"fmt"
	"net/http"
	"time"
)

func statusPlainText(w http.ResponseWriter, code int, text string) {
	w.WriteHeader(code)
	if len(text) > 0 {
		fmt.Fprintf(w, text)
	}
}

func setTokenCookie(w http.ResponseWriter, cookieName string, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

func resetCookie(w http.ResponseWriter, cookieName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		MaxAge:   0,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}
