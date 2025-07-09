package middleware

import (
	"context"
	"log"
	"net/http"

	"auth-jwt-assignment/internal/repo"
	"auth-jwt-assignment/pkg/jwt"
)

func Protected(j *jwt.JWT, tr *repo.TokenRepo, next http.HandlerFunc) http.HandlerFunc {
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

		payload, err := j.ValidateToken(atCookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		blacklisted, err := tr.CheckIfAccessTokenBlacklisted(payload)
		if err != nil {
			log.Printf("ERROR: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		if blacklisted {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		rtValue := ""
		if rtCookie, err := r.Cookie("refresh-token"); err == nil {
			rtValue = rtCookie.Value
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "refresh-token", rtValue)
		ctx = context.WithValue(ctx, "access-token-payload", payload)
		r = r.WithContext(ctx)

		next(w, r)
	}
}
