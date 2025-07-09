package routes

import (
	"encoding/json"
	"log"
	"net/http"

	mw "auth-jwt-assignment/internal/http/middleware"
	"auth-jwt-assignment/internal/repo"
	"auth-jwt-assignment/pkg/jwt"
	"auth-jwt-assignment/pkg/rm"
)

func NewBaseRouter(j *jwt.JWT, tr *repo.TokenRepo) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/whoami", rm.MethodMapper{Get: mw.Protected(j, tr, whoami)})

	return mux
}

func whoami(w http.ResponseWriter, r *http.Request) {
	atp, ok := r.Context().Value("access-token-payload").(*jwt.AccessTokenPayload)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	data := map[string]string{"GUID": atp.Subject}
	response, err := json.Marshal(data)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	w.Write(response)
}
