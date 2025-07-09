package routes

import (
	"encoding/json"
	"log"
	"net/http"

	"auth-jwt-assignment/internal/auth"
	mw "auth-jwt-assignment/internal/http/middleware"
	m "auth-jwt-assignment/internal/models"
	"auth-jwt-assignment/pkg/rm"
)

func NewBaseRouter(service *auth.AuthService) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/whoami", rm.MethodMapper{Get: mw.Protected(service, whoami)})

	return mux
}

// whoami godoc
// @Summary Get current user
// @Description Returns authenticated user GUID
// @Tags user
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401
// @Failure 500
// @Router /whoami [get]
func whoami(w http.ResponseWriter, r *http.Request) {
	atp, ok := r.Context().Value("access-token-payload").(*m.AccessToken)
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
