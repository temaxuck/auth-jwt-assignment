package routes

import (
	"encoding/json"
	"log"
	"net/http"

	"auth-jwt-assignment/pkg/rm"
)

func NewSecurityRouter() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/refresh-new-ip", rm.MethodMapper{Post: securityDummyWebhook})

	return mux
}

// securityDummyWebhook godoc
// @Summary Security notification webhook
// @Description Demo endpoint for a "refresh from new IP" action notifications
// @Tags security
// @Accept json
// @Param payload body routes.securityDummyWebhook.payload true "Notification payload"
// @Success 200
// @Failure 400
// @Router /security/refresh-new-ip [post]
func securityDummyWebhook(w http.ResponseWriter, r *http.Request) {
	type payload struct {
		UserGUID  string `json:"user_guid" example:"123e4567-e89b-12d3-a456-426614174000"`
		NewIP     string `json:"new_ip" example:"10.0.0.1:80085"`
		OldIP     string `json:"old_ip" example:"127.0.0.1:80085"`
		UserAgent string `json:"user_agent" example:"useragent/10.1.1"`
	}

	var body payload
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	log.Printf("INFO: [UserID: %s; UserAgent: %s] Client refreshed token from a new IP address: %s => %s", body.UserGUID, body.UserAgent, body.OldIP, body.NewIP)

	statusPlainText(w, http.StatusOK, http.StatusText(http.StatusOK))
}
