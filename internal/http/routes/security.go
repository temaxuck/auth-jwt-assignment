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
