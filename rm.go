// Route Method Mapper
package main

import "net/http"

type MethodMapper struct {
	Get, Post, Patch, Put, Delete, Options func(w http.ResponseWriter, r *http.Request)
}

func (rm MethodMapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	methodHandlers := map[string]func(http.ResponseWriter, *http.Request){
		http.MethodGet:     rm.Get,
		http.MethodPost:    rm.Post,
		http.MethodPatch:   rm.Patch,
		http.MethodPut:     rm.Put,
		http.MethodDelete:  rm.Delete,
		http.MethodOptions: rm.Options,
	}

	handler, ok := methodHandlers[r.Method]
	if !ok || handler == nil {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	handler(w, r)
}
