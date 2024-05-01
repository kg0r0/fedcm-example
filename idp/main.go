package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("secret"))

type Params struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("GET")
	r.HandleFunc("/signin", signInHandler).Methods("POST")
	r.HandleFunc("/config.json", configJSONHandler).Methods("GET")
	r.HandleFunc("/fedcm_assertion_endpoint", sessionCheckMiddleware(fedcmAssertionHandler)).Methods("POST")
	r.HandleFunc("/accounts", sessionCheckMiddleware(accountsHandler)).Methods("GET")
	r.HandleFunc("/metadata", clientMetadataHandler).Methods("GET")
	r.HandleFunc("/.well-known/web-identity", webIdentityHandler).Methods("GET")
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Not found", "path", r.URL.Path)
		http.Error(w, "Not found", http.StatusNotFound)
	})

	http.Handle("/", r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8002"
	}

	http.ListenAndServe(":"+port, nil)
}

// accountsHandler implements the accounts endpoint.
// Ref: https://developers.google.com/privacy-sandbox/3pcd/fedcm-developer-guide#accounts-list-endpoint
func accountsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Sec-Fetch-Dest") != "webidentity" {
		jsonResponse(w, map[string]string{"error": "Invalid request"}, http.StatusBadRequest)
		return
	}
	jsonResponse(w, map[string]interface{}{"accounts": []map[string]string{{"id": "1234", "name": "John Doe", "email": "john_doe@idp.example"}}}, http.StatusOK)
}

// webIdentityHandler implements the well-known/web-identity endpoint.
// Ref: https://developers.google.com/privacy-sandbox/3pcd/fedcm-developer-guide#well-known-file
func webIdentityHandler(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]string{"provider_urls": "http://localhost:8002/config.json"}, http.StatusOK)
}

// fedcmAssertionHandler implements the ID assertion endpoint.
// Ref: https://developers.google.com/privacy-sandbox/3pcd/fedcm-developer-guide#id-assertion-endpoint
func fedcmAssertionHandler(w http.ResponseWriter, r *http.Request) {
	// Error response is defined in the spec.
	// Ref: https://developers.google.com/privacy-sandbox/3pcd/fedcm-developer-guide#error-response
	if r.Header.Get("Sec-Fetch-Dest") != "webidentity" {
		slog.Info("Invalid request", "Sec-Fetch-Dest", r.Header.Get("Sec-Fetch-Dest"))
		jsonResponse(w, map[string]map[string]string{"error": {"code": "access_denied", "url": "http://localhost:8002?type=access_denied"}}, http.StatusBadRequest)
		return
	}
	if r.Header.Get("Origin") != "http://localhost:8001" || r.FormValue("client_id") != "123" {
		slog.Info("Invalid request", "origin", r.Header.Get("Origin"), "client_id", r.FormValue("client_id"))
		jsonResponse(w, map[string]map[string]string{"error": {"code": "access_denied", "url": "http://localhost:8002?type=access_denied"}}, http.StatusBadRequest)
		return
	}
	if r.FormValue("account_id") != "1234" {
		slog.Info("Invalid request", "account_id", r.FormValue("account_id"))
		jsonResponse(w, map[string]map[string]string{"error": {"code": "access_denied", "url": "http://localhost:8002?type=access_denied"}}, http.StatusBadRequest)
		return
	}
	if r.FormValue("nonce") != "456" {
		slog.Info("Invalid request", "nonce", r.FormValue("nonce"))
	}
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8001")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	// TODO: Implement the issuance of the assertion token using the account ID, client ID, issuer origin and nonce.
	jsonResponse(w, map[string]string{"token": "***********"}, http.StatusOK)
}

// configJSONHandler implements the IdP config file endpoint.
// Ref: https://developers.google.com/privacy-sandbox/3pcd/fedcm-developer-guide#idp-config-file
func configJSONHandler(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"accounts_endpoint":        "/accounts",
		"client_metadata_endpoint": "/metadata",
		"id_assertion_endpoint":    "/fedcm_assertion_endpoint",
		"disconnect_endpoint":      "/disconnect",
		"login_url":                "/login",
	}, http.StatusOK)
}

// clientMetadataHandler implements the client metadata endpoint.
// Ref: https://developers.google.com/privacy-sandbox/3pcd/fedcm-developer-guide#client-metadata-endpoint
func clientMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Sec-Fetch-Dest") != "webidentity" {
		jsonResponse(w, map[string]string{"error": "Invalid request"}, http.StatusBadRequest)
		return
	}
	clientID := r.FormValue("client_id")
	if clientID != "123" {
		jsonResponse(w, map[string]string{"error": "invalid client_id."}, http.StatusBadRequest)
		return
	}
	jsonResponse(w, map[string]string{"privacy_policy_url": "http://localhost:8001/privacy_policy.html", "terms_of_service_url": "http://localhost:8001/terms_of_service.html"}, http.StatusOK)
}

// loginHandler implements the login_url endpoint.
// Ref: https://developers.google.com/privacy-sandbox/blog/fedcm-chrome-120-updates
func loginHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "login.html", nil)
}

func signInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonResponse(w, map[string]string{"error": "Method not allowed"}, http.StatusMethodNotAllowed)
	}
	if err := r.ParseForm(); err != nil {
		jsonResponse(w, map[string]string{"error": "Error parsing form"}, http.StatusBadRequest)
		return
	}
	var p Params
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonResponse(w, map[string]string{"error": "Error decoding JSON"}, http.StatusBadRequest)
		return
	}
	if p.Username != "John" || p.Password != "password" {
		jsonResponse(w, map[string]string{"error": "username or password incorrect"}, http.StatusUnauthorized)
		return
	}
	sess, _ := store.Get(r, "session")
	sess.Values["username"] = r.Form.Get("username")
	sess.Values["status"] = "logged-in"
	err := sess.Save(r, w)
	if err != nil {
		jsonResponse(w, map[string]string{"error": "Error saving session"}, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Set-Login", "logged-in")
	jsonResponse(w, map[string]string{"message": "success"}, http.StatusOK)
}

func sessionCheckMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "session")
		v := sess.Values["status"]
		if v == nil {
			jsonResponse(w, map[string]string{"error": "Unauthorized"}, http.StatusUnauthorized)
			return
		}
		vs, _ := v.(string)
		if vs != "logged-in" {
			jsonResponse(w, map[string]string{"error": "Unauthorized"}, http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func renderTemplate(w http.ResponseWriter, templateFile string, data interface{}) {
	tmpl, err := template.ParseFiles(templateFile)
	if err != nil {
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Template execution error", http.StatusInternalServerError)
		return
	}
}

func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}
