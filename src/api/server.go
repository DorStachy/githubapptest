// Package main — INTENTIONALLY VULNERABLE Go service for CodeFence testing.
//
// Covers: SQL injection, command injection, hardcoded crypto key, weak TLS,
// path traversal in HTTP handler, unvalidated redirect, missing CSRF,
// and SAFE counterparts.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	_ "github.com/lib/pq"
)

var db *sql.DB

// ─────────────────────── HARDCODED CRYPTO KEY (CRITICAL) ────────────────
var encryptionKey = []byte("0123456789ABCDEF0123456789ABCDEF") // 256-bit key in source!

func init() {
	var err error
	// ─── HARDCODED DB CREDENTIALS (CRITICAL) ─────────────────────────
	db, err = sql.Open("postgres", "host=db.prod user=admin password=Pr0dP@ss! dbname=app sslmode=disable")
	if err != nil {
		panic(err)
	}
}

// ─────────────────────── SQL INJECTION (CRITICAL) ───────────────────────
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// String concatenation in SQL query
	query := fmt.Sprintf("SELECT id, email FROM users WHERE username = '%s'", username)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500) // leaks internal error too
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "Results for: %s", username) // reflected XSS
}

// ─────────────────────── SAFE SQL (no vuln) ─────────────────────────────
func getUserSafeHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	rows, err := db.Query("SELECT id, email FROM users WHERE username = $1", username)
	if err != nil {
		http.Error(w, "query failed", 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "Results fetched safely")
}

// ─────────────────────── COMMAND INJECTION (CRITICAL) ───────────────────
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// User input directly in shell command
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}

// ─────────────────────── SAFE COMMAND (no vuln) ─────────────────────────
func pingSafeHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// No shell — arguments passed safely
	out, _ := exec.Command("ping", "-c", "1", host).Output()
	w.Write(out)
}

// ─────────────────────── PATH TRAVERSAL (HIGH) ─────────────────────────
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// No sanitisation — ../../etc/passwd
	http.ServeFile(w, r, "/var/uploads/"+filename)
}

// ─────────────────────── SAFE FILE SERVE (no vuln) ─────────────────────
func downloadSafeHandler(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Query().Get("file"))
	fullPath := filepath.Join("/var/uploads", filename)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, fullPath)
}

// ─────────────────────── WEAK HASH — MD5 (HIGH) ───────────────────────
func hashMD5(data string) string {
	h := md5.Sum([]byte(data))
	return hex.EncodeToString(h[:])
}

// ─────────────────────── WEAK TLS CONFIG (HIGH) ────────────────────────
func startInsecureTLS() {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,                      // skips cert validation
		MinVersion:         tls.VersionTLS10,          // allows TLS 1.0
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}, // RC4!
	}
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}
	server.ListenAndServeTLS("cert.pem", "key.pem")
}

// ─────────────────────── SAFE TLS (no vuln) ───────────────────────────
func startSecureTLS() {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}
	server.ListenAndServeTLS("cert.pem", "key.pem")
}

// ─────────────────────── UNVALIDATED REDIRECT (MEDIUM) ─────────────────
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Redirect(w, r, target, http.StatusFound)
}

// ─────────────────────── XSS VIA TEMPLATE (HIGH) ──────────────────────
func profileHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// Using text/template instead of html/template — no auto-escaping
	tmpl := template.Must(template.New("").Parse("<h1>Welcome {{.}}</h1>"))
	tmpl.Execute(w, name)
}

// ─────────────────────── HARDCODED AES ENCRYPT (shows key in source) ──
func encryptData(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	// ECB-like usage — no IV, no authentication
	ct := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(ct[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}
	return ct, nil
}

// Suppress unused import warnings
var _ = io.Discard
var _ cipher.Block

func main() {
	http.HandleFunc("/user", getUserHandler)
	http.HandleFunc("/user-safe", getUserSafeHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/ping-safe", pingSafeHandler)
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/download-safe", downloadSafeHandler)
	http.HandleFunc("/redirect", redirectHandler)
	http.HandleFunc("/profile", profileHandler)
	http.ListenAndServe(":8080", nil)
}
