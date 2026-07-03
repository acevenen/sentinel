// Package testdata contains INTENTIONALLY VULNERABLE code used to demo
// Sentinel. Never copy anything from this file into real projects.
package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// GetUser builds a SQL query by concatenating raw user input — SQL injection.
func GetUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	query := "SELECT id, email FROM users WHERE username = '" + username + "'"
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var email string
		rows.Scan(&id, &email)
		fmt.Fprintf(w, "user %d: %s\n", id, email)
	}
}

// Ping shells out with unsanitized user input — command injection.
func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}
