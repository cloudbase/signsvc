package main

import (
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func ipAddrFromRemoteAddr(s string) string {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s
	}
	return s[:idx]
}

func requestGetRemoteAddress(r *http.Request) string {
	hdr := r.Header
	hdrRealIP := hdr.Get("X-Real-Ip")
	hdrForwardedFor := hdr.Get("X-Forwarded-For")
	if hdrRealIP == "" && hdrForwardedFor == "" {
		return ipAddrFromRemoteAddr(r.RemoteAddr)
	}
	if hdrForwardedFor != "" {
		parts := strings.Split(hdrForwardedFor, ",")
		for i, p := range parts {
			parts[i] = strings.TrimSpace(p)
		}
		return parts[0]
	}
	return hdrRealIP
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	ipaddr := requestGetRemoteAddress(r)
	log.Println("Signature request received from:", ipaddr)

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(1024 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	exFile, err := os.Executable()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	exPath := filepath.Dir(exFile)

	files := r.MultipartForm.File["file"]

	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = os.MkdirAll(filepath.Join(exPath, "uploads"), os.ModePerm)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		uploadFile := filepath.Base(fileHeader.Filename)
		uploadPath := filepath.Join(exPath, "uploads",
			fmt.Sprintf("%d-%s", time.Now().UnixNano(), uploadFile))

		f, err := os.Create(uploadPath)
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		defer f.Close()

		_, err = io.Copy(f, file)
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f.Close()

		defer os.Remove(uploadPath)

		shFile, err := filepath.Abs(filepath.Join(exPath, "sign.sh"))
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		out, err := exec.Command(shFile, uploadPath).Output()
		if err != nil {
			log.Println(string(out))
			log.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Disposition",
			"attachment; filename="+strconv.Quote(uploadFile))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, uploadPath)
	}
}

func basicAuth(next http.Handler, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare(
			[]byte(user), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass),
				[]byte(password)) != 1 {
			w.Header().Set(
				"WWW-Authenticate",
				`Basic realm="Restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	username := os.Getenv("USERNAME")
	password := os.Getenv("PASSWORD")

	log.Println("Starting the signature service")

	mux := http.NewServeMux()
	mux.HandleFunc("/sign", uploadHandler)

	authenticatedMux := basicAuth(mux, username, password)

	server := &http.Server{
		Addr:    ":443",
		Handler: authenticatedMux,
	}

	err = server.ListenAndServeTLS("cert/cert.pem", "cert/key.pem")
	if err != nil {
		log.Fatalf("Server failed: %s", err)
	}
}
