package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var FILES_DIR = "./testing-only" // will use default as user directory if not passed in flags later

// TODOs
// add use tls/autocert flag later
// add auth for post and puts
// graceful shutdown

var logger *log.Logger

func main() {
	var out string
	var port int

	flag.StringVar(&out, "out", "", "path to log file")
	flag.IntVar(&port, "port", 8080, "port to run server")

	flag.Parse()

	logFlags := log.Ldate | log.Ltime
	if out == "" {
		logger = log.New(os.Stdout, "", logFlags)
	} else {
		logFile, err := os.OpenFile(out, os.O_CREATE|os.O_RDWR, 0774)
		if err != nil {
			log.Println("failed to open log file")
			log.Fatal(err.Error())
		}

		logger = log.New(logFile, "", logFlags)
	}

	err := os.MkdirAll(FILES_DIR, 0774)
	if err != nil {
		panic(err.Error())
	}

	srv := runServer(port)

	k := make(chan os.Signal)

	signal.Notify(k, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGINT)

	<-k

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(10)*time.Second)
	defer cancel()

	err = srv.Shutdown(ctx)
	if err != nil {

	}
	logger.Println("server closed")
}

func runServer(port int) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{OS}/{ARCH}/latest", handleGetLatest)
	mux.HandleFunc("PUT /{OS}/{ARCH}/latest/{VER}", handleUpdateLatest)
	mux.HandleFunc("GET /{OS}/{ARCH}/checksum/{VER}", handleGetChecksum)
	mux.HandleFunc("POST /{OS}/{ARCH}/upload", logRequests(handleUploadBinary))
	mux.HandleFunc("GET /{OS}/{ARCH}/download/{VER}", logRequests(handleDownloadBinary))
	mux.HandleFunc("GET /{$}", handleHome)

	srv := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", port),
		Handler: mux,
	}

	go func(srv *http.Server) {
		if err := srv.ListenAndServe(); err != nil {
			if err == http.ErrServerClosed {
				logger.Println("server shutdown gracefully")
				return
			}

			logger.Println("server not shutdown gracefully")
		}
	}(srv)

	return srv
}

func logRequests(h func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		req := fmt.Sprintf("origin: %s; path: %s; method: %s;", r.RemoteAddr, r.URL.Path, r.Method)
		logger.Println(req)
		h(w, r)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	replyMessage(w, http.StatusOK, "home page")
}

func handleGetLatest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	OS := r.PathValue("OS")
	ARCH := r.PathValue("ARCH")

	p := filepath.Join(FILES_DIR, OS, ARCH, "latest")

	b, err := readFile(p)
	if err != nil {
		replyMessage(w, http.StatusNotFound, "not found")
		return
	}

	w.Write(b)
}

func handleUpdateLatest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	OS := r.PathValue("OS")
	ARCH := r.PathValue("ARCH")
	VER := r.PathValue("VER")

	dir := filepath.Join(FILES_DIR, OS, ARCH)

	_, err := os.Stat(filepath.Join(dir, "bin", VER))
	if err != nil {
		if os.IsNotExist(err) {
			replyMessage(w, http.StatusNotFound, "not found")
			return
		}
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}

	tmp, tmpPath, err := copyToTempFile(strings.NewReader(VER))
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer tmp.Close()

	err = os.Rename(tmpPath, filepath.Join(dir, "latest"))
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}

	replyMessage(w, http.StatusOK, "OK")
}

func handleGetChecksum(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	OS := r.PathValue("OS")
	VER := r.PathValue("VER")
	ARCH := r.PathValue("ARCH")

	p := filepath.Join(FILES_DIR, OS, ARCH, "checksum", VER)
	b, err := readFile(p)
	if err != nil {
		replyMessage(w, http.StatusNotFound, "not found")
		return
	}

	w.Write(b)
}

func handleDownloadBinary(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	OS := r.PathValue("OS")
	ARCH := r.PathValue("ARCH")
	VER := r.PathValue("VER")

	binpath := filepath.Join(FILES_DIR, OS, ARCH, "bin", VER)

	fileDownload(w, r, binpath)
}

func handleUploadBinary(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	OS := r.PathValue("OS")
	ARCH := r.PathValue("ARCH")

	err := r.ParseMultipartForm(10 << 50)
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}

	checksum := r.FormValue("checksum")
	version := r.FormValue("version")
	isLatest := r.FormValue("latest")

	f, _, err := r.FormFile("binary")
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}

	if f == nil {
		replyMessage(w, http.StatusBadRequest, "binary file required")
		return
	}

	if version == "" || checksum == "" {
		replyMessage(w, http.StatusBadRequest, "checksum and version name required")
		return
	}

	tmpBinary, tmpBinaryPath, err := copyToTempFile(f)
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer tmpBinary.Close()

	chx, err := checksumString(tmpBinary)
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}

	if chx != checksum {
		replyMessage(w, http.StatusBadRequest, "file uploaded to server does not match provided checksum and file may be corrupted. try again")
		return
	}

	cxf, tmpChecksumPath, err := copyToTempFile(strings.NewReader(checksum))
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer cxf.Close()

	destDir := filepath.Join(FILES_DIR, OS, ARCH)

	err = os.MkdirAll(filepath.Join(destDir, "bin"), 0777)
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = os.MkdirAll(filepath.Join(destDir, "checksum"), 0777)
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}

	destBinFile := filepath.Join(destDir, "bin", version)
	destChecksum := filepath.Join(destDir, "checksum", version)
	destLatest := filepath.Join(destDir, "latest")

	err = os.Rename(tmpBinaryPath, destBinFile)
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = os.Rename(tmpChecksumPath, destChecksum)
	if err != nil {
		replyMessage(w, http.StatusInternalServerError, err.Error())
		return
	}

	if isLatest == "true" {
		rdr := strings.NewReader(version)
		vf, tmpVerPath, err := copyToTempFile(rdr)
		if err != nil {
			replyMessage(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer vf.Close()

		err = os.Rename(tmpVerPath, destLatest)
		if err != nil {
			replyMessage(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	replyMessage(w, http.StatusCreated, "file uploaded")
}

func copyToTempFile(src io.Reader) (*os.File, string, error) {
	dir := os.TempDir()
	f, err := os.CreateTemp(dir, "binary-server*")
	if err != nil {
		return nil, "", err
	}

	_, err = io.Copy(f, src)
	if err != nil {
		defer f.Close()
		return nil, "", err
	}

	f.Sync()

	f.Seek(0, 0)
	return f, f.Name(), nil
}

func checksumString(target io.Reader) (string, error) {
	h := sha256.New()
	_, err := io.Copy(h, target)
	if err != nil {
		return "", err
	}
	chxRaw := h.Sum(nil)
	return hex.EncodeToString(chxRaw), nil
}

func replyMessage(w http.ResponseWriter, status int, m string) {
	w.WriteHeader(status)
	w.Write([]byte(fmt.Sprintf("%d %s", status, m)))
}

func fileDownload(w http.ResponseWriter, r *http.Request, path string) {
	f, err := os.Open(path)
	if err != nil {
		replyMessage(w, http.StatusNotFound, "not found")
		return
	}
	defer f.Close()

	fileName := filepath.Base(path)

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	w.Header().Set("Content-Type", "application/octet-stream")

	http.ServeContent(w, r, fileName, time.Now(), f)
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	b := make([]byte, info.Size())
	_, err = f.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
