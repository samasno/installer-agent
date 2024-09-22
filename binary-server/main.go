package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
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

var FILES_DIR = "./files"
var CERT string
var OUT string

var logger *log.Logger

func main() {
	var port int
	var files string

	flag.StringVar(&OUT, "out", "", "path to log file")
	flag.StringVar(&files, "files", "", "directory path to hold server files")
	flag.StringVar(&CERT, "cert", "", "path to x509 cert that will be used as certificate authority")

	flag.IntVar(&port, "port", 8080, "port to run server")

	flag.Parse()

	if files != "" {
		FILES_DIR = files
	}

	logFlags := log.Ldate | log.Ltime
	if OUT == "" {
		logger = log.New(os.Stdout, "", logFlags)
	} else {
		logFile, err := os.OpenFile(OUT, os.O_CREATE|os.O_RDWR, 0774)
		if err != nil {
			log.Println("failed to open log file")
			log.Fatal(err.Error())
		}

		logger = log.New(logFile, "", logFlags)
	}

	err := os.MkdirAll(FILES_DIR, 0744)
	if err != nil {
		panic(err.Error())
	}

	srv := runServer(port)

	k := make(chan os.Signal)

	signal.Notify(k, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGINT)

	<-k

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(10)*time.Second)
	defer cancel()

	done := make(chan bool)

	go func() {
		err = srv.Shutdown(ctx)
		if err != nil {
			log.Fatal(err.Error())
		}

		done <- true
	}()

	select {
	case <-ctx.Done():
		log.Println("failed to shutdown server in time")
		os.Exit(1)
	case <-done:
		log.Println("server shutdown")
		os.Exit(0)
	}
}

func runServer(port int) *http.Server {

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{OS}/{ARCH}/latest", logRequests(handleGetLatest))
	mux.HandleFunc("PUT /{OS}/{ARCH}/latest/{VER}", requireCert(handleUpdateLatest))
	mux.HandleFunc("GET /{OS}/{ARCH}/checksum/{VER}", logRequests(handleGetChecksum))
	mux.HandleFunc("POST /{OS}/{ARCH}/upload", requireCert(logRequests(handleUploadBinary)))
	mux.HandleFunc("GET /{OS}/{ARCH}/download/{VER}", logRequests(handleDownloadBinary))
	mux.HandleFunc("GET /", logRequests(handleHome))

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
		wh := newWrappedWriter(w)
		h(wh, r)
		req := fmt.Sprintf("status: %d; method: %s; path: %s; origin: %s; ", wh.Status(), r.Method, r.URL.Path, r.RemoteAddr)
		logger.Println(req)
	}
}

func newWrappedWriter(w http.ResponseWriter) *wrappedResponseWriter {
	return &wrappedResponseWriter{
		w: w,
	}
}

type wrappedResponseWriter struct {
	w           http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

func (wh *wrappedResponseWriter) Header() http.Header {
	return wh.w.Header()
}

func (wh *wrappedResponseWriter) Write(d []byte) (int, error) {
	return wh.w.Write(d)
}

func (wh *wrappedResponseWriter) WriteHeader(statusCode int) {
	wh.statusCode = statusCode
	wh.w.WriteHeader(statusCode)
	return
}

func (wh *wrappedResponseWriter) Status() int {
	return wh.statusCode
}

func requireCert(h func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	caPem, err := os.ReadFile(CERT)
	if err != nil {
		logger.Println("failed to open certificate authority")
		logger.Fatal(err.Error())
	}

	roots := x509.NewCertPool()

	roots.AppendCertsFromPEM(caPem)

	options := x509.VerifyOptions{
		Roots: roots,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.Header.Get("X-Client-Certificate")
		if p == "" {
			replyMessage(w, http.StatusUnauthorized, "no valid certificate in header")
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			replyMessage(w, http.StatusBadRequest, "bad encoding")
			return
		}

		block, _ := pem.Decode(decoded)
		if block == nil {
			replyMessage(w, http.StatusBadRequest, "no blocks decoded")
			return
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			replyMessage(w, http.StatusInternalServerError, "could not parse certificate")
			return

		}
		_, err = cert.Verify(options)
		if err != nil {
			replyMessage(w, http.StatusUnauthorized, "this is not an authorized certificate")
			return
		}

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

	b, err := os.ReadFile(p)
	if err != nil {
		replyMessage(w, http.StatusNotFound, "not found")
		return
	}

	w.WriteHeader(http.StatusOK)
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

	w.WriteHeader(http.StatusOK)
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
