package main

import (
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
	"path/filepath"
	"strings"
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

	var verifyOptions *x509.VerifyOptions

	if CERT != "" {
		opts := getVerifyOptions(CERT)
		verifyOptions = &opts
	}

	srv := newServer(port, FILES_DIR, verifyOptions)
	if err := srv.ListenAndServe(); err != nil {
		if err == http.ErrServerClosed {
			logger.Println("server closed")
			os.Exit(0)
		}
		logger.Println(err.Error())
		logger.Println("server crashed")
		os.Exit(1)
	}
}

func newServer(port int, filesDir string, verifyOptions *x509.VerifyOptions) *http.Server {

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{OS}/{ARCH}/latest", chainMiddleware(handleGetLatest(filesDir), logRequests))
	mux.HandleFunc("PUT /{OS}/{ARCH}/latest/{VER}", chainMiddleware(handleUpdateLatest(filesDir), logRequests))
	mux.HandleFunc("GET /{OS}/{ARCH}/checksum/{VER}", chainMiddleware(handleGetChecksum(filesDir), logRequests))
	mux.HandleFunc("POST /{OS}/{ARCH}/upload", chainMiddleware(handleUploadBinary(filesDir), logRequests, requireCert(verifyOptions)))
	mux.HandleFunc("GET /{OS}/{ARCH}/download/{VER}", chainMiddleware(handleDownloadBinary(filesDir), logRequests))
	mux.HandleFunc("GET /{$}", chainMiddleware(handleHome, logRequests))

	srv := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", port),
		Handler: mux,
	}

	return srv
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	replyMessage(w, http.StatusOK, "home page")
}

func handleGetLatest(files string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		OS := r.PathValue("OS")
		ARCH := r.PathValue("ARCH")

		p := filepath.Join(files, OS, ARCH, "latest")

		b, err := os.ReadFile(p)
		if err != nil {
			replyMessage(w, http.StatusNotFound, "not found")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}

func handleUpdateLatest(files string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		OS := r.PathValue("OS")
		ARCH := r.PathValue("ARCH")
		VER := r.PathValue("VER")

		dir := filepath.Join(files, OS, ARCH)

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
		tmp.Close()

		err = os.Rename(tmpPath, filepath.Join(dir, "latest"))
		if err != nil {
			replyMessage(w, http.StatusInternalServerError, err.Error())
			return
		}

		replyMessage(w, http.StatusOK, "OK")
	}

}

func handleGetChecksum(files string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		OS := r.PathValue("OS")
		VER := r.PathValue("VER")
		ARCH := r.PathValue("ARCH")

		p := filepath.Join(files, OS, ARCH, "checksum", VER)
		b, err := os.ReadFile(p)
		if err != nil {
			replyMessage(w, http.StatusNotFound, "not found")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}

func handleDownloadBinary(files string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		OS := r.PathValue("OS")
		ARCH := r.PathValue("ARCH")
		VER := r.PathValue("VER")

		binpath := filepath.Join(files, OS, ARCH, "bin", VER)

		fileDownload(w, r, binpath)
	}
}

func handleUploadBinary(files string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		defer r.Body.Close()
		OS := r.PathValue("OS")
		ARCH := r.PathValue("ARCH")

		err := r.ParseMultipartForm(20 * 1024 * 1024)
		if err != nil {
			replyMessage(w, http.StatusInternalServerError, err.Error())
			return
		}

		checksum := r.FormValue("checksum")
		version := r.FormValue("version")
		isLatest := r.FormValue("latest")

		// check if this version already exists to prevent update of existing version
		_, err = os.Stat(filepath.Join(files, OS, ARCH, "bin", version))
		if err != nil && !os.IsNotExist(err) {
			replyMessage(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err == nil {
			replyMessage(w, http.StatusUnauthorized, "version already exists")
			return
		}

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

		// first write to tempfile for atomic write later
		tmpBinary, tmpBinaryPath, err := copyToTempFile(f)
		if err != nil {
			replyMessage(w, http.StatusInternalServerError, err.Error())
			return
		}

		chx, err := checksumString(tmpBinary)
		if err != nil {
			replyMessage(w, http.StatusInternalServerError, err.Error())
			return
		}

		tmpBinary.Close()

		if chx != checksum {
			replyMessage(w, http.StatusBadRequest, "file uploaded to server does not match provided checksum and file may be corrupted. try again")
			return
		}

		cxf, tmpChecksumPath, err := copyToTempFile(strings.NewReader(checksum))
		if err != nil {
			replyMessage(w, http.StatusInternalServerError, err.Error())
			return
		}
		cxf.Close()

		destDir := filepath.Join(files, OS, ARCH)

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

		// using rename for atomic write
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
			vf.Close()

			err = os.Rename(tmpVerPath, destLatest)
			if err != nil {
				replyMessage(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		replyMessage(w, http.StatusCreated, "file uploaded")
	}
}

func logRequests(h http.HandlerFunc) http.HandlerFunc {
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

// wrapper to retrieve response data after written by endpoint
type wrappedResponseWriter struct {
	w          http.ResponseWriter
	statusCode int
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
}

func (wh *wrappedResponseWriter) Status() int {
	return wh.statusCode
}

func chainMiddleware(f http.HandlerFunc, mws ...middleware) http.HandlerFunc {
	for _, m := range mws {
		f = m(f)
	}
	return f
}

type middleware func(http.HandlerFunc) http.HandlerFunc

// certs/options used for auth in request header, not tls
func getVerifyOptions(cafile string) x509.VerifyOptions {
	caPem, err := os.ReadFile(cafile)
	if err != nil {
		logger.Println("failed to open certificate authority")
		logger.Fatal(err.Error())
	}

	roots := x509.NewCertPool()

	roots.AppendCertsFromPEM(caPem)

	options := x509.VerifyOptions{
		Roots: roots,
	}

	return options
}

func requireCert(options *x509.VerifyOptions) middleware {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if options == nil {
				h(w, r)
				return
			}
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
			_, err = cert.Verify(*options)
			if err != nil {
				replyMessage(w, http.StatusUnauthorized, "this is not an authorized certificate")
				return
			}

			h(w, r)
		}
	}
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
