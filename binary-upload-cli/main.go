package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// parse flags here
var HOST string
var LATEST bool
var HELP bool
var CERT string

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Error: Expected at least 2 arguments, got %d\n", len(os.Args))
	}

	flag.BoolVar(&HELP, "help", false, helpMessage)
	flag.StringVar(&HOST, "host", "http://localhost:8080", "url for binary server")
	flag.StringVar(&CERT, "cert", "", "path to cert file")
	flag.Parse()

	args := flag.Args()

	if HELP {
		fmt.Println(helpMessage)
		return
	}

	cmd := args[0]

	command, ok := commands[cmd]
	if !ok {
		log.Fatalf("Error: Unknown command \"%s\"\n", cmd)
	}

	result, err := command(args[1:])
	if err != nil {
		log.Fatalf("Error: %s", err.Error())
	}

	log.Println(result)
}

var commands = map[string]func([]string) (string, error){
	"upload":     uploadBinary,
	"set-latest": setLatest,
}

func uploadBinary(args []string) (string, error) {
	if len(args) != 2 {
		return "", fmt.Errorf("expected 2 arg got %d. need $VERSION $FILEPATH", len(args))
	}

	v := args[0]
	f := args[1]

	flag.BoolVar(&LATEST, "latest", true, "set as latest default version when clients check for updates. default true")
	flag.Parse()

	if HOST == "" {
		return "", fmt.Errorf("host is required")
	}

	remote, err := url.Parse(HOST)
	if err != nil {
		return "", err
	}

	OS, ARCH, err := getOsAndArch(f)

	b := bytes.NewBuffer([]byte{})

	bin, err := os.Open(f)
	if err != nil {
		return "", err
	}
	defer bin.Close()

	chx, err := checksumHex(bin)
	if err != nil {
		return "", err
	}

	mp := multipart.NewWriter(b)

	mp.WriteField("version", v)
	mp.WriteField("checksum", chx)
	if LATEST {
		mp.WriteField("latest", "true")
	}

	mpf, err := mp.CreateFormFile("binary", f)
	if err != nil {
		return "", err
	}

	io.Copy(mpf, bin)

	err = mp.Close()
	if err != nil {
		return "", err
	}

	remote.Path = path.Join(remote.Path, OS, ARCH, "upload")

	req, err := http.NewRequest(http.MethodPost, remote.String(), b)

	req.Header.Set("Content-Type", mp.FormDataContentType())

	if CERT != "" {
		cert, err := os.ReadFile(CERT)
		if err != nil {
			log.Fatal(err.Error())
		}

		base := base64.StdEncoding.EncodeToString(cert)

		req.Header.Set("X-Client-Certificate", base)
	}

	c := http.Client{Timeout: time.Duration(5) * time.Second}

	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	msg, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(msg), nil
}

func setLatest(args []string) (string, error) {
	if len(args) < 3 {
		return "", fmt.Errorf("expected 3 args got %d. need $OS $ARCHITECTURE $VERSION", len(args))
	}

	OS := args[0]
	ARCH := args[1]
	VER := args[2]

	remote, err := url.Parse(HOST)
	if err != nil {
		return "", err
	}

	remote.Path = path.Join(OS, ARCH, "latest", VER)

	req, err := http.NewRequest(http.MethodPut, remote.String(), strings.NewReader(""))

	c := http.Client{Timeout: time.Duration(5) * time.Second}

	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	msg, err := io.ReadAll(res.Body)

	return string(msg), nil
}

func getOsAndArch(fp string) (string, string, error) {
	f, err := os.Open(fp)
	if err != nil {
		return "", "", err
	}

	e, err := elf.NewFile(f)
	if err != nil {
		log.Println(err.Error())
		log.Println("not a linux binary")
	} else {
		defer f.Close()
		defer e.Close()
		return "linux", e.Class.String(), nil
	}

	w, err := pe.Open(fp)
	if err != nil {
		log.Println(err.Error())
		log.Println("not a windows executable")
	} else {
		defer w.Close()
		warch := strconv.Itoa(int(w.FileHeader.Machine))
		return "windows", warch, nil
	}

	f, err = os.Open(fp)
	mac, err := macho.NewFile(f)
	if err != nil {
		log.Println(err.Error())
		log.Println("not a darwin binary")
	} else {
		defer f.Close()
		defer mac.Close()
		return "darwin", mac.Cpu.String(), nil
	}

	return "", "", errors.New("Unsupported operating system")
}

func checksumHex(r io.ReadSeeker) (string, error) {
	h := sha256.New()
	_, err := io.Copy(h, r)
	if err != nil {
		return "", err
	}
	defer r.Seek(0, io.SeekStart)

	return hex.EncodeToString(h.Sum(nil)), nil
}

var helpMessage = `
	help message here
`
