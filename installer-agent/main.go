package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

var BINARY_SERVER_URL string
var OS string
var ARCH string
var BIN_DIR string
var BIN_PATH string
var CURRENT_PROCESS exec.Cmd
var BIN_NAME string
var DEFAULT_BIN_NAME = "installer-agent"
var WINDOWS_BIN_NAME = "installer-agent.exe"
var PID int

var SUPPORTED_OS = []string{"windows", "darwin", "linux"}

func main() {
	PID = os.Getpid()
	log.SetPrefix(fmt.Sprintf("PID %d  ", PID))

	var err error
	OS, ARCH, err = getOsAndArch()
	if err != nil {
		panic("failed to identify current runtime")
	}

	flag.StringVar(&BIN_DIR, "bindir", "./", "path to directory where binary file is stored. defaults to current directory.")
	flag.StringVar(&BINARY_SERVER_URL, "host", "http://localhost:8080/", "url for binary server")
	flag.Parse()

	BIN_PATH, err = os.Executable()
	if err != nil {
		panic(err.Error())
	}

	supported := false
	for _, oss := range SUPPORTED_OS {
		if OS == oss {
			supported = true
		}
	}

	if !supported {
		log.Println("operating system not officially supported")
	}

	_, err = url.Parse(BINARY_SERVER_URL)
	if err != nil {
		log.Println(err.Error())
		panic(err.Error())
	}

	err = os.MkdirAll(BIN_DIR, 0755)
	if err != nil {
		panic(err.Error())
	}

	srvDead := make(chan bool)
	srv := runServer(srvDead)

monitorLoop:
	for {
		select {
		case <-srvDead:
			time.Sleep(time.Duration(3) * time.Second)
			srv = runServer(srvDead)

		default:
			log.Printf("starting update cycle")
			updated, err := stayUpdated()
			if err != nil {
				log.Printf("Update failed: %s\n", err.Error())
			}

			if !updated {
				time.Sleep(time.Duration(5) * time.Second)
				continue
			}
			if updated {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(10)*time.Second)
				defer cancel()
				done := make(chan bool)

				go func(done chan bool) {
					err := srv.Shutdown(ctx)
					if err != nil {
						log.Println("failed to shutdown server.")
						log.Fatal(err.Error())
					}
					log.Println("server shut down successfully")
					done <- true
				}(done)

				select {
				case <-ctx.Done():
					log.Fatal("failed to shutdown server while replacing. cannot start new server")
				case <-done:
					err = startSuccessorProcess()
					if err != nil {
						log.Println(err.Error())
						log.Println("failed to start successor process on new update. will try again next update cycle")
						continue
					}
					log.Println("successor process launched, breaking monitoring loop")
					break monitorLoop
				}
			}
		}
	}
}

func stayUpdated() (bool, error) {
	log.Println("fetching latest version and checksum")
	latest, latestChecksum, err := checkForUpdate()
	if err != nil {
		return false, err
	}

	if latest == "" {
		log.Println("current binary checksum matches latest version")
		log.Println("no updates")
		return false, nil
	}

	tmpPath, tmpChecksum, err := downloadBinaryToTemp(latest)
	if err != nil {
		return false, err
	}

	log.Printf("download new binary to %s checksum %s\n", tmpPath, tmpChecksum)
	if tmpChecksum != latestChecksum {
		err := os.RemoveAll(tmpPath)
		if err != nil {
			log.Printf("failed to remove file %s\n", tmpPath)
		} else {
			log.Printf("removed file %s\n", tmpPath)
		}
		return false, errors.New("checksum of downloaded binary does not match latest version")
	}

	log.Printf("checksums matched, moving %s to %s\n", tmpPath, BIN_PATH)
	err = os.Rename(tmpPath, BIN_PATH)
	if err != nil {
		log.Println("faile to rename new binary file")
		return false, err
	}

	err = os.Chmod(BIN_PATH, 0777)
	if err != nil {
		log.Println("failed to update permissions for new binary")
		return false, err
	}

	log.Println("binary succesfully updated")
	return true, nil
}

func runServer(dead chan bool) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Write([]byte("home page 0"))
	})
	srv := &http.Server{
		Addr:    "0.0.0.0:3333",
		Handler: mux,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			if err == http.ErrServerClosed {
				return
			}
			log.Println(err.Error())
			dead <- true
		}
	}()
	return srv
}

func startSuccessorProcess() error {
	groupsUint32 := []uint32{}

	groups, err := os.Getgroups()
	if err != nil {
		return err
	}

	for _, g := range groups {
		groupsUint32 = append(groupsUint32, uint32(g))
	}

	// creds := &syscall.Credential{Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid()), Groups: groupsUint32}
	attr := &syscall.SysProcAttr{
		Foreground: true,
		// Setpgid: true,
		// Setctty: true,
		// Setsid:     true,
		// Credential: &syscall.Credential{
		// 	Gid: uint32(os.Getgid()),
		// 	Uid: uint32(os.Getuid()),
		// },
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	args := []string{}
	if len(os.Args) > 1 {
		args = append(args, os.Args[1:]...)
	}
	cmd := exec.Command(BIN_PATH, args...)

	cmd.Env = os.Environ()
	cmd.Dir = cwd
	cmd.SysProcAttr = attr

	err = cmd.Start()
	if err != nil {
		log.Println("starting child process failed")
		return err
	}

	log.Printf("created new pid %d", cmd.Process.Pid)
	err = cmd.Process.Release()
	if err != nil {
		return err
	}

	log.Printf("closing predecessor pid %d", PID)
	os.Exit(0)
	return nil
}

func checkForUpdate() (string, string, error) {
	bchx, err := binChecksum()
	if err != nil {
		return "", "", err
	}
	u, _ := url.Parse(BINARY_SERVER_URL)
	u.Path = path.Join(OS, ARCH, "latest")
	lv, err := fetch(u.String())
	if err != nil {
		return "", "", err
	}

	u.Path = path.Join(OS, ARCH, "checksum", lv)
	lvchx, err := fetch(u.String())
	if err != nil {
		return "", "", err
	}

	if bchx != lvchx {
		return lv, lvchx, nil
	}

	return "", "", nil
}

func fetch(u string) (string, error) {
	log.Println("fetching " + u)
	req, err := http.NewRequest(http.MethodGet, u, &bytes.Buffer{})
	if err != nil {
		return "", err
	}

	c := http.Client{Timeout: time.Duration(10) * time.Second}

	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	if res.StatusCode != 200 {
		return "", errors.New(string(data))
	}

	return string(data), nil
}

func binChecksum() (string, error) {
	bin, err := os.Open(BIN_PATH)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}

		return "", err
	}
	defer bin.Close()

	chx, err := checksum(bin)
	if err != nil {
		return "", err
	}

	return chx, nil
}

func downloadBinaryToTemp(v string) (string, string, error) {
	u, _ := url.Parse(BINARY_SERVER_URL)
	u.Path = filepath.Join(OS, ARCH, "download", v)

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", "", err
	}

	c := http.Client{Timeout: time.Duration(30) * time.Second}

	res, err := c.Do(req)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()

	dir := os.TempDir()

	tmp, err := os.CreateTemp(dir, "installer-temp-bin")
	if err != nil {
		return "", "", err
	}
	defer tmp.Close()

	_, err = io.Copy(tmp, res.Body)
	if err != nil {
		return "", "", err
	}

	tmp.Seek(0, io.SeekStart)

	chx, err := checksum(tmp)
	if err != nil {
		return "", "", err
	}

	return tmp.Name(), chx, nil
}

func checksum(r io.ReadSeeker) (string, error) {
	h := sha256.New()
	_, err := io.Copy(h, r)
	if err != nil {
		return "", err
	}
	r.Seek(0, io.SeekStart)

	return hex.EncodeToString(h.Sum(nil)), nil
}

func getOsAndArch() (string, string, error) {
	x, err := os.Executable()
	if err != nil {
		return "", "", err
	}

	f, err := os.Open(x)
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

	w, err := pe.Open(x)
	if err != nil {
		log.Println(err.Error())
		log.Println("not a windows executable")
	} else {
		defer w.Close()
		warch := strconv.Itoa(int(w.FileHeader.Machine))
		return "windows", warch, nil
	}

	f, err = os.Open(x)
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
