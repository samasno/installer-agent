package main

import (
	"bytes"
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
	"sync"
	"syscall"
	"time"
)

var BINARY_SERVER_URL string
var OS = "linux"
var ARCH = "ELFCLASS64"
var BIN_DIR string
var BIN_PATH string
var CURRENT_PROCESS exec.Cmd
var BIN_NAME string
var DEFAULT_BIN_NAME = "installer-agent"
var WINDOWS_BIN_NAME = "installer-agent.exe"
var PID int
var CMD = []string{}
var OUT string

var logger *log.Logger

type flagArray []string

func (f *flagArray) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func (f *flagArray) String() string {
	return fmt.Sprintf("%v", *f)
}

func main() {
	var childArgs flagArray
	var childFlags flagArray
	var childEnv flagArray
	flag.StringVar(&BIN_DIR, "dir", "", "path to directory where binary file is or will be stored. defaults to current user directory.")
	flag.StringVar(&BINARY_SERVER_URL, "host", "http://localhost:8080/", "url for binary server")
	flag.StringVar(&OUT, "out", "", "path to log file")
	flag.Var(&childArgs, "arg", "args to pass to child process.")
	flag.Var(&childFlags, "flag", "flags to be passed to child. should be passed as key value pair \"key=value\". flags will be passed before any positional arguments")
	flag.Var(&childEnv, "env", "flags to be passed to child. should be passed as key value pair \"key=value\"")

	flag.Parse()

	logFlags := log.Ldate | log.Ltime
	logPrefix := fmt.Sprintf("PID %d  ", os.Getpid())
	if OUT == "" {
		logger = log.New(os.Stdout, logPrefix, logFlags)
	} else {
		logFile, err := os.OpenFile(OUT, os.O_CREATE|os.O_RDWR, 0774)
		if err != nil {
			log.Printf("failed to open log file \"%s\"", OUT)
			log.Fatal(err.Error())
		}
		logger = log.New(logFile, logPrefix, logFlags)
	}

	var err error
	OS, ARCH, err = getOsAndArch()
	if err != nil {
		logger.Println("failed to identify operating system and architecture. using default linux ELFCLASS64")
	}

	if BIN_DIR == "" {
		BIN_DIR, err = os.Getwd()
		if err != nil {
			panic("couldn't find working directory")
		}
	}

	switch OS {
	case "windows":
		BIN_NAME = WINDOWS_BIN_NAME
	case "linux", "darwin":
		BIN_NAME = DEFAULT_BIN_NAME
	default:
		BIN_NAME = DEFAULT_BIN_NAME
		logger.Printf("operating system \"%s\" might not be supported", OS)
	}

	BIN_PATH = path.Join(BIN_DIR, BIN_NAME)

	CMD = append(CMD, BIN_PATH)

	cfs := []string{}
	for _, f := range childFlags {
		cfs = append(cfs, "--"+f)
	}

	CMD = append(CMD, cfs...)

	CMD = append(CMD, childArgs...)

	_, err = url.Parse(BINARY_SERVER_URL)
	if err != nil {
		logger.Println(err.Error())
		panic(err.Error())
	}

	err = os.MkdirAll(BIN_DIR, 0755)
	if err != nil {
		panic(err.Error())
	}

	RUNNING, err := RunJob(CMD...)

	for {
		updated, err := stayUpdated()
		if err != nil {
			logger.Println("error fetching update")
			logger.Println(err.Error())
		}

		if !updated {
			time.Sleep(time.Duration(5) * time.Second)
			continue
		}

		RUNNING, err = SwapNewJob(RUNNING, CMD...)
		if err != nil {
			logger.Println("Failed to restart running process")
			logger.Fatal(err.Error())
		}
	}
}

func stayUpdated() (bool, error) {
	latest, latestChecksum, err := checkForUpdate()
	if err != nil {
		return false, err
	}

	if latest == "" {
		logger.Println("no updates")
		return false, nil
	}

	tmpPath, tmpChecksum, err := downloadBinaryToTemp(latest)
	if err != nil {
		return false, err
	}

	logger.Printf("download new binary to %s checksum %s\n", tmpPath, tmpChecksum)
	if tmpChecksum != latestChecksum {
		err := os.RemoveAll(tmpPath)
		if err != nil {
			logger.Printf("failed to remove file %s\n", tmpPath)
		} else {
			logger.Printf("removed file %s\n", tmpPath)
		}
		return false, errors.New("checksum of downloaded binary does not match latest version")
	}

	logger.Printf("checksums matched, moving %s to %s\n", tmpPath, BIN_PATH)
	err = os.Rename(tmpPath, BIN_PATH)
	if err != nil {
		logger.Println("faile to rename new binary file")
		return false, err
	}

	err = os.Chmod(BIN_PATH, 0777)
	if err != nil {
		logger.Println("failed to update permissions for new binary")
		return false, err
	}

	logger.Println("binary succesfully updated")
	return true, nil
}

type Job struct {
	cmd   *exec.Cmd
	entry string
	args  []string
	kill  bool
	Ok    chan bool
	mtx   sync.Mutex
}

func SwapNewJob(old *Job, cmd ...string) (*Job, error) {
	if old != nil {
		old.Stop()
	}

	j, err := RunJob(cmd...)
	if err != nil {
		return nil, err
	}

	return j, nil
}

func RunJob(command ...string) (*Job, error) { //
	if len(command) < 1 {
		return nil, errors.New("new job requires at least one command")
	}

	entry := command[0]

	args := []string{}
	if len(command) > 1 {
		args = append(args, command[1:]...)
	}

	j := &Job{
		kill:  false,
		entry: entry,
		args:  args,
		Ok:    make(chan bool),
		mtx:   sync.Mutex{},
	}

	j.Run()

	return j, nil
}

func (j *Job) Run() {
	go func() {
		for {
			j.cmd = exec.Command(j.entry, j.args...)
			j.cmd.Stdout = os.Stdout
			j.cmd.Stderr = os.Stderr

			if err := j.cmd.Run(); err != nil && !j.kill {
				logger.Println("process crashed")
				logger.Println(err.Error())
				time.Sleep(time.Duration(2) * time.Second)
				continue
			}
			break
		}

		j.Ok <- true
	}()
}

func (j *Job) Stop() error {
	j.kill = true
	err := j.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		return err
	}

	<-j.Ok

	return nil
}

func (j *Job) Restart() error {
	err := j.Stop()
	if err != nil {
		return err
	}

	RunJob(CMD...)

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
	logger.Println("fetching " + u)
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
		logger.Println(err.Error())
		logger.Println("not a linux binary")
	} else {
		defer f.Close()
		defer e.Close()
		return "linux", e.Class.String(), nil
	}

	w, err := pe.Open(x)
	if err != nil {
		logger.Println(err.Error())
		logger.Println("not a windows executable")
	} else {
		defer w.Close()
		warch := strconv.Itoa(int(w.FileHeader.Machine))
		return "windows", warch, nil
	}

	f, err = os.Open(x)
	mac, err := macho.NewFile(f)
	if err != nil {
		logger.Println(err.Error())
		logger.Println("not a darwin binary")
	} else {
		defer f.Close()
		defer mac.Close()
		return "darwin", mac.Cpu.String(), nil
	}

	return "", "", errors.New("Unsupported operating system")
}
