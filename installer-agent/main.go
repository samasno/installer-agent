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
	"regexp"
	"strconv"
	"sync"
	"time"
)

var BINARY_SERVER_URL string

var OS = "linux"
var ARCH = "ELFCLASS64"
var LIN_EXT = ".bin"
var WIN_EXT = ".exe"
var APP_NAME = "app"
var AGENT_NAME = "installer"
var BIN_DIR string
var BIN_PATH string
var BIN_NAME string
var INTERVAL_MINUTES = 60

var OUT string

var CMD = []string{}
var FLAGS flagArray
var ARGS flagArray
var EXT string

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
	var logsOut string
	var interval int
	flag.StringVar(&BIN_DIR, "dir", "", "path to directory where binary file is or will be stored. defaults to current directory")
	flag.StringVar(&BINARY_SERVER_URL, "host", "http://localhost:8080/", "url for binary server")
	flag.Var(&ARGS, "arg", "args to pass to child process.")
	flag.Var(&FLAGS, "flag", "flags to be passed to child. should be passed as key value pair \"key=value\". flags will be passed before any positional arguments")
	flag.StringVar(&logsOut, "out", "", "path to log file. writes to std out by default")
	flag.IntVar(&interval, "interval", 0, "interval in minutes that updates will be checked. defaults to 60 minutes")

	flag.Parse()

	if interval != 0 {
		INTERVAL_MINUTES = interval
	}

	logFlags := log.Ldate | log.Ltime
	logPrefix := fmt.Sprintf("PID %d  ", os.Getpid())
	if logsOut == "" {
		logger = log.New(os.Stdout, logPrefix, logFlags)
	} else {
		logFile, err := os.OpenFile(logsOut, os.O_CREATE|os.O_RDWR, 0774)
		if err != nil {
			log.Printf("failed to open log file \"%s\"", logsOut)
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
		wd, err := os.Getwd()
		if err != nil {
			log.Println("failed to get working directory")
			log.Fatal(err.Error())
		}

		BIN_DIR = wd
	}

	err = os.Chdir(BIN_DIR)
	if err != nil {
		log.Println("could not access work directory")
		log.Fatal(err.Error())
	}

	switch OS {
	case "windows":
		BIN_NAME, err = findExecutable(APP_NAME, WIN_EXT, "./", true)
		EXT = WIN_EXT
	case "linux", "darwin":
		BIN_NAME, err = findExecutable(APP_NAME, LIN_EXT, "./", true)
		EXT = LIN_EXT
	default:
		BIN_NAME, err = findExecutable(APP_NAME, LIN_EXT, "./", true)
	}

	if err != nil && !os.IsNotExist(err) {
		logger.Println("error locating executable")
		logger.Fatal(err.Error())
	}

	BIN_PATH = filepath.Join(BIN_DIR, BIN_NAME)

	CMD = getCommand(BIN_DIR, BIN_NAME, FLAGS, ARGS)

	_, err = url.Parse(BINARY_SERVER_URL)
	if err != nil {
		logger.Println(err.Error())
		log.Fatal(err.Error())
	}

	err = os.MkdirAll(BIN_DIR, 0755)
	if err != nil {
		log.Fatal(err.Error())
	}

	var RUNNING *Job

	if BIN_NAME != "" {
		RUNNING, err = RunJob(OS, CMD...)
		if err != nil {
			log.Println("failed initial attempt to run, there may be no binary present")
			log.Println(err.Error())
		}
	}

	for {
		updated, newBin, err := stayUpdated(OS, ARCH, BINARY_SERVER_URL, BIN_NAME, BIN_DIR, EXT)
		if err != nil {
			logger.Println("error fetching update")
			logger.Println(err.Error())
		}

		if !updated {
			time.Sleep(time.Duration(INTERVAL_MINUTES) * time.Minute)
			continue
		}

		CMD = getCommand(BIN_DIR, newBin, FLAGS, ARGS)

		oldBin := BIN_NAME
		BIN_NAME = newBin
		BIN_PATH = path.Join(BIN_DIR, BIN_NAME)

		RUNNING, err = SwapNewJob(OS, RUNNING, CMD...)
		if err != nil {
			logger.Println("Failed to restart running process")
			logger.Fatal(err.Error())
		}

		if oldBin != "" {
			err = os.Remove(oldBin)
			if err != nil {
				logger.Println("Failed to remove old binary")
				logger.Println(err.Error())
			}
		}

		time.Sleep(time.Duration(INTERVAL_MINUTES) * time.Minute)
		continue

	}
}

func stayUpdated(osys, arch, host, bin, dir, ext string) (bool, string, error) {
	latest, latestChecksum, err := checkForUpdate(osys, arch, host, bin)
	if err != nil {
		return false, "", err
	}

	if latest == "" {
		logger.Println("no updates")
		return false, "", nil
	}

	tmpPath, tmpChecksum, err := downloadBinaryToTemp(osys, arch, host, latest)
	if err != nil {
		return false, "", err
	}

	logger.Printf("download new binary to %s checksum %s\n", tmpPath, tmpChecksum)
	if tmpChecksum != latestChecksum {
		err := os.RemoveAll(tmpPath)
		if err != nil {
			logger.Printf("failed to remove file %s\n", tmpPath)
		} else {
			logger.Printf("removed file %s\n", tmpPath)
		}
		return false, "", errors.New("checksum of downloaded binary does not match latest version")
	}

	newBin := fmt.Sprintf("%s%s", filepath.Base(tmpPath), ext)
	newPath := path.Join(dir, newBin)
	logger.Printf("checksums matched, moving %s to %s\n", tmpPath, newPath)

	err = os.Rename(tmpPath, newPath)
	if err != nil {
		logger.Println("failed to rename new binary file")
		return false, "", err
	}

	err = os.Chmod(newPath, 0777)
	if err != nil {
		logger.Println("failed to update permissions for new binary")
		return false, "", err
	}

	logger.Println("binary succesfully updated")
	return true, newBin, nil
}

type Job struct {
	cmd   *exec.Cmd
	entry string
	args  []string
	kill  bool
	Ok    chan bool
	mtx   sync.Mutex
	os    string
}

func SwapNewJob(osys string, old *Job, cmd ...string) (*Job, error) {
	if old != nil {
		old.Stop()
	}

	j, err := RunJob(osys, cmd...)
	if err != nil {
		return nil, err
	}

	return j, nil
}

func RunJob(os string, command ...string) (*Job, error) { //
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
		os:    os,
	}

	j.Run()

	return j, nil
}

func (j *Job) Run() {

	j.cmd = exec.Command(j.entry, j.args...)
	j.cmd.Stdout = os.Stdout
	j.cmd.Stderr = os.Stderr

	err := j.cmd.Start()
	if err != nil {
		log.Println("failed to start job process")
	}

	go func() {
		for {
			if j != nil && j.kill {
				break
			}

			if err := j.cmd.Wait(); err != nil && !j.kill {
				if j.cmd.ProcessState.ExitCode() != 0 {
					logger.Println("process crashed")
					logger.Println(err.Error())
					time.Sleep(time.Duration(250) * time.Millisecond)

					j.cmd = exec.Command(j.entry, j.args...)
					j.cmd.Stdout = os.Stdout
					j.cmd.Stderr = os.Stderr

					continue
				}
			}
			break
		}

		j.Ok <- true
	}()
}

func (j *Job) Stop() error {
	if j == nil || j.cmd == nil {
		return nil
	}

	j.kill = true

	if j.cmd.Process == nil {
		return nil
	}

	if j.os == "windows" {
		cmd := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(j.cmd.Process.Pid))
		err := cmd.Run()
		if err != nil {
			log.Println("failed to kill windows predecessor")
			log.Fatal(err.Error())
		}
	} else {
		err := j.cmd.Process.Signal(os.Interrupt)
		if err != nil {
			return err
		}
	}

	time.Sleep(time.Duration(1) * time.Second)

	<-j.Ok

	return nil
}

func (j *Job) Entry() string {
	return j.entry
}

func checkForUpdate(osys, arch, host, bin string) (string, string, error) {
	bchx, err := binChecksum(bin)
	if err != nil {
		return "", "", err
	}
	u, _ := url.Parse(host)
	u.Path = path.Join(osys, arch, "latest")
	lv, err := fetch(u.String())
	if err != nil {
		return "", "", err
	}

	u.Path = path.Join(osys, arch, "checksum", lv)
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

func binChecksum(name string) (string, error) {
	bin, err := os.Open(name)
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

func downloadBinaryToTemp(osys, arch, host, v string) (string, string, error) {
	u, _ := url.Parse(host)
	u.Path = path.Join(osys, arch, "download", v)

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

	tmp, err := os.CreateTemp(dir, "app-")
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
	if err != nil {
		return "", "", err
	}
	mac, err := macho.NewFile(f)
	if err != nil {
		logger.Println(err.Error())
		logger.Println("not a darwin binary")
	} else {
		defer f.Close()
		defer mac.Close()
		return "darwin", mac.Cpu.String(), nil
	}

	return "", "", errors.New("unsupported operating system")
}

func findExecutable(name string, ext string, dirPath string, remove bool) (string, error) {
	bin := ""
	rgxstr := fmt.Sprintf(`^%s[\w\-\.]+%s$`, name, ext)
	rgx, err := regexp.Compile(rgxstr)
	if err != nil {
		return bin, err
	}

	dir, err := os.ReadDir(dirPath)
	if err != nil {
		return bin, err
	}

	matches := []string{}
	for _, de := range dir {
		if rgx.Match([]byte(de.Name())) {
			matches = append(matches, de.Name())
		}

	}

	fmt.Printf("%v\n", matches)
	if len(matches) == 0 {
		logger.Printf("found no executables")
		return "", nil
	}

	bin = matches[0]

	if len(matches) > 1 && remove {
		for _, m := range matches[1:] {
			err := os.RemoveAll(path.Join(dirPath, m))
			if err != nil {
				logger.Printf("failed to remove %s", m)
			}
		}
	}

	return bin, nil
}

func getCommand(dir, bin string, flags, args flagArray) []string {
	command := []string{}
	binPath := filepath.Join(dir, bin)
	command = append(command, binPath)
	command = append(command, flags...)
	command = append(command, args...)
	return command
}
