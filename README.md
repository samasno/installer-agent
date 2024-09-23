## Update agent
Polls a server at regular intervals for the latest version of an application. It will download, install, and restart application when a new version is available. 

### Description
This system is comprised of 3 components(binary-server, binary-upload-cli, installer-agent) + 1 target application. A compiled binary/executable is uploaded to the binary-server using the binary-upload cli. The installer-agent is run on a client machine and polls the binary server for the latest version of the target application.

Binary Server
- Http append-only file server that hosts executables and versioning for an application.

- Intended to store executables for a single application and organizes them by operating system, architecture, and version.

- On upload the server will perform a checksum of the upload file and atomic write to ensure data integrity.

- Binaries and checksums may not be changed after initial upload, but the designated latest version for an os/architecture can be changed to another existing version to allow for rollbacks.

- To employ the Binary Server, compile your target application then upload it using the binary-upload-cli.

Upload CLI  
- CLI tool with commands to upload a new binary and set the latest version for a given architecture. 

- On upload, the tool Upload CLI will detect the operating system and architecture from the target binary and include it in its request to the Binary Server.

Installer Agent
- Installer Agent runs on a clients machine and checks for updates on start then regularly polls the binary server for the latest version of hosted given application. 

- If the local executable does not match the latest version by checksum, the binary for the latest version will download the new executable, stop the process running locally, then restart the application with the new executable. Application is run as a child process

- Binary Server must have at least one version of the target application uploaded that matches the operating sytem and architecture of the local machine.

Target Application
- Target Application should be a single executable file that does not assume any elevated privileges.

### Dependencies
Requires go 1.22 or higher

### Run

- (Optional - Requires OpenSSL) Navigate to `./keys` and run `./keys.sh` to generate signed CA and client keys.
- Navigate to `./binary-server`
- Run the binary server with one of the following:  
```
go run main.go
```  
or
```
go build -o binary-server main.go  
./binary-server
```  
  - add the flag `--cert ../keys/ca/ca.crt` to protect upload routes with certificate based authentication
- Navigate to `./bin-upload-cli`
- Upload a binary with the following 
```
go build -o upload-cli 
./upload-cli upload --cert ../keys/client/client.crt <VERSIONNAME> <PATHTOFILE>
```
  - omit the cert flag if you did not perform step 0
- Navigate to `./installer-agent`
- Run the installer-agent
```
go build -o installer-agent main.go
./installer-agent
```
  - if running the Binary Server on a remote machine add the `--host <URL>` with the full url of the server.
  - add the `--interval <NUMBER>` flag to set the polling interval in minutes
- In `./testapp` there are a few simple http servers that can be built and uploaded for testing. Server runs on `http://localhost:3333`

### Troubleshooting
- Make sure the Binary Server is running with one suitable executable before starting the Installer-Agent
- If compiling binaries for a different architectures, most machines will be covered by a combination of "linux"/"darwin"/"windows" and "amd64"/"arm64"



