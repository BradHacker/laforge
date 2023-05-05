package main

//go:generate fileb0x assets.toml
import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gen0cide/laforge/grpc/agent/static"
	pb "github.com/gen0cide/laforge/grpc/proto"
	"github.com/kardianos/service"
	"github.com/mholt/archiver"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	TaskFailed    = "FAILED"
	TaskRunning   = "INPROGRESS"
	TaskSucceeded = "COMPLETE"
)

var (
	logger  service.Logger
	address = "localhost:50051"
	// defaultName      = "Laforge Agent"
	certFile         = "service.pem"
	heartbeatSeconds = 10
	clientID         = "1"
	previousTask     = ""
)

// Program structures.
//
//	Define Start and Stop methods.
type program struct {
	exit chan struct{}
}

// Start What is Run when the executable is started up.
func (p *program) Start(s service.Service) error {
	p.exit = make(chan struct{})

	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}

// ExecuteCommand Runs the Command that is inputted and either returns the error or output
func ExecuteCommand(command string, args ...string) (string, error) {
	return SystemExecuteCommand(command, args...)
}

// DeleteObject Deletes the Object that is inputted and either returns the error or nothing
func DeleteObject(file string) error {
	err := os.RemoveAll(file)
	if err != nil {
		return err
	}
	return nil
}

// Reboot Reboots Host Operating System
func Reboot() {
	RebootSystem()
}

// ExtractArchive will extract archive to foler path.
func ExtractArchive(filepath string, folderpath string) error {
	err := archiver.Unarchive(filepath, folderpath)
	return err
}

// CreateUser will create a new user.
func CreateUser(username string, password string) error {
	return CreateSystemUser(username, password)
}

// ChangeUserPassword will change the users password
func ChangeUserPassword(username string, password string) error {
	return ChangeSystemUserPassword(username, password)
}

// AddUserGroup will extract archive to foler path.
func AddUserGroup(groupname string, username string) error {
	return AddSystemUserGroup(groupname, username)
}

// DownloadFile will download a url to a local file.
func DownloadFile(path, url, is_txt string) error {
	return SystemDownloadFile(path, url, is_txt)
}

// ExecuteAnsible will execute an Ansible Playbook
func ExecuteAnsible(playbookPath, connectionMethod, inventoryList string) (string, error) {
	return SystemExecuteAnsible(playbookPath, connectionMethod, inventoryList)
}

// ChangePermissions will download a url to a local file.
func ChangePermissions(path string, perms int) error {
	var err error
	_, err = os.Stat(path)
	if err == nil {
		// Make sure we have rwx permissions if it's a script
		err = os.Chmod(path, os.FileMode(perms))
		if err != nil {
			return err
		}
		return nil
	}
	return err
}

// AppendFile will download a url to a local file.
func AppendFile(path string, content string) error {
	var err error
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return err
	}
	return nil
}

// ValidateMD5Hash Validates the MD5 Hash of a file with the provided MD5 Hash
func ValidateMD5Hash(filepath string, md5hash string) error {
	var calculatedMD5Hash string

	// Open the file
	file, err := os.Open(filepath)

	// Can't open the file, assuming false
	if err != nil {
		return err
	}

	// Close the file when we're done
	defer file.Close()

	// Open a new hash interface
	hash := md5.New()

	// Hash the file
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	byteHash := hash.Sum(nil)[:16]

	// Convert bytes to string
	calculatedMD5Hash = hex.EncodeToString(byteHash)

	if calculatedMD5Hash == md5hash {
		return errors.New("MD5 hashes do not match")
	} else {
		return nil
	}
}

// RequestTask Function Requests task from the GRPC server to be run on the client
func RequestTask(c pb.LaforgeClient) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request := &pb.TaskRequest{ClientId: clientID}
	r, err := c.GetTask(ctx, request)

	if r.GetCommand() == pb.TaskReply_DEFAULT {
		logger.Error("Recived empty task")
		return
	} else if r.Id == previousTask {
		logger.Error("Recived duplicate Task")
		return
	}

	taskRequest := &pb.TaskStatusRequest{
		TaskId: r.GetId(),
		Status: TaskRunning,
	}
	c.InformTaskStatus(ctx, taskRequest)

	if err != nil {
		logger.Errorf("Error: %v", err)
	} else {
		switch r.GetCommand() {
		case pb.TaskReply_ANSIBLE:
			taskArgs := strings.Split(r.GetArgs(), "💔")
			playbookPath := taskArgs[0]
			connectionMethod := taskArgs[1]
			inventoryList := taskArgs[2]
			taskoutput, taskerr := ExecuteAnsible(playbookPath, connectionMethod, inventoryList)
			taskoutput = strings.ReplaceAll(taskoutput, "\n", "🔥")
			RequestTaskStatusRequest(taskoutput, taskerr, r.Id, c)
		case pb.TaskReply_EXECUTE:
			taskArgs := strings.Split(r.GetArgs(), "💔")
			command := taskArgs[0]
			args := taskArgs[1:]
			taskoutput, taskerr := ExecuteCommand(command, args...)
			taskoutput = strings.ReplaceAll(taskoutput, "\n", "🔥")
			// logger.Infof("Command Output: %s", output)
			RequestTaskStatusRequest(taskoutput, taskerr, r.Id, c)
		case pb.TaskReply_DOWNLOAD:
			taskArgs := strings.Split(r.GetArgs(), "💔")
			filepath := taskArgs[0]
			url := taskArgs[1]
			is_txt := taskArgs[2]
			taskerr := DownloadFile(filepath, url, is_txt)
			RequestTaskStatusRequest("", taskerr, r.Id, c)
		case pb.TaskReply_EXTRACT:
			taskArgs := strings.Split(r.GetArgs(), "💔")
			filepath := taskArgs[0]
			folder := taskArgs[1]
			taskerr := ExtractArchive(filepath, folder)
			RequestTaskStatusRequest("", taskerr, r.Id, c)
		case pb.TaskReply_DELETE:
			taskerr := DeleteObject(r.GetArgs())
			RequestTaskStatusRequest("", taskerr, r.Id, c)
		case pb.TaskReply_REBOOT:
			// taskRequest := &pb.TaskStatusRequest{TaskId: r.Id, Status: TaskSucceeded}
			// c.InformTaskStatus(ctx, taskRequest)
			// Reboot after telling server task succeeded
			RequestTaskStatusRequest("", nil, r.Id, c)
			Reboot()
		case pb.TaskReply_CREATEUSER:
			taskArgs := strings.Split(r.GetArgs(), "💔")
			username := taskArgs[0]
			password := taskArgs[1]
			taskerr := CreateUser(username, password)
			RequestTaskStatusRequest("", taskerr, r.Id, c)
		case pb.TaskReply_ADDTOGROUP:
			taskArgs := strings.Split(r.GetArgs(), "💔")
			group := taskArgs[0]
			username := taskArgs[1]
			taskerr := AddUserGroup(group, username)
			RequestTaskStatusRequest("", taskerr, r.Id, c)
		case pb.TaskReply_CREATEUSERPASS:
			taskArgs := strings.Split(r.GetArgs(), "💔")
			username := taskArgs[0]
			password := taskArgs[1]
			taskerr := ChangeUserPassword(username, password)
			RequestTaskStatusRequest("", taskerr, r.Id, c)
		case pb.TaskReply_VALIDATE:
			taskArgs := strings.Split(r.GetArgs(), "💔")
			filepath := taskArgs[0]
			md5hash := taskArgs[1]
			taskerr := ValidateMD5Hash(filepath, md5hash)
			RequestTaskStatusRequest("", taskerr, r.Id, c)
		case pb.TaskReply_CHANGEPERMS:
			taskArgs := strings.Split(r.GetArgs(), "💔")
			path := taskArgs[0]
			permsString := taskArgs[1]
			perms, taskerr := strconv.Atoi(permsString)
			if taskerr == nil {
				taskerr = ChangePermissions(path, perms)
			}
			RequestTaskStatusRequest("", taskerr, r.Id, c)
		case pb.TaskReply_APPENDFILE:
			taskArgs := strings.Split(r.GetArgs(), "💔")
			path := taskArgs[0]
			content := strings.ReplaceAll(taskArgs[1], "🔥", "\n")
			taskerr := AppendFile(path, content)
			RequestTaskStatusRequest("", taskerr, r.Id, c)
		case pb.TaskReply_VALIDATOR: // new agent command type processing
			taskArgs := strings.Split(r.GetArgs(), "💔")
			validatorName := taskArgs[0]
			switch validatorName {
			case "linux-apt-installed": // checked
				package_name := taskArgs[1]
				installed, err := LinuxAPTInstalled(package_name)
				RequestTaskStatusRequest(strconv.FormatBool(installed), err, r.Id, c)
			case "net-tcp-open": // checked
				ip := taskArgs[1]
				port, err := strconv.Atoi(taskArgs[2])
				if err != nil {
					RequestTaskStatusRequest(strconv.FormatBool(false), err, r.Id, c)
				}
				open, err := NetTCPOpen(ip, port)
				RequestTaskStatusRequest(strconv.FormatBool(open), err, r.Id, c)
			case "net-udp-open": // checked
				ip := taskArgs[1]
				port, err := strconv.Atoi(taskArgs[2])
				if err != nil {
					RequestTaskStatusRequest(strconv.FormatBool(false), err, r.Id, c)
				}
				open, err := NetUDPOpen(ip, port)
				RequestTaskStatusRequest(strconv.FormatBool(open), err, r.Id, c)
			case "net-http-content-regex": // checked
				url := taskArgs[1]
				regex := taskArgs[2]
				matched, err := NetHttpContentRegex(url, regex)
				RequestTaskStatusRequest(strconv.FormatBool(matched), err, r.Id, c)
			case "file-exists": // checked
				filepath := taskArgs[1]
				exists, err := FileExists(filepath)
				RequestTaskStatusRequest(strconv.FormatBool(exists), err, r.Id, c)
			case "file-hash": // checked
				filepath := taskArgs[1]
				hash := taskArgs[2]
				matched, err := FileHash(filepath, hash)
				RequestTaskStatusRequest(strconv.FormatBool(matched), err, r.Id, c)
			case "file-content-regex": // checked
				filepath := taskArgs[1]
				regex := taskArgs[2]
				matched, err := FileContentRegex(filepath, regex)
				RequestTaskStatusRequest(strconv.FormatBool(matched), err, r.Id, c)
			case "dir-exists": // checked
				dirpath := taskArgs[1]
				exists, err := DirectoryExists(dirpath)
				RequestTaskStatusRequest(strconv.FormatBool(exists), err, r.Id, c)
			case "user-exists": // checked
				username := taskArgs[1]
				exists, err := UserExists(username)
				RequestTaskStatusRequest(strconv.FormatBool(exists), err, r.Id, c)
			case "user-group-membership": // checked
				username := taskArgs[1]
				groupname := taskArgs[2]
				ismember, err := UserGroupMember(username, groupname)
				RequestTaskStatusRequest(strconv.FormatBool(ismember), err, r.Id, c)
			case "host-port-open": // checked
				port, err := strconv.Atoi(taskArgs[1])
				if err != nil {
					RequestTaskStatusRequest("false", err, r.Id, c)
				}
				open, err := HostPortOpen(port)
				RequestTaskStatusRequest(strconv.FormatBool(open), err, r.Id, c)
			case "host-process-running": // checked
				processname := taskArgs[1]
				running, err := HostProcessRunning(processname)
				RequestTaskStatusRequest(strconv.FormatBool(running), err, r.Id, c)
			case "host-service-state": // checked
				servicename := taskArgs[1]
				servicestatus := taskArgs[2]
				status, err := HostServiceState(servicename, servicestatus)
				RequestTaskStatusRequest(strconv.FormatBool(status), err, r.Id, c)
			case "net-icmp": // checked
				ip := taskArgs[1]
				replied, err := NetICMP(ip)
				RequestTaskStatusRequest(strconv.FormatBool(replied), err, r.Id, c)
			case "file-content-string": // checked
				filepath := taskArgs[1]
				searchstring := taskArgs[2]
				exists, err := FileContentString(filepath, searchstring)
				RequestTaskStatusRequest(strconv.FormatBool(exists), err, r.Id, c)
			case "file-permission": // checked
				filepath := taskArgs[1]
				file_permissions := taskArgs[2]
				matched, err := FilePermission(filepath, file_permissions)
				RequestTaskStatusRequest(strconv.FormatBool(matched), err, r.Id, c)
			default:
				logger.Warningf("Could not run unhandled validation: %v", validatorName)
			}
		default:
			logger.Infof("Response Message: %v", r)
			RequestTaskStatusRequest("", nil, r.Id, c)
		}

		previousTask = r.Id
	}
}

// RequestTaskStatusRequest Tell the server the status of a completed task
func RequestTaskStatusRequest(taskoutput string, taskerr error, taskID string, c pb.LaforgeClient) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if taskerr != nil {
		logger.Errorf("Error: %v", taskerr)
		taskRequest := &pb.TaskStatusRequest{TaskId: taskID, Status: TaskFailed, ErrorMessage: taskerr.Error(), Output: taskoutput}
		c.InformTaskStatus(ctx, taskRequest)
	} else {
		taskRequest := &pb.TaskStatusRequest{TaskId: taskID, Status: TaskSucceeded, ErrorMessage: "", Output: taskoutput}
		c.InformTaskStatus(ctx, taskRequest)
	}
}

// SendHeartBeat Send the GRPC server a Heartbeat with specified parameters
func SendHeartBeat(c pb.LaforgeClient, taskChannel chan *pb.HeartbeatReply) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := &pb.HeartbeatRequest{ClientId: clientID}
	hostInfo, hostErr := host.Info()
	if hostErr == nil {
		(*request).Hostname = hostInfo.Hostname
		(*request).Uptime = hostInfo.Uptime
		(*request).Boottime = hostInfo.BootTime
		(*request).Numprocs = hostInfo.Procs
		(*request).Os = hostInfo.OS
		(*request).Hostid = hostInfo.HostID
	}
	mem, memErr := mem.VirtualMemory()
	if memErr == nil {
		(*request).Totalmem = mem.Total
		(*request).Freemem = mem.Free
		(*request).Usedmem = mem.Used
	}
	load, loadErr := load.Avg()
	if loadErr == nil {
		(*request).Load1 = load.Load1
		(*request).Load5 = load.Load5
		(*request).Load15 = load.Load15
	}
	(*request).Timestamp = timestamppb.Now()
	r, err := c.GetHeartBeat(ctx, request)
	if err != nil {
		logger.Errorf("Error: %v", err)
	} else {
		taskChannel <- r
	}

}

// StartTaskRunner Gets a Heartbeat reply from the task channel, and if there are avalible tasks it will request them
func StartTaskRunner(c pb.LaforgeClient, taskChannel chan *pb.HeartbeatReply, doneChannel chan bool) {
	r := <-taskChannel
	// logger.Infof("Response Message: %s", r.GetStatus())
	// logger.Infof("Avalible Tasks: %s", r.GetAvalibleTasks())

	if r.GetAvalibleTasks() {
		RequestTask(c)
	}

	doneChannel <- true
}

// genSendHeartBeat A goroutine that is called, which periodically send a heartbeat to the GRPC Server
func genSendHeartBeat(p *program, c pb.LaforgeClient, taskChannel chan *pb.HeartbeatReply) chan bool {
	// func genSendHeartBeat(p *program, c pb.LaforgeClient, taskChannel chan *pb.HeartbeatReply, wg *sync.WaitGroup) chan bool {
	ticker := time.NewTicker(time.Duration(heartbeatSeconds) * time.Second)
	stop := make(chan bool, 1)

	go func() {
		defer logger.Info("ticker stopped")
		for {
			select {
			case <-ticker.C:
				go SendHeartBeat(c, taskChannel)
			case <-p.exit:
				stop <- true
				return
			}
		}
	}()

	return stop
	// defer wg.Done()
	// for {
	// 	select {
	// 	case <-ticker.C:
	// 		SendHeartBeat(c, taskChannel)
	// 	case <-p.exit:
	// 		ticker.Stop()
	// 	}
	// }
}

// genStartTaskRunner A goroutine that is called, which checks responses from GRPC server for avalible tasks
func genStartTaskRunner(p *program, c pb.LaforgeClient, taskChannel chan *pb.HeartbeatReply) chan bool {
	// func genStartTaskRunner(p *program, c pb.LaforgeClient, taskChannel chan *pb.HeartbeatReply, wg *sync.WaitGroup) {
	ticker := time.NewTicker(time.Duration(heartbeatSeconds) * time.Second)
	stop := make(chan bool, 1)

	go func() {
		defer logger.Info("ticker stopped")
		taskIsDone := make(chan bool, 1)
		// Kick off first task grab
		taskIsDone <- true
		for {
			select {
			case <-ticker.C:
				select {
				case <-taskIsDone:
					go StartTaskRunner(c, taskChannel, taskIsDone)
				default:
					logger.Info("Task in progress")
				}
			case <-p.exit:
				stop <- true
				return
			}
		}
	}()

	return stop
}

// run Function that is called when the program starts and run all the Go Routines
func (p *program) run() error {
	logger.Infof("I'm running %v.", service.Platform())
	// var wg sync.WaitGroup

	// TLS Cert for verifying GRPC Server
	certPem, certerr := static.ReadFile(certFile)
	if certerr != nil {
		fmt.Println("File reading error", certerr)
		return nil
	}

	// Starts GRPC Connection with cert included in the binary
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPem)
	creds := credentials.NewClientTLSFromCert(certPool, "")
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))

	if err != nil {
		logger.Errorf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewLaforgeClient(conn)

	// START VARS
	taskChannel := make(chan *pb.HeartbeatReply)
	// wg.Add(2)
	heartbeatDone := genSendHeartBeat(p, c, taskChannel)
	taskRunnerDone := genStartTaskRunner(p, c, taskChannel)

	<-heartbeatDone
	<-taskRunnerDone
	// wg.Wait()
	return nil
}

// Stop Called when the Agent is closed
func (p *program) Stop(s service.Service) error {
	// Any work in Stop should be quick, usually a few seconds at most.
	logger.Error("I'm Stopping!")
	close(p.exit)
	return nil
}

// Service setup.
//
//	Define service config.
//	Create the service.
//	Setup the logger.
//	Handle service controls (optional).
//	Run the service.
func main() {
	svcFlag := flag.String("service", "", "Control the system service.")
	flag.Parse()

	options := make(service.KeyValue)
	options["Restart"] = "always"
	// options["SuccessExitStatus"] = "1 2 8 SIGKILL"
	svcConfig := &service.Config{
		Name:         "laforge-agent",
		DisplayName:  "Laforge Agent",
		Description:  "Tool used for monitoring hosts. NOT IN COMPETITION SCOPE",
		Dependencies: GetSystemDependencies(),
		Option:       options,
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		logger.Error(err)
	}
	errs := make(chan error, 5)
	logger, err = s.Logger(errs)
	if err != nil {
		logger.Error(err)
	}

	go func() {
		for {
			err := <-errs
			if err != nil {
				logger.Error(err)
			}
		}
	}()

	if len(*svcFlag) != 0 {
		err := service.Control(s, *svcFlag)
		if err != nil {
			logger.Infof("Valid actions: %q\n", service.ControlAction)
			logger.Error(err)
		}
		return
	}
	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}

// Validation functions

func NetHttpContentRegex(url string, pattern string) (bool, error) { // content hash (string)
	resp, err := http.Get(url)
	if err != nil {
		return false, fmt.Errorf("filaure to request url: \"%s\"; encountered error: \"%s\"", url, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("filaure to parse request body: \"%s\"; encountered error: \"%s\"", url, err)
	}

	matched, err := regexp.MatchString(pattern, string(body))
	if err != nil {
		return false, fmt.Errorf("failure to parse pattern: \"%s\"; encountered error: \"%s\"", pattern, err)
	}

	if matched {
		return true, nil
	} else {
		return false, fmt.Errorf("no pattern match found of \"%s\" on \"%s\"", pattern, url)
	}
}

func FileExists(file_location string) (bool, error) { // exists (boolean)
	stat_info, read_err := os.Stat(file_location)
	if read_err != nil {
		return false, read_err
	}
	return !stat_info.IsDir(), nil
}

func FileHash(file_location string, expected_hash string) (bool, error) { // hash of the file (string)
	content, err := ioutil.ReadFile(file_location)
	if err != nil {
		return false, fmt.Errorf("failure to open file: \"%s\"; encountered error: %s", file_location, err)
	}

	hash := sha256.New()
	_, err = hash.Write(content)
	if err != nil {
		return false, fmt.Errorf("failure to compute hash; encountered error: %s", err)
	}

	calculated_hash := hex.EncodeToString(hash.Sum(nil))

	if calculated_hash == expected_hash {
		return true, nil
	} else {
		return false, fmt.Errorf("hash of \"%s\" does not match; calculated: \"%s\", expected: \"%s\"", file_location, calculated_hash, expected_hash)
	}
}

func FileContentRegex(file_location string, pattern string) (bool, error) { // page content to be returned and checked serverside (string)
	content, err := ioutil.ReadFile(file_location)
	if err != nil {
		return false, fmt.Errorf("failure to read file \"%s\"; encountered error %s", file_location, err)
	}

	matched, err := regexp.MatchString(pattern, string(content))
	if err != nil {
		return false, fmt.Errorf("failure to parse pattern: \"%s\"; encountered error: \"%s\"", pattern, err)
	}

	if matched {
		return true, nil
	} else {
		return false, fmt.Errorf("no pattern match found of \"%s\" in \"%s\"", pattern, file_location)
	}
}

func DirectoryExists(path string) (bool, error) { // exists (boolean)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, fmt.Errorf("directory \"%s\" does not exist; encountered error: \"%s\"", path, err)
		}
		return false, fmt.Errorf("failure to check if directory \"%s\" exists: encountered error: \"%s\"", path, err)
	}
	if info.IsDir() {
		return true, nil
	} else {
		return false, fmt.Errorf("failure to detect directory: \"%s\" is not a directory", path)
	}
}

func UserExists(user_name string) (bool, error) { // exists (boolean)
	_, err := user.Lookup(user_name)
	if err != nil {
		return false, fmt.Errorf("failure to detect user \"%s\"; encountered error \"%s\"", user_name, err)
	}
	return true, nil
}

func UserGroupMember(user_name string, group_name string) (bool, error) { // is in the group or not (boolean)
	usr, err := user.Lookup(user_name)
	if err != nil {
		return false, fmt.Errorf("failure to detect user \"%s\"; encountered error: \"%s\"", user_name, err)
	}

	group, err := user.LookupGroup(group_name)
	if err != nil {
		return false, fmt.Errorf("failure to detect group \"%s\"; encountered error: \"%s\"", group_name, err)
	}

	groups, err := usr.GroupIds()
	if err != nil {
		return false, fmt.Errorf("failure to retrieve groups of user \"%s\"; encountered error: \"%s\"", user_name, err)
	}

	for _, groupID := range groups {
		if groupID == group.Gid {
			return true, nil
		}
	}

	return false, fmt.Errorf("failure to detect user \"%s\" in group \"%s\"", user_name, group_name)
}

func NetTCPOpen(ip string, port int) (bool, error) { // exists (boolean)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		return false, fmt.Errorf("failure to establish TCP connection to \"%s:%d\"; encountered error: \"%s\" ", ip, port, err)
	}
	defer conn.Close()

	if conn != nil {
		return true, nil
	} else {
		return false, fmt.Errorf("failure to establish TCP connection to \"%s:%d\"", ip, port)
	}
}

func NetUDPOpen(ip string, port int) (bool, error) { // exists (boolean)
	timeout := time.Second * 10

	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// Since UDP is connectionless, we need to send a simple message to check if the port is open.
	_, err = conn.Write([]byte("ping"))
	if err != nil {
		return false, fmt.Errorf("failure to establish UDP connection to \"%s:%d\"; encountered error: \"%s\" ", ip, port, err)
	}

	// Set a read deadline to avoid waiting indefinitely for a response.
	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Read timed out, so the port is likely open but not responding.
			return true, nil
		}
		return false, fmt.Errorf("failure to establish UDP connection to \"%s:%d\"; encountered error: \"%s\" ", ip, port, err)
	}

	// If we received a response, the port is open.
	return true, nil
}

func NetICMP(ip string) (bool, error) { // responded (boolean)
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", ip)
	}

	err := cmd.Run()
	if err != nil {
		return false, fmt.Errorf("failure to ping ip \"%s\"; encountered error: \"%s\"", ip, err)
	}

	return true, nil
}

func FileContentString(filepath string, text string) (bool, error) { // matches
	file, err := os.Open(filepath)
	if err != nil {
		return false, fmt.Errorf("failure to open file \"%s\"; encountered error: \"%s\"", filepath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), text) {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failure to read file \"%s\"; encountered error: \"%s\"", filepath, err)
	}

	return false, fmt.Errorf("failure to detect string \"%s\" in file \"%s\"", text, filepath)
}

func FilePermission(filepath string, permissions string) (bool, error) {
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return false, fmt.Errorf("failure retrieving file \"%s\"; encountered error: \"%s\"", filepath, err)
	}

	filePermissions := fileInfo.Mode().Perm().String()
	if filePermissions == permissions {
		return true, nil
	} else {
		return false, fmt.Errorf("failuring matching permission of file \"%s\"; expected: \"%s\", detected: \"%s\"", filepath, permissions, filePermissions)
	}
}

func HostPortOpen(port int) (bool, error) {
	addr := net.JoinHostPort("localhost", strconv.Itoa(port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return false, fmt.Errorf("failure detecting if port \"%d\" is open; encountered error: \"%s\"", port, err)
	}
	defer listener.Close()

	return true, nil
}
