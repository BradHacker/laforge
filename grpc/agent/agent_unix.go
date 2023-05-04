//go:build unix || linux
// +build unix linux

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/apenella/go-ansible/pkg/execute"
	"github.com/apenella/go-ansible/pkg/options"
	"github.com/apenella/go-ansible/pkg/playbook"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func MD5Sum(content string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(content)))
}

// RebootSystem Reboots Host Operating System
func RebootSystem() {
	syscall.Sync()
	syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)

	time.Sleep(1 * time.Hour) // sleep forever bc we need to restart
}

// CreateSystemUser Create a new User
func CreateSystemUser(username string, password string) error {
	_, err := user.Lookup(username)
	if err != nil {
		// ExecuteCommand("useradd", username)
		ChangeSystemUserPassword(username, password)
	}
	return nil
}

// ChangeSystemUserPassword Change user password.
func ChangeSystemUserPassword(username string, password string) error {
	cmd := exec.Command("passwd", username)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		// logger.Error(err)
	}
	defer stdin.Close()

	passnew := fmt.Sprintf("%s\n%s\n", password, password)

	io.WriteString(stdin, passnew)

	if err = cmd.Start(); err != nil {
		// logger.Errorf("An error occured: ", err)
	}

	cmd.Wait()

	return nil
}

// AddSystemUserGroup Change user password.
func AddSystemUserGroup(groupname string, username string) error {
	// ExecuteCommand("usermod", "-a", "-G", groupname, username)
	return nil
}

// SystemDownloadFile Download a file with OS specific file endings
func SystemDownloadFile(path, url, is_txt string) error {
	retryCount := 5
	var resp *http.Response
	var err error
	for i := 0; i < retryCount; i++ {
		// Get the data
		resp, err = http.Get(url)
		if err == nil {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	// Create the file
	out, err := os.Create(absolutePath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// SystemExecuteCommand Runs the Command that is inputted and either returns the error or output
func SystemExecuteCommand(command string, args ...string) (string, error) {
	var err error
	_, err = os.Stat(command)
	// output := ""
	if err == nil {
		// Make sure we have rwx permissions if it's a script
		err = os.Chmod(command, 0700)
		if err != nil {
			return "", err
		}
	}
	// Execute the command
	cmd := exec.Command(command, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// SystemExecuteAnsible Runs Ansible Playbook
func SystemExecuteAnsible(playbookPath, connectionMethod, inventoryList string) (string, error) {

	buff := new(bytes.Buffer)

	ansiblePlaybookConnectionOptions := &options.AnsibleConnectionOptions{
		Connection: connectionMethod,
	}

	ansiblePlaybookOptions := &playbook.AnsiblePlaybookOptions{
		Inventory: inventoryList,
	}

	executePlaybook := execute.NewDefaultExecute(
		execute.WithWrite(io.Writer(buff)),
	)

	playbook := &playbook.AnsiblePlaybookCmd{
		Playbooks:         []string{playbookPath},
		ConnectionOptions: ansiblePlaybookConnectionOptions,
		Options:           ansiblePlaybookOptions,
		Exec:              executePlaybook,
	}

	err := playbook.Run(context.TODO())
	return buff.String(), err
}

func GetSystemDependencies() []string {
	return []string{
		"Requires=network.target",
		"After=network-online.target"}
}

// Validation functions
func GetNetBanner(portnum int64) (bool, error) { // exists (boolean)
	return true, nil
}

func NetHttpContentRegex(full_url string) (string, error) { // content hash (string)
	net_resp, err := http.Get(full_url)
	if err != nil {
		return "", err
	}
	defer net_resp.Body.Close()
	page_html, deserialize_err := ioutil.ReadAll(net_resp.Body)
	if deserialize_err != nil {
		return "", deserialize_err
	}

	// return MD5Sum(fmt.Sprintf("%s", page_html)), nil
	return string(page_html[:]), nil // stringify
}

func FileExists(file_location string) (bool, error) { // exists (boolean)
	stat_info, read_err := os.Stat(file_location)
	if read_err != nil {
		return false, read_err
	}
	return !stat_info.IsDir(), nil
}

func FileHash(file_location string) (string, error) { // hash of the file (string)
	file_read, read_err := os.Open(file_location)
	if read_err != nil {
		return "", read_err
	}
	file_hash := md5.New()
	if _, err := io.Copy(file_hash, file_read); err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%x", file_hash.Sum(nil)), nil
}

func FileContentRegex(file_location string, pattern string) (bool, error) { // page content to be returned and checked serverside (string)
	content, err := ioutil.ReadFile(file_location)
	if err != nil {
		return false, err
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}

	return regex.Match(content), nil
}

func DirectoryExists(directory string) (bool, error) { // exists (boolean)
	stat_info, read_err := os.Stat(directory)
	if read_err != nil {
		return false, read_err
	}
	return stat_info.IsDir(), nil
}

func UserExists(user_name string) (bool, error) { // exists (boolean)
	passwd_contents, read_err := ioutil.ReadFile("/etc/passwd")
	if read_err != nil {
		return false, read_err
	}
	passwd_text := strings.Split(string(passwd_contents), "\n")
	for i := 0; i < len(passwd_text); i++ {
		if strings.HasPrefix(passwd_text[i], user_name) {
			return true, nil
		}
	}
	return false, nil
}

func UserGroupMember(user_name string, group_name string) (bool, error) { // is in the group or not (boolean)
	group_contents, read_err := ioutil.ReadFile("/etc/group")
	if read_err != nil {
		return false, read_err
	}
	groups := strings.Split(string(group_contents), "\n")
	for i := 0; i < len(groups); i++ {
		// example groups
		/*
			adm:x:4:piero
			tty:x:5:
			disk:x:6:
			lp:x:7:
			mail:x:8:
			news:x:9:
			uucp:x:10:
			man:x:12:
			proxy:x:13:
			kmem:x:15:
			dialout:x:20:
			fax:x:21:
			voice:x:22:
			cdrom:x:24:piero
		*/
		group_line_chunks := strings.Split(groups[i], ":")
		if group_line_chunks[0] == group_name && len(group_line_chunks) > 3 {
			// first part of /etc/group entry matches and there are users assigned to the group
			users_in_group := strings.Split(group_line_chunks[3], ",")
			for j := 0; j < len(users_in_group); j++ {
				if users_in_group[j] == user_name {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func HostProcessRunning(process_name string) (bool, error) { // running (boolean)
	result := exec.Command("ps", "-a")
	ps_output, err := result.Output()
	if err != nil {
		return false, err
	}
	ps_lines := strings.Split(string(ps_output), "\n")
	for i := 0; i < len(ps_lines); i++ {
		if strings.HasSuffix(ps_lines[i], process_name) {
			return true, nil
		}
	}
	return false, nil
}

// Adapted from https://stackoverflow.com/questions/48263281/how-to-find-sshd-service-status-in-golang
func HostServiceState(service_name string, service_status string) (bool, error) {
	cmd := exec.Command("systemctl", "check", service_name) // ASSUMPTION: the computer uses systemd
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	if string(bytes.TrimSpace(out)) == service_status {
		return true, nil
	}
	return false, fmt.Errorf("service status expected \"%s\" but got \"%s\"", service_status, string(bytes.TrimSpace(out)))
}

func LinuxAPTInstalled(package_name string) (bool, error) { // installed
	result := exec.Command("apt", "-qq", "list", package_name)
	ps_output, err := result.Output()
	if err != nil {
		return false, err
	}
	apt_lines := strings.Split(string(ps_output), "\n")
	for i := 0; i < len(apt_lines); i++ {
		if strings.HasPrefix(apt_lines[i], package_name) && (strings.HasSuffix(apt_lines[i], "[installed]") || strings.HasSuffix(apt_lines[i], "[installed,local]") || strings.HasSuffix(apt_lines[i], "[installed,automatic]")) {
			return true, nil
		}
	}
	return false, nil
}

func LinuxYumInstalled(package_name string) (bool, error) { // installed
	result := exec.Command("yum", "list", "--installed")
	ps_output, err := result.Output()
	if err != nil {
		return false, err
	}
	apt_lines := strings.Split(string(ps_output), "\n")
	for i := 0; i < len(apt_lines); i++ {
		if strings.HasPrefix(apt_lines[i], package_name) {
			return true, nil
		}
	}
	return false, nil
}

func NetTCPOpen(ip string, port int) (bool, error) { // exists (boolean)
	// net.Dial or net.DialTimeout will succeed if the following succeeds:
	/*
	   Client -> Server: SYN
	   Server -> Client: SYN-ACK
	   Client -> Server: ACK
	*/
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 10*time.Second)
	if err != nil && !strings.HasSuffix(err.Error(), "connection refused") {
		return false, err
	}
	if conn != nil {
		defer conn.Close() // no hanging processes
		return true, nil
	} else {
		return false, nil
	}
}

func NetUDPOpen(ip string, port int, open_socket_payload string) (bool, error) { // exists (boolean)
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, strconv.Itoa(port)), 10*time.Second)
	// we don't really know if a udp connection is alive or not, so
	if err != nil {
		return false, err
	}
	recv_chan := make(chan bool)
	go UDPOpenTest(conn, recv_chan, open_socket_payload)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	select {
	case <-recv_chan:
		return true, nil
	case <-time.After(10 * time.Second):
		return false, nil
	case <-ctx.Done():
		return false, nil
	}
}

func UDPOpenTest(socket net.Conn, return_chan chan bool, optional_payload string) {
	socket.Write([]byte(optional_payload))
	socket.Read([]byte(""))
	return_chan <- true
}

func NetICMP(ip string) (bool, error) { // responded (boolean)
	// // This WILL block the thread! However, agent tasks are on their own threads.
	// result := exec.Command("ping", "-c", "5", ip) // you can write a ping packet and send it using pure golang, however it's quite complicated and requires more importing of libraries
	// ps_output, err := result.Output()
	// if err != nil {
	// 	return false, err
	// }
	// ps_lines := strings.Split(string(ps_output), "\n")
	// for i := 0; i < len(ps_lines); i++ {
	// 	if strings.HasPrefix(ps_lines[i], "5 packets transmitted, 5 received") { // this is pretty jank
	// 		return true, nil
	// 	}
	// }
	// return false, nil
	icmp_conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer icmp_conn.Close()
	raw_icmp_packet := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(""),
		},
	}
	_, err = raw_icmp_packet.Marshal(nil)
	if err != nil {
		return false, err
	}
	echo := make([]byte, 1500)
	err = icmp_conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return false, err
	}
	pkt, _, err := icmp_conn.ReadFrom(echo)
	if pkt != 0 {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

func FileContentString(filepath string, text string) (bool, error) { // matches
	file_contents, read_err := ioutil.ReadFile(filepath)
	if read_err != nil {
		return false, read_err
	}
	lines := strings.Split(string(file_contents), "\n")
	for i := 0; i < len(lines); i++ {
		if strings.Contains(lines[i], text) {
			return true, nil
		}
	}
	return false, nil
}

// https://stackoverflow.com/questions/45429210/how-do-i-check-a-files-permissions-in-linux-using-go
func FilePermission(filepath string) (string, error) { // permissions (in the form of SRWXRWXRWX, where S is setuid bit)
	info, err := os.Stat(filepath)
	if err != nil {
		return "", err
	}
	return info.Mode().String(), nil
}

func HostPortOpen(port int) (bool, error) {
	result := exec.Command("netstat", "-na")
	ps_output, err := result.Output()
	if err != nil {
		return false, err
	}
	ps_lines := strings.Split(string(ps_output), "\n")
	for i := 0; i < len(ps_lines); i++ {
		if strings.Contains(ps_lines[i], " localhost:"+strconv.Itoa(port)+" ") || strings.Contains(ps_lines[i], " 0.0.0.0:"+strconv.Itoa(port)+" ") || strings.Contains(ps_lines[i], " 127.0.0.1:"+strconv.Itoa(port)+" ") {
			return true, nil
		}
	}
	return false, nil
}

func HostFirewallPort(port int) (bool, error) {
	result := exec.Command("iptables", "-L", "-n")
	ps_output, err := result.Output()
	if err != nil {
		return false, err
	}
	ps_lines := strings.Split(string(ps_output), "\n")
	for i := 0; i < len(ps_lines); i++ {
		if strings.Contains(ps_lines[i], "dpt:"+strconv.Itoa(port)) {
			return true, nil
		}
	}
	return false, nil
}
