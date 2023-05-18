//go:build unix || linux
// +build unix linux

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/apenella/go-ansible/pkg/execute"
	"github.com/apenella/go-ansible/pkg/options"
	"github.com/apenella/go-ansible/pkg/playbook"
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

func HostProcessRunning(process_name string) (bool, error) {
	cmd := exec.Command("pgrep", "-f", process_name)
	output, err := cmd.Output()

	if err != nil {
		return false, fmt.Errorf("failure detecting if process \"%s\" is running; encountered error: \"%s\"", process_name, err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) > 0 {
		return true, nil
	}

	return false, fmt.Errorf("failure process \"%s\" is not running", process_name)
}

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

func LinuxAPTInstalled(package_name string) (bool, error) {
	cmd := exec.Command("apt", "policy", package_name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(err)
		if exitError, ok := err.(*exec.ExitError); ok {
			// The command returned a non-zero status, which might mean the package is not installed.
			if exitError.ExitCode() == 1 {
				return false, fmt.Errorf("APT package \"%s\" is not installed; encountered an error: \"%s\"", package_name, err)
			}
		}
		return false, err
	}

	// Check if the package status contains "Unable to locate package".
	if strings.Contains(string(output), "Unable to locate package") {
		return false, fmt.Errorf("APT package \"%s\" is not installed", package_name)
	}

	return true, nil
}

func LinuxYumInstalled(package_name string) (bool, error) {
	cmd := exec.Command("yum", "list", "installed", package_name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			// The command returned a non-zero status, which might mean the package is not installed.
			if exitError.ExitCode() == 1 {
				return false, fmt.Errorf("yum package \"%s\" is not installed; encounter an error: %s", package_name, err)
			}
		}
		return false, err
	}

	// Check if the package is listed in the output.
	if strings.Contains(string(output), package_name) {
		return true, nil
	} else {
		return false, fmt.Errorf("yum package \"%s\" is not installed", package_name)
	}
}

func HostPortOpen(port int) (bool, error) {
	cmd := exec.Command("lsof", "-i", fmt.Sprintf(":%d", port))
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("failure to list open ports; encountered error: \"%s\"", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) > 1 {
		return true, nil
	}

	return false, fmt.Errorf("failure to detect port \"%d\" being open", port)
}
