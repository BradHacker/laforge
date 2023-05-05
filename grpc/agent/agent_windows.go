//go:build windows
// +build windows

package main

import (
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
	"regexp"

	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	wapi "github.com/iamacarpet/go-win64api"
)

// RebootSystem Reboots Host Operating System
func RebootSystem() {
	// This is how to properlly rebot windows
	user32 := syscall.MustLoadDLL("user32")
	defer user32.Release()

	exitwin := user32.MustFindProc("ExitWindowsEx")

	r1, _, _ := exitwin.Call(0x02, 0)
	if r1 != 1 {
		SystemExecuteCommand("cmd", "/C", "shutdown", "/r", "/f")
	}

	time.Sleep(1 * time.Hour) // sleep forever bc we need to restart
}

// CreateSystemUser Creates User with specified password.
func CreateSystemUser(username string, password string) error {
	_, err := wapi.UserAdd(username, username, password)
	return err
}

// ChangeSystemUserPassword Change user password.
func ChangeSystemUserPassword(username string, password string) error {
	_, err := wapi.ChangePassword(username, password)
	return err
}

// AddSystemUserGroup Add user to group.
func AddSystemUserGroup(groupname string, username string) error {
	_, err := wapi.LocalGroupAddMembers(groupname, []string{username})
	return err
}

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

	if is_txt == "true" {
		// Convert Unix line endings to windows line endings
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		body := strings.Replace(string(bodyBytes), "\n", "\r\n", -1)

		// Write the body to file
		_, err = io.WriteString(out, body)
	} else {
		// Write the body to file
		_, err = io.Copy(out, resp.Body)
	}

	return err
}

// SystemExecuteAnsible Runs Ansible Playbook
func SystemExecuteAnsible(playbookPath, connectionMethod, inventoryList string) (string, error) {
	return "", fmt.Errorf("Not Implemented for Windows")
}

// SystemExecuteCommand Runs the Command that is inputted and either returns the error or output
func SystemExecuteCommand(command string, args ...string) (string, error) {
	var err error
	_, err = os.Stat(command)
	output := ""
	if err == nil {
		// Make sure we have rwx permissions if it's a script
		err = os.Chmod(command, 0700)
		if err != nil {
			return output, err
		}
	}
	// Execute the command
	arguments := []string{}
	arguments = append(arguments, command)
	arguments = append(arguments, args...)
	cmd := exec.Command("powershell.exe", arguments...)
	out, err := cmd.CombinedOutput()

	return string(out), err
}

func GetSystemDependencies() []string {
	return []string{}
}

// Validation Functions

func HostProcessRunning(process_name string) (bool, error) { // running (boolean)
	cmd := exec.Command("tasklist", "/NH", "/FO", "CSV", "/FI", "IMAGENAME eq "+processName)
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("failure detecting if process \"%s\" is running; encountered error: \"%s\"", process_name, err)
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" || strings.Contains(outputStr, "No tasks are running") {
		return false, fmt.Errorf("failure process \"%s\" is not running", process_name)
	}

	return true, nil
}

func HostServiceState(service_name string, service_status string) (bool, error) {
	return false, fmt.Errorf("failure: this validation is not available for Windows")
}

func LinuxAPTInstalled(package_name string) (bool, error) {
	return false, fmt.Errorf("failure: this validation is not available for Windows")
}

func LinuxYumInstalled(package_name string) (bool, error) {
	return false, fmt.Errorf("failure: this validation is not available for Windows")
}
