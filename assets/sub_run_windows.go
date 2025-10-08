//go:build windows
// +build windows

package assets

import (
    "os/exec"
    "syscall"
)

func setSysProcAttr(cmd *exec.Cmd) {
    cmd.SysProcAttr = &syscall.SysProcAttr{
        CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
    }
}
