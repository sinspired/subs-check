//go:build darwin
// +build darwin

package assets

import (
    "os/exec"
    "syscall"
)

func setSysProcAttr(cmd *exec.Cmd) {
    cmd.SysProcAttr = &syscall.SysProcAttr{
        Setpgid: true,
    }
}
