package update_manager

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

func isSystemAccount() bool {
	currentUser, err := user.Current()
	if err != nil {
		return false
	}

	return currentUser.Uid == "S-1-5-18"
}

func (manager *updateManagr) restart(exePath string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	nullFile, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		nullFile = nil
	} else {
		defer nullFile.Close()
	}

	needHide := isSystemAccount()
	for {
		_, err = os.StartProcess(exePath, os.Args, &os.ProcAttr{
			Dir:   wd,
			Env:   append(os.Environ(), "update_manager_ppid="+strconv.Itoa(os.Getpid())),
			Files: []*os.File{nullFile, nullFile, nullFile},
			Sys:   &syscall.SysProcAttr{HideWindow: needHide},
		})

		if err != nil {
			manager.logger.Printf("exePath: %v, args: %v", exePath, os.Args)
			manager.logger.Print("restart err:", err)
			time.Sleep(time.Minute * 60)
			continue
		} else {
			os.Exit(0)
		}
	}

}
