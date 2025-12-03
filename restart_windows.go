package update_manager

import (
	"os"
	"strconv"
	"syscall"
	"time"
)

func (manager *updateManagr) restart(exePath string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	for {
		_, err = os.StartProcess(exePath, os.Args, &os.ProcAttr{
			Dir:   wd,
			Env:   append(os.Environ(), "update_manager_ppid="+strconv.Itoa(os.Getpid())),
			Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
			Sys:   &syscall.SysProcAttr{HideWindow: true},
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
