package update_manager

import (
	"os/exec"
	"path/filepath"
	"strings"
)

func (manager *updateManagr) restart(exePath string) error {
	filename := filepath.Base(exePath)
	modName := strings.Split(filename, ".")[0]
	cmd := exec.Command("service", modName, "restart")
	return cmd.Run()
}
