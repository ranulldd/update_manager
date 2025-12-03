//go:build !windows
// +build !windows

package update_manager

func hideFile(_ string) error {
	return nil
}
