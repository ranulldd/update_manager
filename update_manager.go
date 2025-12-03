package update_manager

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

type updateManagr struct {
	publicKey crypto.PublicKey
	aesKey    []byte
	verifier  Verifier
	hosts     []string
	mutex     sync.RWMutex

	logger *log.Logger
}

type structVersion struct {
	Major int
	Minor int
	Patch int
}

func formatVersion(version string) structVersion {
	version = strings.TrimSpace(version)
	arr := strings.Split(version, ".")
	if len(arr) != 3 {
		return structVersion{0, 0, 0}
	}

	verMajor, err := strconv.Atoi(arr[0])
	if err != nil {
		return structVersion{0, 0, 0}
	}
	verMinor, err := strconv.Atoi(arr[1])
	if err != nil {
		return structVersion{0, 0, 0}
	}
	verPatch, err := strconv.Atoi(arr[2])
	if err != nil {
		return structVersion{0, 0, 0}
	}

	return structVersion{verMajor, verMinor, verPatch}
}

func NewUpdateManager(aeskey []byte, logger *log.Logger) *updateManagr {
	return &updateManagr{
		publicKey: ed25519.PublicKey{33, 205, 244, 215, 215, 31, 28, 203, 59, 249, 116, 219, 21, 42, 227, 2, 147, 46, 39, 118, 144, 74, 101, 110, 175, 40, 20, 92, 63, 19, 5, 164},
		aesKey:    aeskey,
		verifier:  NewECDSAVerifier(),
		hosts:     []string{},
		mutex:     sync.RWMutex{},
		logger:    logger,
	}
}

func compareVersion(v1, v2 string) int {
	ver1 := formatVersion(v1)
	ver2 := formatVersion(v2)

	if ver1.Major > ver2.Major {
		return 1
	} else if ver1.Major < ver2.Major {
		return -1
	}

	if ver1.Minor > ver2.Minor {
		return 1
	} else if ver1.Minor < ver2.Minor {
		return -1
	}

	if ver1.Patch > ver2.Patch {
		return 1
	} else if ver1.Patch < ver2.Patch {
		return -1
	}
	return 0
}

func (manager *updateManagr) needUpdate(host, modName, curVersion string) (bool, string) {
	versions := manager.getRemoteVersions(host, modName)

	for version := range strings.SplitSeq(versions, "\n") {
		version = strings.TrimSpace(version)
		if compareVersion(version, curVersion) > 0 {
			return true, version
		}
	}

	return false, curVersion
}

func (manager *updateManagr) getRemoteVersions(host string, modName string) string {
	url := "https://" + host + "/update/" + runtime.GOOS + "-" + runtime.GOARCH + "-" + modName + ".package_version"
	resp, err := http.Get(url)
	if err != nil {
		// manager.logger.Print("get NewVersion err:", err)
		return "0.0.0"
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// manager.logger.Printf("get NewVersion code: %v, url: %v", resp.StatusCode, url)
		return "0.0.0"
	}

	data, _ := io.ReadAll(resp.Body)

	return string(data)
}

func (manager *updateManagr) decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (manager *updateManagr) unzip(content []byte, prefix, version string) ([]byte, []byte, error) {
	archive, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, nil, err
	}

	data := []byte{}
	signature := []byte{}

	for _, f := range archive.File {
		if f.FileInfo().IsDir() {
			continue
		}

		switch f.Name {
		case prefix + "-" + version:
			rd, err := f.Open()
			if err != nil {
				return nil, nil, err
			}
			data, _ = io.ReadAll(rd)
			rd.Close()
		case prefix + "-" + version + ".ed25519":
			rd, err := f.Open()
			if err != nil {
				return nil, nil, err
			}
			signature, _ = io.ReadAll(rd)
			rd.Close()
		}
	}

	if len(signature) != 64 {
		return nil, nil, errors.New("bad signature file")
	}

	if len(data) == 0 {
		return nil, nil, errors.New("bad zip file")
	}

	return data, signature, nil
}

func (manager *updateManagr) fetchPackage(host, modName, version string) ([]byte, error) {
	url := "https://" + host + "/update/" + runtime.GOOS + "-" + runtime.GOARCH + "-" + modName + "-" + version + ".update_package"

	manager.logger.Print("fetching data:", url)

	resp, err := http.Get(url)
	if err != nil {
		manager.logger.Print("fetch data err:", err)
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		manager.logger.Print("read data err:", err)
		return nil, err
	}

	return data, nil
}

func checksumFor(h crypto.Hash, payload []byte) ([]byte, error) {
	if !h.Available() {
		return nil, errors.New("requested hash function not available")
	}
	hash := h.New()
	hash.Write(payload) // guaranteed not to error
	return hash.Sum([]byte{}), nil
}

func (manager *updateManagr) verifySignature(data []byte, signature []byte) error {
	if publicKey, ok := manager.publicKey.(ed25519.PublicKey); ok {
		valid := ed25519.Verify(publicKey, data, signature)
		if !valid {
			return errors.New("invalid ed25519 signature")
		}
		return nil
	}
	checksum, err := checksumFor(crypto.SHA256, data)
	if err != nil {
		return err
	}
	return manager.verifier.VerifySignature(checksum, signature, crypto.SHA256, manager.publicKey)
}

func (manager *updateManagr) apply(data []byte, exePath string, signature []byte) error {
	const targetMode = 0755

	// get target path
	var err error

	if err = manager.verifySignature(data, signature); err != nil {
		return err
	}

	// get the directory the executable exists in
	updateDir := filepath.Dir(exePath)
	filename := filepath.Base(exePath)

	// Copy the contents of the new binary to a new executable file
	newPath := filepath.Join(updateDir, fmt.Sprintf(".%s.new", filename))
	fp, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, targetMode)
	if err != nil {
		return err
	}
	os.Chmod(newPath, targetMode)
	defer fp.Close()

	_, err = io.Copy(fp, bytes.NewReader(data))
	if err != nil {
		return err
	}
	// if we don't call fp.Sync(), a system power off could lose the file
	fp.Sync()
	// if we don't call fp.Close(), windows won't let us move the new executable
	// because the file will still be "in use"
	fp.Close()

	// this is where we'll move the executable to so that we can swap in the updated replacement
	oldPath := filepath.Join(updateDir, fmt.Sprintf(".%s.old", filename))

	// delete any existing old exec file - this is necessary on Windows for two reasons:
	// 1. after a successful update, Windows can't remove the .old file because the process is still running
	// 2. windows rename operations fail if the destination file already exists
	_ = os.Remove(oldPath)

	// move the existing executable to a new file in the same directory
	err = os.Rename(exePath, oldPath)
	if err != nil {
		return err
	}

	// move the new executable in to become the new program
	err = os.Rename(newPath, exePath)

	if err != nil {
		// move unsuccessful
		//
		// The filesystem is now in a bad state. We have successfully
		// moved the existing binary to a new location, but we couldn't move the new
		// binary to take its place. That means there is no file where the current executable binary
		// used to be!
		// Try to rollback by restoring the old binary to its original path.
		err := os.Rename(oldPath, exePath)

		return err
	}

	// move successful, remove the old binary if needed
	errRemove := os.Remove(oldPath)

	// windows has trouble with removing old binaries, so hide it instead
	if errRemove != nil {
		_ = hideFile(oldPath)
	}

	return nil
}

func (manager *updateManagr) doUpdate(data []byte, exePath, prefix, version string) error {
	manager.logger.Print("decripting data")
	data, err := manager.decrypt(data, manager.aesKey)
	if err != nil {
		manager.logger.Print("decrypt err:", err)
		return err
	}

	manager.logger.Print("unzipping data")
	data, signature, err := manager.unzip(data, prefix, version)
	if err != nil {
		manager.logger.Print("unzip err:", err)
		return err
	}

	manager.logger.Print("applying update")
	manager.apply(data, exePath, signature)

	return err
}

func (manager *updateManagr) Run(host string, curVersion string, interval time.Duration) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if slices.Contains(manager.hosts, host) {
		return
	}

	manager.hosts = append(manager.hosts, host)
	if len(manager.hosts) != 1 {
		return
	}

	curVersion = strings.TrimSpace(curVersion)
	go func() {
		exePath, _ := os.Executable()
		filename := filepath.Base(exePath)
		modName := strings.Split(filename, ".")[0]
		for {
			for _, host := range manager.hosts {
				need, version := manager.needUpdate(host, modName, curVersion)
				if !need {
					continue
				}

				manager.logger.Printf("curVersion: %v, newVersion: %v, updating", curVersion, version)
				data, err := manager.fetchPackage(host, modName, version)
				if err != nil {
					continue
				}

				prefix := runtime.GOOS + "-" + runtime.GOARCH + "-" + modName
				err = manager.doUpdate(data, exePath, prefix, version)
				if err != nil {
					continue
				}

				manager.logger.Print("restarting")
				err = manager.restart(exePath)
				if err != nil {
					manager.logger.Print("restart err:", err)
				}
			}

			time.Sleep(interval)
		}
	}()
}

func (manager *updateManagr) DoUpdate(data []byte, prefix, version string) error {
	exePath, _ := os.Executable()
	err := manager.doUpdate(data, exePath, prefix, version)
	if err != nil {
		return err
	}

	manager.logger.Print("restarting")
	err = manager.restart(exePath)
	if err != nil {
		manager.logger.Print("restart err:", err)
	}
	return nil
}

func (manager *updateManagr) VerifyPackage(encPackage []byte, prefix, version string) error {
	manager.logger.Print("decripting data")
	data, err := manager.decrypt(encPackage, manager.aesKey)
	if err != nil {
		manager.logger.Print("decrypt err:", err)
		return err
	}

	manager.logger.Print("unzipping data")
	data, signature, err := manager.unzip(data, prefix, version)
	if err != nil {
		manager.logger.Print("unzip err:", err)
		return err
	}

	if !manager.verify(data, signature) {
		return errors.New("bad signature")
	}

	return nil
}

func (manager *updateManagr) verify(content []byte, sig []byte) bool {
	if publicKey, ok := manager.publicKey.(ed25519.PublicKey); ok {
		return ed25519.Verify(publicKey, content, sig)
	}

	return false
}

func (manager *updateManagr) WaitforUpdate() {
	ppidStr := os.Getenv("update_manager_ppid")
	if len(ppidStr) == 0 {
		return
	}

	ppid, err := strconv.Atoi(ppidStr)
	if err != nil {
		return
	}

	p, err := process.NewProcess(int32(ppid))
	if err != nil {
		return
	}

	for range 10 {
		if running, err := p.IsRunning(); err != nil || !running {
			return
		}

		time.Sleep(time.Second * 1)
	}
}
