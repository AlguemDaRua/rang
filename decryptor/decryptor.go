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
	targetDir = `C:\teste`
)

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
		uintptr(0x0014), // SPI_SETDESKWALLPAPER
		0,
		uintptr(unsafe.Pointer(pathUTF16)),
		uintptr(0x01|0x02), // SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
	)
}

func removeFromStartup() {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return
	}
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
		fmt.Println(`  
        ⚠️⚠️⚠️ CHAVE INVÁLIDA! ⚠️⚠️⚠️  
        SEUS ARQUIVOS SERÃO DELETADOS EM 10 SEGUNDOS!  
        `)
		fmt.Print("\033[0m")
		time.Sleep(10 * time.Second)
		return
	}

	// Remover persistência
	removeFromStartup()

	// Restaurar wallpaper padrão
	restoreDefaultWallpaper()

	// Apagar arquivos residuais
	os.Remove(filepath.Join(targetDir, "!!!WARNING!!!.txt"))
	os.Remove(filepath.Join(targetDir, "wallpaper.jpg")) // <--- NOVO!

	// Descriptografar arquivos
	filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".aeehh") {
			return nil
		}

		data, _ := os.ReadFile(path)
		decryptedData := xorEncrypt(data)

		originalName := strings.TrimPrefix(strings.TrimSuffix(info.Name(), ".aeehh"), "[RANSOM]")
		os.WriteFile(filepath.Join(filepath.Dir(path), originalName), decryptedData, 0644)
		os.Remove(path)

		return nil
	})

	fmt.Print("\033[32m")
	fmt.Println("[+] Sistema restaurado com sucesso!")
	fmt.Print("\033[0m")
}
