package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	targetDir        = `C:\teste`
	defaultWallpaper = `C:\Windows\Web\Wallpaper\Windows\img0.jpg`
	startupKeyName   = "RansomDemo"
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	systemParameters = user32.NewProc("SystemParametersInfoW")
)

func decryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("dados criptografados inválidos")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func restoreWallpaper() {
	pathUTF16, _ := windows.UTF16PtrFromString(defaultWallpaper)
	systemParameters.Call(
		uintptr(0x0014), // SPI_SETDESKWALLPAPER
		0,
		uintptr(unsafe.Pointer(pathUTF16)),
		uintptr(0x01|0x02),
	)
}

func removeFromStartup() error {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return fmt.Errorf("erro ao abrir registro: %v", err)
	}
	defer key.Close()

	if err := key.DeleteValue(startupKeyName); err != nil {
		return fmt.Errorf("erro ao remover da inicialização: %v", err)
	}
	return nil
}

func decryptFiles(key []byte) error {
	return filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".aeehh") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[!] Erro ao ler %s: %v", path, err)
			return nil
		}

		decryptedData, err := decryptAES(data, key)
		if err != nil {
			log.Printf("[!] Erro ao descriptografar %s: %v", path, err)
			return nil
		}

		originalName := strings.TrimPrefix(
			strings.TrimSuffix(info.Name(), ".aeehh"),
			"[RANSOM]",
		)
		originalPath := filepath.Join(filepath.Dir(path), originalName)

		if err := os.WriteFile(originalPath, decryptedData, 0644); err != nil {
			log.Printf("[!] Erro ao escrever %s: %v", originalPath, err)
			return nil
		}

		if err := os.Remove(path); err != nil {
			log.Printf("[!] Erro ao remover criptografado %s: %v", path, err)
		}

		log.Printf("[+] Descriptografado: %s -> %s", path, originalPath)
		return nil
	})
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Println("[*] Iniciando descriptografia...")

	// Opção 1: Ler chave do arquivo (copiado do Fedora)
	key, err := os.ReadFile("stolen_key.bin")
	if err != nil {
		log.Fatal("[!] Erro ao ler chave: ", err)
	}

	// Opção 2: Inserir manualmente (para testes)
	// fmt.Print("Insira a chave (hex): ")
	// var inputKeyHex string
	// fmt.Scanln(&inputKeyHex)
	// key, _ := hex.DecodeString(inputKeyHex)

	// Restaurar sistema
	if err := removeFromStartup(); err != nil {
		log.Println("[!] Aviso: ", err)
	}

	restoreWallpaper()
	os.Remove(filepath.Join(targetDir, "!!!WARNING!!!.txt"))

	// Descriptografar arquivos
	if err := decryptFiles(key); err != nil {
		log.Fatal("[!] ERRO na descriptografia: ", err)
	}

	log.Println("[+] Sistema restaurado com sucesso!")
}
