// Este código foi feito por Azam Usman
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
	password  = "123"      // Chave de descriptografia
	targetDir = `C:\teste` // Pasta alvo para descriptografia
)

// Função para descriptografar dados usando XOR
func xorEncrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	for i := range data {
		// Aplica operação XOR com a senha (criptografia simétrica)
		encrypted[i] = data[i] ^ password[i%len(password)]
	}
	return encrypted
}

// Restaura o papel de parede padrão do Windows
func restoreDefaultWallpaper() {
	defaultWallpaper := `C:\Windows\Web\Wallpaper\Windows\img0.jpg` // Caminho do wallpaper padrão
	user32 := windows.NewLazySystemDLL("user32.dll")
	systemParameters := user32.NewProc("SystemParametersInfoW")

	// Converte caminho para formato UTF-16 (requerido pelo Windows)
	pathUTF16, _ := windows.UTF16PtrFromString(defaultWallpaper)

	// Chama API do Windows para restaurar wallpaper
	systemParameters.Call(
		uintptr(0x0014), // SPI_SETDESKWALLPAPER
		0,
		uintptr(unsafe.Pointer(pathUTF16)),
		uintptr(0x01|0x02), // SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
	)
}

// Remove o programa da inicialização automática do Windows
func removeFromStartup() {
	// Abre chave de registro de inicialização
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return
	}
	defer key.Close()

	// Remove entrada específica
	key.DeleteValue("RansomDemo")
}

func main() {
	// Imprime prompt colorido (azul)
	fmt.Print("\033[36m")
	fmt.Println("[?] Insira a chave de descriptografia:")
	fmt.Print("\033[0m")

	var inputKey string
	fmt.Scanln(&inputKey) // Lê chave do usuário

	// Verifica se a chave está correta
	if inputKey != password {
		// Mensagem de erro em vermelho
		fmt.Print("\033[31m")
		fmt.Println("⚠️ CHAVE INVÁLIDA! OS ARQUIVOS SERÃO DELETADOS!")
		fmt.Print("\033[0m")
		time.Sleep(10 * time.Second)
		return
	}

	// Etapas de recuperação do sistema
	removeFromStartup()       // Remove da inicialização
	restoreDefaultWallpaper() // Restaura wallpaper

	// Remove arquivo de aviso
	os.Remove(filepath.Join(targetDir, "!!!WARNING!!!.txt"))

	// Descriptografa arquivos na pasta alvo
	filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		// Ignora erros, pastas e arquivos não criptografados
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".aeehh") {
			return nil
		}

		// Lê arquivo criptografado
		data, _ := os.ReadFile(path)
		// Descriptografa dados
		decryptedData := xorEncrypt(data)

		// Recupera nome original do arquivo
		originalName := strings.TrimPrefix(strings.TrimSuffix(info.Name(), ".aeehh"), "[RANSOM]")
		// Salva arquivo descriptografado
		os.WriteFile(filepath.Join(filepath.Dir(path), originalName), decryptedData, 0644)
		// Remove arquivo criptografado
		os.Remove(path)

		return nil
	})

	// Mensagem de sucesso em verde
	fmt.Print("\033[32m")
	fmt.Println("[+] Sistema restaurado com sucesso!")
	fmt.Print("\033[0m")
}
