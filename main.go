package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type model struct {
	passInput    textinput.Model
	filepicker   filepicker.Model
	selectedFile string
	temp         int
	tempSh       bool
	quitting     bool
	err          error
}

type clearErrorMsg struct{}

func clearErrorAfter(t time.Duration) tea.Cmd {
	return tea.Tick(t, func(_ time.Time) tea.Msg {
		return clearErrorMsg{}
	})
}

func (m model) Init() tea.Cmd {
	return m.filepicker.Init()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if m.tempSh {
		m.quitting = true
		return m, tea.Quit
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "ctrl+t":
			m.temp++
		case "enter":
			// "The reason for the checks here is that the file picker uses the Enter key, so if we've received all inputs, we allow quitting."
			// "If inputs have not been received, we continue with the update function."
			// "If someone wonders why I'm checking for powers of 2, they just need to know that I'm simply crazy."
			if m.selectedFile != "" && m.passInput.Value() != "" && iot(utf8.RuneCountInString(m.passInput.Value())) {
				// "The temp section adjusts the time based on how many times you press 'Ctrl+T', and after a while, it disappears from the console."
				// "The temp section is only available for decryption."
				// "Since I couldn't find a solution for temporary printing (didn't want to spend too much time on it), we're just logging the output as an error instead."
				if m.temp > 0 && strings.HasSuffix(m.selectedFile, ".enc") {
					fmt.Println("\n  " + m.filepicker.Styles.Selected.Render("Temporarily decrypting the file..."))
					data := getData(m.selectedFile)
					txt := decryptText(data, string(hashKey([]byte(m.passInput.Value()), 32)))
					// "Creates an error message to display the decrypted text."
					m.err = errors.New(txt)
					m.tempSh = true
					return m, tea.Batch(cmd, clearErrorAfter(time.Duration(m.temp)*time.Second))
				}
				m.quitting = true
				return m, tea.Quit
			} else {
				m.passInput, _ = m.passInput.Update(msg)
			}
		default:
			if m.selectedFile != "" {
				m.passInput, _ = m.passInput.Update(msg)
			}
		}
	case clearErrorMsg:
		m.err = nil
	}
	// "The file picker is updated here."
	m.filepicker, cmd = m.filepicker.Update(msg)
	if didSelect, path := m.filepicker.DidSelectFile(msg); didSelect {
		m.selectedFile = path
	}
	// "We just check if the file is disabled."
	if didSelect, path := m.filepicker.DidSelectDisabledFile(msg); didSelect {
		m.err = errors.New(path + " is not valid.")
		m.selectedFile = ""
		return m, tea.Batch(cmd, clearErrorAfter(2*time.Second))
	}

	return m, cmd
}

func (m model) View() string {
	if m.quitting {
		return ""
	}
	var s strings.Builder
	s.WriteString("\n  ")
	if m.err != nil {
		// "The error message is displayed in red."
		s.WriteString(m.filepicker.Styles.DisabledFile.Render(m.err.Error()))
	} else if m.selectedFile == "" {
		// "Welcome message."
		s.WriteString("Welcome to the file picker, please select a file for encryption or decryption.")
		s.WriteString("\n\n" + m.filepicker.View() + "\n")
	} else {
		// "Selected file message."
		s.WriteString("Selected file: " + m.filepicker.Styles.Selected.Render(m.selectedFile))
		if strings.HasSuffix(m.selectedFile, ".enc") {
			m.passInput.Placeholder = "Decrypting a file? Enter the password here."
			s.WriteString(" (encrypted)")
		} else {
			m.passInput.Placeholder = "Encrypting a file? Enter the password here. Must be a power of (2)."
			s.WriteString(" (plaintext)")
		}
		s.WriteString("\n" + m.passInput.View() + "\n")
	}
	return s.String()
}

func main() {
	// "The text input is used to get the password from the user."
	ti := textinput.New()
	ti.Focus()
	ti.CharLimit = 2147483646
	ti.Width = 100

	// "File picker is a simple tool that allows you to select a file from the current directory."
	fp := filepicker.New()
	// "File picker is set to allow only .txt and .enc files."
	fp.AllowedTypes = []string{".txt", ".enc"}
	// "File picker sets the current directory to the current directory."
	fp.CurrentDirectory, _ = os.Getwd()

	// "Model."
	m := model{
		filepicker: fp,
		passInput:  ti,
	}
	
	// "Program."
	tm, _ := tea.NewProgram(&m).Run()
	mm := tm.(model)

	// "Let's see what you've selected."
	fmt.Println("\n  You selected: " + m.filepicker.Styles.Selected.Render(mm.selectedFile))

	// "The selected file is encrypted or decrypted according to the file extension."
	if strings.HasSuffix(mm.selectedFile, ".txt") {
		data := getData(mm.selectedFile)
		enc := encryptText(data, string(hashKey([]byte(mm.passInput.Value()), 32)))
		writeToFile(enc, strings.ReplaceAll(mm.selectedFile, ".txt", ".enc"))
		os.Remove(mm.selectedFile)
	} else {
		// "Check temp here too."
		if mm.temp == 0 {
			data := getData(mm.selectedFile)
			dec := decryptText(data, string(hashKey([]byte(mm.passInput.Value()), 32)))
			writeToFile(dec, strings.ReplaceAll(mm.selectedFile, ".enc", ".txt"))
			os.Remove(mm.selectedFile)
		}
	}
	// "Job done!"
	fmt.Println("\n  " + m.filepicker.Styles.Selected.Render("Job Done!"))
}

func iot(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// "AES Encryption needs 128, 192 or 256 bit key. This function generates a hash key based on the key size."
func hashKey(key []byte, size int) []byte {
	var hash []byte

	switch size {
	case 16: // 128 bit
		hashBytes := sha256.Sum256(key)
		hash = hashBytes[:16]
	case 24: // 192 bit
		hashBytes := sha256.Sum256(key)
		hash = hashBytes[:24]
	case 32: // 256 bit
		hashBytes := sha256.Sum256(key)
		hash = hashBytes[:32]
	default:
		panic("Unsupported key size")
	}

	return hash
}

func decryptText(ciphertext []byte, keyStr string) string {
	key := []byte(keyStr)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("Text is too short")
	}

	iv := ciphertext[:aes.BlockSize]

	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext)
}

func encryptText(plaintext []byte, keyStr string) string {
	key := []byte(keyStr)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return string(ciphertext)
}

func getData(file string) []byte {
	data, err := readFromFile(file)
	if err != nil {
		println("Error reading file")
	}
	return data
}

func writeToFile(data, file string) {
	err := ioutil.WriteFile(file, []byte(data), 777)
	if err != nil {
		return
	}
}

func readFromFile(file string) ([]byte, error) {
	data, err := ioutil.ReadFile(file)
	return data, err
}
