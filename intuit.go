/* author: Orian Zinger
 * date: August 2016
 * description: This is a HTTP server that recieve text from the client
 *				 and encrypt it using AES-256-GCM encryption
 */

package main

import (
	"html/template"
	"fmt"
	"net/http"
	"regexp"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type Page struct {
	Title string
	Body  []byte
}

const PORT = 8080

var templates = template.Must(template.ParseFiles("index.html"))
var validPath = regexp.MustCompile("/encrypt|/index.html")
var key []byte

// This function is the handler for "/index.html" routes
func indexHandler(w http.ResponseWriter, r *http.Request, title string) {
	p := &Page{Title: title}
	renderTemplate(w, "index", p)
}

// This function create a nonce word and encrypt the text its recieved
func encrypt (text string) ([]byte, []byte) {
	plaintext := []byte(text)
	
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce
}

// This function decrypt the cipher text using the correct nonce
func decrypt(ciphertext, nonce []byte) string {
	
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return string(plaintext)
}

// This function is the handler for "/encrypt" routes
func encryptHandler(w http.ResponseWriter, r *http.Request, title string) {
	fmt.Println("--- Data recieved ---")
	plaintext := r.FormValue("plaintext")
	generateNewKey()
	ciphertext, nonce := encrypt(plaintext)
	fmt.Printf("Key: 0x%x\n", key)
	fmt.Println("Plain text: \"" + plaintext + "\"")
	fmt.Printf("Encrypted text: \"%x\"\n", ciphertext)
	fmt.Println("After decryption: \"" + decrypt(ciphertext, nonce) + "\"")
	http.Redirect(w, r, "/index.html", http.StatusFound)
}

// This function is a wrapper for handler functions
func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := validPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		fn(w, r, m[0])
	}
}

// This function creates the HTML page using templates
func renderTemplate(w http.ResponseWriter, tmpl string, p *Page) {
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// This function generates new random AES-256 key everytime the server recieve text
func generateNewKey() {
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
}

func main() {
	key = make([]byte, 32)
	http.HandleFunc("/index.html", makeHandler(indexHandler))
	http.HandleFunc("/encrypt", makeHandler(encryptHandler))
	fmt.Printf("Please surf to http://localhost:%d/index.html\n", PORT)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
