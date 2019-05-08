package main

import (
	"fmt"
	"io"
	"crypto/sha256"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/pbkdf2"
	"encoding/json"
	"net"
	"encoding/hex"
	"strings"
	"os"
	"time"
    "strconv"
)
const (
	password = "This is my password"
	bufferSize = 65536 // Large enough for information passing through
	iter = 100 // Iterations for key creation
	ivlen = 16 // Length of the IV
)
var dk []byte
var salt string
var err error
var activity map[int]bool
var portMap map[string]int
func main() {
	activity = map[int]bool{1: false, 2: false, 3: false}
	portMap = map[string]int{":8081": 1}
	fmt.Println("Starting")

	go clock()
	go listenTCP(":8080")
	listenTCP(":8081")
}
func clock() {
	for{
		time.Sleep(1)
		//activity = map[int]bool{1: false, 2: false, 3: false}
	}
}
func listenTCP(port string) {
	listener, err := net.Listen("tcp", port) // Listen to connect to client
	check(err)
	for {
		conn, err := listener.Accept() // Accept a connection
		check(err)
		go handleConnection(conn, port) // Handle connection
	}
}
func handleConnection(conn net.Conn, port string){
	for {
		tmp := make([]byte, bufferSize)
		buf := make([]byte, 0, bufferSize) // Create large enough buffer fro response
	    n, err := conn.Read(tmp)
	    if err != nil {
	        if err != io.EOF {
				activity[portMap[port]] = true
	            break
	        }
	    	continue
	    }
		buf = append(buf, tmp[:n]...)
	    result := string(buf)
	    handle(result, conn, port) // Handling of input from client
	}
}
func handle(result string, conn net.Conn, port string){
	result = decrypt(result)
	fmt.Println(result)
	if(strings.HasPrefix(result, "update")){
    	activityJSON, _ := json.Marshal(activity)
	    conn.Write([]byte(string(activityJSON))) // Send data back

	} else if (strings.HasPrefix(result, "file")) {
		fmt.Println(result[4:5])
    	activityJSON, _ := json.Marshal(activity)
	    conn.Write([]byte(string(activityJSON))) // Send data back
	
	} else if (strings.HasPrefix(result, "active")) {
		num,err := strconv.Atoi((result[6:7]))
		check(err)
		activity[num] = true
		portMap[port] = num
	    conn.Write([]byte("done.")) // Send data back
	
	}
}
func encrypt(message string)(string){
	dk = pbkdf2.Key([]byte(password), []byte(salt), iter, ivlen, sha256.New) // Create key
	block, err := aes.NewCipher(dk)  // Create a new cipher using the key
	check(err);
	
	ciphertext := make([]byte, len(message)) // Allocate space for ciphertext
	iv := make([]byte, aes.BlockSize) // Create IV
	_, err = io.ReadFull(rand.Reader, iv) // Randomize IV
	check(err)

	mode := cipher.NewCBCEncrypter(block, iv) // CBC mode of encryption
	mode.CryptBlocks(ciphertext, []byte(message)) // Encrypt message

	final := hex.EncodeToString(iv)+":"+hex.EncodeToString(ciphertext)+":"+salt // Group IV, message, and salt together
	return final
}
func decrypt(message string) (string) {
	m,s,iv := splitMessage(message)

	dk = pbkdf2.Key([]byte(password), []byte(s), iter, ivlen, sha256.New) // Create key
	block, err := aes.NewCipher(dk) // Create cipher from key
	 // Convert iv from hex
	check(err);

	mode := cipher.NewCBCDecrypter(block, iv) // Create decrypter

	mode.CryptBlocks(m, m) // Decript message
	return string(m)
}
func check(e error) {
    if e != nil {
        fmt.Println(err)
    }
}
func splitMessage(message string)(m []byte,s []byte,iv []byte) {
	parts := strings.Split(message,":")
	s,err = hex.DecodeString(parts[2])
	check(err)
	m,err = hex.DecodeString(parts[1])
	check(err)
	iv,err = hex.DecodeString(parts[0])
	check(err)
	return
}
/* ReadFS to be used later, ignore for now */
func readFS(path string) ([]string) { 
	m := make([]string,0)
	dirname := "./"+path
    d, err := os.Open(dirname) // Open directory
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    defer d.Close() // Make sure directory is closed
    fi, err := d.Readdir(-1)  // Read directory
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    for _, fi := range fi {
        if fi.Mode().IsRegular() {
        	m = append(m,fi.Name()) // Add file name to list
        }
    }
    return m
}