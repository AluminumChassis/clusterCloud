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
  	"encoding/base64"
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
var portMap []string
var connMap map[string]net.Conn
func main() {
	activity = map[int]bool{1: false, 2: false, 3: false}
	connMap = map[string]net.Conn{}
	portMap = []string{":8081"}
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
		connMap[port]=conn
		check(err)
		go handleConnection(conn, port) // Handle connection
	}
}
func handleConnection(conn net.Conn, port string){
	for {
		tmp := make([]byte, bufferSize)
		buf := make([]byte, 0, bufferSize) // Create large enough buffer for response
	    n, err := conn.Read(tmp)
	    if err != nil {
	        if err != io.EOF {
				activity[find(portMap,port)] = true
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
	r := decrypt(result)
	fmt.Println(r)
	if(strings.HasPrefix(r, "update")){
    	activityJSON, _ := json.Marshal(activity)
	    conn.Write([]byte(encrypt(string(activityJSON)))) // Send data back

	} else if (strings.HasPrefix(r, "file")) {
		num,err := strconv.Atoi((r[4:5]))
		check(err)
		fmt.Println(num)
    	activityJSON, _ := json.Marshal(activity)
	    conn.Write([]byte(string(activityJSON))) // Send data back
		connMap[portMap[num]].Write([]byte(result))
	} else if (strings.HasPrefix(r, "active")) {
		num,err := strconv.Atoi((r[6:7]))
		check(err)
		activity[num] = true
		portMap[num-1] = port
	    conn.Write([]byte(encrypt("done."))) // Send data back
	
	}
}
func encrypt(message string)(string){
  salt,err := GenerateRandomString(4)
  message = pad(message)
  check(err)
  dk = pbkdf2.Key([]byte(password), []byte(salt), iter, ivlen, sha256.New) // Create key
  block, err := aes.NewCipher(dk)  // Create a new cipher using the key
  check(err);
  
  ciphertext := make([]byte, len(message)) // Allocate space for ciphertext
  iv := make([]byte, aes.BlockSize) // Create IV
  _, err = io.ReadFull(rand.Reader, iv) // Randomize IV
  check(err)

  mode := cipher.NewCBCEncrypter(block, iv) // CBC mode of encryption
  mode.CryptBlocks(ciphertext, []byte(message)) // Encrypt message

  final := hex.EncodeToString(iv)+":"+hex.EncodeToString(ciphertext)+":"+hex.EncodeToString([]byte(salt)) // Group IV, message, and salt together
  fmt.Println(final)
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
func find(a []string, x string) int {
    for i, n := range a {
        if x == n {
            return i
        }
    }
    return len(a)
}
func GenerateRandomString(s int) (string, error) {
    b, err := GenerateRandomBytes(s)
    return base64.URLEncoding.EncodeToString(b), err
}
func GenerateRandomBytes(n int) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    // Note that err == nil only if we read len(b) bytes.
    if err != nil {
        return nil, err
    }

    return b, nil
}
func pad(s string)(string){
  return s+strings.Repeat("#", (16-len(s)%16))
}