package main

import (
  "fmt"
  "io"
  "crypto/sha256"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "golang.org/x/crypto/pbkdf2"
  "net"
  "encoding/hex"
  "strings"
  "encoding/base64"
  "time"
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
func main() {
  // connect to this socket
  fmt.Println("starting")
  conn, _ := net.Dial("tcp", "127.0.0.1:8081")
  for {
    time.Sleep(100 * time.Millisecond)
    m := encrypt("active1")
    conn.Write([]byte(m))
    tmp := make([]byte, bufferSize)
    buf := make([]byte, 0, bufferSize) // Create large enough buffer fro response
      n, err := conn.Read(tmp)
      if err != nil {
          if err != io.EOF {
              fmt.Println("read error:", err)
              break
          }
        continue
      }
      
    buf = append(buf, tmp[:n]...)
    result := string(buf)
    fmt.Println(result)
  }
}
func encrypt(message string)(string){
  salt,err := GenerateRandomString(8);
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