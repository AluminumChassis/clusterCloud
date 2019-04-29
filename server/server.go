package main

import (
	"fmt"
	//"os/exec"
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
	//"time" 
)
const (
	password = "This is my password"
)
var dk []byte
var salt string
var err error
func main() {
	fmt.Println("Starting")
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		// handle error
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
		}
		go handleConnection(conn)
	}
}
func handleConnection(conn net.Conn){
	for {
		tmp := make([]byte, 256)
		buf := make([]byte, 0, 4096)
	    n, err := conn.Read(tmp)
	    if err != nil {
	        if err != io.EOF {
	            fmt.Println("read error:", err)
	            break
	        }
	    	continue
	    }
	    //fmt.Println("got", n, "bytes.")
	    buf = append(buf, tmp[:n]...)
	    mapD := map[string]bool{"node1": true, "node2": true}
	    mapD["node3"] = true
    	mapB, _ := json.Marshal(mapD)
	    conn.Write([]byte(string(mapB)))
	    result := string(buf)
	    handle(result)
	}
}
func handle(result string){

	fmt.Println(decrypt(result))
}
func encrypt(message string)(string){
	dk = pbkdf2.Key([]byte(password), []byte(salt), 100, 16, sha256.New)
	block, err := aes.NewCipher(dk)
	check(err);
	
	ciphertext := make([]byte, len(message))
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	check(err)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, []byte(message))

	final := hex.EncodeToString(iv)+":"+hex.EncodeToString(ciphertext)+":"+salt
	return final
}
func decrypt(message string) (string) {
	c,err := hex.DecodeString(strings.Split(message,":")[1])
	check(err);
	s,err:= hex.DecodeString(strings.Split(message,":")[2])
	check(err);
	dk = pbkdf2.Key([]byte(password), []byte(s), 100, 16, sha256.New)
	block, err := aes.NewCipher(dk)
	iv,err := hex.DecodeString(strings.Split(message,":")[0])
	check(err);

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(c, c)
	return string(c)
}
func check(e error) {
    if e != nil {
        panic(e)
    }
}

func readFS(path string) ([]string) {
	m := make([]string,0)
	dirname := "./"+path
    d, err := os.Open(dirname)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    defer d.Close()
    fi, err := d.Readdir(-1)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    for _, fi := range fi {
        if fi.Mode().IsRegular() {
        	m = append(m,fi.Name())
        }
    }
    return m
}