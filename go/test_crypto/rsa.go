/**
 * Auth :   liubo
 * Date :   2021/4/28 10:24
 * Comment:
 */

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// =================== RSA ======================
// 加密
func RsaEncrypt(origData, publicKey  []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey) //将密钥解析成公钥实例
	if block == nil {
		return nil, errors.New("public key error")
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData) //RSA算法加密
}

// 解密
func RsaDecrypt(ciphertext, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey) //将密钥解析成私钥实例
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext) //RSA算法解密
}

// 加密
func RsaEncrypt8(origData, publicKey  []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey) //将密钥解析成公钥实例
	if block == nil {
		return nil, errors.New("public key error")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), origData) //RSA算法加密
}

// 解密
func RsaDecrypt8(ciphertext, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey) //将密钥解析成私钥实例
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv.(*rsa.PrivateKey), ciphertext) //RSA算法解密
}

func GenRsaKey() {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)

	publicKey := key.PublicKey

	saveGobKey("private.key", key)
	savePEMKey("private.pem", key)

	saveGobKey("public.key", publicKey)
	savePublicPEMKey("public.pem", publicKey)

	savePEMKey8("private8.pem", key)
	savePublicPEMKey8("public8.pem", publicKey)
}
func saveGobKey(fileName string, key interface{}) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	encoder := gob.NewEncoder(outFile)
	err = encoder.Encode(key)
	checkError(err)
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePEMKey8(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var data, err2 = x509.MarshalPKCS8PrivateKey(key)
	checkError(err2)

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}
func savePublicPEMKey8(fileName string, pubkey rsa.PublicKey) {

	//asn1Bytes, err := asn1.Marshal(pubkey)
	//checkError(err)
	//
	//pub, err := x509.ParsePKIXPublicKey(asn1Bytes)
	//checkError(err)

	asn1Bytes, err := x509.MarshalPKIXPublicKey(&pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}