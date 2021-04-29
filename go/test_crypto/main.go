/**
 * Auth :   liubo
 * Date :   2021/4/27 16:03
 * Comment:
 */

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {

	GenRsaKey()

	testAES()
	testAES_ECB()
	testRSA()
	testRSA8()
}

func testAES() {

	var key = GenKey("123456")
	var str = "l82FD+d88GP8dv5eY/4TWA=="

	//var result, e = Decrypt(str, []byte(key), []byte(key))

	origData,err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Errorf(err.Error())
		return
	}

	var result, e = AesDecryptCBC([]byte(key), origData)
	if e == nil {
		fmt.Println("cbc result:", string(result))
	}

	var new, e2 = AesEncryptCBC(key, result)
	if e2 != nil {
		fmt.Errorf(e2.Error())
		return
	}
	var newStr = base64.StdEncoding.EncodeToString(new)
	fmt.Println("cbc encrypt result:", newStr)
	fmt.Println("check result:", newStr == str)
}

func testAES_ECB() {

	var key = GenKeyCommon("123456", 32, '0')
	var plain = "ECB Mode Test"

	var new, e2 = AesEncryptECB(key, []byte(plain))
	if e2 != nil {
		fmt.Errorf(e2.Error())
		return
	}
	//var result, e = Decrypt(str, []byte(key), []byte(key))

	var str = ToBase64(new)

	fmt.Println("ecb, plain:", plain)
	fmt.Println("ecb, result:", str)

	origData,err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Errorf(err.Error())
		return
	}

	var result, e = AesDecryptECB([]byte(key), origData)
	if e == nil {
		fmt.Println("ecb result:", string(result))
	}

	var newStr = base64.StdEncoding.EncodeToString(new)

	fmt.Println("check result:", newStr == str)
}

func testRSA() {
	//私钥
	var privateKey = []byte(`
-----BEGIN PRIVATE KEY-----
MIIEpAIBAAKCAQEA1DlApYd9UXzHFnSORV0YiChQr2sQJVy63zgJcrUlFiRBgtNZ
YsDiXTsl6Kqb21Atyl67rePloFPXiqGhzVOgSQySVcf93L1SBNglVrmFC0xSlTos
FOUAZkFtkD1CzjeHnO/BSBJfEfYbX9KSOLkXuK95M/h8WQM6Qza+r2N6K6VXvSVm
FHxYBukmzP6AzQOQ87fgumuaX5AmpWAYkigzMQIShtiecTO4QCafqYNPBdaBe/Bz
ePA0iB4X1xFKCQlHQejbfgeqqBGoGxSNUSZO7yju2yQpZb5OW0UH/PSXig/3/uaR
dNUW+XqOncBJN+f4ezLYnJCHD/zetmmLvBdX8QIDAQABAoIBAHF5U2musoE5uLH3
DINmLdHPzKSfGHkBxiHIsrSUywm1xRmQrICzJdY35CMt5jwz+Of2E1/9NTCu49cK
aZuCFXg5sp0PXFwFFq/kasKeW9cYrieAfUWG1NnYLh8rwmbFJkvxnmVM/Wx7LVPl
Ia4WuepUWPhC6yolIagCw57AD/j5a+XlJhmQSM+WZhWVRxnW3cbWoIjnDV5cxCVz
3IyymapDSbhpPFeYscyjxn5tFnt0uoQRBWwlZ65nOgZz/7367mNqE+8jhzV74VuA
IMoI/CWB+FUkEqWv9hc6HK17srQzZJiHJu7dDIU2lUqeLsxAFv0sFFq4tz1zI7KJ
eM+Wr0kCgYEA25ZgY3vypUYXzOzGKVBKf+kP9Q76o2GxbONDlgYn3hsLXk79JQfz
l6tUtrIG4Pka3aA3vPTuKn0nRnH5Dxcyu5HCS7SOHLKXqUd8rJ1Vi6KgUAkaIwKa
M/k7hCFhQLN1IS1XqUHlqm4rwPqq7zv4G8IbpjhUDV4cHgy/PHdiCr8CgYEA92pH
j08/AP8Jj+hZNip2h9xZwZBp8xSH37dUD6Q/SebsfbEms3Rn36tacSAjE6WzoihY
XxqZD2gPHOv0UJztrBfEyhN/jp+ksoSB6kz4VAhFIhev4FtC4CJ6SKRjDGGVloQX
pByFpQOQLxk3rVZBg6UYS88UNSc7JIgUn9NuuU8CgYBeYtLnsD1qQSi10wiSdYqw
VHOheGDPnYxwK3e/osG8PI+0Z+tz4WkZRnHRXdCLH0gm/1k2BWniJY2eQBs4G1aZ
PVvwwplbSIDcKHg0kiRVMwAJpv/vEI1LzdOBRf/RmdG9AwptHIAls9lmx9h1oKdS
9yp/VjL60/ruB7ijuwUPbQKBgQDaClOePFxt6FTo+f8E+U8UVGDVcQuuKX3E7q+q
STltS5FHBAPzSrbwKva9k3DWM8WnNp8K0Unqhe4rstXQ5Tuf2iKXY6+aZZ6jpJtJ
fSOsCs3CSdW5hzPciwXxVs3jb2yBBVBAVNKCpi0/FJ44qDd8aNaMmKZaYYSBoVtr
rs15iQKBgQDAIMLts8lY0mgyL8PW8CYRwqLG63fY0DCRx7oprj/Q3XI46FrkvMRb
fLAXEFtgDjMxjO7l0U5eYPwB9wKpoH2NVneRfdSPMSQHWfbTjbxZIyVznkeuinLF
YE17IDfcYkyqZxTNRP4SPn7hRFpaqJI7TK8gL2OqCfHFc5e+/Oi+zg==
-----END PRIVATE KEY-----
`)


	//公钥
	var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBCgKCAQEA1DlApYd9UXzHFnSORV0YiChQr2sQJVy63zgJcrUlFiRBgtNZYsDi
XTsl6Kqb21Atyl67rePloFPXiqGhzVOgSQySVcf93L1SBNglVrmFC0xSlTosFOUA
ZkFtkD1CzjeHnO/BSBJfEfYbX9KSOLkXuK95M/h8WQM6Qza+r2N6K6VXvSVmFHxY
BukmzP6AzQOQ87fgumuaX5AmpWAYkigzMQIShtiecTO4QCafqYNPBdaBe/BzePA0
iB4X1xFKCQlHQejbfgeqqBGoGxSNUSZO7yju2yQpZb5OW0UH/PSXig/3/uaRdNUW
+XqOncBJN+f4ezLYnJCHD/zetmmLvBdX8QIDAQAB
-----END PUBLIC KEY-----
`)

	data, err := RsaEncrypt([]byte("RSA Test."), publicKey) //RSA加密
	if err != nil {
		panic(err)
	}
	//fmt.Println("RSA加密", string(data))
	fmt.Println("RSA加密成功")
	origData, err := RsaDecrypt(data, privateKey) //RSA解密
	if err != nil {
		panic(err)
	}
	fmt.Println("RSA解密结果:", string(origData))
}

func testRSA8() {
	//私钥
	var privateKey8 = []byte(`
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCatJvQZEsAyJtw
nNwck2r+tT10ia2a+T/esjPDbDrAyQILKdl+ountzNv39XhNI5qrOlfusGlA5yfR
/9L9BNVDMGVvbk7+OZeoyDP0Raf4rXxexMpf1eZjhHMs72YJKQBK1dSjrPRRx028
lsKEu9sT2d40umrA3FE9e0eWegAzZre45v11ZbPeB4BDpdeDiXn9pFDh8Ki1RtxM
fYnbGiz42lATWOF6Et3ufXo5e0nE0renYMe1NMN7XdOePaeY2qBVSvJW7tM9BBXW
BAnjUlyQdi2w1c4VSo/wRtEH2FfybWPC95FePx8/ADNZ7/oLsC/w8glWVA4S1dJL
pSyaN9NjAgMBAAECggEAFnymIVZSqJyAK5BBVk3/QWKquiPA/kO4ivAwIfm7WIZf
K6w7lvKrOguK9bHSeLPyKW1jlqhBxFNVMGsVCf4H2apRNC8+gCly5++hzaHKVpUw
/L1yBRgcUt7PtvpdRHuXNUl7jQb4xGJJ5F2tjImZwHrsl5F5LutXS659q1u0Z8QO
k53I69tgOVUOPJ4gvyUoQL7TutdVOW0QsLEBYFcGdHQlA1Os7NlSFaXE4We4lhxR
v8UKOmc7cEYypeVKyic8oOnqWHzH1ixEuM27s1UNjTwrjdhsKPRGwourKPbXHiCw
57Em/NxvI5kwa3U0YkcWFQTeb+k5+BSkDqJ6cadi8QKBgQDBWAelr6/wiDwTq+tr
4cASDsL5ZPFSjl77EaJS3PnomkFGxV4S/JCsB7+Eu9100CHyHyXz9atOnN5SNIOf
OeCEq3zvBpF+4wfn1BXGN0h2Xv1hZVgDeBI/jfnTKnCA1adH7Ks1DDteRlEM3klE
3SPL1eBuICouoTCcj1/PhaGwDwKBgQDM1xuGmJuV8/5H8hF0d1QlEty06Rvtsy3o
7B/Lg9bhU53+1oixj1ifd30Egis9+7UFfUw9zqePN/9mbd3q7qTKH8Qkri18Qqfh
Hp6mif8EttPFhbNgsb1mnQkQA7pJdhuKK7OlM6msOVVx7WQsI6bhAy3kZRgjqxXO
uH6FqAVTbQKBgGnUprLxvOt7lu7pnv65XmpD/EOJFnMrDSB+4Yxb+stwjCSR6lGY
QBR6VUHxl2HWf45JsHueULvCMAttRVLF2nikaclongGHgg9KzvRl1Fs+2ZETaR7U
/aAeNc55n4VV7a/4AysRW/nZoYnart5r8akklCmTn6NQhgxcioRMUFnPAoGBAJiK
R7E/y/0rKd0h4uW8Rykklr8SKP4mRLYDwNmpYEeEIVA5KqoveWuna64D0XfjDbb8
y93rGtSIeuUoQ+5DsOvkJAi8vJqgeKwoRTT35rT4AVRCcIY9VjIoFyuZ2wwBrBiE
2s7XXi8msv6YLdTA5/EAkRhYQFWvfhnnQjD+IpkxAoGAFk7q8dbFPM+acxyPDdU8
2YoOC5ULl2I/dUF/b92IindC3SmKkub/H3JiT1uz9V1v5gyLwcgPWC+Fw1/2Uc6g
z3b5dZLJmvfai/4wN4OmtPYmcsnk9nuZYzT/ZCdhVfciDdZJNMVi25BYvSnvq4PG
hLXzaw/6oEgRXEJBpsLpy0c=
-----END PRIVATE KEY-----
`)


	//公钥
	var publicKey8 = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmrSb0GRLAMibcJzcHJNq
/rU9dImtmvk/3rIzw2w6wMkCCynZfqLp7czb9/V4TSOaqzpX7rBpQOcn0f/S/QTV
QzBlb25O/jmXqMgz9EWn+K18XsTKX9XmY4RzLO9mCSkAStXUo6z0UcdNvJbChLvb
E9neNLpqwNxRPXtHlnoAM2a3uOb9dWWz3geAQ6XXg4l5/aRQ4fCotUbcTH2J2xos
+NpQE1jhehLd7n16OXtJxNK3p2DHtTTDe13Tnj2nmNqgVUryVu7TPQQV1gQJ41Jc
kHYtsNXOFUqP8EbRB9hX8m1jwveRXj8fPwAzWe/6C7Av8PIJVlQOEtXSS6UsmjfT
YwIDAQAB
-----END PUBLIC KEY-----
`)

	var plain = []byte("RSA Test.")
	data, err := RsaEncrypt8(plain, publicKey8) //RSA加密
	if err != nil {
		panic(err)
	}
	//fmt.Println("RSA加密", string(data))
	fmt.Println("RSA8加密成功:", base64.StdEncoding.EncodeToString(data))
	origData, err := RsaDecrypt8(data, privateKey8) //RSA解密
	if err != nil {
		panic(err)
	}
	fmt.Println("RSA8解密结果:", string(origData))

	// 解谜cpp中的
	{
		var base64 = "ZtMzdyYomTqtnhYVryKewLU8CL70Bx0qveDVfSw1zQohqcdZDuw8IGXrfT9d2meiz3mlbiVVStF/qRaNzYFLZW09xvkERvn3w5CdtjWeUl+LxVUldl8baYSRjuqfw5j5V/LpQFAb+Pygg3eYhyUyZG718KQOyUV31eGFv7M7MdVDjqvkPRN17Fm9RWoGgVYFd8HOTu7wFSUZrhA5boTVZYNonnI7dl0p7raMgdOAQVPFHP3fNy2cOJmhgAebRHo2UMmbCbnDCMc2iRjD3wXjbrUbJiAPjsa/eOYdwmwfvPKCAs79nwGPZhXy1j2Kv4CNC7fbtf7PRtTYlcidWIvmZA=="
		var data2 = FromBase64(base64)
		origData2, err2 := RsaDecrypt8(data2, privateKey8)
		if err2 != nil {
			panic(err2)
		}
		fmt.Println("cpp RSA8解密结果:", string(origData2))
	}
}

func MarshalPKCS8PrivateKey(key *rsa.PrivateKey) []byte {
	info := struct {
		Version             int
		PrivateKeyAlgorithm []asn1.ObjectIdentifier
		PrivateKey          []byte
	}{}
	info.Version = 0
	info.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	info.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	info.PrivateKey = x509.MarshalPKCS1PrivateKey(key)

	k, err := asn1.Marshal(info)
	if err != nil {
		log.Panic(err.Error())
	}
	return k
}
