/**
 * Auth :   liubo
 * Date :   2021/4/27 16:03
 * Comment:
 */

package main

import (
	"encoding/base64"
	"fmt"
)

func main() {
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
