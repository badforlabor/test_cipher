/**
 * Auth :   liubo
 * Date :   2021/4/28 11:17
 * Comment:
 */

package main

import (
	"encoding/base64"
)

func ToBase64(data []byte) string {
	var newStr = base64.StdEncoding.EncodeToString(data)
	return newStr
}

func FromBase64(str string) []byte {
	origData,err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil
	}
	return origData
}
