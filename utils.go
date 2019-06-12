/**
 * @author [Double]
 * @email [2637309949@qq.com.com]
 * @create date 2019-01-12 22:46:31
 * @modify date 2019-01-12 22:46:31
 * @desc [bulrush openapi]
 */

package openapi

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
)

func priKeyFromByte(privateKey []byte) (*rsa.PrivateKey, error) {
	pk := []byte(`
-----BEGIN RSA PRIVATE KEY-----
` + string(privateKey) + `
-----END RSA PRIVATE KEY-----
and some more`)

	block, _ := pem.Decode(pk)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println(block.Type)
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func pubKeyFromByte(publicKey []byte) (*rsa.PublicKey, error) {
	pk := []byte(`
-----BEGIN PUBLIC KEY-----
` + string(publicKey) + `
-----END PUBLIC KEY-----
and some more`)
	block, _ := pem.Decode(pk)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	return pub.(*rsa.PublicKey), err
}

func rsaDecrypt(key *rsa.PrivateKey, encrypted []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, key, encrypted, []byte{})
}

func rsaEncrypted(key *rsa.PublicKey, message []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, key, message, []byte{})
}

func rsaSignPKCS1v15(key *rsa.PrivateKey, data []byte) (string, error) {
	hash := sha256.New()
	hash.Write(data)
	retByte, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash.Sum(nil))
	return base64.StdEncoding.EncodeToString(retByte), err
}

func rsaVerifyPKCS1v15(key *rsa.PublicKey, data []byte, base64Sign string) error {
	hash := sha256.New()
	hash.Write(data)
	descB64, err := base64.StdEncoding.DecodeString(base64Sign)
	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash.Sum(nil), descB64)
	return err
}

func map2SignString(puData interface{}) string {
	var puJSON map[string]string
	var puKeys = make([]string, 0, len(puJSON))
	puByte, _ := json.Marshal(puData)
	json.Unmarshal(puByte, &puJSON)
	for k := range puJSON {
		if k != "sign" {
			puKeys = append(puKeys, k)
		}
	}
	sort.Strings(puKeys)
	var signString = ""
	for _, k := range puKeys {
		if signString != "" {
			signString = signString + "&" + k + "=" + puJSON[k]
		} else {
			signString = signString + k + "=" + puJSON[k]
		}
	}
	return signString
}

func getForm(c *gin.Context) (*CRP, error) {
	puData := &CRP{}
	if c.Request.Method != "POST" {
		if err := c.ShouldBindQuery(puData); err != nil {
			return nil, err
		}
	} else {
		if err := c.ShouldBind(puData); err != nil {
			return nil, err
		}
	}
	return puData, nil
}

func rsaVerify(puData *CRP, appKeySecret *AppInfo) error {
	sign := puData.Sign
	signString := map2SignString(puData)
	if pubkey, err := pubKeyFromByte([]byte(appKeySecret.PublicKey)); err == nil {
		if err := rsaVerifyPKCS1v15(pubkey, []byte(signString), sign); err != nil {
			rushLogger.Warn("rsaVerifyPKCS1v15 error %s", err.Error())
			return errors.New("sign not match")
		}
		return nil
	}
	rushLogger.Warn("pubKeyFromByte error")
	return errors.New("read application public key error")
}

func postRequest(url string, data interface{}) ([]byte, error) {
	buf, err := json.Marshal(data)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(buf))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()
	if resp.Status != "200" {
		return []byte{}, errors.New("status error")
	}
	body, err := ioutil.ReadAll(resp.Body)
	return body, nil
}
