package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

const POST = "POST"

var (
	baseURL      = os.Getenv("KAIROS_API_URL")
	clientID     = os.Getenv("KAIROS_CLIENT_ID")
	clientSecret = os.Getenv("KAIROS_CLIENT_SECRET")
)

type loginResponse struct {
	Challenge string `json:"challenge"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func prettyPrint(data map[string]interface{}) string {
	jsondata, _ := json.MarshalIndent(data, "", "    ")
	return string(jsondata)
}

func decrypt(data, privateKey string) (string, error) {
	data2, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode([]byte(privateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, data2, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func login() (challenge string, err error) {
	url, err := url.JoinPath(baseURL, "login")
	if err != nil {
		return "", err
	}
	fmt.Println("Attempt login to:", url)

	data := map[string]interface{}{
		"client_id": clientID,
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	j := prettyPrint(data)
	fmt.Println("With payload:", j)

	client := &http.Client{}
	req, err := http.NewRequest(POST, url, bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var response loginResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}

	return response.Challenge, nil
}

func token(challenge string) (token string, err error) {
	url, err := url.JoinPath(baseURL, "token")
	if err != nil {
		return "", err
	}
	fmt.Println("Attempt to request a token:", url)

	data := map[string]interface{}{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"challenge":     challenge,
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	j := prettyPrint(data)
	fmt.Println("With payload:", j)

	client := &http.Client{}
	req, err := http.NewRequest(POST, url, bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var response tokenResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}

	return response.AccessToken, nil
}

func main() {
	fmt.Println("Kairos API usage example in Go")
	fmt.Println("------------------------------")

	// Perform the login
	encryptedChallenge, err := login()
	if err != nil {
		log.Fatal(err.Error())
	}

	// Decrypt the challenge
	privateKey := os.Getenv("RSA_PRIVATE_KEY")
	decryptedChallenge, err := decrypt(encryptedChallenge, privateKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Ask for an access token
	token, err := token(decryptedChallenge)
	fmt.Println("Here is your token:", token)
}
