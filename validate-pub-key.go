package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func main() {
	// Load CA certificate
	caCertPEM, err := ioutil.ReadFile("ca_cert.pem")
	if err != nil {
		fmt.Println("Error reading CA certificate:", err)
		return
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		fmt.Println("Error decoding CA certificate PEM")
		return
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing CA certificate:", err)
		return
	}

	// Load public key
	publicKeyPEM, err := ioutil.ReadFile("public_key.pem")
	if err != nil {
		fmt.Println("Error reading public key:", err)
		return
	}
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)
	if publicKeyBlock == nil {
		fmt.Println("Error decoding public key PEM")
		return
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return
	}

	// Verify public key against CA certificate
	err = caCert.CheckSignature(x509.ECDSAWithSHA256, publicKey.(*crypto.PublicKey), publicKeyBlock.Bytes)
	if err != nil {
		fmt.Println("Public key verification failed:", err)
		return
	}

	fmt.Println("Public key verification succeeded!")
}
