// Command mkaccount writes a synthetic WARP account file for local smoke
// testing. It is a throwaway helper and is not part of the shipped program.
package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"marp/internal/warpapi"
)

func main() {
	key, err := warpapi.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	priv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}

	out := fmt.Sprintf(`{
  "private_key": %q,
  "endpoint_v4": "162.159.198.1",
  "endpoint_v6": "2606:4700:103::",
  "endpoint_h2_v4": "162.159.198.2",
  "endpoint_h2_v6": "",
  "endpoint_pub_key": %q,
  "license": "",
  "id": "00000000-0000-0000-0000-000000000000",
  "access_token": "smoke-test-token",
  "ipv4": "172.16.0.2",
  "ipv6": "2606:4700:110:8101:1:1:1:1"
}
`, base64.StdEncoding.EncodeToString(priv), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))

	if err := os.WriteFile(os.Args[1], []byte(out), 0o600); err != nil {
		panic(err)
	}
	fmt.Println("wrote", os.Args[1])
}
