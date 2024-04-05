# goech

`Encrypted Client Hello (ECH)` is an extension to the TLS version 1.3, it prevents leaking the `Server Name Indication (SNI)` (and other fields in the `ClientHello` message).

This is done using public key cryptography, by either having the client preconfigured with an ECH Configuration, or fetching that configuration by making a DNS lookup using a special `HTTPS` record.

This library helps with parsing and generating those ECH configurations.

## Example

```sh
go get -u github.com/OmarTariq612/goech
```

```go
package main

import (
	"fmt"

	"github.com/OmarTariq612/goech"
)

func main() {
	echConfigList, err := goech.ECHConfigListFromBase64("AEX+DQBBrAAgACCInfIgdvp+4xqPkMYvPt1Rv7zxtllWm3SjIjWxBoEgfAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(echConfigList[0].RawPublicName)) // cloudflare-ech.com
	pk, _ := echConfigList[0].PublicKey.MarshalBinary()
	fmt.Printf("%x\n", pk)                              // 889df22076fa7ee31a8f90c62f3edd51bfbcf1b659569b74a32235b10681207c
	fmt.Println(goech.KemMapping[echConfigList[0].KEM]) // X25519-SHA256
}
```

```go
package main

import (
	"fmt"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
)

func main() {
	echKeySet, err := goech.GenerateECHKeySet(5, "example.com", hpke.KEM_X25519_HKDF_SHA256)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(echKeySet.ECHConfig.RawPublicName)) // example.com
	pk, _ := echKeySet.ECHConfig.PublicKey.MarshalBinary()
	fmt.Printf("%x\n", pk)                                 // 0b7288f2cd9c0f4063ab2a9478407136f448f7ffe4a6410fee855fdf4f3ed811
	fmt.Println(goech.KemMapping[echKeySet.ECHConfig.KEM]) // X25519-SHA256
}

```

## REF

* https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18

* https://datatracker.ietf.org/doc/html/draft-ietf-tls-svcb-ech-01


## License

goech is available under the MIT license.
