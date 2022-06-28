# simple-jwt
A very simple JWT implementation written in Go.

 
### Install
```sh
$ go get -u github.com/mrsih/simple-jwt
```


### Usage
```go
package main

import (
	"fmt"

	sjwt "github.com/mrsih/simple-jwt"
)

var secret = "53cr3tk3y"

func main() {
	// Create new token
	jwt := sjwt.New()
	jwt.SetPayload("name", "mrsih")
	token, _ := jwt.Sign(secret)

	// Verify token
	jwt2, _ := sjwt.Parse(token)
	err := jwt2.Verify(token, secret)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// Identify user
	name, ok := jwt2.Payload("name")
	if ok {
		fmt.Println(name)
	}
}

```