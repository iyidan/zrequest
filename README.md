# zhttpclient
a httpclient write by golang
## Example
```go
package main

import (
	"fmt"

	"github.com/iyidan/zhttpclient"
)

type httpBinResponse struct {
	Args        map[string]string `json:"args"`
	Data        string            `json:"data"`
	Form        map[string]string `json:"form"`
	RespHeaders map[string]string `json:"headers"`
	// more ...
}

func init() {
	zhttpclient.LogOn = true
	zhttpclient.LogBody = true
	zhttpclient.LogDetail = true
}

func main() {

	reqBody := map[string]interface{}{
		"username": "iyidan",
		"age":      22,
	}
	res := httpBinResponse{}
	err := zhttpclient.Open(). // client with default timeout
					SetBody(reqBody). // client will auto detect the request content-type
					Post("http://httpbin.org/post").
					Unmarshal(&res) // client will marshal response to struct, support xml or json

	fmt.Printf("res: %#v, err: %#v\n", res, err)
}
```

More Examples: See the zhttpclient_test.go 