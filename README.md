# zrequest
[![GoDoc](http://img.shields.io/badge/go-documentation-brightgreen.svg?style=flat-square)](https://godoc.org/github.com/iyidan/zrequest)
[![Go Report](https://goreportcard.com/badge/github.com/iyidan/zrequest)](https://goreportcard.com/badge/github.com/iyidan/zrequest)

a http client written with golang, which is useful and powerful
## Example
```go
package main

import (
	"fmt"
	"github.com/iyidan/zrequest"
)

// HTTPBinResponse The structure of httpbin response
type HTTPBinResponse struct {
	Args    map[string]string
	Data    string
	Files   map[string]string
	Form    map[string]string
	Headers map[string]string
	JSON    interface{}
	Origin  string
	URL     string `json:"url"`
}

func main() {
	// the request data
	data := map[string]interface{}{"username": "iyidan","age":22}
	// the response type
	res := HTTPBinResponse{}
	// request and unmarshal response into res
	err := zrequest.Open().SetBody(data).Post("http://httpbin.org/post?arg1=arg1").Unmarshal(&res)
	// handle error
	if err != nil {
		panic(err)
	}
	fmt.Printf("The response is: %#v", res)
}
```

More Examples: See the test files *_test.go 