# zrequest
[![GoDoc](http://img.shields.io/badge/go-documentation-brightgreen.svg?style=flat-square)](https://godoc.org/github.com/iyidan/zrequest)
[![Go Report](https://goreportcard.com/badge/github.com/iyidan/zrequest)](https://goreportcard.com/badge/github.com/iyidan/zrequest)

A http client written with golang
## Install
* directly install
```bash
go get -u github.com/iyidan/zrequest
```
* use [govendor](https://github.com/kardianos/govendor) package manager
```bash
cd $GOPATH/src/mysomeproject
govendor fetch github.com/iyidan/zrequest@v1.0.4
```
## Tests
* test with online server (http://httpbin.org)
```bash
go test github.com/iyidan/zrequest
# go test -v github.com/iyidan/zrequest
```
* test with local server(need python environment)
```bash
pip install httpbin
pip install gunicorn
go test -local github.com/iyidan/zrequest
# go test -v -local github.com/iyidan/zrequest
```
## Docs
See the [godoc](https://godoc.org/github.com/iyidan/zrequest) for more information

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
