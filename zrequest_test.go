package zrequest

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type NormalRes struct {
	Args    map[string]string
	Data    string
	Files   map[string]string
	Form    map[string]string
	Headers map[string]string
	JSON    User `json:"json"` // use User struct for test
	Origin  string
	URL     string `json:"url"`
}

type CookieGetRes struct {
	Cookies map[string]string
}

type User struct {
	Name string
	Age  int
	Male bool
}

type BasicAuthRes struct {
	Authenticated bool
	User          string
}

var (
	wd, err = os.Getwd()
	// upload imgFile test
	imgFile = filepath.Join(wd, "testuploadfile.png")

	// httpbin for test http client
	dumpURL = "http://httpbin.org"

	// cmdContext is used for run a local server for test
	// when test completed
	cmdContext context.Context
)

func TestBasicAuth(t *testing.T) {
	res := BasicAuthRes{}
	err := Open().
		SetBasicAuth("uname", "upwd").
		Get(dumpURL + "/basic-auth/uname/upwd").Unmarshal(&res)
	if err != nil {
		t.Fatal(err)
	}
	if res.Authenticated != true || res.User != "uname" {
		t.Fatal(`res.Authenticated != true || res.User != "uname"`)
	}
}

func TestGet(t *testing.T) {
	queryParams := map[string]interface{}{
		"v2":    "v2",
		"v3":    3,
		"float": 32.11,
		"ids":   "1,2,31",
	}
	cookie := &http.Cookie{Name: "testcookie", Value: "testcookiev"}
	cookieStr := " cka=ckav; ckb=ckbv;"
	headers := map[string]string{
		"Testhd1": "testhdv1",
		"Testhd2": "testhdv2",
	}
	res := NormalRes{}
	err := Open().SetQueryParam("single1", "single1").SetQueryParamAny("single2", 2).
		SetQueryParamsAny(queryParams).
		SetCookie(cookie).
		SetCookieString(cookieStr).
		SetHeader("testhd", "testhdv").
		SetHeaders(headers).
		Get(dumpURL + "/get?ori=1").Unmarshal(&res)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("getres: %#v\n", res)

	// query param
	if res.Args["ori"] != "1" {
		t.Fatal(`res.Args["ori"] != "1"`)
	}
	if res.Args["single1"] != "single1" {
		t.Fatal(`res.Args["single1"] != "single1"`)
	}
	if res.Args["single2"] != "2" {
		t.Fatal(`res.Args["single2"] != "2"`)
	}
	for k, v := range queryParams {
		if rv, ok := res.Args[k]; !ok || rv != fmt.Sprintf("%v", v) {
			t.Fatalf("res.Args[%s] != %v, res=%s, ok:%t", k, v, rv, ok)
		}
	}

	resCookieStr := res.Headers["Cookie"]
	if !strings.Contains(resCookieStr, "testcookie=testcookiev") {
		t.Fatal(`!strings.Contains(resCookieStr, "testcookie=testcookiev")`)
	}
	if !strings.Contains(resCookieStr, "cka=ckav") {
		t.Fatal(`!strings.Contains(resCookieStr, "ckb=ckbv")`)
	}
	if !strings.Contains(resCookieStr, "ckb=ckbv") {
		t.Fatal(`!strings.Contains(resCookieStr, "ckb=ckbv")`)
	}

	for k, v := range headers {
		if rv, ok := res.Headers[k]; !ok || rv != v {
			t.Fatalf("res.Headers[%s] != %s, res=%s, ok:%t", k, v, rv, ok)
		}
	}
	if res.Headers["Testhd"] != "testhdv" {
		t.Fatal(`res.Headers["testhd"] != "testhdv"`)
	}
}

func TestSetCookie(t *testing.T) {
	res := CookieGetRes{}
	zr := Open()
	err := zr.Get(dumpURL + "/cookies/set?ckname=ckvalue").Unmarshal(&res)
	if err != nil {
		t.Fatal(err)
	}
	if res.Cookies["ckname"] != "ckvalue" {
		t.Fatal(`res.Cookies["ckname"] != "ckvalue"`)
	}
}

func TestSendRawBody(t *testing.T) {
	raw := "aaaa"

	res := NormalRes{}
	err := Open().
		SetBody(raw).
		SetContentType("application/octet-stream").
		Post(dumpURL + "/post?abc=va").Unmarshal(&res)
	if err != nil {
		t.Fatal(err)
	}

	if res.Data != raw {
		t.Fatal(`res.Data != raw`)
	}
}

func TestSendJSONBody(t *testing.T) {
	body := &User{Name: "liwei", Age: 28, Male: true}
	bodyBytes, _ := json.Marshal(body)

	testBodys := []interface{}{
		body,
		*body,
		bodyBytes,
		string(bodyBytes),
		bytes.NewBufferString(string(bodyBytes)),
	}

	for k, v := range testBodys {
		res := NormalRes{}
		err := Open().
			SetBody(v).
			SetContentType(JSONContentType).
			Post(dumpURL + "/post?v=jsontest").Unmarshal(&res)
		if err != nil {
			t.Fatal(k, err)
		}
		t.Log("res.JSON:", k, res.JSON)
		if !reflect.DeepEqual(res.JSON, *body) {
			t.Fatalf("res.JSON not match test json: res.JSON=%#v, testJSON=%#v\n", res.JSON, *body)
		}
	}
}

func TestSendFormBody(t *testing.T) {
	correctForm := map[string]string{"a": "a", "b": "1", "c": "true"}
	testBodys := []interface{}{
		correctForm,
		map[string]interface{}{"a": "a", "b": 1, "c": true},
		"a=a&b=1&c=true",
		[]byte("a=a&b=1&c=true"),
	}
	for k, v := range testBodys {
		res := NormalRes{}
		err := Open().
			SetBody(v).
			Post(dumpURL + "/post?qk=qk").Unmarshal(&res)
		if err != nil {
			t.Fatal(k, err)
		}
		if !reflect.DeepEqual(correctForm, res.Form) {
			t.Fatalf("res.Form not correct, res.Form=%#v, correct=%#v\n", res.Form, correctForm)
		}
	}
}

func TestTimeoutErr(t *testing.T) {
	cli := NewClient(time.Second*2, FlagLogOn, nil)
	body, err := cli.Open().Get(dumpURL + "/delay/3").RespBody()
	if !IsTimeout(err) {
		t.Fatal("err is not timeout err", err, err.Error())
	}
	t.Logf("timeout request ret: %#v, %s\n", err, body)

	res := NormalRes{}
	err = cli.Open().Get(dumpURL + "/delay/3").Unmarshal(&res)
	if !IsTimeout(err) {
		t.Fatal("err is not timeout err", err, err.Error())
	}
	t.Logf("timeout request res: %#v, %#v\n", err, res)
}

func TestSendFileBody(t *testing.T) {
	cli := NewClient(time.Second*20, FlagLogOn, nil)

	testBodys := []interface{}{
		map[string]interface{}{"posta": "postav", "postb": 1, "postc": true, "@file1": imgFile},
	}

	for k, v := range testBodys {
		res := NormalRes{}
		err := cli.Open().
			EnableAtUpload().
			//DisableAtUpload().
			SetBody(v).
			SetQueryParam("func", "TestSendFileBody").
			Post(dumpURL + "/post").Unmarshal(&res)
		if err != nil {
			t.Fatal(k, err)
		}
		base64Data := strings.Split(res.Files["file1"], ",")[1]
		rawData, err := base64.StdEncoding.DecodeString(base64Data)
		if err != nil {
			t.Fatal(k, err)
		}
		h := md5.New()
		h.Write(rawData)
		resMD5 := hex.EncodeToString(h.Sum(nil))
		imgData, _ := ioutil.ReadFile(imgFile)
		h.Reset()
		h.Write(imgData)
		imgMD5 := hex.EncodeToString(h.Sum(nil))
		if imgMD5 != resMD5 {
			t.Fatal(k, `imgMD5 != resMD5`)
		}
	}
}

func TestRawResp(t *testing.T) {
	resp, err := Open().
		SetQueryParam("func", "TestRawResp").
		Delete(dumpURL + "/delete").Resp()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if body, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else {
		t.Log(string(body))
		res := NormalRes{}
		err = json.Unmarshal(body, &res)
		if err != nil {
			t.Fatal(err)
		}
		if res.Args["func"] != "TestRawResp" {
			t.Fatal(`res.Args["func"] != "TestRawResp"`)
		}
	}
}

func TestBeforeHookFunc(t *testing.T) {
	zr := Open()
	zr.BeforeHookFunc = func(zr *ZRequest) error {
		return errors.New("test hook")
	}
	_, err := zr.Get(dumpURL + "/get").Resp()
	if err == nil {
		t.Fatal("beforefunc err not returned")
	} else if err.Error() != "test hook" {
		t.Fatal("beforefunc", `err.Error() != "test hook"`)
	}
	t.Log(err)

	zr = Open()
	zr.BeforeHookFunc = func(zr *ZRequest) error {
		t.Logf("####contentType:%s\n", zr.headers.Get(HdrContentType))
		t.Logf("####bodybuf:%#v\n", zr.GetBodyBuf())
		return nil
	}
	zr.SetBody("a=1&b=2").Put(dumpURL + "/put")
}

func TestRespBodyN(t *testing.T) {
	cli := NewClient(time.Second*30, 0, nil)
	zr := cli.Open()
	body, err := zr.SetQueryParam("key", "val").Get(dumpURL + "/get").RespBodyN(1)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "{" {
		t.Fatal(err)
	}
	bodyLeft, err := ioutil.ReadAll(zr.resp.Body)
	if err == nil {
		t.Fatal("read on closed body not return error")
	}
	t.Logf("err: %#v", err)
	if len(bodyLeft) > 0 {
		t.Fatal("bodyLeft gt zero:", string(bodyLeft))
	}

	body, err = zr.RespBody()
	if err != nil || string(body) != "{" {
		t.Fatal("reread body err")
	}
	if bodyStr, err := zr.RespBodyStringN(1); err != nil || bodyStr != "{" {
		t.Fatal("reread body string n err")
	}
	if bodyStr, err := zr.RespBodyString(); err != nil || bodyStr != "{" {
		t.Fatal("reread body string err")
	}
}

func BenchmarkGet(b *testing.B) {
	res := NormalRes{}
	cli := NewClient(time.Second*30, 0, nil)
	for i := 0; i < b.N; i++ {
		err := cli.Open().SetQueryParam("key", "val").Get(dumpURL + "/get").Unmarshal(&res)
		if err != nil {
			b.Fatal(err)
		}
		if res.Args["key"] != "val" {
			b.Fatal(`res.Args["key"] != "val"`)
		}
	}
}

func BenchmarkStdHTTPGet(b *testing.B) {
	res := NormalRes{}
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(dumpURL + "/get?key=val")
		if err != nil {
			b.Fatal(err)
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			b.Fatal(err)
		}
		err = json.Unmarshal(body, &res)
		if err != nil {
			b.Fatal(err)
		}
		if res.Args["key"] != "val" {
			b.Fatal(`res.Args["key"] != "val"`)
		}
	}
}

func getFreePort() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer listener.Close()

	addr := listener.Addr().String()
	_, portString, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	return portString, nil
}

func TestMain(m *testing.M) {

	var testLocal bool
	var inbenchmark bool
	flag.BoolVar(&testLocal, "local", false, "if passed, will use local server for test")
	flag.Parse()

	defaultClient = NewClient(time.Second*30, FlagLogOn, nil)

	for _, v := range os.Args {
		if strings.Contains(v, "bench=") {
			inbenchmark = true
			break
		}
	}

	// if not testlocal and not in benchmark, test with online server
	if !testLocal && !inbenchmark {
		os.Exit(m.Run())
		return
	}

	fmt.Printf("\n########################\n")
	fmt.Println("We will run a local http server(httpbin) to test zrequest")
	fmt.Println("The httpbin app is written with python")
	fmt.Println("You need to install the httpbin and gunicorn before test")
	fmt.Println("Home page: http://httpbin.org")

	freePort, err := getFreePort()
	if err != nil {
		panic("get free port failed:" + err.Error())
	}

	fmt.Println("httpbin listen on: localhost:" + freePort)
	fmt.Println("run command: gunicorn -b localhost:"+freePort, "httpbin:app")
	fmt.Printf("########################\n\n")

	dumpURL = "http://localhost:" + freePort

	ctx, cancelf := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "gunicorn", "-b localhost:"+freePort, "httpbin:app")
	go func() {
		output, err := cmd.CombinedOutput()
		fmt.Printf("run httpbin: %s, %s\n", output, err)
	}()

	// waiting for gunicorn running
	time.Sleep(5 * time.Second)

	exitCode := m.Run()
	cancelf()
	time.Sleep(3 * time.Second)
	os.Exit(exitCode)
}
