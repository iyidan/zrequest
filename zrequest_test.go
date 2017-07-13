package zrequest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
	"time"
)

/*
<?php
if (!isset($_SERVER['PHP_AUTH_USER'])) {
    header('WWW-Authenticate: Basic realm="My Realm"');
    header('HTTP/1.1 401 Unauthorized');
    echo 'Text to send if user hits Cancel button';
    exit;
} elseif($_SERVER['PHP_AUTH_PW'] != "123456" || $_SERVER['PHP_AUTH_USER'] != "liwei") {
    header('HTTP/1.1 403 forbidden');
    echo "forbidden";
    exit;
}
$emptyObj = new stdClass();
echo json_encode(array(
    "GET" => count($_GET) > 0 ? $_GET : $emptyObj,
    "POST" => count($_POST) > 0 ? $_POST : $emptyObj,
    "rawBody" => file_get_contents("php://input"),
    "COOKIE" => count($_COOKIE) > 0 ? $_COOKIE : $emptyObj,
    "FILES" => count($_FILES) > 0 ? $_FILES : $emptyObj,
    "SERVER" => $_SERVER,
));
?>
*/
type DumpStruct struct {
	GET     map[string]string
	POST    map[string]string
	RawBody string `json:"rawBody"`
	COOKIE  map[string]string
	FILES   map[string]map[string]interface{}
	SERVER  map[string]interface{}
}

type User struct {
	Name string
	Age  int
	Male bool
}

var dumpUrl = "http://php.localhost.com/dumprequest.php?v=1"
var timeoutUrl = "http://php.localhost.com/timeout.php"

// ---------- start ------ //

func TestGet(t *testing.T) {

	res := DumpStruct{}
	err := Open().SetQueryParam("v2", "v2").SetQueryParamAny("v3", 3).
		SetCookie(&http.Cookie{Name: "testcookie", Value: "testcookiev"}).
		SetCookieString(" cka=ckav; ckb=ckbv;").
		SetHeader("testhd", "testhdv").
		SetBasicAuth("liwei", "123456").
		Get(dumpUrl).Unmarshal(&res)
	if err != nil {
		t.Fatal(err)
	}

	// query param
	if res.GET["v2"] != "v2" {
		t.Fatal(`res.GET["v2"] != "v2"`)
	}
	if len(res.POST) != 0 {
		t.Fatal(`len(res.POST) != 0`)
	}

	// cookie
	if res.COOKIE["testcookie"] != "testcookiev" {
		t.Fatal(`res.COOKIE["testcookie"] != "testcookiev"`)
	}
	if res.COOKIE["cka"] != "ckav" {
		t.Fatal(`res.COOKIE["cka"] != "ckav"`)
	}
	if res.COOKIE["ckb"] != "ckbv" {
		t.Fatal(`res.COOKIE["ckb"] != "ckbv"`)
	}

	// header
	if res.SERVER["HTTP_TESTHD"].(string) != "testhdv" {
		t.Fatal(`res.SERVER["HTTP_TESTHD"].(string) != "testhdv"`)
	}
}

func TestSendRawBody(t *testing.T) {
	raw := "aaaa"

	res := DumpStruct{}
	err := Open().
		SetBasicAuth("liwei", "123456").
		SetBody(raw).
		Post(dumpUrl).Unmarshal(&res)
	if err != nil {
		t.Fatal(err)
	}

	if res.RawBody != raw {
		t.Fatal(`res.RawBody != raw`)
	}
}

func TestSendJSONBody(t *testing.T) {
	body := &User{Name: "liwei", Age: 28, Male: true}
	bodyBytes, _ := json.Marshal(body)

	testBodys := []interface{}{
		&User{Name: "liwei", Age: 28, Male: true},
		User{Name: "liwei", Age: 28, Male: true},
		bodyBytes,
		`{"Name":"liwei","Age":28,"Male":true}`,
		bytes.NewBufferString(`{"Name":"liwei","Age":28,"Male":true}`),
	}

	for k, v := range testBodys {
		res := DumpStruct{}
		err := Open().
			SetBasicAuth("liwei", "123456").
			SetBody(v).
			//SetContentType(JSONContentType).
			Post(dumpUrl).Unmarshal(&res)
		if err != nil {
			t.Fatal(k, err)
		}
		t.Log("res.RawBody:", k, res.RawBody)
		if res.RawBody != string(bodyBytes) {
			t.Fatal(k, `res.RawBody != bodyStr`)
		}
	}
}

func TestSendFormBody(t *testing.T) {
	testBodys := []interface{}{
		map[string]string{"posta": "postav", "postb": "postbv"},
		map[string]interface{}{"posta": "postav", "postb": 1, "postc": true},
	}

	for k, v := range testBodys {
		res := DumpStruct{}
		err := Open().
			SetBasicAuth("liwei", "123456").
			SetBody(v).
			Post(dumpUrl).Unmarshal(&res)
		if err != nil {
			t.Fatal(k, err)
		}
		t.Log("res.POST:", k, res.POST)
	}
}

func TestTimeoutErr(t *testing.T) {
	cli := NewClient(time.Second * 2)
	body, err := cli.Open().SetQueryParamAny("sec", 3).Get(timeoutUrl).RespBody()
	if !IsTimeout(err) {
		t.Fatal("err is not timeout err", err, err.Error())
	}
	t.Logf("timeout request ret: %#v, %s", err, body)
}

func TestSendFileBody(t *testing.T) {
	imgFile := "/Users/liwei/Documents/images/FullSizeRender.jpg"

	testBodys := []interface{}{
		map[string]interface{}{"posta": "postav", "postb": 1, "postc": true, "@file1": imgFile},
	}

	for k, v := range testBodys {
		res := DumpStruct{}
		err := Open().
			EnableAtUpload().
			//DisableAtUpload().
			SetBasicAuth("liwei", "123456").
			SetBody(v).
			SetQueryParam("func", "TestSendFileBody").
			Post(dumpUrl).Unmarshal(&res)
		if err != nil {
			t.Fatal(k, err)
		}
		t.Log("res.FILES:", k, res.FILES)
	}
}

func TestRawResp(t *testing.T) {
	resp, err := Open().
		SetBasicAuth("liwei", "123456").
		SetQueryParam("func", "TestRawResp").
		Post(dumpUrl).Resp()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if body, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	} else {
		t.Log(string(body))
		res := DumpStruct{}
		err = json.Unmarshal(body, &res)
		if err != nil {
			t.Fatal(err)
		}
		if res.GET["func"] != "TestRawResp" {
			t.Fatal(`res.GET["func"] != "TestRawResp"`)
		}
	}

}

func TestBeforeHookFunc(t *testing.T) {
	zr := Open()
	zr.BeforeHookFunc = func(zr *ZRequest) error {
		return errors.New("test hook")
	}
	err := zr.Get(dumpUrl)
	if err == nil {
		t.Fatal("beforefunc err not returned")
	}
	t.Log(err)

	zr = Open()
	zr.BeforeHookFunc = func(zr *ZRequest) error {
		log.Printf("####contentType:%s\n", zr.headers.Get(HdrContentType))
		log.Printf("####bodybuf:%#v\n", zr.GetBodyBuf())
		return nil
	}
	zr.SetBody("a=1&b=2").Post(dumpUrl)
}

func TestSetLogger(t *testing.T) {
	SetLogger(log.New(os.Stderr, "test-zhttpclient", log.Lshortfile|log.LstdFlags))
	Open().SetBasicAuth("liwei", "123456").SetQueryParam("v2", "v2").SetQueryParamAny("v3", 3).Get(dumpUrl).RespBodyString()
}

func BenchmarkLog(b *testing.B) {
	b.StopTimer()

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Open().SetBasicAuth("liwei", "123456").SetQueryParam("v2", "v2").SetQueryParamAny("v3", 3).Get(dumpUrl).RespBodyString()
	}
	b.StopTimer()
}

func init() {
	LogBody = false
	LogDetail = false
	LogOn = true
}
