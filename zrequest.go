package zrequest

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// GET HTTP method
	GET = "GET"

	// POST HTTP method
	POST = "POST"

	// PUT HTTP method
	PUT = "PUT"

	// DELETE HTTP method
	DELETE = "DELETE"

	// PATCH HTTP method
	PATCH = "PATCH"

	// HEAD HTTP method
	HEAD = "HEAD"

	// OPTIONS HTTP method
	OPTIONS = "OPTIONS"
)

var (
	HdrUserAgent   = http.CanonicalHeaderKey("User-Agent")
	HdrContentType = http.CanonicalHeaderKey("Content-Type")

	FormBoundary = "FormBoundarykKyzkULVDem6riojjQMsLa2tgA"

	PlainTextType        = "text/plain; charset=utf-8"
	JSONContentType      = "application/json; charset=utf-8"
	FormContentType      = "application/x-www-form-urlencoded"
	MultipartContentType = "multipart/form-data; boundary=" + FormBoundary
	StreamContentType    = "application/octet-stream"

	plainTextCheck = regexp.MustCompile("(?i:text/plain)")
	jsonCheck      = regexp.MustCompile("(?i:[application|text]/json)")
	xmlCheck       = regexp.MustCompile("(?i:[application|text]/xml)")
	formDataCheck  = regexp.MustCompile("(?i:(multipart/form\\-data)|(x\\-www\\-form\\-urlencoded))")
)

var (
	// TransportWithSSLSkipVerify is the default transport which not auth the ssl server
	TransportWithSSLSkipVerify = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	defaultClient    = NewClient(time.Second * 30)
	defaultUserAgent = "iyidan/zhttpclient(" + runtime.Version() + ")"

	// LogDetail log body and headers, should init it before any client request
	LogDetail = false
	LogBody   = false
	LogOn     = false

	logDumpReqPrefix = []byte("\n#request\n")
	logDumpResPrefix = []byte("\n\n#response\n")
	logger           = log.New(os.Stderr, "[zhttpclient]", log.Lshortfile|log.LstdFlags)
)

// SetLogger set the request output log
func SetLogger(lg *log.Logger) {
	logger = lg
}

// Open defaultClient
func Open() *ZRequest {
	return defaultClient.Open()
}

// ZClient wrapped with http client
type ZClient struct {
	c *http.Client
}

// NewClient all client share the same http.Transport obj
func NewClient(timeout time.Duration) *ZClient {
	jar, _ := cookiejar.New(nil)
	return &ZClient{
		c: &http.Client{
			Timeout: timeout,
			Jar:     jar,
		},
	}
}

// NewClientWithHttpClient wrapped with a exist http client
func NewClientWithHttpClient(hc *http.Client) *ZClient {
	return &ZClient{c: hc}
}

// NewClientWithTransport wrapped with a exist http transport
func NewClientWithTransport(timeout time.Duration, ts *http.Transport) *ZClient {
	jar, _ := cookiejar.New(nil)
	return &ZClient{
		c: &http.Client{
			Timeout:   timeout,
			Transport: ts,
			Jar:       jar,
		},
	}
}

// NewClientWithSSLSkipVerify client not auth ssl server
func NewClientWithSSLSkipVerify(timeout time.Duration) *ZClient {
	jar, _ := cookiejar.New(nil)
	return &ZClient{
		c: &http.Client{
			Timeout:   timeout,
			Transport: TransportWithSSLSkipVerify,
			Jar:       jar,
		},
	}
}

// Open a request
func (c *ZClient) Open() *ZRequest {
	zr := ZRequest{
		query:   url.Values{},
		headers: http.Header{},
		client:  c,
	}
	return zr.SetUserAgent(defaultUserAgent)
}

type ZRequest struct {
	method string
	urlStr string

	query url.Values

	body    interface{}
	bodyBuf io.Reader

	headers http.Header
	cookies []*http.Cookie

	basicAuthUsername string
	basicAuthPassword string

	req     *http.Request
	reqDump []byte

	client *ZClient

	startTime time.Time
	endTime   time.Time

	resp           *http.Response
	respBody       []byte
	respBodyParsed bool

	atUploadFlag bool

	err error

	BeforeHookFunc func(*ZRequest) error
}

// EnableAtUpload enable '@' prefix to upload a file, default is false
func (zr *ZRequest) EnableAtUpload() *ZRequest {
	zr.atUploadFlag = true
	return zr
}

// DisableAtUpload enable '@' prefix to upload a file, default is false
func (zr *ZRequest) DisableAtUpload() *ZRequest {
	zr.atUploadFlag = false
	return zr
}

func (zr *ZRequest) SetHeader(key, value string) *ZRequest {
	zr.headers.Set(key, value)
	return zr
}

func (zr *ZRequest) SetHeaders(headers map[string]string) *ZRequest {
	for key, value := range headers {
		zr.headers.Set(key, value)
	}
	return zr
}

func (zr *ZRequest) GetHeader() http.Header {
	return zr.headers
}

func (zr *ZRequest) SetUserAgent(ua string) *ZRequest {
	zr.headers.Set(HdrUserAgent, ua)
	return zr
}

func (zr *ZRequest) SetContentType(contentType string) *ZRequest {
	zr.headers.Set(HdrContentType, contentType)
	return zr
}

func (zr *ZRequest) SetCookie(ck *http.Cookie) *ZRequest {
	zr.cookies = append(zr.cookies, ck)
	return zr
}

func (zr *ZRequest) SetCookies(cks []*http.Cookie) *ZRequest {
	zr.cookies = append(zr.cookies, cks...)
	return zr
}

func (zr *ZRequest) SetCookieString(str string) *ZRequest {
	str = strings.Trim(strings.TrimSpace(str), ";")
	lst := strings.Split(str, "; ")
	for _, v := range lst {
		tmp := strings.SplitN(v, "=", 2)
		if len(tmp) == 2 {
			zr.SetCookie(&http.Cookie{Name: tmp[0], Value: tmp[1]})
		}
	}
	return zr
}

func (zr *ZRequest) SetBasicAuth(username, password string) *ZRequest {
	zr.basicAuthUsername = username
	zr.basicAuthPassword = password
	return zr
}

func (zr *ZRequest) SetQueryParam(key, value string) *ZRequest {
	zr.query.Set(key, value)
	return zr
}

func (zr *ZRequest) SetQueryParams(params map[string]string) *ZRequest {
	for key, value := range params {
		zr.query.Set(key, value)
	}
	return zr
}

func (zr *ZRequest) SetQueryParamAny(key string, value interface{}) *ZRequest {
	zr.query.Set(key, AnyToString(value))
	return zr
}

func (zr *ZRequest) SetQueryParamsAny(params map[string]interface{}) *ZRequest {
	for key, value := range params {
		zr.SetQueryParamAny(key, value)
	}
	return zr
}

func (zr *ZRequest) SetBody(body interface{}) *ZRequest {
	zr.body = body
	return zr
}

func (zr *ZRequest) GetBodyBuf() io.Reader {
	return zr.bodyBuf
}

func (zr *ZRequest) SetBodyBuf(buf io.Reader) *ZRequest {
	zr.bodyBuf = buf
	return zr
}

func (zr *ZRequest) GetUrlStr() string {
	return zr.urlStr
}

func (zr *ZRequest) SetUrlStr(urlStr string) *ZRequest {
	zr.urlStr = urlStr
	return zr
}

func (zr *ZRequest) doRequest(method, urlStr string) *ZRequest {

	zr.method = method

	// queryParams
	if len(zr.query) > 0 {
		reqUrl, err := url.Parse(urlStr)
		if err != nil {
			zr.err = err
			return zr
		}
		query := reqUrl.Query()
		for k, _ := range zr.query {
			query.Set(k, zr.query.Get(k))
		}
		reqUrl.RawQuery = query.Encode()
		urlStr = reqUrl.String()
	}
	zr.urlStr = urlStr

	// parse request body
	parseRequestBody(zr)
	if zr.err != nil {
		return zr
	}

	// call beforefunc
	if zr.BeforeHookFunc != nil {
		if err := zr.BeforeHookFunc(zr); err != nil {
			zr.err = err
			return zr
		}
	}

	// create request obj
	zr.req, zr.err = http.NewRequest(zr.method, zr.urlStr, zr.bodyBuf)
	if zr.err != nil {
		return zr
	}

	// headers
	zr.req.Header = zr.headers

	//  HTTP Basic Authentication
	if zr.basicAuthUsername != "" {
		zr.req.SetBasicAuth(zr.basicAuthUsername, zr.basicAuthPassword)
	}

	// cookies
	for _, ck := range zr.cookies {
		zr.req.AddCookie(ck)
	}

	// dump request
	if LogDetail {
		dump, err := httputil.DumpRequestOut(zr.req, LogBody)
		if err != nil {
			zr.reqDump = []byte(err.Error())
		} else {
			zr.reqDump = dump
		}
	}

	// do request
	zr.startTime = time.Now()
	resp, err := zr.client.c.Do(zr.req)
	zr.endTime = time.Now()

	if err != nil {
		zr.err = err
		return zr
	}
	zr.resp = resp
	return zr
}

func (zr *ZRequest) log() *ZRequest {
	if zr.err != nil {
		logger.Println(zr.Duration().String(), "-", zr.RespStatusCode(), "-", zr.method, zr.urlStr, "-", zr.err.Error())
		return zr
	}

	var detail []byte
	if LogDetail {
		detail = append(detail, logDumpReqPrefix...)
		detail = append(detail, zr.reqDump...)
		detail = append(detail, logDumpResPrefix...)
		dresp, _ := httputil.DumpResponse(zr.resp, LogBody)
		detail = append(detail, dresp...)
	}
	logger.Println(zr.Duration().String(), "-", zr.RespStatusCode(), "-", zr.method, zr.req.URL.String(), "-", string(detail))
	return zr
}

func (zr *ZRequest) Do(method, urlStr string) *ZRequest {
	return zr.doRequest(method, urlStr).log()
}

func (zr *ZRequest) Get(urlStr string) *ZRequest {
	return zr.Do(GET, urlStr)
}
func (zr *ZRequest) Post(urlStr string) *ZRequest {
	return zr.Do(POST, urlStr)
}
func (zr *ZRequest) Put(urlStr string) *ZRequest {
	return zr.Do(PUT, urlStr)
}
func (zr *ZRequest) Delete(urlStr string) *ZRequest {
	return zr.Do(DELETE, urlStr)
}
func (zr *ZRequest) Patch(urlStr string) *ZRequest {
	return zr.Do(PATCH, urlStr)
}
func (zr *ZRequest) Head(urlStr string) *ZRequest {
	return zr.Do(HEAD, urlStr)
}
func (zr *ZRequest) Options(urlStr string) *ZRequest {
	return zr.Do(OPTIONS, urlStr)
}

// Resp get raw response , the response.Body is not closed
func (zr *ZRequest) Resp() (*http.Response, error) {
	if zr.resp == nil {
		return nil, errors.New("resp is nil, request not completed")
	}
	return zr.resp, zr.err
}

func (zr *ZRequest) RespBody() ([]byte, error) {
	parseRespBody(zr)
	return zr.respBody, zr.err
}

func (zr *ZRequest) RespBodyString() (string, error) {
	parseRespBody(zr)
	if zr.err != nil {
		return "", zr.err
	}
	return string(zr.respBody), nil
}

func (zr *ZRequest) RespHeader(key string) string {
	if zr.resp == nil {
		return ""
	}
	return zr.resp.Header.Get(key)
}

func (zr *ZRequest) RespHeaders() http.Header {
	if zr.resp == nil {
		return nil
	}
	return zr.resp.Header
}

func (zr *ZRequest) RespCookies() []*http.Cookie {
	if zr.resp == nil {
		return nil
	}
	return zr.resp.Cookies()
}

func (zr *ZRequest) RespStatusCode() int {
	if zr.resp == nil {
		return 0
	}
	return zr.resp.StatusCode
}

func (zr *ZRequest) RespStatus() string {
	if zr.resp == nil {
		return ""
	}
	return zr.resp.Status
}

func (zr *ZRequest) Unmarshal(v interface{}) error {
	if zr.resp == nil {
		if zr.err != nil {
			return zr.err
		}
		return errors.New("resp is nil, request not completed")
	}
	if zr.resp.StatusCode > 199 && zr.resp.StatusCode < 300 {
		parseRespBody(zr)
		if zr.err != nil {
			return zr.err
		}
		respContentType := zr.resp.Header.Get(HdrContentType)
		if xmlCheck.MatchString(respContentType) {
			zr.err = xml.Unmarshal(zr.respBody, v)
			if zr.err != nil {
				zr.err = errors.New("xml.Unmarshal: " + zr.err.Error())
				return zr.err
			}
			return nil
		} else {
			zr.err = json.Unmarshal(zr.respBody, v)
			if zr.err != nil {
				zr.err = errors.New("json.Unmarshal: " + zr.err.Error())
				return zr.err
			}
			return nil
		}
	}
	return errors.New(zr.resp.Status)
}

func (zr *ZRequest) Duration() time.Duration {
	return zr.endTime.Sub(zr.startTime)
}

func parseRespBody(zr *ZRequest) {
	if zr.err != nil {
		return
	}
	if zr.resp == nil {
		return
	}
	if zr.respBodyParsed {
		return
	}
	zr.respBodyParsed = true

	defer zr.resp.Body.Close()
	zr.respBody, zr.err = ioutil.ReadAll(zr.resp.Body)
}

func AnyToString(i interface{}) string {

	value := reflect.ValueOf(i)

	switch value.Kind() {

	case reflect.Ptr:
		return AnyToString(value.Elem().Interface())

	case reflect.String:
		return value.String()

	case reflect.Struct, reflect.Map:
		bjs, err := json.Marshal(i)
		if err != nil {
			return fmt.Sprintf("%v", i)
		}
		return string(bjs)

	case reflect.Slice:
		if ii, ok := i.([]byte); ok {
			if utf8.Valid(ii) {
				return string(ii)
			}
			return base64.StdEncoding.EncodeToString(ii)
		}
		fallthrough

	default:
		return fmt.Sprintf("%v", i)
	}
}

func parseRequestBody(zr *ZRequest) {

	if zr.err != nil {
		return
	}
	if zr.body == nil {
		return
	}
	contentType := zr.headers.Get(HdrContentType)

RETRY:
	value := reflect.ValueOf(zr.body)
	kind := value.Kind()

	if reader, ok := zr.body.(io.Reader); ok {
		zr.bodyBuf = reader

	} else if kind == reflect.Ptr {
		zr.body = value.Elem().Interface()
		goto RETRY

	} else if bbody, ok := zr.body.([]byte); ok {
		zr.bodyBuf = bytes.NewBuffer(bbody)

	} else if kind == reflect.String {
		if contentType == "" {
			zr.SetHeader(HdrContentType, FormContentType)
		}
		zr.bodyBuf = bytes.NewBufferString(value.String())

	} else if xmlCheck.MatchString(contentType) {
		bxml, err := xml.Marshal(zr.body)
		if err != nil {
			zr.err = err
			return
		}
		zr.bodyBuf = bytes.NewBuffer(bxml)

	} else if jsonCheck.MatchString(contentType) || (contentType == "" && (kind != reflect.Map)) {
		bjs, err := json.Marshal(zr.body)
		if err != nil {
			zr.err = err
			return
		}
		zr.bodyBuf = bytes.NewBuffer(bjs)

	} else if kind == reflect.Map && (contentType == "" || formDataCheck.MatchString(contentType)) {
		// auto detch contentType
		var formMap map[string]string
		var fileMap map[string]string
		switch tmp := zr.body.(type) {
		case map[string]interface{}:
			formMap = make(map[string]string)
			for k, v := range tmp {
				formMap[k] = AnyToString(v)
				if zr.atUploadFlag && strings.HasPrefix(k, "@") {
					if fileMap == nil {
						fileMap = make(map[string]string)
					}
					fileMap[k] = formMap[k]
					delete(formMap, k)
				}
			}
		case map[string]string:
			for k, v := range tmp {
				if zr.atUploadFlag && strings.HasPrefix(k, "@") {
					if fileMap == nil {
						fileMap = make(map[string]string)
					}
					fileMap[k] = v
					delete(tmp, k)
				}
			}
			formMap = tmp
		default:
			zr.err = errors.New("parseRequestBody: can not parse the request body ")
			return
		}
		// has file
		if fileMap == nil {
			zr.SetHeader(HdrContentType, FormContentType)
			u := url.Values{}
			for k, v := range formMap {
				u.Set(k, v)
			}
			zr.bodyBuf = bytes.NewBufferString(u.Encode())
		} else {
			// multi-part
			var part io.Writer
			var err error
			var file *os.File

			zr.SetHeader(HdrContentType, MultipartContentType)

			zr.bodyBuf = &bytes.Buffer{}
			w := multipart.NewWriter(zr.bodyBuf.(io.Writer))

			err = w.SetBoundary(FormBoundary)
			if err != nil {
				zr.err = err
				return
			}
			// form-value
			for k, v := range formMap {
				if err := w.WriteField(k, v); err != nil {
					zr.err = err
					return
				}
			}
			// file
			for k, filename := range fileMap {
				part, err = w.CreateFormFile(k[1:], filepath.Base(filename))
				if err != nil {
					zr.err = err
					return
				}
				file, err = os.Open(filename)
				if err != nil {
					zr.err = err
					return
				}
				_, err = io.Copy(part, file)
				file.Close()
				if err != nil {
					zr.err = err
					return
				}
			}
			w.Close()
		}

	} else {
		zr.err = errors.New("client parse request body failed")
	}
}

// IsTimeout go 1.6 http://stackoverflow.com/questions/23494950/specifically-check-for-timeout-error
func IsTimeout(err interface{}) bool {
	switch err := err.(type) {
	case net.Error:
		if err.Timeout() {
			return true
		}
	case *url.Error:
		if err, ok := err.Err.(net.Error); ok && err.Timeout() {
			return true
		}
	}
	return false
}
