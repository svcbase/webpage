package webpage

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/svcbase/hierpath"

	"crypto/md5"
	"errors"
	"log"
	"strings"
	"time"
)

var timeConnectLimit time.Duration = 10  //10
var timeGetHeadLimit time.Duration = 10  //10
var timeGetPageLimit time.Duration = 120 //30

func SetGetHeadLimit(seconds int) {
	timeGetHeadLimit = time.Duration(seconds)
}

func GetPageHeader(url string) (resp *http.Response, weberr error) {
	righturl := url
	urlprefix := "http"
	if !strings.HasPrefix(righturl, urlprefix) {
		righturl = urlprefix + "://" + righturl
	}

	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			conn, err := net.DialTimeout(network, addr, timeConnectLimit*time.Second) //seconds connect limit
			if err != nil {
				return nil, err
			}
			deadline := time.Now().Add(timeGetHeadLimit * time.Second) //seconds get head limit
			e := conn.SetDeadline(deadline)
			if e != nil {
				return nil, e
			}
			return conn, nil
		},
		ResponseHeaderTimeout: timeGetHeadLimit * time.Second,
		DisableKeepAlives:     true,
	}
	client := &http.Client{Transport: transport, Timeout: timeGetPageLimit * time.Second}

	request, err := http.NewRequest("HEAD", righturl, nil)
	if err == nil {
		r, e := client.Do(request)
		return r, e
	}
	return nil, err
}

func PostJsonRequest(url, jsontxt string) (ret string, derr error) {
	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			conn, err := net.DialTimeout(network, addr, timeConnectLimit*time.Second) //seconds connect limit
			if err != nil {
				return nil, errors.New("net.DialTimeout:" + err.Error())
			}
			deadline := time.Now().Add(timeGetHeadLimit * time.Second) //seconds get head limit
			e := conn.SetDeadline(deadline)
			if e != nil {
				return nil, errors.New("net.SetDeadline:" + e.Error())
			}
			return conn, nil
		},
		ResponseHeaderTimeout: timeGetHeadLimit * time.Second,
		DisableKeepAlives:     true,
	}
	client := &http.Client{Transport: transport, Timeout: timeGetPageLimit * time.Second}

	req, err := http.NewRequest("POST", url, strings.NewReader(jsontxt))
	if err != nil {
		derr = errors.New("POST:" + err.Error())
		return
	}

	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp, err := client.Do(req)
	if err != nil {
		derr = errors.New("client.Do:" + err.Error())
	} else {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			derr = errors.New("ioutil.ReadAll:" + err.Error())
		}
		ret = string(body)
	}
	return
}

func PostJsonRequestResult2file(url, jsontxt, filetrunk string) (derr error, filename, fileextension string) { //filetrunk: filepath+filename  [no file extension]
	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			conn, err := net.DialTimeout(network, addr, timeConnectLimit*time.Second) //seconds connect limit
			if err != nil {
				return nil, errors.New("net.DialTimeout:" + err.Error())
			}
			deadline := time.Now().Add(timeGetHeadLimit * time.Second) //seconds get head limit
			e := conn.SetDeadline(deadline)
			if e != nil {
				return nil, errors.New("net.SetDeadline:" + e.Error())
			}
			return conn, nil
		},
		ResponseHeaderTimeout: timeGetHeadLimit * time.Second,
		DisableKeepAlives:     true,
	}
	client := &http.Client{Transport: transport, Timeout: timeGetPageLimit * time.Second}

	req, err := http.NewRequest("POST", url, strings.NewReader(jsontxt))
	if err != nil {
		derr = errors.New("POST:" + err.Error())
		return
	}

	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	r, e := client.Do(req)
	if e == nil {
		if r.StatusCode == 200 {
			fileextension = "."
			ct := ""
			contenttypee := r.Header["Content-Type"]
			if len(contenttypee) > 0 {
				ct = contenttypee[0]
				ctct := strings.Split(contenttypee[0], "/")
				if len(ctct) == 2 {
					fileextension += ctct[1]
				}
			}
			if strings.Contains(ct, "application/json") {
				ret := ""
				var buf [256]byte
				reader := r.Body
				for {
					n := 0
					n, derr = reader.Read(buf[0:])
					if derr == nil || (derr == io.EOF && n > 0) {
						ret += string(buf[:n])
					}
					if derr == io.EOF {
						break
					}
				}
				derr = errors.New(ret)
			} else {
				filename = filetrunk + fileextension
				var fo *os.File
				fo, derr = os.Create(filename)
				if derr == nil {
					var buf [9182]byte
					reader := r.Body
					for {
						n := 0
						n, derr = reader.Read(buf[0:])
						if derr == nil || (derr == io.EOF && n > 0) {
							if _, e = fo.Write(buf[:n]); e != nil {
								derr = e
								break
							}
						}
						if derr == io.EOF {
							derr = nil
							break
						}
					}
				}
				defer fo.Close()
			}
		} else {
			derr = errors.New("request status: " + r.Status)
		}
	}
	return
}

// HEAD + BODY
func GetPageData(url string) (data string, dt time.Duration, err error) {
	tmStart := time.Now()
	righturl := url
	urlprefix := "http"
	if !strings.HasPrefix(righturl, urlprefix) {
		righturl = urlprefix + "://" + righturl
	}
	response, err := GetWebpage(righturl)
	defer response.Body.Close()
	tmEnd := time.Now()

	if err == nil {
		b, err := httputil.DumpResponse(response, true)
		return string(b), tmEnd.Sub(tmStart), err
	}
	return "", tmEnd.Sub(tmStart), err
}

// BODY
func PickUrlData(url string) (data string, dt time.Duration, e error) {
	tmStart := time.Now()
	righturl := url
	urlprefix := "http"
	if !strings.HasPrefix(righturl, urlprefix) {
		righturl = urlprefix + "://" + righturl
	}
	response, err := GetWebpage(righturl)
	if err == nil {
		defer response.Body.Close()
		var body bytes.Buffer
		/*int64*/ _, err = body.ReadFrom(response.Body)
		return body.String(), time.Now().Sub(tmStart), err
	} else {
		return "", time.Now().Sub(tmStart), errors.New("GetWebpage:" + err.Error())
	}
}
func StrMD5(ss string) string {
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(ss))
	return hex.EncodeToString(md5Ctx.Sum(nil))
}
func GetImage(url, salt, despath string) (urlpath string, dt time.Duration, e error) {
	client := &http.Client{
		Transport: &http.Transport{
			Dial:                  (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).Dial,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: timeGetHeadLimit * time.Second,
			ExpectContinueTimeout: 10 * time.Second,
			DisableKeepAlives:     true,
		},
		Timeout: timeGetPageLimit * time.Second,
	}
	var request *http.Request
	request, e = http.NewRequest("GET", url, nil)
	if e == nil {
		request.Header.Add("User-Agent", "Mozilla/4.0 (compatible; MSID 7.0; Windows NT 6.1)")
		var r *http.Response
		tmStart := time.Now()
		r, e = client.Do(request)
		if e == nil {
			if r.StatusCode == 200 {
				imageType := "."
				contenttypee := r.Header["Content-Type"]
				if len(contenttypee) > 0 {
					ctct := strings.Split(contenttypee[0], "/")
					if len(ctct) == 2 {
						imageType += ctct[1]
					}
				}
				filename := StrMD5(url+salt) + imageType
				urlpath = hierpath.UrlHierarchicalPath(3, filename)
				fullname := hierpath.MappingHierarchicalPath(3, despath, filename)
				var fo *os.File
				fo, e = os.Create(fullname)
				if e == nil {
					var buf [9182]byte
					reader := r.Body
					for {
						n := 0
						//tS := time.Now()
						n, e = reader.Read(buf[0:])
						if e == nil || (e == io.EOF && n > 0) {
							//fmt.Println(n, time.Now().Sub(tS))
							if _, e = fo.Write(buf[:n]); e != nil {
								break
							}
						}
						if e == io.EOF {
							e = nil
							break
						}
					}
				}
				defer fo.Close()
				dt = time.Now().Sub(tmStart)
			}
		}
	}
	return
}

func WriteBody2File(url, filename string) (dt time.Duration, e error) {
	tmStart := time.Now()
	response, err := GetWebpage(url)
	defer response.Body.Close()
	tmEnd := time.Now()

	if err == nil {
		fo, err := os.Create(filename)
		if err != nil {
			return tmEnd.Sub(tmStart), err
		}
		defer fo.Close()

		var buf [1024]byte
		reader := response.Body
		for {
			n := 0
			n, err = reader.Read(buf[0:])
			rerr := err
			if err == nil || (err == io.EOF && n > 0) {
				if _, err = fo.Write(buf[:n]); err != nil {
					break
				}
			}
			if rerr == io.EOF {
				err = nil
				break
			}
		}
	}
	return tmEnd.Sub(tmStart), err
}

func GetPage2File(url, filename string) (dt time.Duration, err error) {
	tmStart := time.Now()
	response, err := GetWebpage(url)
	defer response.Body.Close()
	tmEnd := time.Now()

	if err == nil {
		fo, err := os.Create(filename)
		if err != nil {
			panic("create file error!")
		}
		defer fo.Close()
		err = response.Write(fo)

		/*ss := response.Proto+" "+response.Status+"\r\n";
			if len(response.TransferEncoding)>0 { ss += "Transfer-Encoding: "+response.TransferEncoding[0]+"\r\n" }
			_, err = fo.WriteString( ss );
			if err != nil { panic("error in writing status!") }

			err = response.Header.Write( fo )
			if err != nil { panic("error in writing head") }

			fo.WriteString( "\r\n" )

			var buf [512]byte
			reader := response.Body
			for {
				n, err := reader.Read(buf[0:])
				if err == nil {
					if _, err = fo.Write(buf[:n]); err != nil {
		        	    panic("error in writing body")
			        }
				}else{ break }
			}*/
	}
	return tmEnd.Sub(tmStart), err
}

func GetPageString(pageurl string, limit int, buf []byte) (header string, bodylen int, gerr error) {
	bodylen = 0
	var data bytes.Buffer

	righturl := pageurl
	urlprefix := "http"
	if !strings.HasPrefix(righturl, urlprefix) {
		righturl = urlprefix + "://" + righturl
	}

	tmStart := time.Now()
	response, err := GetWebpage(righturl)
	tmEnd := time.Now()

	if err == nil {
		defer response.Body.Close() //must confirm err is nil, otherwise it will cause memory or pointer error
		if response.ContentLength < int64(limit) {
			ss := tmStart.Format("2006-01-02 03:04:05") + " - " + fmt.Sprintf("%d", tmEnd.Sub(tmStart)) + "\r\n"
			ss += response.Proto + " " + response.Status + "\r\n" //		ss += "ServerIP: "+fmt.Sprintf("%d",iplong)+"\r\n";
			if len(response.TransferEncoding) > 0 {
				ss += "Transfer-Encoding: " + response.TransferEncoding[0] + "\r\n"
			}
			_, err = data.WriteString(ss)
			if err == nil {
				for k, v := range response.Header {
					if len(v) > 0 {
						ss = k + ": " + v[0] + "\r\n"
					}
					_, err = data.WriteString(ss)
					if err != nil {
						gerr = err
						break
					}
				}
				if err == nil {
					for bodylen < limit && gerr == nil {
						m, e := response.Body.Read(buf[bodylen:limit])
						bodylen += m
						if e == io.EOF {
							break
						}
						if e != nil {
							gerr = e
						}
					}
				}
			}
		} else {
			gerr = errors.New("ContentLength over limit")
		}
	}
	return data.String(), bodylen, gerr
}

func GetPageRawDataWithHeader(pageurl, method, query string, headermap map[string]string) (alltxt, headertxt, bodytxt string, err error) {
	var header, body bytes.Buffer

	righturl := pageurl
	urlprefix := "http"
	if !strings.HasPrefix(righturl, urlprefix) {
		righturl = urlprefix + "://" + righturl
	}

	tmStart := time.Now()
	var response *http.Response
	response, err = GetWebpageWithHeader(righturl, method, query, headermap)
	tmEnd := time.Now()
	if err == nil {
		defer response.Body.Close() //must confirm err is nil, otherwise it will cause memory or pointer error
		ss := tmStart.Format("2006-01-02 03:04:05") + " - " + fmt.Sprintf("%d", tmEnd.Sub(tmStart)) + "\r\n"
		ss += response.Proto + " " + response.Status + "\r\n"
		if len(response.TransferEncoding) > 0 {
			ss += "Transfer-Encoding: " + response.TransferEncoding[0] + "\r\n"
		}
		_, err = header.WriteString(ss)
		if err == nil {
			for k, v := range response.Header {
				if len(v) > 0 {
					ss = k + ": " + v[0] + "\r\n"
				}
				_, err = header.WriteString(ss)
				if err != nil {
					break
				}
			}
			ss = ""
			if err == nil {
				if _, err = header.WriteString("\r\n"); err == nil {
					body.ReadFrom(response.Body)
				}
			}
		}
	}
	headertxt = header.String()
	bodytxt = body.String()
	alltxt = headertxt + bodytxt
	return
}

func GetPageRawData(pageurl string, sizelimit int) (string, error) {
	var data, body bytes.Buffer

	righturl := pageurl
	urlprefix := "http"
	if !strings.HasPrefix(righturl, urlprefix) {
		righturl = urlprefix + "://" + righturl
	}

	tmStart := time.Now()
	response, err := GetWebpage(righturl)
	tmEnd := time.Now()
	if err == nil {
		defer response.Body.Close() //must confirm err is nil, otherwise it will cause memory or pointer error
		ss := tmStart.Format("2006-01-02 03:04:05") + " - " + fmt.Sprintf("%d", tmEnd.Sub(tmStart)) + "\r\n"
		ss += response.Proto + " " + response.Status + "\r\n"
		if len(response.TransferEncoding) > 0 {
			ss += "Transfer-Encoding: " + response.TransferEncoding[0] + "\r\n"
		}
		_, err = data.WriteString(ss)
		if err == nil {
			for k, v := range response.Header {
				if len(v) > 0 {
					ss = k + ": " + v[0] + "\r\n"
				}
				_, err = data.WriteString(ss)
				if err != nil {
					break
				}
			}
			ss = ""
			if err == nil {
				if _, err = data.WriteString("\r\n"); err == nil {
					if sizelimit > 0 {
						var bd *bytes.Buffer = bytes.NewBuffer(make([]byte, 0, sizelimit))
						defer func() {
							e := recover()
							if e == nil {
								return
							}
							if panicErr, ok := e.(error); ok && panicErr == bytes.ErrTooLarge {
								err = panicErr
								fmt.Println(pageurl, "PAGE TOO LARGE")
								return
							} else {
								panic(e)
							}
						}()
						_, err = bd.ReadFrom(response.Body)
						if err == nil {
							data.Write(bd.Bytes())
						}
					} else {
						body.ReadFrom(response.Body)
					}
				}
			}
		}
	}
	return data.String() + body.String(), err
}

/*totalsize := 0
var buf [1024]byte
reader := response.Body
for {
	n := 0
	n, err = reader.Read(buf[0:])
	rerr := err
	if err==nil || (err==io.EOF && n>0) {
		totalsize += n
		if totalsize<sizelimit {
			if _, err = data.Write(buf[:n]); err != nil { break }
			//fmt.Println( totalsize,n,sizelimit,err )
		}else{ break }
	}
	if rerr == io.EOF {
		err = nil
		break
	}
}*/ //从response.Body提取数据至data buffer,耗费时间可能大于http远程请求, 当然也可以直接返回*Response以节约转换时间

func GetPageRawBody(pageurl string) (bytes.Buffer, error) {
	var data bytes.Buffer

	righturl := pageurl
	urlprefix := "http"
	if !strings.HasPrefix(righturl, urlprefix) {
		righturl = urlprefix + "://" + righturl
	}

	response, err := GetWebpage(righturl)

	if err == nil {
		defer response.Body.Close() //must confirm err is nil, otherwise it will cause memory or pointer error
		data.ReadFrom(response.Body)
	}
	return data, err
}

func GetPage2Buffer(pageurl string, data *bytes.Buffer) error {
	righturl := pageurl
	urlprefix := "http"
	if !strings.HasPrefix(righturl, urlprefix) {
		righturl = urlprefix + "://" + righturl
	}

	response, err := GetWebpage(righturl)

	if err == nil {
		defer response.Body.Close() //must confirm err is nil, otherwise it will cause memory or pointer error
		// If the buffer overflows, we will get bytes.ErrTooLarge.
		// Return that as an error. Any other panic remains.
		defer func() {
			e := recover()
			if e == nil {
				return
			}
			if panicErr, ok := e.(error); ok && panicErr == bytes.ErrTooLarge {
				err = panicErr
			} else {
				panic(e)
			}
		}()
		_, err = data.ReadFrom(response.Body)
	}
	return err
}

func DoDownloadFile(url, filepath string) (err error, dt time.Duration) {
	tmStart := time.Now()
	var resp *http.Response
	// Get the data
	resp, err = http.Get(url)
	if err != nil {
		dt = time.Now().Sub(tmStart)
		return
	}
	defer resp.Body.Close()

	// Create the file
	var out *os.File
	out, err = os.Create(filepath)
	if err != nil {
		dt = time.Now().Sub(tmStart)
		return
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	dt = time.Now().Sub(tmStart)
	return
}

func DownloadFile(url, filepath string) (err error) {
	err, _ = DoDownloadFile(url, filepath)
	return
}

func GetWebpage(url string) (resp *http.Response, weberr error) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("GetWebpage error:", url, err)
			log.Println("GetWebpage error:", url, err)
		}
	}()
	client := &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: timeGetHeadLimit * time.Second,
			ExpectContinueTimeout: 10 * time.Second,
			DisableKeepAlives:     true,
		},
		Timeout: timeGetPageLimit * time.Second,
	}
	request, err := http.NewRequest("GET", url, nil)
	if err == nil {
		request.Header.Add("User-Agent", "Mozilla/4.0 (compatible; MSID 7.0; Windows NT 6.1)") //set http header
		//request.Header.Set("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		//request.Header.Set("Accept-Charset","GBK,utf-8;q=0.7,*;q=0.3")
		//request.Header.Set("Accept-Encoding","gzip,deflate,sdch")
		//request.Header.Set("Accept-Language","zh-CN,zh;q=0.8")
		//request.Header.Set("Cache-Control","max-age=0")
		//request.Header.Set("Connection","keep-alive")
		r, e := client.Do(request)
		return r, e
	}
	return nil, err
}

type RequestHeader struct {
	MapHeader map[string]string
}

func (rh *RequestHeader) Init() {
	rh.MapHeader = make(map[string]string)
	rh.MapHeader["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	//	rh.MapHeader["Accept-Encoding"] = "gzip,deflate"
	rh.MapHeader["Accept-Language"] = "zh-CN,zh;q=0.9"
	rh.MapHeader["Connection"] = "keep-alive"
	rh.MapHeader["Upgrade-Insecure-Requests"] = "1"
	rh.MapHeader["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

func (rh *RequestHeader) Add(key, val string) {
	rh.MapHeader[key] = val
}

func GetWebpageWithHeader(url, method, query string, mapheader map[string]string) (resp *http.Response, weberr error) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("GetWebpage error:", url, err)
			log.Println("GetWebpage error:", url, err)
		}
	}()
	client := &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: timeGetHeadLimit * time.Second,
			ExpectContinueTimeout: 10 * time.Second,
			DisableKeepAlives:     true,
		},
		Timeout: timeGetPageLimit * time.Second,
	}
	var request *http.Request
	var err error
	if len(query) > 0 {
		request, err = http.NewRequest(method, url, strings.NewReader(query))
	} else {
		request, err = http.NewRequest(method, url, nil)
	}
	if err == nil {
		for k, v := range mapheader {
			request.Header.Set(k, v)
		}
		r, e := client.Do(request)
		return r, e
	} else {
		fmt.Println("New Request Err:", err)
	}
	return nil, err
}
