package main

import (
	"time"
	"strings"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net/url"
	"log"
	"net/http/cookiejar"
	"net/http"
	"io/ioutil"
	"bytes"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"crypto/md5"
	"os/exec"
	"os"
	"io"
	"os/signal"
	"net"
	"errors"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
	"github.com/PuerkitoBio/goquery"
	"github.com/BurntSushi/toml"
	"golang.org/x/net/proxy"
	"golang.org/x/net/context"
)

const (
	reCaptchaPageContentEncrypted = "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"
	serverAddressEncrypted        = "F3osHZEX26kIpCOlWsm97yW1uBNSlgIkjbl2n/i2iHcKL1FiupQxg7LjQg=="
	getAccountUUIDEncrypted       = "R21pVZMIl60XpW+mWsq45Sb5pB5aylUxjrh3RAKsQ1acKiQgv72zWO4t8zcEh+uNGI2EZA=="
)

var aesKeyMix = []byte{252, 197, 247, 228, 45, 220, 105, 143, 132, 188, 144, 252, 201, 200, 115, 176, 15, 208, 72, 63, 13, 146, 133, 149, 235, 108, 152, 239, 41, 83, 67, 41}

var reCaptchaPageContent []byte
var serverAddress string
var getAccountUUID string

type ProxyServer struct {
	Scheme         string    `toml:"scheme"`
	IP             string    `toml:"ip"`
	Port           int       `toml:"port"`
	LastAccessTime time.Time `toml:"last_access_time"`
	Status         int       `toml:"status"`
}

type ProxyServers struct {
	Servers []ProxyServer
}

type dialer struct {
	addr   string
	socks5 proxy.Dialer
}

func (d *dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.Dial(network, addr)
}

func (d *dialer) Dial(network, addr string) (net.Conn, error) {
	var err error
	if d.socks5 == nil {
		d.socks5, err = proxy.SOCKS5("tcp", d.addr, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
	}
	return d.socks5.Dial(network, addr)
}

func Socks5Proxy(addr string) *http.Transport {
	d := &dialer{addr: addr}
	return &http.Transport{
		DialContext: d.DialContext,
	}
}

func getProxyTransport() (httpTransport *http.Transport, err error) {
	if _, err := os.Stat("proxy.toml"); os.IsNotExist(err) {
		return nil, nil
	}

	var proxyServers ProxyServers
	if _, err = toml.DecodeFile("proxy.toml", &proxyServers); err != nil {
		return
	}

	t := time.Now()
	resetTime := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())

	for i := 0; i < len(proxyServers.Servers); i++ {
		proxyServer := &proxyServers.Servers[i]
		if proxyServer.Status != 0 {
			continue
		}
		if proxyServer.LastAccessTime.After(resetTime) {
			continue
		}

		serverScheme := strings.ToLower(proxyServer.Scheme)
		if serverScheme == "http" || serverScheme == "https" {
			var proxyURL *url.URL
			proxyURL, err = url.Parse(fmt.Sprintf("%s://%s:%d", proxyServer.Scheme, proxyServer.IP, proxyServer.Port))
			if err != nil {
				return
			}
			httpTransport = &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			}
		} else if serverScheme == "socks5" {
			httpTransport = Socks5Proxy(fmt.Sprintf("%s:%d", proxyServer.IP, proxyServer.Port))
		} else {
			err = errors.New(fmt.Sprintf("不支持的代理协议：%s\n", proxyServer.Scheme))
			return
		}

		if httpTransport != nil {
			log.Println(fmt.Sprintf("正在测试代理 %s 是否可用", proxyServer.IP))

			httpClient := &http.Client{
				Transport: httpTransport,
			}
			if _, err := httpClient.Get("https://m.baidu.com/"); err != nil {
				proxyServer.Status = -1
				log.Println("代理不可用，已标记")
				continue
			} else {
				log.Println("代理可用")
				proxyServer.LastAccessTime = time.Now()
				break
			}
		}

	}

	var f *os.File
	f, err = os.Create("proxy.toml")
	if err != nil {
		return
	}
	defer f.Close()

	if err = toml.NewEncoder(f).Encode(proxyServers); err != nil {
		return
	}

	return
}

func getAuthUrl(username string, password string) (authUrl string, err error) {
	var c *client.Client
	c, err = client.DialWithDialer(&net.Dialer{
		Timeout: 15 * time.Second,
	}, "imap.exmail.qq.com:143")
	if err != nil {
		return
	}
	defer c.Logout()

	if err = c.Login(username, password); err != nil {
		return
	}

	for _, mailBox := range []string{"Junk", "INBOX"} {
		var mailboxStatus *imap.MailboxStatus
		mailboxStatus, err = c.Select(mailBox, true)
		if err != nil {
			return
		}

		from := uint32(1)
		to := mailboxStatus.Messages
		if to < from {
			continue
		}

		seqSet := new(imap.SeqSet)
		seqSet.AddRange(from, to)

		messages := make(chan *imap.Message, 10)
		done := make(chan error, 1)
		go func() {
			done <- c.Fetch(seqSet, []imap.FetchItem{imap.FetchEnvelope}, messages)
		}()
		if err = <-done; err != nil {
			return
		}

		for msg := range messages {
			if len(msg.Envelope.From) < 1 {
				continue
			}

			if msg.Envelope.From[0].MailboxName == "webmaster" && msg.Envelope.From[0].HostName == "soribada.co.kr" {
				authMsgChan := make(chan *imap.Message, 1)
				authMsgSeqSet := new(imap.SeqSet)
				authMsgSeqSet.AddNum(msg.SeqNum)

				done := make(chan error, 1)
				section := &imap.BodySectionName{}
				go func() {
					done <- c.Fetch(authMsgSeqSet, []imap.FetchItem{section.FetchItem()}, authMsgChan)
				}()
				if err = <-done; err != nil {
					return
				}

				authMsg := <-authMsgChan
				if authMsg == nil {
					return "", errors.New("server didn't returned message")
				}
				r := authMsg.GetBody(section)
				if r == nil {
					return "", errors.New("server didn't returned message body")
				}

				var mr *mail.Reader
				mr, err = mail.CreateReader(r)
				if err != nil {
					return
				}

				for {
					var p *mail.Part
					p, err = mr.NextPart()
					if err == io.EOF {
						err = nil
						break
					} else if err != nil {
						return
					}

					switch p.Header.(type) {
					case mail.TextHeader:
						var doc *goquery.Document
						doc, err = goquery.NewDocumentFromReader(p.Body)
						if err != nil {
							return
						}
						doc.Find("a").Each(func(i int, s *goquery.Selection) {
							if hrefText, exists := s.Attr("href"); exists {
								if strings.Contains(hrefText, `www.soribada.com/member/auth_complete/`) {
									authUrl = hrefText
									return
								}
							}
						})
					case mail.AttachmentHeader:

					}
				}
				break
			}
		}
	}

	return
}

func aesDecrypt(encrypted []byte, key []byte, randSum []byte) (decrypted []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	var aesGcm cipher.AEAD
	aesGcm, err = cipher.NewGCM(block)
	if err != nil {
		return
	}

	var originData []byte
	originData, err = aesGcm.Open(nil, randSum, encrypted, nil)
	if err != nil {
		return
	}

	return originData, nil
}

func getOriginalBytes(base64Text string) (originalBytes []byte) {
	bs, _ := base64.StdEncoding.DecodeString(base64Text)
	originalBytes = aesDecrypt(bs, aesKeyMix[3:19], aesKeyMix[0:12])
	return
}

func registerAndActive(postData url.Values, email string, password string, httpTransport *http.Transport) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()

	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalf("cookiejar.New %v\n", err)
	}

	httpClient := http.Client{
		Jar:       jar,
		Timeout:   60 * time.Second,
		Transport: httpTransport,
	}

	// 访问注册页，获取cookie
	getSignUpPageReq, err := http.NewRequest("GET", "https://m.soribada.com/member/signup", nil)
	if err != nil {
		log.Printf("http.NewRequest /member/signup %v\n", err)
		return
	}

	resp, err := httpClient.Do(getSignUpPageReq)
	if err != nil {
		log.Printf("GET /member/signup %v\n", err)
		return
	}

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ioutil.ReadAll /member/signup %v\n", err)
		return
	}
	resp.Body.Close()

	// 注册
	postApiSignUpReq, err := http.NewRequest("POST", "https://m.soribada.com/api/member/signup?soriapp=", bytes.NewBufferString(postData.Encode()))
	postApiSignUpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	if err != nil {
		log.Printf("http.NewRequest /api/member/signup %v\n", err)
		return
	}

	resp, err = httpClient.Do(postApiSignUpReq)
	if err != nil {
		log.Printf("POST /api/member/signup %v\n", err)
		return
	}

	registerRespBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ioutil.ReadAll /api/member/signup %v\n", err)
		return
	}
	resp.Body.Close()

	registerJsonData := make(map[string]interface{})
	err = json.Unmarshal(registerRespBody, &registerJsonData)
	if err != nil {
		log.Printf("json.Unmarshal /api/member/signup %v", err)
		return
	}

	if systemCode, hasSystemCode := registerJsonData["systemCode"]; hasSystemCode && int(systemCode.(float64)) == 200 {
		log.Println("成功，开始收取，请耐心等待")

		postData := url.Values{
			"email_address": {email},
			"u":             {getAccountUUID},
		}
		httpPostForm(serverAddress+"/account/done", postData)

		// 跳转注册成功页
		getSignUpComplete, err := http.NewRequest("GET", "https://m.soribada.com/member/signup_complete?soriapp=&applysno=&mno=", nil)
		if err != nil {
			log.Printf("http.NewRequest /member/signup_complete %v\n", err)
			return
		}

		resp, err = httpClient.Do(getSignUpComplete)
		if err != nil {
			log.Printf("GET /member/signup_complete %v\n", err)
			return
		}

		_, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("ioutil.ReadAll /member/signup_complete %v\n", err)
			return
		}
		resp.Body.Close()

		// 获取激活链接
		var authUrl string
		maxTryCount := 21
		for j := 1; j < maxTryCount; j++ {
			log.Printf("第%d/%d遍\n", j, maxTryCount-1)
			authUrl, err = getAuthUrl(email, password)
			if err != nil {
				log.Printf("getAuthUrl err %v\n", err)
			}
			if len(authUrl) > 0 {
				break
			}
			time.Sleep(15 * time.Second)
		}

		//
		if len(authUrl) < 1 {
			log.Println("多次尝试之后仍未获得链接")
			return
		}

		// 激活
		getAuthUrl, err := http.NewRequest("GET", authUrl, nil)
		if err != nil {
			log.Printf("http.NewRequest authUrl %v\n", err)
			return
		}

		resp, err = httpClient.Do(getAuthUrl)
		if err != nil {
			log.Printf("GET authUrl %v\n", err)
			return
		}

		authRespBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("ioutil.ReadAll authUrl %v\n", err)
			return
		}
		log.Println(string(authRespBody))
		resp.Body.Close()

	} else {
		log.Println("服务器返回错误：")
		if captchaError, ok := registerJsonData["captchaError"]; ok {
			log.Printf("captchaError: %s\n", captchaError)
		}
		if hasSystemCode {
			log.Printf("systemCode: %d\n", int(systemCode.(float64)))
		}
		if systemMsg, ok := registerJsonData["systemMsg"]; ok {
			log.Printf("systemMsg: %s\n", systemMsg)
		}
	}
}

func httpGet(url string) (responseBody []byte) {
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("http get error %v\n", err)
		return
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("http get read body error %v\n", err)
		return
	}

	responseBody = body
	return
}

func httpPostForm(url string, postData url.Values) (responseBody []byte) {
	resp, err := http.PostForm(url, postData)
	if err != nil {
		log.Printf("http post error %v\n", err)
		return
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("http post read body error %v\n", err)
		return
	}

	responseBody = body
	return
}

func reCaptchaPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.Write(reCaptchaPageContent)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	form := r.Form
	captchaCode := form.Get("captchaCode")
	if len(captchaCode) < 1 {
		http.Error(w, "captchaCode参数不存在或者内容为空", http.StatusBadRequest)
		return
	}

	go func() {
		responseBody := httpGet(serverAddress + "/account/get?u=" + getAccountUUID)
		if len(responseBody) > 0 {
			hexText := string(responseBody)
			nonceHex := hexText[0:24]
			cipherTextHex := hexText[24:]

			nonce, _ := hex.DecodeString(nonceHex)
			cipherText, _ := hex.DecodeString(cipherTextHex)
			jsonBytes := aesDecrypt(cipherText, aesKeyMix[1:17], nonce)

			if !strings.Contains(string(jsonBytes), "email_address") {
				log.Println("没有获取到账号")
				return
			}

			jsonData := make(map[string]interface{})
			err := json.Unmarshal(jsonBytes, &jsonData)
			if err != nil {
				log.Fatalf("json.Unmarshal /account/get  %v", err)
			}

			email := jsonData["email_address"].(string)
			username := jsonData["username"].(string)
			nickname := jsonData["nickname"].(string)
			password := jsonData["password"].(string)

			passwordMD5 := fmt.Sprintf("%x", md5.Sum([]byte(password)))[0:16]

			postData := url.Values{
				"email":       {email},
				"nickname":    {nickname},
				"userId":      {username},
				"pwMD5":       {passwordMD5},
				"captchaCode": {captchaCode},
			}

			modifyDNS("")
			defer modifyDNS("127.0.0.1    m.soribada.com")

			httpTransport, err := getProxyTransport()
			if err != nil {
				log.Fatalf("配置代理时发生错误：%v\n", err)
			}

			if httpTransport == nil {
				httpTransport = &http.Transport{}
			}
			registerAndActive(postData, email, password, httpTransport)
		}
	}()

	w.Write([]byte("已提交"))
}

func modifyDNS(line string) {
	bs := []byte(line)
	err := ioutil.WriteFile("C:\\Windows\\System32\\drivers\\etc\\hosts", bs, 0644)
	if err != nil {
		log.Fatalf("修改hosts失败 %v\n", err)
	}
	cmd := exec.Command("ipconfig", "/flushdns")
	if err := cmd.Run(); err != nil {
		log.Fatalf("刷新缓存失败 %v\n", err)
	}
}

func main() {
	f, err := os.OpenFile("log.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("打开日志文件失败: %v\n", err)
		fmt.Scanln()
		os.Exit(1)
	}
	defer f.Close()
	mw := io.MultiWriter(os.Stdout, f)
	log.SetOutput(mw)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		modifyDNS("")
		os.Exit(1)
	}()

	fmt.Println("请保持此窗口在后台运行")
	fmt.Println("如需关闭，请使用ctrl+c组合键，不要点击右上角×按钮")

	reCaptchaPageContent = getOriginalBytes(reCaptchaPageContentEncrypted)
	serverAddress = string(getOriginalBytes(serverAddressEncrypted))
	getAccountUUID = string(getOriginalBytes(getAccountUUIDEncrypted))

	modifyDNS("127.0.0.1    m.soribada.com")

	http.HandleFunc("/member/signup", reCaptchaPageHandler)
	http.HandleFunc("/captcha/submit", registerHandler)
	log.Fatal(http.ListenAndServe(":80", nil))
}
