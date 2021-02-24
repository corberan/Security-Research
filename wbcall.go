package main

import (
	"strings"
	"log"
	"flag"
	"time"
	"os"
	"bufio"
	"encoding/base64"
	"fmt"
	"crypto/rsa"
	"math/big"
	"strconv"
	"crypto/rand"
	"crypto/sha512"
	"github.com/google/go-querystring/query"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"sync"
	"io"
	"crypto/des"
	"crypto/cipher"
	"net/url"
)

const (
	singleAccountMaxCall = 101

	gPin           = "" // wb官方版本app secret
	gFrom          = "1084295010"                       // com.sn.wb 8.4.2 3604版本
	iParam         = "c206d09"
	cParam         = "android"
	wbVersionParam = "3604"
	wmParam        = "4251_4002"
	langParam      = "zh_CN"
	uaParam        = "xiaomi-mi 5__wb__8.4.1__android__android5.1.1"

	loginUrl       = "https://api.wb.cn/2/account/login"
	buttonEventUrl = "https://api.wb.cn/2/page/button"
	pKeyBase64     = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC46y69c1rmEk6btBLCPgxJkCxdDcAH9k7kBLffgG1KWqUErjdv+aMkEZmBaprEW846YEwBn60gyBih3KU518fL3F+sv2b6xEeOxgjWO+NPgSWmT3q1up95HmmLHlgVwqTKqRUHd8+Tr43D5h+J8T69etX0YNdT5ACvm+Ar0HdarwIDAQAB" // 登录时加密密码用的public key

	doCallSucceed             = 1
	doCallTooFast             = -1
	doCallDailyLimited        = -2
	doCallNetError            = -3
	doCallResultUnknown       = -4
	doCallAccountLock         = -5
	doCallSameContent         = -6
	doCallAccountNeedActivate = -7
	doCallServerBusy          = -8

	// _log的级别
	LOG_INFO    = 400
	LOG_VERBOSE = 550
	LOG_ERROR   = 200

	// des key 只用k3，其他是幌子，混淆二进制猜测
	k1 = "H22vXEIZs1UvdipKt0NTJpIh"
	k2 = "0S6cG8Wn8p4GGUoBN5IpFfZl"
	k3 = "XRNAbbazPbpMxde1vwA4kCJH"
	k4 = "zEA3XbINZfxc2fndrcaBw3RK"
	k5 = "9VS932M7iCxeFAe01Q6VbQ"

	netClientTimeOut = 15 * time.Second

	//httpProxyUrl = "http://HM972J58DRV370WD:6903E543DA0AA41A@http-dyn.abuyun.com:9020" // 下载wb验证码时返回字符串(null)
)

// 登录附带的query数据，已经减去了一部分，未仔细了解删去参数的含义
type loginQueryData struct {
	Networktype string `url:"networktype"`
	Uicode      string `url:"uicode"`
	ModuleID    string `url:"moduleID"`
	Wb_version  string `url:"wb_version"`
	C           string `url:"c"`
	I           string `url:"i"`
	P           string `url:"p"`
	S           string `url:"s"`
	U           string `url:"u"`
	Ft          int    `url:"ft"`
	Ua          string `url:"ua"`
	Wm          string `url:"wm"`
	V_f         int    `url:"v_f"`
	V_p         int    `url:"v_p"`
	Flag        int    `url:"flag"`
	From        string `url:"from"`
	Lang        string `url:"lang"`
	Oldwm       string `url:"oldwm"`
	Sflag       int    `url:"sflag"`
	Guestid     string `url:"guestid"`
	Cpt         string `url:"cpt"`
	CptCode     string `url:"cptcode"`
}

// 登录附带的post数据，作用顾名思义
type loginPostData struct {
	Device_name string `url:"device_name"`
	FirstLogin  int    `url:"firstLogin"`
	Getuser     int    `url:"getuser"`
	Getcookie   int    `url:"getcookie"`
	Getoauth    int    `url:"getoauth"`
}

type voteQueryData struct {
	Request_url    string `url:"request_url"`
	Networktype    string `url:"networktype"`
	Accuracy_level int    `url:"accuracy_level"`
	Cardid         string `url:"cardid"`
	Uicode         string `url:"uicode"`
	ModuleID       string `url:"moduleID"`
	Featurecode    string `url:"featurecode"`
	Wb_version     string `url:"wb_version"`
	C              string `url:"c"`
	I              string `url:"i"`
	S              string `url:"s"`
	Ft             int    `url:"ft"`
	Ua             string `url:"ua"`
	Wm             string `url:"wm"`
	Fid            string `url:"fid"`
	V_f            int    `url:"v_f"`
	V_p            int    `url:"v_p"`
	From           string `url:"from"`
	Gsid           string `url:"gsid"`
	Lang           string `url:"lang"`
	Lfid           string `url:"lfid"`
	Oldwm          string `url:"oldwm"`
	Sflag          int    `url:"sflag"`
	Luicode        string `url:"luicode"`
}

// 命令行参数
var accountFilePath = flag.String("i", "accounts.txt", "账号文件的位置")
var lineStrSep = flag.String("sep", " ", "账号和密码之间的分隔符")
var loginDuration = flag.Duration("ld", 5*time.Second, "账号登录的间隔时间")
var callDuration = flag.Duration("d", 5*time.Second, "单个账号打call的间隔时间")
var callMaxCount = flag.Int("mc", 0, "最大打call次数（线程数量多时有少许出入），0表示无限制")
var callThreadNum = flag.Uint("ma", 5, "允许同时登录的账号数")
var httpProxyUrl = flag.String("p", "", "用于下载验证码的动态代理地址")
var verbose = flag.Bool("verbose", false, "输出详细信息") // todo release前设为false

// some chan
var accountChan = make(chan [2]string) // work线程拿account用
var readFileDoneChan = make(chan int)  // 读账号文件线程用，阻塞主线程
var workDoneChan = make(chan int)      // work线程用，阻塞主线程

// global variable
var callCount uint // 打call次数，用于控制最大打call次数
var callCountMutex sync.Mutex

var lastLoginTime = time.Unix(0, 0) // 上次有账号登录时的时刻，用于控制两次登录间隔
var lastLoginTimeMutex sync.Mutex

var pKey rsa.PublicKey

// 输出日志用
func _log(level int, format string, v ...interface{}) {
	if !*verbose && level > 400 {
		return
	}
	log.Printf(format, v...)
}

// 提取文本行中的账号密码
func parseNameAndPass(line string) (username string, password string, ok bool) {
	lineStr := strings.TrimSpace(line)
	if loc := strings.Index(lineStr, *lineStrSep); !(0 < loc && loc < len(lineStr)-1) { // 分隔符不能在字符串首尾
		_log(LOG_ERROR, "账户%s格式不正确，已跳过\n", line)
		return "", "", false
	}
	lineStrSplit := strings.SplitN(lineStr, *lineStrSep, 2) // split以找到的第一个sep将其前后两个字符串分开
	u := strings.TrimSpace(lineStrSplit[0])
	p := strings.TrimSpace(lineStrSplit[1])
	return u, p, true
}

// 读取账号密码到chan，一直占有文件，被work线程阻塞
func readAccountFileBlocked(path string) {
	defer func() {
		close(accountChan) // 只能由close来发出关闭信号
		readFileDoneChan <- 1
	}()
	//
	_log(LOG_VERBOSE, "读取文件%s\n", path)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			_log(LOG_ERROR, "文件%s不存在，请检查或使用-i指定文件位置\n", path)
			return
		} else {
			log.Fatal(err)
		}
	}
	defer file.Close()
	//
	scanner := bufio.NewScanner(file)
	for scanner.Scan() && !isCallDone() {
		n, p, ok := parseNameAndPass(scanner.Text())
		if ok {
			np := [2]string{n, p}
			accountChan <- np // 注意不要使用其他方式关闭读accountChan的线程，以免panic
		}
	}
	if err = scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func genPublicKey(pubKeyBase64 string) (key rsa.PublicKey) {
	decBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		log.Fatal(err)
	}
	hexStr := fmt.Sprintf("%x", decBytes)
	mStart := 29 * 2
	eStart := 159 * 2
	mLen := 128 * 2
	eLen := 3 * 2
	modulus := hexStr[mStart : mStart+mLen]
	exponent := hexStr[eStart : eStart+eLen]
	modulusInt := big.NewInt(0)
	modulusInt.SetString(modulus, 16)
	exponentInt, err := strconv.ParseInt(exponent, 16, 32)
	if err != nil {
		log.Fatal(err)
	}
	return rsa.PublicKey{N: modulusInt, E: int(exponentInt)}
}

// 登录时query参数列表中的p，登录密码的公钥加密结果
func getP(password string) (key string) {
	out, err := rsa.EncryptPKCS1v15(rand.Reader, &pKey, []byte(password))
	if err != nil {
		log.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(out)
}

func getSha512(input string) (out string) {
	s512 := sha512.New()
	s512.Write([]byte(input))
	return fmt.Sprintf("%x", s512.Sum(nil))
}

func hexByte2int(b uint8) (i uint8) {
	if b-48 <= 9 {
		return b - 48
	} else if b-65 > 5 {
		return b - 87
	} else {
		return b - 55
	}
}

// 登录时query参数列表中的s，关键代码，勿扩散
func calculateS(uid string) (s string) {
	originString := getSha512(gPin + uid + gFrom)
	keyString := getSha512(gFrom)
	i := 0
	var result []string
	for loop := 0; loop < 8; loop++ {
		i += int(hexByte2int(keyString[i]))
		result = append(result, string(originString[i]))
	}
	return strings.Join(result, "")
}

func httpPost(urlStr string, postData string) (result string, cookies []*http.Cookie, ok bool) {
	c := &http.Client{
		Timeout: netClientTimeOut,
	}
	resp, err := c.Post(urlStr,
		"application/x-www-form-urlencoded",
		strings.NewReader(postData))
	if err != nil {
		_log(LOG_ERROR, "%v\n", err)
		return "", nil,false
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		_log(LOG_ERROR, "%v\n", err)
		return "", nil,false
	}
	return string(body), resp.Cookies(),true
}

func httpGet(urlStr string) (result string, ok bool) {
	c := &http.Client{
		Timeout: netClientTimeOut,
	}
	resp, err := c.Get(urlStr)
	if err != nil {
		_log(LOG_ERROR, "%v\n", err)
		return "", false
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		_log(LOG_ERROR, "%v\n", err)
		return "", false
	}
	return string(body), true
}

func downloadImage(urlStr string, name string, cookies []*http.Cookie) (ok bool) {
	var transport *http.Transport
	if len(*httpProxyUrl) > 0 {
		httpProxy, err := url.Parse(*httpProxyUrl)
		if err != nil {
			log.Fatal(err) // 这个还真的要fatal一下
		}
		transport = &http.Transport{
			Proxy: http.ProxyURL(httpProxy),
		}
	} else {
		transport = &http.Transport{}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   netClientTimeOut,
	}
	//
	request, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		log.Fatal(err) // 这个也，不过应该不会出错
	}
	for i := 0; i < len(cookies); i++ {
		request.AddCookie(cookies[i])
	}
	resp, err := client.Do(request)
	if err != nil {
		_log(LOG_ERROR, "%v\n", err)
		return false
	}
	defer resp.Body.Close()
	//
	gifFile, err := os.Create(name + ".gif")
	if err != nil {
		_log(LOG_ERROR, "%v\n", err)
		return false
	}
	_, err = io.Copy(gifFile, resp.Body)
	if err != nil {
		_log(LOG_ERROR, "%v\n", err)
		return false
	}
	defer gifFile.Close()
	return true
}

// 登录以获取几个参数供打call用
func login2GetParams(username string, password string, cpt string, cptCode string) (gSid string, uid string, ok bool) {
	_log(LOG_VERBOSE, "登录账户%s\n", username)
	q := loginQueryData{
		Networktype: "wifi",
		Uicode:      "10000058",
		ModuleID:    "701",
		Wb_version:  wbVersionParam,
		C:           cParam,
		I:           iParam,
		P:           getP(password),
		S:           calculateS(username + password),
		U:           username,
		Ft:          0,
		Ua:          uaParam,
		Wm:          wmParam,
		V_f:         2,
		V_p:         60,
		Flag:        1,
		From:        gFrom,
		Lang:        langParam,
		Oldwm:       wmParam,
		Sflag:       1,
		Guestid:     "1010019573720",
		Cpt:         cpt,
		CptCode:     cptCode,
	}
	p := loginPostData{
		Device_name: "xiaomi-mi 5",
		FirstLogin:  1,
		Getuser:     1,
		Getcookie:   1,
		Getoauth:    1,
	}
	queryData, err := query.Values(q)
	if err != nil {
		log.Fatal(err)
	}
	postData, err := query.Values(p)
	if err != nil {
		log.Fatal(err)
	}
	result, loginCookies, ok := httpPost(loginUrl+"?"+queryData.Encode(), postData.Encode()) // 没有返回cookie，长度为0
	if !ok {
		_log(LOG_ERROR, "%s: 登录时发生错误\n", username)
		return "", "", false
	}
	bs := []byte(result)
	resultMap := make(map[string]interface{})
	err = json.Unmarshal(bs, &resultMap)
	if err != nil {
		log.Fatal(err)
	}
	g, gOk := resultMap["gsid"]
	u, uOk := resultMap["uid"]
	if gOk && uOk {
		_log(LOG_VERBOSE, "获取用户%s数据成功\n", username)
		return g.(string), u.(string), true
	} else {
		// 验证码
		errno, hasErrno := resultMap["errno"]
		if hasErrno {
			errNumber := int(errno.(float64))
			if errNumber == -1005 {
				if annotationsNode, hasAnnotationsNode := resultMap["annotations"]; hasAnnotationsNode {
					cpt, hasCpt := (annotationsNode.(map[string]interface{}))["cpt"]
					pic, hasPic := (annotationsNode.(map[string]interface{}))["pic"]
					if hasCpt && hasPic {
						if downloadOk := downloadImage(pic.(string), cpt.(string), loginCookies); downloadOk {
							reader := bufio.NewReader(os.Stdin)
							_log(LOG_INFO, "[%s] - 请打开目录下的%s.gif查看验证码，回到此窗口输入后按回车键\n", username, cpt)
							text, _ := reader.ReadString('\n')
							os.Remove(cpt.(string) + ".gif")
							return login2GetParams(username, password, cpt.(string), strings.TrimSpace(text))
						} else {
							return login2GetParams(username, password, "", "")
						}
					}
				}
			} else if errNumber == 20003 {
				_log(LOG_ERROR, "[%s] - 账号异常，需要激活，已跳过该账号\n", username)
				return "", "", false
			}
		}
		_log(LOG_ERROR, "获取用户%s数据失败：%v\n", username, result)
		return "", "", false
	}
}

func addCallCount(count uint) {
	callCountMutex.Lock()
	callCount += count
	callCountMutex.Unlock()
}

func getCallCount() (count uint) {
	callCountMutex.Lock()
	defer callCountMutex.Unlock()
	return callCount
}

func isCallDone() (result bool) {
	callCountMutex.Lock()
	defer callCountMutex.Unlock()
	if *callMaxCount <= 0 {
		return false
	}
	return callCount >= uint(*callMaxCount)
}

// 3DES解密
func TripleDesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func genDoCallUrl(gSid string, uid string) (urlStr string) {
	// https://m.wb.cn/status/4236624743632786
	bs, err := base64.StdEncoding.DecodeString("6xNVmnIhNOQh/o2efLQV6T55HNIbIL+Z")
	if err != nil {
		log.Fatal(err)
	}
	dec, err := TripleDesDecrypt(bs, []byte(k3))
	if err != nil {
		log.Fatal(err)
	}
	mid := string(dec)
	unknownStr := "231219"
	activityId := "2793"
	newArtificialId := "1001"
	fid := fmt.Sprintf("%s_%s_newartificial_%s", unknownStr, activityId, newArtificialId)
	r := fmt.Sprintf("http://i.dianshi.wb.com/ji_gouvote?mid=%s&uid=%s&active_id=%s&na_id=%s", mid, uid, activityId, newArtificialId)
	v := voteQueryData{
		Request_url:    r,
		Networktype:    "wifi",
		Accuracy_level: 0,
		Cardid:         "Square_DoubleButton",
		Uicode:         "10000011",
		ModuleID:       "700",
		Featurecode:    "10000085",
		Wb_version:     wbVersionParam,
		C:              cParam,
		I:              iParam,
		S:              calculateS(uid),
		Ft:             0,
		Ua:             uaParam,
		Wm:             wmParam,
		Fid:            fid,
		V_f:            2,
		V_p:            60,
		From:           gFrom,
		Gsid:           gSid,
		Lang:           langParam,
		Lfid:           fid, // 3604版本有更改，暂时保持这样
		Oldwm:          wmParam,
		Sflag:          1,
		Luicode:        "10000011",
	}
	queryData, err := query.Values(v)
	if err != nil {
		log.Fatal(err)
	}
	return buttonEventUrl + "?" + queryData.Encode()
}

func doCall(doCallUrlStr string) (code int, msg string) {
	result, isReceiveData := httpGet(doCallUrlStr)
	if isReceiveData {
		bs := []byte(result)
		resultMap := make(map[string]interface{})
		err := json.Unmarshal(bs, &resultMap)
		if err != nil {
			log.Fatal(err)
		}
		//
		r, hasResult := resultMap["result"] // 打call失败也是1，注意打call地址生成不能有错
		m, hasMsg := resultMap["msg"]
		if hasResult && hasMsg {
			// 可以继续打call的返回数据中会包含["button"]["params"]["action"]
			hasAction := false
			buttonNode, hasButton := resultMap["button"]
			if hasButton {
				paramsNode, hasParams := (buttonNode.(map[string]interface{}))["params"]
				if hasParams {
					_, hasAction = (paramsNode.(map[string]interface{}))["action"]
				}
			}
			if !hasAction {
				return doCallDailyLimited, m.(string)
			}
			// 调整上下顺序，确保打call是成功的
			if int(r.(float64)) == 1 && m.(string) == "为她打call成功" { // json.Unmarshal float64, for JSON numbers
				return doCallSucceed, m.(string)
			}
		}
		if codeNode, hasCodeNode := resultMap["code"]; hasCodeNode {
			codeInt := int(codeNode.(float64))
			if codeInt == 20016 {
				return doCallTooFast, m.(string)
			} else if codeInt == 20034 {
				return doCallAccountLock, m.(string)
			} else if codeInt == 20019 {
				return doCallSameContent, m.(string)
			} else if codeInt == 20003 {
				return doCallAccountNeedActivate, m.(string)
			}
		}
		errNo, hasErrNo := resultMap["errno"]
		errMsg, hasErrMsg := resultMap["errmsg"]
		if hasErrNo && hasErrMsg {
			errNoInt := int(errNo.(float64))
			if errNoInt == 1040002 {
				return doCallServerBusy, errMsg.(string)
			}
		}
		return doCallResultUnknown, result
	} else {
		return doCallNetError, ""
	}
}

func doWork() {
	defer func() { workDoneChan <- 1 }()
	//
	for {
		np, ok := <-accountChan
		if !ok {
			break // 注意这个线程唯一的退出情况就是accountChan被close了，其他方式退出可能会导致readAccountBlocked没有接收者而报错
		}
		if isCallDone() {
			continue
		} else {
			_log(LOG_VERBOSE, "[%s] - 获取登录锁\n", np[0])
			lastLoginTimeMutex.Lock()
			_log(LOG_VERBOSE, "[%s] - 获取登录锁成功\n", np[0])
			if lastLoginTime != time.Unix(0, 0) {
				remainDuration := *loginDuration - time.Now().Sub(lastLoginTime)
				if remainDuration > 0 {
					_log(LOG_VERBOSE, "[%s] - 等待%v开始登录 \n", np[0], remainDuration)
					<-time.After(remainDuration)
				}
			}
		}
		gSid, uid, ok := login2GetParams(np[0], np[1], "", "") // 登录
		lastLoginTime = time.Now()
		lastLoginTimeMutex.Unlock() // 登录行为互斥
		//
		if ok {
			breakFor := false
			doCallUrlStr := genDoCallUrl(gSid, uid)
			for i := 0; i < singleAccountMaxCall && !isCallDone(); i++ {
				resultCode, msg := doCall(doCallUrlStr) // 打call
				switch resultCode {
				case doCallSucceed:
					addCallCount(1)
					_log(LOG_VERBOSE, "[%s] - %s\n", np[0], msg)
				case doCallTooFast:
					addCallCount(1)
					_log(LOG_VERBOSE, "[%s] - 发布内容过于频繁\n", np[0])
				case doCallDailyLimited:
					_log(LOG_INFO, "[%s] - %s\n", np[0], msg)
					breakFor = true
				case doCallNetError:
					_log(LOG_ERROR, "请检查网络\n")
				case doCallAccountLock:
					_log(LOG_ERROR, "[%s] - %s，已跳过该账号\n", np[0], msg)
					breakFor = true
				case doCallSameContent:
					addCallCount(1)
					_log(LOG_VERBOSE, "[%s] - %s\n", np[0], msg)
					//_log(LOG_INFO, "[%s] - 等待10分钟\n", np[0])
					//<-time.After(10 * time.Minute)
				case doCallAccountNeedActivate:
					_log(LOG_ERROR, "[%s] - %s\n", np[0], msg)
					breakFor = true
				case doCallServerBusy:
					_log(LOG_ERROR, "[%s] - %s\n", np[0], msg)
				case doCallResultUnknown:
					_log(LOG_ERROR, "[%s] - %s\n", np[0], msg)
					breakFor = true
				default:
					_log(LOG_INFO, "请设置打call结果的处理方式\n")
					os.Exit(1)
				}
				//
				if breakFor {
					break
				}
				_log(LOG_INFO, "共计打call次数：%d次\n", getCallCount())
				if isCallDone() { // 为了性能没有让doCall互斥，所以结果可能比maxCallCount稍多几次
					break
				}
				<-time.After(*callDuration) // 休息一下
			}
		}
	}
}

func main() {
	flag.Parse()
	pKey = genPublicKey(pKeyBase64)
	//
	for i := uint(0); i < *callThreadNum; i++ {
		go doWork()
	}
	go readAccountFileBlocked(*accountFilePath)

	// 阻塞main直到线程完成
	<-readFileDoneChan
	for i := uint(0); i < *callThreadNum; i++ {
		<-workDoneChan
	}
	_log(LOG_INFO, "已结束，退出请按回车键或直接关闭窗口\n")
	reader := bufio.NewReader(os.Stdin)
	reader.ReadRune()
}
