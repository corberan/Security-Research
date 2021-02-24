# -*- coding:utf-8 -*-
import requests
import time
import random
import json
import os
from urllib import parse
from lxml import html
from PIL import Image
import copy
import csv
import warnings

import config
from tool import proxy, namegenerator, qqmailreceiver
from tool.captcha import captcha_recognize

# 忽略HTTPS警告
warnings.filterwarnings("ignore")


class Register:
    def __init__(self, email_address, password):
        self.email_address = email_address
        self.password = password
        self.nickname = None
        #
        self.session = requests.session()
        self.proxy = proxy.get_proxy("local")
        #
        self.act_as_human_on = True
        #
        self.auth_continue_url = None
        self.create_from = "kauth"  # 这个值在注册页面的body开始的js的config中可解析
        self.footsteps_referer = None
        self.footsteps_url = None
        self.authenticity_token = None
        self.verification_code = None
        self.mwave_auth_code = None
        self.post_data_for_mwave_ifuser001 = None
        self.post_data_for_mwave_ifuser002 = None
        #
        self.headers = {
            "User-Agent": config.data["user-agent"]
        }
        self.session.headers.update(self.headers)

    @staticmethod
    def refresh_tor_identity():
        proxy.refresh_tor_identity()

    def get_real_ip_address(self):
        r = requests.session().get("https://ifconfig.co/json", proxies=self.proxy, verify=False)
        result = json.loads(r.text)
        return result["ip"]

    def get_new_ip_address(self):
        file_path = "ips_expired.txt"
        while True:
            new_ip = self.get_real_ip_address()
            # 对比
            if os.path.exists(file_path):
                with open(file_path, "r+") as f:
                    ips_expired = f.read()
                    if new_ip not in ips_expired:
                        f.write(new_ip + "\n")
                        break
                    else:
                        Register.refresh_tor_identity()
                        time.sleep(2)
            else:
                with open(file_path, "w") as f:
                    f.write(new_ip + "\n")
                    break

    @staticmethod
    def raise_error(msg):
        raise Exception("unexpected_error", msg)

    @staticmethod
    def check_response(response_text):
        # status->int result->str
        status_or_result_in_json = 0
        if len(response_text) > 0:
            response_json = json.loads(response_text)
            if "status" in response_json:
                status_or_result_in_json = response_json["status"]
            elif "result" in response_json:
                status_or_result_in_json = int(response_json["result"])
        return status_or_result_in_json

    def act_as_human(self, wait_time):
        if self.act_as_human_on:
            # print("[*] {}秒后继续操作".format(wait_time))
            time.sleep(wait_time)

    def update_session_headers(self, name, value):
        self.headers[name] = value
        self.session.headers.update(self.headers)

    def kakao_footsteps(self, sections, pname):
        params = {
            "dummy": '%.0f' % (time.time() * 1000 + round(random.random() * 2147483647)),
            "ishome": "U",
            "referer": self.footsteps_referer,
            "title": "Kakao Web Login",  # 这里的空格会被转成+号，暂时没处理
            "sections": sections,
            "pname": pname,
            "version": "2.8.0",
            "dpr": 1,
            "cke": "Y",
            "tz": "+8",
            "rand_id": '%.0f' % (time.time() * 1000),
            "pck": "Y",
            "puid": '%.0f' % (time.time() * 1000),  # 源文件就是这么写的
            "url": self.footsteps_url
        }
        self.session.get("https://track.tiara.kakao.com/queen/footsteps",
                         params=params,
                         proxies=self.proxy,
                         verify=False)

    # 流程

    def mwave_auth_to_kakao_signup(self):
        response = self.session.get("http://www.mwave.me/auth/kakao",
                                    proxies=self.proxy,
                                    verify=False,
                                    allow_redirects=False)
        if response.status_code == 302:
            self.auth_continue_url = response.headers['Location']
        else:
            Register.raise_error("GET http://www.mwave.me/auth/kakao 没有跳转页面")

        # 跳转注册页面
        kakao_login_url = "https://accounts.kakao.com/login"
        kakao_signup_url = "https://accounts.kakao.com/weblogin/create_account"
        #
        params = {"continue": self.auth_continue_url}
        self.update_session_headers("Referer", "{}?{}".format(kakao_login_url, parse.urlencode(params)))
        response = self.session.get(kakao_signup_url,
                                    params=params,
                                    proxies=self.proxy,
                                    verify=False)

        self.update_session_headers("Referer", response.url)
        #
        tree = html.fromstring(response.text)
        input_node_value = tree.xpath("//input[@id='authenticity_token']/@value")
        self.authenticity_token = input_node_value[0]
        if len(self.authenticity_token) < 1:
            Register.raise_error("没有从注册页面中获取到authenticity_token")
        #
        self.footsteps_referer = kakao_login_url
        self.footsteps_url = kakao_signup_url

    def kakao_check_nickname(self):
        nickname_passed = False
        for i in range(15):
            nickname = namegenerator.gen_one_word_digit(lowercase=True)
            response = self.session.get("https://accounts.kakao.com/profiles/check_nickname.json",
                                        params={"os": "web", "nickname": nickname},
                                        proxies=self.proxy,
                                        verify=False)
            if Register.check_response(response.text) == 0:
                self.nickname = nickname
                nickname_passed = True
                break
            time.sleep(1)
        if not nickname_passed:
            Register.raise_error("多次尝试后昵称任不可用")

    def kakao_send_passcode_for_create(self):
        post_data = {
            "os": "web",
            "authenticity_token": self.authenticity_token,
            "email": self.email_address,
            "created_from": self.create_from
        }
        response = self.session.post("https://accounts.kakao.com/kakao_accounts/send_passcode_for_create.json",
                                     data=post_data,
                                     proxies=self.proxy,
                                     verify=False)
        status = Register.check_response(response.text)
        if status != 0:
            # {"status":-442,"message":"The email address you entered is not in the correct format."}
            if status == -442:
                print(response.text)
                print("30秒后重试")
                self.act_as_human(30)
                register_child = Register(self.email_address, self.password)
                register_child.get_new_ip_address()
                register_child.register()
            # {"status":-441,"message":"This email address is already registered for your Kakao account."}
            elif status == -441:
                # todo 跳转登录-连接，暂时先跳过，参考js中的处理方法
                print(response.text)
            else:
                Register.raise_error(response.text)
        return status

    def receive_email_find_passcode(self):
        verification_code_received = False
        for i in range(10):
            verification_code = qqmailreceiver.get_verification_code_from_mail(self.email_address, self.password)
            if verification_code is not None and len(verification_code) > 0:
                self.verification_code = verification_code
                verification_code_received = True
                break
            time.sleep(15)
            print("15秒后重试...")
        if not verification_code_received:
            Register.raise_error("多次重试后未收取到验证码")

    def kakao_check_passcode_for_create(self):
        post_data = {
            "os": "web",
            "email": self.email_address,
            "passcode": self.verification_code
        }
        response = self.session.post("https://accounts.kakao.com/kakao_accounts/check_passcode_for_create.json",
                                     data=post_data,
                                     proxies=self.proxy,
                                     verify=False)
        if Register.check_response(response.text) != 0:
            Register.raise_error(response.text)

    def kakao_create_account_with_profile(self):
        post_data = {
            "os": "web",
            "email": self.email_address,
            "password": self.password,
            "terms[0]": 30,
            "terms[30]": 30,
            "terms[40]": 30,
            "terms[50]": 30,
            "passcode": self.verification_code,
            "created_from": self.create_from,
            "profile": '{"nickname":\"%s\","gender":null,"birthday":{"yyyymmdd":%s}}' % (
                self.nickname, namegenerator.gen_year(1980, 1995) + namegenerator.gen_birthday())
        }
        # 注意：request在urlencoding时把空格转成+，所以profile字符串里不要有多余的空格
        response = self.session.post("https://accounts.kakao.com/kakao_accounts/create_account_with_profile.json",
                                     data=post_data,
                                     proxies=self.proxy,
                                     verify=False)
        status = Register.check_response(response.text)
        if status != 0:
            # {"status":-500,"message":"An unexpected error has occurred. The error may have been caused by
            # temporary errors in the server or in the network connection.
            # The Kakao Team is working to solve the problem."}'
            if status == -500:
                print("kakao注册完成时出现-500错误，跳过本次注册")
            else:
                Register.raise_error(response.text)
        return status

    def kakao_weblogin_authenticate(self):
        post_data = {
            "type": "w",
            "continue": self.auth_continue_url,
            "remember": "false",
            "email": self.email_address,
            "password": self.password,
            "callback_url": "https://accounts.kakao.com/cb.html",
            "scriptVersion": "1.4.2"
        }
        response = self.session.post("https://accounts.kakao.com/weblogin/authenticate",
                                     data=post_data,
                                     proxies=self.proxy,
                                     verify=False,
                                     allow_redirects=False)
        if response.status_code == 302:
            callback_url = response.headers['Location']
            callback_url_params = parse.parse_qs(parse.urlsplit(callback_url).query)
            if callback_url_params["status"][0] != '0':
                Register.raise_error(callback_url_params["message"][0])
            else:
                self.session.get(callback_url,
                                 proxies=self.proxy,
                                 verify=False)
        else:
            Register.raise_error("POST https://accounts.kakao.com/weblogin/authenticate 没有跳转页面")

    def kakao_auth_to_mwave_signup(self):
        response = self.session.get(self.auth_continue_url,
                                    proxies=self.proxy,
                                    verify=False)
        self.update_session_headers("Referer", self.auth_continue_url)
        #
        post_data = {}
        tree = html.fromstring(response.text)
        input_nodes = tree.xpath("//button[@id='acceptButton']/ancestor::form/descendant::input")
        for input_node in input_nodes:
            input_value = input_node.xpath("@value")[0]
            post_data[input_node.name] = input_value
            #
            if input_node.name == "stsc" and len(input_value) < 1:
                Register.raise_error("错误，没有登录成功，第三方连接页面缺少必要参数")
        #
        self.act_as_human(2)
        #
        post_data["user_oauth_approval"] = "true"
        response = self.session.post(self.auth_continue_url,
                                     data=post_data,
                                     proxies=self.proxy,
                                     verify=False,
                                     allow_redirects=False)
        if response.status_code == 302:
            # http://www.mwave.me/auth/kakao?code=(86chars)&state=(UUID)
            kakao_auth_callback_url_with_code = response.headers['Location']
            kakao_auth_callback_url_params = parse.parse_qs(parse.urlsplit(kakao_auth_callback_url_with_code).query)
            self.mwave_auth_code = kakao_auth_callback_url_params["code"][0]
            if len(self.mwave_auth_code) < 1:
                Register.raise_error("没有从第三方连接页面返回的链接中获得code值")
            else:
                # 继续跳转
                self.headers.pop("Referer")
                self.session.headers.update(self.headers)
                #
                response = self.session.get(kakao_auth_callback_url_with_code,
                                            proxies=self.proxy,
                                            verify=False)
                # 跳转到 http://www.mwave.me/signup
                self.update_session_headers("Referer", response.url)
        else:
            Register.raise_error("POST {} 没有跳转页面".format(self.auth_continue_url))

    def mwave_signup_step1(self):
        # 302 -> http://www.mwave.me/xx/account/register/agree
        response = self.session.get("http://www.mwave.me/account/register/agree",
                                    proxies=self.proxy,
                                    verify=False)
        self.update_session_headers("Referer", response.url)

        post_data_for_ifuser001 = {}
        tree = html.fromstring(response.text)
        input_nodes = tree.xpath("//form[@id='_defaultFrm']/input")
        for input_node in input_nodes:
            input_value = input_node.xpath("@value")[0]
            post_data_for_ifuser001[input_node.name] = input_value
            if input_node.name == "snsKey" and len(input_value) < 1:
                Register.raise_error("错误，mwave agree页面获取的snsKey为空")
        # 隐私和语言
        post_data_for_ifuser001["infoOttpAgreeYn"] = "false"
        post_data_for_ifuser001["langCd"] = "eng"  # tor代理基本都是eng

        self.act_as_human(1)

        # 同意协议
        post_data_for_ifuser001["sbscShapCd"] = 1  # 2 : Mobile Web  1 : PC Web
        response = self.session.post("http://www.mwave.me/api/member/IfUser001",
                                     data=post_data_for_ifuser001,
                                     proxies=self.proxy,
                                     verify=False)
        if Register.check_response(response.text) != 200:
            Register.raise_error(response.text)

        #
        response = self.session.get("http://www.mwave.me/memberSession?sessionTypeCd=temp",
                                    proxies=self.proxy,
                                    verify=False)
        if Register.check_response(response.text) != 200:
            Register.raise_error(response.text)

        #
        self.post_data_for_mwave_ifuser001 = copy.deepcopy(post_data_for_ifuser001)
        post_data_for_ifuser001.pop("langCd")
        response = self.session.post("http://www.mwave.me/en/account/register/information",  # tor代理就固定en
                                     data=post_data_for_ifuser001,
                                     proxies=self.proxy,
                                     verify=False)
        self.update_session_headers("Referer", response.url)

    def mwave_signup_step2(self):
        # 验证码识别
        captcha_image_path = 'mbrCaptcha.jpg'
        captcha_image_cuted_path = "{}_cut.jpg".format(captcha_image_path)

        ifuser002_passed = False
        for i in range(1, 16):
            # GET http://www.mwave.me/captcha/image?namespace=mbrCaptcha&cb=(ms)
            response = self.session.get(
                "http://www.mwave.me/captcha/image?namespace=mbrCaptcha&cb=%.0f" % (time.time() * 1000),
                stream=True,
                proxies=self.proxy,
                verify=False)
            if response.status_code == 200:
                with open(captcha_image_path, 'wb') as img_file:
                    for chunk in response:
                        img_file.write(chunk)
            del response

            # 裁剪图片
            if os.path.exists(captcha_image_path):
                img = Image.open(captcha_image_path)
                img_cuted = img.crop((175, 3, 330, 70))
                img_cuted.save(captcha_image_cuted_path)

            # 识别图片
            verification_code_text = captcha_recognize.run_predict(os.path.abspath(captcha_image_cuted_path))
            print("验证码识别结果为：{}".format(verification_code_text))

            # 测试验证码
            # result: "505", resultMessage: "Captcha Key Validate Failed. Please Retry!"
            post_data_for_ifuser002 = {
                "snsTypeCd": 3,
                "snsKey": self.post_data_for_mwave_ifuser001["snsKey"],
                "aliasNm": self.post_data_for_mwave_ifuser001["aliasNm"],
                "infoOttpAgreeYn": self.post_data_for_mwave_ifuser001["infoOttpAgreeYn"],
                "emailRcvYn": "false",
                "intrstCdList": "",
                "bthYear": namegenerator.gen_year(1980, 1995),
                "sexCd": 2,
                "cntryCd": "CHN",  # 考虑是否要选别的地区
                "email": "",
                "vd": verification_code_text,
                "langCd": self.post_data_for_mwave_ifuser001["langCd"]
            }
            response = self.session.post("http://www.mwave.me/api/member/IfUser002",
                                         data=post_data_for_ifuser002,
                                         proxies=self.proxy,
                                         verify=False)
            ifuser002_response_result = Register.check_response(response.text)
            if ifuser002_response_result == 200:
                self.post_data_for_mwave_ifuser002 = copy.deepcopy(post_data_for_ifuser002)
                ifuser002_passed = True
                break
            elif ifuser002_response_result == 505:
                print("验证码识别错误{}次，重试".format(i))
                self.session.get(
                    "http://www.mwave.me/en/cmmn/popup/alert?message=You%20have%20input%20wrong%20the%20characters.",
                    proxies=self.proxy,
                    verify=False)
                self.act_as_human(1)
            else:
                Register.raise_error(response.text)

        #
        if os.path.isfile(captcha_image_path):
            os.remove(captcha_image_path)
        if os.path.isfile(captcha_image_cuted_path):
            os.remove(captcha_image_cuted_path)
        #
        if not ifuser002_passed:
            Register.raise_error("多次重试后验证码任认证失败")

        #
        response = self.session.get("http://www.mwave.me/memberSession?sessionTypeCd=default",
                                    proxies=self.proxy,
                                    verify=False)
        if Register.check_response(response.text) != 200:
            Register.raise_error(response.text)

        #
        self.post_data_for_mwave_ifuser002.pop("vd")
        self.post_data_for_mwave_ifuser002.pop("langCd")
        response = self.session.post("http://www.mwave.me/en/account/register/complete",
                                     data=self.post_data_for_mwave_ifuser002,
                                     proxies=self.proxy,
                                     verify=False)
        if response.text.index(self.post_data_for_mwave_ifuser002["aliasNm"]) > 0:
            with open('./profiles/user_succeed.csv', 'a+') as f:
                f_csv = csv.writer(f)
                f_csv.writerow([self.email_address, self.password])
            print("注册完成")

    def register(self):
        print("开始注册帐号：{}".format(self.email_address))
        self.mwave_auth_to_kakao_signup()
        self.kakao_footsteps("signup", "step1")
        self.act_as_human(2)
        self.kakao_footsteps("signup|check_profile", "step2")
        self.act_as_human(10)
        self.kakao_check_nickname()
        # 新的ip能不能用还得这一步来确定，不能用就递归
        if self.kakao_send_passcode_for_create() != 0:
            return
        self.kakao_footsteps("signup|check_profile", "step3")
        self.act_as_human(10)
        self.receive_email_find_passcode()
        self.kakao_check_passcode_for_create()
        # 注册到最后一步会偶发-500错误，暂未查明原因，跳过本次注册
        if self.kakao_create_account_with_profile() != 0:
            return
        self.kakao_weblogin_authenticate()
        self.kakao_footsteps("signup|check_profile", "step4")
        self.kakao_auth_to_mwave_signup()
        self.mwave_signup_step1()
        self.act_as_human(3)
        self.mwave_signup_step2()
