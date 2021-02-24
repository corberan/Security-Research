# -*- coding:utf-8 -*-
import json
import time
import uuid
import warnings

import requests

import config
from tool import mail, proxy

warnings.filterwarnings("ignore")


class Register:
    def __init__(self):
        self.proxy_site = "local"
        self.proxy = proxy.get_proxy(self.proxy_site)
        self.session = requests.session()
        self.cookie_file_path = './' + "instagram.cookie"
        print("ok")

    @staticmethod
    def gen_uuid_str():
        return str(uuid.uuid5(uuid.uuid1(), str(uuid.uuid1()))).replace("-", "")

    def gen_user_profile(self):
        print("[*] Generate User Profile", end="...")
        user_profile = {
            'email': mail.get_mail_address("guerrillamail", self.proxy),  # 注册邮箱
            'first_name': Register.gen_uuid_str()[0:15],  # 全名（30字符以内）官网元素名称就是first_name
            'username': Register.gen_uuid_str()[0:15],  # 账号（不能重复）
            'password': Register.gen_uuid_str()  # 密码
        }
        print("ok")
        return user_profile

    def access_index_get_cookie(self):
        print("[*] Access Instagram Index Page", end="...")
        index_url = 'https://www.instagram.com'
        self.session.get(index_url, proxies=self.proxy, verify=False)
        print("ok")

    def user_profile_verify(self, user_profile):
        print("[*] Verify Generated User Profile", end="...")
        attempt_url = 'https://www.instagram.com/accounts/web_create_ajax/attempt/'
        header = {
            "Accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded",
            "accept-language": "zh-CN,zh;q=0.8,en;q=0.6",
            "origin": "https://www.instagram.com",
            "referer": "https://www.instagram.com/",
            "user-Agent": config.data["user-agent"],
            "X-csrftoken": self.session.cookies.get_dict()["csrftoken"],
            "X-Instagram-AJAX": "1",
            "X-Requested-With": "XMLHttpRequest",
        }
        response = self.session.post(attempt_url,
                                     data=user_profile,
                                     headers=header,
                                     proxies=self.proxy,
                                     verify=False)
        result = json.loads(response.text)
        return result["dryrun_passed"]

    def signup(self, user_profile):
        print("[*] Signup With User Profile", end="...")
        url = "https://www.instagram.com/accounts/web_create_ajax/"
        header = {
            "Accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded",
            "accept-language": "zh-CN,zh;q=0.8,en;q=0.6",
            "origin": "https://www.instagram.com",
            "referer": "https://www.instagram.com/",
            "user-Agent": config.data["user-agent"],
            "X-csrftoken": self.session.cookies.get_dict()["csrftoken"],
            "X-Instagram-AJAX": "1",
            "X-Requested-With": "XMLHttpRequest",
        }
        response = self.session.post(url,
                              data=user_profile,
                              headers=header,
                              proxies=self.proxy,
                              verify=False)
        result = json.loads(response.text)
        print(result)
        if len(result["errors"]["ip"][0]) > 0:
            if self.proxy_site == "local":
                proxy.refresh_tor_identity()

    def after_signup(self):
        self.session = requests.session()
        time.sleep(5)
        self.run()

    def run(self):
        # test proxy
        print("[*] Test Proxy", end="...")
        test_count = 1000
        for i in range(1, test_count):
            try:
                r = requests.session().get("https://www.instagram.com",
                    timeout=30,
                    proxies=self.proxy, 
                    verify=False)
                if r.status_code == requests.codes.ok:
                    break
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                print("proxy error, retry")
                if self.proxy_site == "local":
                    proxy.refresh_tor_identity()
                self.proxy = proxy.get_proxy(self.proxy_site)
        print("ok")

        print("[*] Proxy IP Info", end=": ")
        r = requests.session().get("https://ifconfig.co/json", proxies=self.proxy, verify=False)
        result = json.loads(r.text)
        print("<" + result["ip"], result["country"] + ">")

        # 访问首页拿到cookie
        self.access_index_get_cookie()
        # 新账号
        user_profile = None
        # 验证帐号是否正确
        user_profile_passed = False
        retry_time = 10
        for i in range(0, retry_time):
            user_profile = self.gen_user_profile()
            user_profile_passed = self.user_profile_verify(user_profile)
            if user_profile_passed:
                print("Passed!")
                break
            else:
                print("retry", end="...")
        if not user_profile_passed:
            print("after " + str(retry_time) + " times retry, user profile verify failed, please check")
            return
        #
        if user_profile is not None:
            print(user_profile)
            self.signup(user_profile)
            self.after_signup()
