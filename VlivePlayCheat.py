# -*- coding: utf-8 -*-
import threading
import random
import time
import json
import copy
import re
import requests
from urllib import parse
from requests.adapters import HTTPAdapter
import xml.etree.ElementTree as ET

import hmac
from hashlib import sha1
from base64 import b64encode
import uuid


# 视频类型
VIDEO_TYPE_LIVE = "live"  # 直播/预告
VIDEO_TYPE_VOD = "vod"  # 频道上传的视频

temp_mutex = threading.Lock()
vod_play_count = 0


class PlayVideo(threading.Thread):
    def __init__(self, master_seq, video_type, total_loop_count, cookies):
        super().__init__()
        self.master_seq = master_seq
        self.video_type = video_type
        self.total_loop_count = total_loop_count
        self.cookies = cookies
        self.join_leave_interval = 5  # 每次进入到离开的时间
        #
        self.channel_seq = 0  # 从每个方法第一个链接中获取
        self.service_id = 0  # 从playInfo返回的数据，vod视频play的参数
        self.master_video_id = None  # vod视频play时的参数
        self.device_key = None
        self.device_name = "C8817D"
        # 网络请求
        self.live_v3_url = "http://kr.apis.naver.com/globalV2/globalV/v3/live/{}".format(self.master_seq)
        self.live_api_url = "http://kr.apis.naver.com/globalV2/globalV/live/{}".format(self.master_seq)
        self.vod_v3_url = "http://kr.apis.naver.com/globalV2/globalV/v3/vod/{}".format(self.master_seq)
        self.vod_api_url = "http://kr.apis.naver.com/globalV2/globalV/vod/{}".format(self.master_seq)
        self.session = requests.Session()
        if self.video_type == VIDEO_TYPE_LIVE:
            self.session.mount(self.live_v3_url, HTTPAdapter(max_retries=5))
            self.session.mount(self.live_api_url, HTTPAdapter(max_retries=5))
        elif self.video_type == VIDEO_TYPE_VOD:
            self.session.mount(self.vod_v3_url, HTTPAdapter(max_retries=5))
            self.session.mount(self.vod_api_url, HTTPAdapter(max_retries=5))
        else:
            raise Exception("构造函数参数video_type不合法", "unexpected exception")
        #
        self.last_naver_play_count_jsessionid = None
        self.last_vlive_video_play_vod_jsessionid = None
        # 自定义
        self.play_interval = (60, 70)  # 两次播放随机间隔时间范围(s)
        self.locale = "zh_CN"  # 韩国 ko_KR 中国 zh_CN
        self.mcc = 460  # 韩国 450 中国 460
        self.gcc = "CN"  # 韩国 KR 中国 CN

    def configure(self):
        # vlive会检测UA，移动端的UA不能访问 http://www.vlive.tv/video/xxxxx，远程主机强制关闭
        if self.video_type == VIDEO_TYPE_LIVE:
            self.session.headers.update({
                "User-Agent": "Mozilla/5.0 (Linux; Android 4.4.2; C8817D Build/HuaweiC8817D) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 "
                              "Mobile Safari/537.36 Vapp(inapp; global_v; 100; 2.3.7)"
            })
        elif self.video_type == VIDEO_TYPE_VOD:
            self.session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0"
            })
        self.device_key = uuid.uuid5(uuid.NAMESPACE_DNS, 'python.org')

    @staticmethod
    def get_url_params(url):
        msgpad = '%.0f' % (time.time() * 1000)
        md = b64encode(
            hmac.new('y4nRKGR9QhCnP10vCJ4tvfUUHYpOMq9N8WRmWWTA9DHBVkd9t3xaRCUdeyYW5I3z'.encode('ascii'),
                     (url[:255] + msgpad).encode('ascii'), sha1).digest()
        )
        return {"msgpad": msgpad, "md": md}

    def join_and_leave(self):
        #
        v3_query = {
            "version": 1,
            "locale": self.locale,
            "mcc": self.mcc,
            "gcc": self.gcc,
            "platformType": "ANDROID",
            "device.key": self.device_key,
            "device.name": self.device_name
        }
        v3_url = "{}?{}".format(self.live_v3_url, parse.urlencode(v3_query))
        params = PlayVideo.get_url_params(v3_url)
        response = self.session.get(v3_url,
                                    params=params,
                                    cookies=self.cookies)
        response_json = json.loads(response.text)
        if response_json["code"] == 1000:
            self.channel_seq = response_json["result"]["channelSeq"]
        else:
            raise Exception(response_json["message"], "unexpected exception")
        #
        join_query = {
            "version": 1,
            "locale": self.locale,
            "mcc": self.mcc,
            "gcc": self.gcc,
            "platformType": "ANDROID"
        }
        join_url = "{}/join?{}".format(self.live_api_url, parse.urlencode(join_query))
        params = PlayVideo.get_url_params(join_url)
        post_data = {"masterSeq": self.master_seq, "channelSeq": self.channel_seq}
        #
        response = self.session.put(join_url,
                                    params=params,
                                    data=post_data,
                                    cookies=self.cookies)
        response_json = json.loads(response.text)
        if response_json["code"] != 1000:
            raise Exception(response_json["message"], "unexpected exception")
        #
        time.sleep(self.join_leave_interval)
        #
        leave_query = {
            "version": 1,
            "locale": self.locale,
            "mcc": self.mcc,
            "gcc": self.gcc,
            "platformType": "ANDROID",
            "device.key": self.device_key,
            "device.name": self.device_name
        }
        leave_url = "{}/leave?{}".format(self.live_api_url, parse.urlencode(leave_query))
        params = PlayVideo.get_url_params(leave_url)
        post_data = {"masterSeq": self.master_seq}
        #
        response = self.session.put(leave_url,
                                    params=params,
                                    data=post_data,
                                    cookies=self.cookies)
        response_json = json.loads(response.text)
        if response_json["code"] == 1000:
            print(response_json["result"]["watchedCount"])
        else:
            raise Exception(response_json["message"], "unexpected exception")

    def vod_play(self):
        global vod_play_count

        vod_query = {
            "version": 1,
            "locale": self.locale,
            "mcc": self.mcc,
            "gcc": self.gcc,
            "platformType": "ANDROID"
        }
        vod_url = "{}?{}".format(self.vod_v3_url, parse.urlencode(vod_query))
        params = PlayVideo.get_url_params(vod_url)
        response = self.session.get(vod_url,
                                    params=params,
                                    cookies=self.cookies)
        response_json = json.loads(response.text)
        if response_json["code"] == 1000:
            self.channel_seq = response_json["result"]["channelSeq"]
            print(response_json["result"]["playCount"])
        else:
            raise Exception(response_json["message"], "unexpected exception")
        #
        play_info_query = {
            "version": 1,
            "locale": self.locale,
            "mcc": self.mcc,
            "gcc": self.gcc,
            "platformType": "ANDROID",
            "device.key": self.device_key,
            "device.name": self.device_name,
            "ad": "true"
        }
        play_info_url = "{}/playInfo?{}".format(self.vod_v3_url, parse.urlencode(play_info_query))
        params = PlayVideo.get_url_params(play_info_url)
        response = self.session.get(play_info_url,
                                    params=params,
                                    cookies=self.cookies)
        response_json = json.loads(response.text)
        if response_json["code"] == 1000:
            self.master_video_id = response_json["result"]["meta"]["masterVideoId"]
            self.service_id = response_json["result"]["meta"]["serviceId"]
        else:
            raise Exception(response_json["message"], "unexpected exception")
        #
        play_query = {
            "version": 1,
            "locale": self.locale,
            "mcc": self.mcc,
            "gcc": self.gcc,
            "platformType": "ANDROID"
        }
        play_url = "{}/play?{}".format(self.vod_api_url, parse.urlencode(play_query))
        params = PlayVideo.get_url_params(play_url)
        post_data = {
            "channelSeq": self.channel_seq,
            "p": '{"os":"android",'
                 '"sid":"%s",'
                 '"u":"v",'
                 '"d":"%s",'
                 '"osv":"4.4.2",'
                 '"pt":"v_a",'
                 '"inout":"in",'
                 '"pv":"2.3.7",'
                 '"stp":0,'
                 '"vid":"%s",'
                 '"cc":"%s"}' % (self.service_id, self.device_name, self.master_video_id, self.gcc)
        }
        response = self.session.post(play_url,
                                     params=params,
                                     data=post_data,
                                     cookies=self.cookies)
        response_json = json.loads(response.text)

        temp_mutex.acquire(1)
        vod_play_count += 1
        print("-->", vod_play_count)
        temp_mutex.release()

        if response_json["code"] != 1000:
            raise Exception(response_json["message"], "unexpected exception")

    @staticmethod
    def get_rtt_str(rtt_timestamp):
        rrt_list = rtt_timestamp.split(",")
        if not rrt_list[2].isdigit():
            return None
        performance_timing_navigation_start = int(rrt_list[2]) - random.randint(500, 600)
        performance_timing_response_start = performance_timing_navigation_start + random.randint(300, 500)
        rrt_list.insert(1, str(performance_timing_navigation_start))
        rrt_list.append(str(performance_timing_response_start))
        return ','.join(rrt_list)

    def vod_play_pc(self):
        global vod_play_count

        # 模拟新请求
        if "Referer" in self.session.headers.keys():
            self.session.headers.pop("Referer")
        self.session.cookies.clear()

        # http://www.vlive.tv/video/xxxxx
        video_page_url = "http://www.vlive.tv/video/{}".format(self.master_seq)
        # 第一次访问，获得rtt值，作为后续logging的cookie参数
        response = self.session.get(video_page_url)
        first_video_page_rtt = None
        if "RTT_TIMESTAMP" in response.cookies.keys():
            first_video_page_rtt = response.cookies.get("RTT_TIMESTAMP")
        time.sleep(1)
        # 第二次访问，带上地区参数
        if self.gcc == "KR":
            timezone_offset = 0
        elif self.gcc == "CN":
            timezone_offset = -60
        else:
            print("请补充国家对应的timezoneOffset")
            return
        locale_cookies = {
            "timezoneOffset": str(timezone_offset),
            "userLanguage": self.locale.split("_")[0],
            "userCountry": self.gcc
        }
        # ------------------------
        if self.last_vlive_video_play_vod_jsessionid is not None:
            temp_cookies = copy.deepcopy(locale_cookies)
            temp_cookies["JSESSIONID"] = self.last_vlive_video_play_vod_jsessionid
            response = self.session.get(video_page_url, cookies=temp_cookies)
        else:
            response = self.session.get(video_page_url, cookies=locale_cookies)
        # ------------------------
        # 拿到channel_code
        init_pattern = re.compile(r'^[\S\s]*vlive\.tv\.common\.init\("\w{2,5}", "\w{2}", "(\w+)"\);[\S\s]*'
                                  r'vlive\.video\.init\(([\S\s]+?)\);[\S\s]*$')
        init_match = init_pattern.match(response.text)
        channel_code = init_match.groups()[0]
        # 拿videoId和key
        video_init_params_list = init_match.groups()[1].split(',')
        naver_video_info_query_key = video_init_params_list[6]\
            .replace("\n", "").replace("\t", "").replace('"', "").replace(' ', "")
        naver_video_info_query_video_id = video_init_params_list[5]\
            .replace("\n", "").replace("\t", "").replace('"', "").replace(' ', "")
        # 获得第二次的rtt，用于第二次logging
        second_video_page_rtt = None
        if "RTT_TIMESTAMP" in response.cookies.keys():
            second_video_page_rtt = response.cookies.get("RTT_TIMESTAMP")
            # print("second_video_page_rtt", second_video_page_rtt)
        # 会检查
        self.session.headers["Referer"] = video_page_url

        # 第一遍

        # 拿第一次访问video_page_url获得的rtt作为cookie参数来提交
        # http://www.vlive.tv/logging?url=/video/30028&width=xxxx&height=xxx
        width = random.uniform(1366, 1920)
        height = random.uniform(768, 1080)
        url = "http://www.vlive.tv/logging?url=/video/{}&width={}&height={}".format(self.master_seq, width, height)
        temp_cookies = copy.deepcopy(locale_cookies)
        temp_cookies["RTT"] = PlayVideo.get_rtt_str(first_video_page_rtt)
        if temp_cookies["RTT"] is None:
            self.last_naver_play_count_jsessionid = None
            self.last_vlive_video_play_vod_jsessionid = None
            return
        response = self.session.get(url, cookies=temp_cookies)
        # first_logging_jsessionid = response.cookies.get("JSESSIONID")

        # http://www.vlive.tv/auth/giftCoin
        response = self.session.get("http://www.vlive.tv/auth/giftCoin", cookies=locale_cookies)
        # first_gift_coin_jsessionid = response.cookies.get("JSESSIONID")

        # http://www.vlive.tv/auth/loginInfo?channelCode=E2B38F&_=1512296354703
        url = "http://www.vlive.tv/auth/loginInfo?channelCode={}".format(channel_code)
        response = self.session.get(url, cookies=locale_cookies)
        first_login_info_channel_code_jsessionid = response.cookies.get("JSESSIONID")

        # 这条可能不必要
        # http://www.vlive.tv/video/init/view?videoSeq=30028&channelCode=E2B38F&_=1512296354704
        url = "http://www.vlive.tv/video/init/view?videoSeq={}&channelCode={}".format(self.master_seq, channel_code)
        response = self.session.get(url, cookies=locale_cookies)

        # http://www.vlive.tv/auth/channels/subscription?channelCode=E2B38F&_=1512315077928
        temp_cookies = copy.deepcopy(locale_cookies)
        temp_cookies["JSESSIONID"] = first_login_info_channel_code_jsessionid
        url = "http://www.vlive.tv/auth/channels/subscription?channelCode={}".format(channel_code)
        response = self.session.get(url, cookies=temp_cookies)
        first_channels_subscription_jsessionid = response.cookies.get("JSESSIONID")

        # 第二遍
        time.sleep(1)  # 对应上面的sleep

        # http://www.vlive.tv/logging?url=/video/30028&width=xxxx&height=xxx
        url = "http://www.vlive.tv/logging?url=/video/{}&width={}&height={}".format(self.master_seq, width, height)
        temp_cookies = copy.deepcopy(locale_cookies)
        temp_cookies["RTT"] = PlayVideo.get_rtt_str(second_video_page_rtt)
        if temp_cookies["RTT"] is None:
            self.last_naver_play_count_jsessionid = None
            self.last_vlive_video_play_vod_jsessionid = None
            return
        if self.last_vlive_video_play_vod_jsessionid is not None:
            temp_cookies["JSESSIONID"] = self.last_vlive_video_play_vod_jsessionid
        else:
            temp_cookies["JSESSIONID"] = first_channels_subscription_jsessionid
        response = self.session.get(url, cookies=temp_cookies)
        # second_logging_jsessionid = response.cookies.get("JSESSIONID")

        # http://www.vlive.tv/auth/giftCoin
        # temp_cookies = copy.deepcopy(locale_cookies)
        # temp_cookies["JSESSIONID"] = first_channels_subscription_jsessionid
        response = self.session.get("http://www.vlive.tv/auth/giftCoin", cookies=temp_cookies)
        # second_gift_coin_jsessionid = response.cookies.get("JSESSIONID")

        # http://www.vlive.tv/auth/loginInfo?channelCode=E2B38F&_=1512296354703
        url = "http://www.vlive.tv/auth/loginInfo?channelCode={}".format(channel_code)
        # temp_cookies = copy.deepcopy(locale_cookies)
        # temp_cookies["JSESSIONID"] = first_channels_subscription_jsessionid
        response = self.session.get(url, cookies=temp_cookies)
        second_login_info_channel_code_jsessionid = response.cookies.get("JSESSIONID")

        # 这条可能不必要
        # http://www.vlive.tv/video/init/view?videoSeq=30028&channelCode=E2B38F&_=1512296354704
        url = "http://www.vlive.tv/video/init/view?videoSeq={}&channelCode={}".format(self.master_seq, channel_code)
        response = self.session.get(url, cookies=temp_cookies)

        # http://www.vlive.tv/auth/channels/subscription?channelCode=E2B38F&_=1512315077928
        temp_cookies = copy.deepcopy(locale_cookies)
        temp_cookies["JSESSIONID"] = second_login_info_channel_code_jsessionid
        url = "http://www.vlive.tv/auth/channels/subscription?channelCode={}".format(channel_code)
        response = self.session.get(url, cookies=temp_cookies)
        # second_channels_subscription_jsessionid = response.cookies.get("JSESSIONID")

        # http://global.apis.naver.com/rmcnmv/rmcnmv/vod_play_videoInfo.json?
        vod_play_video_info_query = {
            "key": naver_video_info_query_key,
            "pid": "rmcPlayer_{}{}".format('%.0f' % (time.time() * 1000), random.randint(1000, 9999)),
            "sid": 2024,
            "ver": "2.0",
            "devt": "html5_pc",
            "doct": "json",
            "ptc": "http",
            "cpt": "vtt",
            "ctls": '{"visible":{"fullscreen":true,"logo":false,"playbackRate":false,"scrap":false,"playCount":true,"commentCount":true,"title":true,"writer":true,"expand":false,"subtitles":true,"thumbnails":true,"quality":true,"setting":true,"script":false,"logoDimmed":true,"badge":true,"seekingTime":true,"linkCount":false,"createTime":false,"thumbnail":true},"clicked":{"expand":false,"subtitles":false}}',
            "cpl": self.locale,
            "lc": self.locale,
            "videoId": naver_video_info_query_video_id,
            "cc": self.gcc
        }
        url = "http://global.apis.naver.com/rmcnmv/rmcnmv/vod_play_videoInfo.json"
        if self.last_naver_play_count_jsessionid is not None:
            temp_cookies = {"JSESSIONID": self.last_naver_play_count_jsessionid}
            response = self.session.get(url, params=vod_play_video_info_query, cookies=temp_cookies)
        else:
            response = self.session.get(url, params=vod_play_video_info_query)
        response_json = json.loads(response.text)
        # print(response_json)
        # 返回数据中有count计数
        nave_play_count_url = None
        for api_source in response_json["meta"]["apiList"]:
            if api_source["name"] == "count":
                nave_play_count_url = api_source["source"]
        if nave_play_count_url is None:
            print("没有获得playCount url")
            return
        # print(nave_play_count_url)
        # 换韩国区返回 http://serviceapi.rmcnmv.naver.com/etc/pc.nhn?
        # 中国区返回 http://global.apis.naver.com/rmcnmv/rmcnmv/PlayCount.json?

        # http://www.vlive.tv/auth/loginInfo?channelCode=E2B38F&videoSeq=30028&comment=Y&_=1512315085557
        url = "http://www.vlive.tv/auth/loginInfo?channelCode={}&videoSeq={}&comment=Y".format(channel_code,
                                                                                               self.master_seq)
        temp_cookies = copy.deepcopy(locale_cookies)
        temp_cookies["JSESSIONID"] = second_login_info_channel_code_jsessionid
        response = self.session.get(url, cookies=temp_cookies)
        third_login_info_jsessionid = response.cookies.get("JSESSIONID")

        # m3u8

        # ts

        # http://global.apis.naver.com/rmcnmv/rmcnmv/PlayCount.json?
        naver_play_count_data = {
            "p": '{"pv":"4.4.10","sid":2024,"pt":"html5_pc","cc":"","vid":"%s","os":"Windows","osv":"10","stp":0,"d":";Firefox/57.0","inout":"in"}' % naver_video_info_query_video_id
        }
        if self.last_naver_play_count_jsessionid is not None:
            temp_cookies = {"JSESSIONID": self.last_naver_play_count_jsessionid}
            response = self.session.post(nave_play_count_url, data=naver_play_count_data, cookies=temp_cookies)
        else:
            response = self.session.post(nave_play_count_url, data=naver_play_count_data)
        self.last_naver_play_count_jsessionid = response.cookies.get("JSESSIONID")

        # http://www.vlive.tv/video/play/vod?videoSeq=30028&channelCode=E2B38F
        # 下次刷新页面用的就是第三次的loginInfo请求获得的cookie
        url = "http://www.vlive.tv/video/play/vod?videoSeq={}&channelCode={}".format(self.master_seq, channel_code)
        temp_cookies = copy.deepcopy(locale_cookies)
        temp_cookies["JSESSIONID"] = third_login_info_jsessionid
        response = self.session.get(url, cookies=temp_cookies)
        self.last_vlive_video_play_vod_jsessionid = third_login_info_jsessionid

        temp_mutex.acquire(1)
        vod_play_count += 1
        print("-->", vod_play_count)
        temp_mutex.release()

        # 计数
        vod_query = {
            "version": 1,
            "locale": self.locale,
            "mcc": self.mcc,
            "gcc": self.gcc,
            "platformType": "ANDROID"
        }
        vod_url = "{}?{}".format(self.vod_v3_url, parse.urlencode(vod_query))
        params = PlayVideo.get_url_params(vod_url)
        response = self.session.get(vod_url,
                                    params=params,
                                    cookies=self.cookies)
        response_json = json.loads(response.text)
        if response_json["code"] == 1000:
            self.channel_seq = response_json["result"]["channelSeq"]
            print(response_json["result"]["playCount"])
        else:
            raise Exception(response_json["message"], "unexpected exception")

    def run(self):
        self.configure()
        # 开始循环
        loop_count = 0
        while True:
            try:
                if self.video_type == VIDEO_TYPE_LIVE:
                    self.join_and_leave()
                elif self.video_type == VIDEO_TYPE_VOD:
                    self.vod_play_pc()
            except requests.exceptions.ConnectionError as ex:
                print(ex)
                pass
            # 循环控制
            if self.total_loop_count > 0:
                loop_count += 1
                if loop_count >= self.total_loop_count:
                    break
            # 间隔暂停
            temp_interval = random.randint(self.play_interval[0], self.play_interval[1])
            time.sleep(temp_interval)


if __name__ == '__main__':
    # 设定
    custom_video_type = VIDEO_TYPE_VOD  # 直播 VIDEO_TYPE_LIVE  视频 VIDEO_TYPE_VOD

    if custom_video_type == VIDEO_TYPE_LIVE:
        tree = ET.parse("VliveClickHeart.xml")
        cookie_nodes = tree.findall('.//Config/cookies/')
        for cookies_node in cookie_nodes:
            cookies_dict = dict(cookie_str.split("=", 1) for cookie_str in cookies_node.text.split("; "))
            PlayVideo(49581, custom_video_type, 0, {
                "NEO_SES": cookies_dict["NEO_SES"],
                "NEO_CHK": cookies_dict["NEO_CHK"]
            }).start()
            time.sleep(15)

    if custom_video_type == VIDEO_TYPE_VOD:
        for i in range(1):
            PlayVideo(32193, custom_video_type, 0, {}).start()
            time.sleep(30)
