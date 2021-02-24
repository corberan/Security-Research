import requests
import base64
import time
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import md5
from bs4 import BeautifulSoup


def kakao_oauth(email, password, proxies=None):
    session = requests.session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.81 Safari/537.36'
    })

    session.get('https://www.mwave.me/cn/')
    session.get('https://www.mwave.me/cn/signin')

    r = session.post('https://www.mwave.me/cn/authSns', data={'snsTypeNm': 'kakao', 'initDivn': 'signin'},
                     proxies=proxies)
    session.headers.update({'Referer': r.url})

    aes_pass = None
    oauth_redirect_url = None

    soup = BeautifulSoup(r.text, 'lxml')
    hidden_inputs = soup.select_one('#login-form > fieldset').find_all('input', type='hidden')
    for hidden_input in hidden_inputs:
        if hidden_input['name'] == 'p':
            aes_pass = hidden_input['value']
        elif hidden_input['name'] == 'continue':
            oauth_redirect_url = hidden_input['value']

    session.get('https://track.tiara.kakao.com/queen/footsteps', params={
        'dummy': int(round(time.time() * 1000)) + round(random.random() * 2147483647),
        'ishome': 'U',
        'referer': 'https://www.mwave.me/cn/signin',
        'title': '',
        'sections': 'login',
        'pname': 'login',
        'version': '2.8.3',
        'dpr': 1,
        'cke': 'Y',
        'tz': '+8',
        'rand_id': int(round(time.time() * 1000)),
        'pck': 'Y',
        'puid': int(round(time.time() * 1000)),
        'url': 'https://accounts.kakao.com/login'
    }, proxies=proxies)

    session.get('https://track.tiara.kakao.com/queen/footsteps', params={
        'dummy': int(round(time.time() * 1000)) + round(random.random() * 2147483647),
        'ishome': 'U',
        'referer': 'https://www.mwave.me/cn/signin',
        'title': '',
        'sections': 'login',
        'pname': 'pageLogin',
        'version': '2.8.3',
        'dpr': 1,
        'cke': 'Y',
        'tz': '+8',
        'rand_id': int(round(time.time() * 1000)),
        'pck': 'Y',
        'puid': int(round(time.time() * 1000)),
        'url': 'https://accounts.kakao.com/login'
    }, proxies=proxies)

    r = session.post('https://accounts.kakao.com/weblogin/authenticate.json', data={
        'os': 'web',
        'webview_v': 2,
        'email': str(encrypt(email.encode(), aes_pass.encode()), 'UTF-8'),
        'password': str(encrypt(password.encode(), aes_pass.encode()), 'UTF-8'),
        'third': 'false',
        'k': 'true'
    }, proxies=proxies)
    result = r.json()

    if result['status'] != 0:
        raise RuntimeError(result['message'])

    session.get(oauth_redirect_url, proxies=proxies)

    r = session.get('https://www.mwave.me/cn/')
    soup = BeautifulSoup(r.text, 'lxml')
    nickname = soup.find('a', href='/my/shopping/dashBoard/list')
    print('用户[%s]登录成功' % nickname.string.replace('Hi, ', ''))
    return session


def bytes_to_key(data, salt, output=48):
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]


def pad(data):
    length = 16 - (len(data) % 16)
    return data + (chr(length) * length).encode()


def encrypt(message, pass_phrase):
    salt = get_random_bytes(8)
    key_iv = bytes_to_key(pass_phrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b'Salted__' + salt + aes.encrypt(pad(message)))


if __name__ == '__main__':
    kakao_oauth('', '', {
        'http': 'http://127.0.0.1:8118',
        'https': 'http://127.0.0.1:8118'
    })
