# -*- coding: utf-8 -*-

import requests
from lxml import html
from io import BytesIO

def get_posturl(text):
    tree = html.fromstring(text)
    form = tree.xpath('/html/body/div/form[3]')[0]
    return 'http://zjuam.zju.edu.cn' + form.action

def check_passport(studentid, password):
    s = requests.Session()
    try:
        homepage = s.get("http://zjuam.zju.edu.cn/amserver/UI/Login")
        posturl = get_posturl(homepage.text)
        loginform = {'IDToken0': '', 'IDToken1': studentid, 'IDToken2': password,
                    'IDButton': 'undefined', 'goto':'', 'encoded': 'false', 'gx_charset': 'UTF-8'}
        response = s.post(posturl, data=loginform)
        if "ShowAction.do" in response.url:
            return True
        else:
            return False
    except Exception as e:
        raise IOError("Validation returns an error")

if __name__ == '__main__':
    print (check_passport("ID", "TTTT"))