import requests
import json
import urllib.parse

class ProxyVPNDetectionWrapper(object):
    def __init__(self, api_key, base_url):
        self.api_key = api_key
        self.base_url = base_url
        self.ip_detection_api_url = "api/json/ip/{}/{}?strictness={}&allow_public_access_points={}&fast={}&lighter_penalties={}&mobile={}"
        self.email_validation_api_url = "api/json/email/{}/{}?fast={}&timeout={}&suggest_domain={}&strictness={}&abuse_strictness={}"
        self.url_checker_api_url = "api/json/url/{}/{}?strictness={}"

    def ip_detection(self, ip, strictness=0, allow_public_access_points="true", fast="true", lighter_penalties="true", mobile="true"):
        # form api request url
        url = self.ip_detection_api_url.format(self.api_key, ip,
                                               strictness, allow_public_access_points,
                                               fast, lighter_penalties, mobile)
        url = self.base_url + url
        resp = requests.get(url)
        if resp.status_code == 200:
            return resp.json()
        return

    def email_validation(self, email, fast=False, timeout=7, suggest_domain=False, strictness=0, abuse_strictness=0):
        url = self.email_validation_api_url.format(self.api_key, email,
                                                   fast, timeout, suggest_domain,
                                                   strictness, abuse_strictness)
        url = self.base_url + url
        resp = requests.get(url)
        if resp.status_code == 200:
            return resp.json()
        return

    def url_checker(self, url, strictness=0):
        url = self.url_checker_api_url.format(self.api_key, urllib.parse.quote_plus(url), strictness)
        url = self.base_url + url
        resp = requests.get(url)
        if resp.status_code == 200:
            return resp.json()
        return
