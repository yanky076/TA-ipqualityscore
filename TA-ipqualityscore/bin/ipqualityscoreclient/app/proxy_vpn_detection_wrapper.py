# encoding = utf-8

import requests
import json
import urllib.parse
import concurrent.futures
import time

class ProxyVPNDetectionWrapper(object):
    def __init__(self, api_key, base_url, logger):
        self.api_key = api_key
        self.base_url = base_url
        self.logger = logger
        self.ip_detection_api_url = "api/json/ip/{}/{}?strictness={}&allow_public_access_points={}&fast={}&lighter_penalties={}&mobile={}"
        self.email_validation_api_url = "api/json/email/{}/{}?fast={}&timeout={}&suggest_domain={}&strictness={}&abuse_strictness={}"
        self.url_checker_api_url = "api/json/url/{}/{}?strictness={}"

    def request_get(self, url):
        return requests.get(url)

    def ip_detection_multithreaded(self, ips, strictness=0, allow_public_access_points="true", fast="true", lighter_penalties="true", mobile="true"):
        urls = []
        start_time = time.time()
        for ip in ips:
            url = self.ip_detection_api_url.format(self.api_key, ip,
                                               strictness, allow_public_access_points,
                                               fast, lighter_penalties, mobile)
            url = self.base_url + url
            urls.append(url)
        with concurrent.futures.ThreadPoolExecutor() as executor: # optimally defined number of threads
            res = [executor.submit(self.request_get, url) for url in urls]
            concurrent.futures.wait(res)
        
        end_time = time.time()
        duration = end_time - start_time
        self.logger.info('Total responses received: '+ str(len(res))+', Total time taken: '+str(duration)+' sec')
        
        results_dict = {}
        for i,ip in enumerate(ips):
            resp = res[i].result()   
            if resp.status_code == 200:
                self.logger.info('ip_address: '+ip+', status: API Call success, response: '+json.dumps(resp.json()))
                results_dict[ip] = resp.json()
        return results_dict

    def ip_detection(self, ip, strictness=0, allow_public_access_points="true", fast="true", lighter_penalties="true", mobile="true"):
        # form api request url
        url = self.ip_detection_api_url.format(self.api_key, ip,
                                               strictness, allow_public_access_points,
                                               fast, lighter_penalties, mobile)
        url = self.base_url + url
        resp = requests.get(url)
        if resp.status_code == 200:
            return resp.json()
        return None

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
