import requests
from .app.proxy_vpn_detection_wrapper import ProxyVPNDetectionWrapper


class IPQualityScoreClient(object):
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://ipqualityscore.com/"
        self.proxy_vpn_detection_object = ProxyVPNDetectionWrapper(
            self.api_key, self.base_url)

    def get_prefix(self,):
        return "ipqualityscore"

    def ip_detection(self, ip, strictness=0, allow_public_access_points=True, fast=False, lighter_penalties=True, mobile=True):
        allow_public_access_points = "true" if allow_public_access_points else "false"
        fast = "true" if fast else "false"
        lighter_penalties = "true" if lighter_penalties else "false"
        mobile = "true" if mobile else "false"
        return self.proxy_vpn_detection_object.ip_detection(ip, strictness, allow_public_access_points, fast, lighter_penalties, mobile)

    def email_validation(self, email, fast=False, timeout=7, suggest_domain=False, strictness=0, abuse_strictness=0):
        fast = "true" if fast else "false"
        suggest_domain = "true" if suggest_domain else "false"
        return self.proxy_vpn_detection_object.email_validation(email, fast, timeout, suggest_domain, strictness, abuse_strictness)

    def url_checker(self, url, strictness=0):
        return self.proxy_vpn_detection_object.url_checker(url, strictness)


if __name__ == "__main__":
    ipqualityscore_client = IPQualityScoreClient(
        "DLI5aJIBw29HiylQYxN8vJuDZjRCtfkf")
    ipqualityscore_client.url_checker("https://www.google.com")
