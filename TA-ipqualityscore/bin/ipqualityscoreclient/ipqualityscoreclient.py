# encoding = utf-8

import requests
from .app.proxy_vpn_detection_wrapper import ProxyVPNDetectionWrapper
import logging
import os
import splunk

class IPQualityScoreClient(object):
    def __init__(self, api_key):
        self.logger = self.setup_logging()
        self.api_key = api_key
        self.base_url = "https://ipqualityscore.com/"
        self.proxy_vpn_detection_object = ProxyVPNDetectionWrapper(
            self.api_key, self.base_url, self.logger)

    def setup_logging(self):
        logger = logging.getLogger('splunk.foo')
        SPLUNK_HOME = os.environ['SPLUNK_HOME']

        LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log.cfg')
        LOGGING_LOCAL_CONFIG_FILE = os.path.join(
            SPLUNK_HOME, 'etc', 'log-local.cfg')
        LOGGING_STANZA_NAME = 'python'
        LOGGING_FILE_NAME = "ipqualityscore.log"
        BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
        LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
        splunk_log_handler = logging.handlers.RotatingFileHandler(
            os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a')
        splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
        logger.addHandler(splunk_log_handler)
        splunk.setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE,
                                LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
        return logger

    def get_prefix(self,):
        return "ipqualityscore"

    def ip_detection(self, ip, strictness=0, allow_public_access_points=True, fast=False, lighter_penalties=True, mobile=True):
        allow_public_access_points = "true" if allow_public_access_points else "false"
        fast = "true" if fast else "false"
        lighter_penalties = "true" if lighter_penalties else "false"
        mobile = "true" if mobile else "false"
        return self.proxy_vpn_detection_object.ip_detection(ip, strictness, allow_public_access_points, fast, lighter_penalties, mobile)

    def ip_detection_multithreaded(self, ips, strictness=0, allow_public_access_points=True, fast=False, lighter_penalties=True, mobile=True):
        self.logger.info('Inside ip_detection_multithreaded')
        self.logger.info('IP Address received: '+ ','.join(ips))
        allow_public_access_points = "true" if allow_public_access_points else "false"
        fast = "true" if fast else "false"
        lighter_penalties = "true" if lighter_penalties else "false"
        mobile = "true" if mobile else "false"
        return self.proxy_vpn_detection_object.ip_detection_multithreaded(ips, strictness, allow_public_access_points, fast, lighter_penalties, mobile)

    def email_validation(self, email, fast=False, timeout=7, suggest_domain=False, strictness=0, abuse_strictness=0):
        fast = "true" if fast else "false"
        suggest_domain = "true" if suggest_domain else "false"
        return self.proxy_vpn_detection_object.email_validation(email, fast, timeout, suggest_domain, strictness, abuse_strictness)

    def url_checker(self, url, strictness=0):
        return self.proxy_vpn_detection_object.url_checker(url, strictness)