# encoding = utf-8

import sys
import os
import logging
import logging.handlers
import splunk
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import splunk.entity as entity
from ipqualityscoreclient.ipqualityscoreclient import IPQualityScoreClient
import json


def setup_logging():
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


def get_credentials(sessionKey):
    myapp = 'ipqualityscore_realm'
    try:
        # list all credentials
        entities = entity.getEntities(['admin', 'passwords'], namespace=myapp,
                                      owner='nobody', sessionKey=sessionKey)
    except Exception as e:
        raise Exception("Could not get %s credentials from splunk. Error: %s"
                        % (myapp, str(e)))

    # return first set of credentials
    for i, c in entities.items():
        return c['username'], c['clear_password']

    raise Exception("No credentials have been found")


@Configuration(distributed=True, local=False)
class IPDetectionCommand(StreamingCommand):

    field = Option(
        require=True, default=True, validate=validators.Fieldname())
    allow_public_access_points = Option(
        require=False, default=True, validate=validators.Boolean())
    mobile = Option(require=False, default=True, validate=validators.Boolean())
    fast = Option(require=False, default=True, validate=validators.Boolean())
    strictness = Option(require=False, default=0,
                        validate=validators.Integer())
    lighter_penalties = Option(
        require=False, default=True, validate=validators.Boolean())

    def stream(self, records):
        logger = setup_logging()

        correct_records = []
        incorrect_records = []

        for record in records:
            if self.field in record:
                correct_records.append(record)
            else:
                incorrect_records.append(record)
                
        if len(incorrect_records) > 0:
            self.logger.error('ip field missing from '+str(len(incorrect_records))+" events. They will be ignored.")

        if len(correct_records) > 0:
            storage_passwords = self.service.storage_passwords
            for credential in storage_passwords:
                usercreds = {'username': credential.content.get(
                    'username'), 'password': credential.content.get('clear_password')}
            if usercreds is not None:
                ipqualityscoreclient = IPQualityScoreClient(
                    usercreds.get('password'), logger)

                ips = []
                rs = []
                for record in correct_records:
                    ips.append(record.get(self.field))
                    rs.append(record)
                    
                results_dict = ipqualityscoreclient.ip_detection_multithreaded(ips,
                                                                                allow_public_access_points=self.allow_public_access_points,
                                                                                mobile=self.mobile,
                                                                                fast=self.fast,
                                                                                strictness=self.strictness,
                                                                                lighter_penalties=self.lighter_penalties)
                for record in rs:
                    detection_result = results_dict.get(record[self.field])
                    
                    if detection_result is not None:
                        for key, val in detection_result.items():
                            new_key = ipqualityscoreclient.get_prefix() + "_" + key
                            record[new_key] = val
                        record[ipqualityscoreclient.get_prefix(
                        ) + "_status"] = 'api call success'
                    else:
                        record[ipqualityscoreclient.get_prefix(
                        ) + "_status"] = 'api call failed'
                        
                    yield record
            else:
                raise Exception("No credentials have been found")
        else:
            raise Exception("There are no events with ip field.")

if __name__ == "__main__":
    dispatch(IPDetectionCommand, sys.argv, sys.stdin, sys.stdout, __name__)
