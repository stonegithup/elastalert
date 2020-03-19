#! /usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
from elastalert.alerts import Alerter, BasicMatchString
from requests.exceptions import RequestException
from elastalert.util import elastalert_logger,EAException
import os
import sys
import logging as LOG

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from alertaclient.api import Client

__version__ = '3.4.1'

LOG_PATH = '/var/log/elastalert/'
LOG_FILE = LOG_PATH + 'elastalert_alerta.log'
LOG_FORMAT = "%(asctime)s.%(msecs).03d %(name)s[%(process)d] %(threadName)s %(levelname)s - %(message)s"
LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S"
debug=os.environ.get("ElastAlertDebug",False)

if debug or not os.path.isdir(LOG_PATH):
    LOG.basicConfig(stream=sys.stderr, format=LOG_FORMAT, datefmt=LOG_DATE_FMT, level=LOG.DEBUG)
else:
    LOG.basicConfig(filename=LOG_FILE, format=LOG_FORMAT, datefmt=LOG_DATE_FMT, level=LOG.INFO)


OPTIONS = {
    'config_file': '/etc/alertclient.conf',
    'profile':     "production",
    'endpoint':    'http://localhost:8080',
    'key':         '',
    'sslverify':   False,
    'debug':      False
}

class AlertaAlerter(Alerter):

    def __init__(self, *args):
        super(AlertaAlerter, self).__init__(*args)
        self.expires_in=datetime.datetime.now() - datetime.timedelta(seconds=60)

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])
        return subject

    def alert(self, matches):

        # 参考elastalert的写法
        # https://github.com/Yelp/elastalert/blob/master/elastalert/alerts.py#L236-L243
        # body = self.create_alert_body(matches)
        # LOG.error(body)
        '''
        resource={HOST}
        event={subject}
        environment=Production
        severity=warning
        status=Open
        ack={EVENT.ACK.STATUS}
        service={Service_NAME}
        value={Num_hits}
        text={NAME + Message}
        tags={}
        attributes.name={Name}
        attributes.ip={HOST.IP1}
        type=elastAlert
        dateTime={@timestamp}
        attributes.models=["dingding"]
        attributes.app={project_name}

        '''

        body = self.create_alert_body(matches)
        if len(body) >= 1000:
            body = body[:1000]

        payload = {
            # "resource":matches[0]["fields"].get("ip",""),
            "resource": self.rule["name"],
            "event":self.create_custom_title(matches),
            "environment":"Production",
            "severity":"warning",
            "status": "open",
            "service":[self.rule["app"]],
            "value": matches[0]["num_hits"],
            # "text": self.rule["name"] + "\t" + matches[0]["message"],
            "text": body,
            "type": "elastAlert",
            "tags":"",
            "dateTime":matches[0]["@timestamp"]
        }
        attributes = {}
        attributes["name"] = self.rule["name"]
        fields = matches[0].get("fields",{})
        attributes["ip"] = fields.get("ip","")
        attributes["models"] = "dingding"
        attributes["app"] = self.rule["app"]
        payload["attributes"] = attributes


        #matches 是json格式
        #self.create_alert_body(matches)是String格式,详见 [create_alert_body 函数](https://github.com/Yelp/elastalert/blob/master/elastalert/alerts.py)
        LOG.debug(payload)
        elastalert_logger.info("send message to alerta")
        self.senddata(payload)

    def senddata(self, content):
        config_file = os.environ.get('ALERTA_CONF_FILE') or OPTIONS['config_file']
        config = configparser.RawConfigParser(defaults=OPTIONS)
        try:
            config.read(os.path.expanduser(config_file))
        except Exception:
            sys.exit("Problem reading configuration file %s - is this an ini file?" % config_file)

        want_profile = os.environ.get('ALERTA_DEFAULT_PROFILE') or config.defaults().get('profile')
        if want_profile and config.has_section('profile %s' % want_profile):
            for opt in OPTIONS:
                try:
                    OPTIONS[opt] = config.getboolean('profile %s' % want_profile, opt)
                except (ValueError, AttributeError):
                    OPTIONS[opt] = config.get('profile %s' % want_profile, opt)
        else:
            for opt in OPTIONS:
                try:
                    OPTIONS[opt] = config.getboolean('DEFAULT', opt)
                except (ValueError, AttributeError):
                    OPTIONS[opt] = config.get('DEFAULT', opt)
        try:
            LOG.debug("[alerta] sendto=%s ", OPTIONS.get("endpoint"))
            api = Client(endpoint=OPTIONS.get("endpoint"), key=OPTIONS.get("key"), ssl_verify=OPTIONS.get("sslverify"))
            api.send_alert(**content)
        except RequestException as e:
            raise EAException("send message has error: %s" % e)

        elastalert_logger.info("send msg success" )

    def get_info(self):
        return {'type': 'ElastAlert'}
