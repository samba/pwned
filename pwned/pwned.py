#!/usr/bin/env python3

import urllib
import hashlib
import time
import pprint
import json
import random
import datetime
import typing

from urllib import request
from urllib.request import quote
from urllib.error import URLError, HTTPError

ACCOUNT_API_BASE = "https://haveibeenpwned.com/api/v2/{service}/{parameter}"
PASSWORD_API_BASE = "https://api.pwnedpasswords.com/range/{hash5}"

AGENT_STRING = "pwnedcli/v1; python/3; (https://github.com/samba)"
# AGENT_STRING = "curl/7.54.0"

ACCOUNT_SERVICES_VALID = [
    'breachedaccount',
    'breaches',
    'breach',
    'pasteaccount'
]


class CaseSensitiveHeader(object):
    """
    This is a gnarly workaround for Python3's urllib.request causing HTTP
    request headers to be mutated, changing their cases. While the default
    behavior is compliant with HTTP standards, some services do not honor
    the same expectations, and thus do not tolerate case variants of
    required headers. Therefore we provide a case-constant header string.
    """
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return '' + self.text

    def capitalize(self):
        return '' + self.text

    def title(self):
        return '' + self.text


class BreachModel(object):

    def __init__(self, breachdata: dict):
        self.data = breachdata

    @property
    def name(self) -> str:
        return self.data.get('Name', None)
    
    @property
    def title(self) -> str:
        return self.data.get('Title', None)

    @property
    def date_breached(self) -> datetime.date:
        return self.data.get('BreachDate', None)

    @property
    def date_added(self) -> datetime.date:
        return self.data.get('AddedDate', None)

    @property
    def date_modified(self) -> datetime.date:
        return self.data.get('ModifiedDate', None)

    @property
    def domain(self) -> str:
        return self.data.get('Domain', None)

    @property
    def verified(self) -> bool:
        return self.data.get('IsVerified', None)
    
    @property
    def sensitive(self) -> bool:
        return self.data.get('IsSensitive', None)
    
    @property
    def spamlist(self) -> bool:
        return self.data.get('IsSpamList', None)

    @property
    def dataclasses(self) -> typing.List[str]:
        return self.data.get('DataClasses')


class ServiceLock(object):
    """Some of the relevant APIs assert a rate limiting policy."""

    __locks__ = dict()

    @classmethod
    def get(cls, service):
        if service not in cls.__locks__:
            cls.__locks__[service] = ServiceLock(service)
        return cls.__locks__[service]

    def __init__(self, service):
        self.threshold_ns = 0  # nanoseconds
        if service in ACCOUNT_SERVICES_VALID:
            # The policy is stated as 1 request per 1500 milliseconds
            self.threshold_ns = 1500 * 1E6  
        
        self.next = 0  # time at which this will next be unlocked.
        

    @property
    def locked(self):
        return (time.time_ns() > self.next)

    def lock(self):
        self.next = (time.time_ns() + self.threshold_ns)

    def wait(self, pad_ms=100):
        if self.next > time.time_ns():
            delay_sec = (self.next - time.time_ns()) / 1E9
            pad_ms = int(pad_ms) + random.randint(10, 100)
            time.sleep(delay_sec + (pad_ms / 1E3))
        self.lock()
        return True
    

def URL(service, parameter, **params) -> str:
    """Perform a query against the API."""
    if service in ACCOUNT_SERVICES_VALID:
        return ACCOUNT_API_BASE.format(
            service=service, 
            parameter=parameter, 
            **params)
    elif service in ('passhash',):
        return PASSWORD_API_BASE.format(hash5=parameter)
    else:
        raise KeyError("Unrecognized API service type: %s" % (service))


def gethostname(url: str) -> str:
    return urllib.parse.urlparse(url).hostname
    

def inject_request_error(e, req):
    class __err__(e.__class__):
        request = req
    
    e.__class__ = __err__
    return e
    

def fetch(url: str, accept=None, **params):
    headers = dict()
    headers[CaseSensitiveHeader("User-Agent")] = AGENT_STRING
    headers[CaseSensitiveHeader('Accept')] = (accept or '*/*')
    headers[CaseSensitiveHeader('Host')] = gethostname(url)

    method = params.pop('method', 'GET')
    req = request.Request(url, data=params, headers=headers, method=method)
    while True:
        try:
            result = request.urlopen(req)
            return result
        except HTTPError as e:
            # Retry logic when the API tells us to slow down...
            if e.code == 429:
                delay = result.getheader('Retry-After')
                time.sleep(float(delay))
                continue
            else: 
                raise inject_request_error(e, req)
        except URLError as u:
            raise inject_request_error(u, req)


def body(response) -> bytes:
    return response.read().decode('utf-8')


def get_email_breaches(address: str):
    ServiceLock.get('breachedaccount').wait()  # wait for API cooldown
    data = fetch(URL('breachedaccount', quote(address)))
    data = json.loads(body(data))
    return data


def breaches_as_objects(data: typing.List[dict]):
    for breach in data:
        yield BreachModel(breach)


def count_password_breaches(passwd: str, hash=True) -> int:
    ServiceLock.get('passhash').wait()  # wait for API cooldown (maybe)
    if hash:
        if isinstance(passwd, str):
            passwd = passwd.encode('utf-8')
        assert isinstance(passwd, bytes)
        digest = hashlib.sha1(passwd).hexdigest()
        text = digest.upper()
    else:
        # assume the incoming text is already a SHA1 hash
        text = str(passwd).upper()
    data = fetch(URL('passhash', text[0:5]))
    for rec in body(data).splitlines():
        stub, count = rec.split(':')
        if stub == text[5:]:
            return int(count)
    # else
    return 0

