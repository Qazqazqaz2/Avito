import ssl
import requests

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from requests.packages.urllib3.util import ssl_
from requests import Session
from bs4 import BeautifulSoup as BS
import random

CIPHERS = """ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:AES256-SHA"""


class TlsAdapter(HTTPAdapter):

    def __init__(self, ssl_options=0, **kwargs):
        self.ssl_options = ssl_options
        super(TlsAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, *pool_args, **pool_kwargs):
        ctx = ssl_.create_urllib3_context(ciphers=CIPHERS, cert_reqs=ssl.CERT_REQUIRED, options=self.ssl_options)
        self.poolmanager = PoolManager(*pool_args, ssl_context=ctx, **pool_kwargs)

url = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"
resp = requests.get(url)
http = str(resp.text).split('\n')

session = requests.session()
adapter = TlsAdapter(ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
session.mount("https://", adapter)

try:
    r = session.request('GET', 'https://www.avito.ru/rossiya/predlozheniya_uslug?context=H4sIAAAAAAAA_0q0MrSqLraysFJKK8rPDUhMT1WyLrYyNLNSKk5NLErOcMsvyg3PTElPLVGyrgUEAAD__xf8iH4tAAAA&p=2&q=%D1%80%D0%B0%D0%B1%D0%BE%D1%82%D0%B0', proxies={
    'http': http[random.randint(0, len(http) - 1)]})
    print(r.status_code)
except Exception as exception:
    print(exception)




#session = Session()

#response = session.get("https://www.avito.ru/rossiya/predlozheniya_uslug?context=H4sIAAAAAAAA_0q0MrSqLraysFJKK8rPDUhMT1WyLrYyNLNSKk5NLErOcMsvyg3PTElPLVGyrgUEAAD__xf8iH4tAAAA&p=2&q=%D1%80%D0%B0%D0%B1%D0%BE%D1%82%D0%B0", proxies={
 #   'http': http[random.randint(0, len(http) - 1)]})
#print(response.status_code)