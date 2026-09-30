# /// script
# requires-python = ">=3.13"
# dependencies = ["requests", "httpx[http2]"]
# ///
import json

import httpx
import requests

URL = "https://credshim.test/"


def report(name, body):
    doctor = json.loads(body)
    assert doctor["credshim"] == "doctor" and doctor["via_proxy"] and doctor["ca_trusted"], body
    print(name, doctor["protocol"])


report("requests", requests.get(URL, timeout=30).text)
report("httpx", httpx.get(URL, timeout=30).text)
with httpx.Client(http2=True, timeout=30) as client:
    report("httpx-h2", client.get(URL).text)
