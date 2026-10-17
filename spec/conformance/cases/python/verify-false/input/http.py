import asyncio
import aiohttp
import httpx
import requests
def add_channel_update(upd, verify=True): pass
add_channel_update({}, verify=False)                          # 6: nothing (not an HTTP client)
requests.get("https://example.org", verify=False)             # 7: validation disabled
s = requests.Session()
s.post("https://example.org", data=b"", verify=False)         # 9: validation disabled (HTTP method name)
httpx.Client(verify=False)                                    # 10: validation disabled
aiohttp.TCPConnector(ssl=False)                               # 11: validation disabled
asyncio.open_connection("host", 25, ssl=False)                # 12: nothing (no TLS at all, not disabled validation)
oauth.fetch_token("https://example.org/token", verify=False)  # 13: validation disabled (OAuth session, passed to requests)
db.lookup(key, verify=False)                                  # 14: nothing
