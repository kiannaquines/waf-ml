import asyncio
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import http
import json

class RequestLogger:
    def __init__(self):
        self.log_file = open("bad_http_traffic.log", "a")

    def __del__(self):
        self.log_file.close()

    def request(self, flow: http.HTTPFlow):
        request_data = {
            "method": flow.request.method,
            "url": flow.request.url,
            "host": flow.request.host,
            "path": flow.request.path,
            "http_version": flow.request.http_version,
            "headers": dict(flow.request.headers),
            "query_parameters": dict(flow.request.query),
            "cookies": dict(flow.request.cookies),
            "content_length": flow.request.headers.get("Content-Length"),
            "user_agent": flow.request.headers.get("User-Agent"),
            "referrer": flow.request.headers.get("Referer"),
            "content_type": flow.request.headers.get("Content-Type"),
            "payload": flow.request.get_text() if flow.request.method in ["POST", "PUT"] else None,
        }
        self.log_request(request_data)

    def log_request(self, data):
        log_entry = {"type": "request", "data": data}
        self.log_file.write(json.dumps(log_entry) + "\n")
        self.log_file.flush()

async def start_proxy():
    opts = options.Options(
        listen_host='0.0.0.0',
        listen_port=8080,
        ignore_hosts=["^(.+\\.)?google\\.com:443$", "^(.+\\.)?chatgpt\\.com:443$", "^(.+\\.)?mozilla\\.com:443$", "^(.+\\.)?ghostery\\.net:443$" , "^(.+\\.)?firefox\\.com:443$", "^(.+\\.)?github\\.com:443$", "^(.+\\.)?facebook\\.com:443$", "^(.+\\.)?youtube\\.com:443$", "^(.+\\.)?googleapis\\.com:443$", "^(.+\\.)?gstatic\\.com:443$", "^(.+\\.)?googleusercontent\\.com:443$", "^(.+\\.)?mozilla\\.org:443$"]
    )
    m = DumpMaster(opts)
    m.addons.add(RequestLogger())

    try:
        await m.run()
    except KeyboardInterrupt:
        print("Proxy server shutting down...")

if __name__ == "__main__":
    asyncio.run(start_proxy())
