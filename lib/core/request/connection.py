import socket
import os
import sys

sys.path.append(os.getcwd())
from lib.core.request.inits.TCP._init import socket_init
from lib.logger.log import logger
from lib.core.parser.cmdline import url as _url
from lib.core.parser.cmdline import port as _port
from urllib.parse import urlparse
import thirdparty.requests as requests

def test_connection(url=_url, port=_port):
    logger.warning(f"Testing connection to the target URL: {url}")
    req = requests.get(url)
    _ = req.status_code
    logger.debug("current status code of the response code is:|%s|"%_)

    # Extract host and path from the URL
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path or "/"

    try:
        sock = socket_init()
        
        sock.settimeout(5)

        sock.connect((host, port))

        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"

        sock.sendall(request.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        logger.info("Connection established with the target.")

        sock.close()
        logger.debug("Closing the test connection socket...")
        
    except socket.error as e:
        logger.critical("Got error%s"%str(e))

# Example usage
# test_connection("http://testfire.net/index.jsp?content=business_deposit.htm", 80)
        