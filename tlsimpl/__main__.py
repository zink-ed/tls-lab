import os
import os.path
import subprocess
import sys
import time

from tlsimpl.client import TLSSocket

proc = None

try:
    s = TLSSocket.create_connection(("127.0.0.1", 8080))
    s.close()
finally:
    if proc is not None:
        time.sleep(1)
        proc.terminate()
