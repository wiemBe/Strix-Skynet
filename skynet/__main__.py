"""Single-process service entry point; one scheduler and queue owner per installation."""
import uvicorn
from .config import HOST, PORT

if __name__ == "__main__":
    uvicorn.run("skynet.main:app", host=HOST, port=PORT, access_log=False, workers=1,
                proxy_headers=True, forwarded_allow_ips="127.0.0.1")
