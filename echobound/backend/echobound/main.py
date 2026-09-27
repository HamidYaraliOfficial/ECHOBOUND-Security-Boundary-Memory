"""
Entry point for `python -m echobound.main` / uvicorn deployment.
"""
import uvicorn

from .config import settings


def run():
    uvicorn.run("echobound.api:app", host=settings.api_host, port=settings.api_port, reload=False)


if __name__ == "__main__":
    run()
