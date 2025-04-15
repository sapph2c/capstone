from pipeline.callback import Listener
from pipeline.llm import Client

import click


DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 4444
DEFAULT_TIMEOUT = 60
DEFAULT_URL = "https://api.deepseek.com"


@click.group()
def cli():
    """
    CLI tool used for CI/CD pipeline tasks.

    Authored by sapph2c
    """
    pass


@cli.command(short_help="test callback from evasive malware")
@click.option("--lhost", envvar="LHOST", default=DEFAULT_HOST)
@click.option("--lport", envvar="LPORT", default=DEFAULT_PORT, type=int)
@click.option("--timeout", envvar="TIMEOUT", default=DEFAULT_TIMEOUT, type=int)
def callback(lhost, lport, timeout):
    listener = Listener(lhost, lport, timeout)
    result = listener.test()
    print(result)


@cli.command(short_help="generate a pre-build script")
@click.option("--api-key", envvar="DEEPSEEK_API_KEY")
@click.option("--base-url", default=DEFAULT_URL)
@click.option("--path", envvar="BASE_MALWARE_PATH")
def prebuild(api_key, base_url, path):
    client = Client(api_key, base_url, path)
    client.prebuild()
