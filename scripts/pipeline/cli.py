from pipeline.callback import Listener

import click
import sys
import os


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 4444
DEFAULT_TIMEOUT = 60


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
    sys.exit(result)
