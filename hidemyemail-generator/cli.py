#!/usr/bin/env python3

import asyncio
import click

from main import generate
from main import list


@click.group()
def cli():
    pass


@click.command()
@click.option(
    "--count", default=5, help="How many emails to generate", type=int
)
def generatecommand(count: int):
    "Generate emails"
    loop = asyncio.new_event_loop()
    try:
        created = loop.run_until_complete(generate(count))
        if not created:
            raise click.ClickException(
                "No email was created. Check the Cookie/session error above."
            )
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()


@click.command()
@click.option(
    "--active/--inactive", default=True, help="Filter Active / Inactive emails"
)
@click.option("--search", default=None, help="Search emails")
def listcommand(active, search):
    "List emails"
    loop = asyncio.new_event_loop()
    try:
        ok = loop.run_until_complete(list(active, search))
        if not ok:
            raise click.ClickException(
                "Unable to list emails. Check the Cookie/session error above."
            )
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()


cli.add_command(listcommand, name="list")
cli.add_command(generatecommand, name="generate")

if __name__ == "__main__":
    cli()
