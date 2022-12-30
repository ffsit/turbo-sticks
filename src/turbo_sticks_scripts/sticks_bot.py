import asyncio

from turbo_sticks.bot import SticksBot
from turbo_sticks.config import discord


def main() -> None:
    async def runner() -> None:
        client = SticksBot()
        async with client:
            await client.start(discord.bot_token.get_secret_value())

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
