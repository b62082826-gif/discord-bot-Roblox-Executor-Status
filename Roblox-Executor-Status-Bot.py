"""
bot.py

Standalone Discord bot for WEAO (weao.xyz) exploit status tracking.
Run this file directly to start the bot — it loads the WeaoCog from
weao_cog.py and syncs its slash commands on startup.

Setup:
    1. pip install -r requirements.txt
    2. Set your bot token as an environment variable:
           export DISCORD_TOKEN=your_token_here      (Linux/Mac)
           set DISCORD_TOKEN=your_token_here          (Windows cmd)
       or create a .env file next to this script with:
           DISCORD_TOKEN=your_token_here
    3. python bot.py

Slash commands (from weao_cog.py):
    /exploits              - list all tracked exploit statuses
    /exploit <name>        - status of one specific exploit
    /version <which>       - Roblox current/past/future version info
    /setnotifychannel      - set this channel for auto status-change alerts
"""

import os

import discord
from discord.ext import commands

# Load a .env file if python-dotenv is installed and one exists; optional,
# env vars set directly (Render, Railway, etc.) work without it.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

TOKEN = os.getenv("DISCORD_TOKEN")

intents = discord.Intents.default()
# Not strictly needed for slash-only commands, but harmless to enable if
# you plan to bolt on prefix commands later (matches BOB_BOT's setup).
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (id: {bot.user.id})")
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} slash command(s)")
    except Exception as e:
        print(f"Slash command sync failed: {e}")


async def main():
    if not TOKEN:
        raise RuntimeError(
            "DISCORD_TOKEN is not set. Set it as an environment variable "
            "or put it in a .env file next to bot.py."
        )
    async with bot:
        await bot.load_extension("weao_cog")
        await bot.start(TOKEN)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
