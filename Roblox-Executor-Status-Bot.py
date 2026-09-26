"""
weao_cog.py

Discord.py cog that exposes the WEAO (weao.xyz) exploit-status API
as slash commands: exploit status (all / single), version info
(current / past / future), and an auto-notification loop that posts
to a configured channel whenever an exploit's status changes.

Usage:
    from weao_cog import WeaoCog
    await bot.add_cog(WeaoCog(bot))

Requires: discord.py >= 2.0, aiohttp (already a discord.py dependency)
"""

import json
import os

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands, tasks

WEAO_BASE = "https://weao.xyz/api"
HEADERS = {
    "User-Agent": "WEAO-3PService",
    "Accept": "application/json",
}

# Per-guild notify-channel config, stored alongside your other JSON configs
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "weao_notify_config.json")

POLL_INTERVAL_MINUTES = 7  # anywhere in the 5-10 min range you mentioned


class WeaoCog(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.session: aiohttp.ClientSession | None = None
        self.notify_channels: dict[str, int] = self._load_config()
        # last known working/not-working state per exploit name, e.g. {"solara": True}
        self.last_state: dict[str, bool] = {}
        self._seeded = False  # avoid a notification storm on first poll after startup

    async def cog_load(self):
        self.session = aiohttp.ClientSession(headers=HEADERS)
        self.poll_status.start()

    async def cog_unload(self):
        self.poll_status.cancel()
        if self.session:
            await self.session.close()

    # ---------- config persistence ----------

    def _load_config(self) -> dict:
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_config(self):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(self.notify_channels, f, ensure_ascii=False, indent=2)

    async def _get(self, path: str):
        """GET a WEAO endpoint, returning (data, error)."""
        try:
            async with self.session.get(f"{WEAO_BASE}{path}") as resp:
                if resp.status != 200:
                    return None, f"Upstream returned status {resp.status}"
                return await resp.json(), None
        except Exception as e:
            return None, str(e)

    # ---------- /exploits ----------

    @app_commands.command(name="exploits", description="List all tracked Roblox exploit statuses")
    async def exploits(self, interaction: discord.Interaction):
        await interaction.response.defer()
        data, err = await self._get("/status/exploits")
        if err:
            await interaction.followup.send(f"Couldn't fetch exploit list: {err}")
            return

        embed = discord.Embed(title="Exploit Status", color=discord.Color.blurple())
        # data is expected to be a list of exploit dicts; adjust keys to match the real schema
        for item in data[:25]:  # embeds cap at 25 fields
            name = item.get("title") or item.get("name", "Unknown")
            working = item.get("working")
            status = "🟢 Working" if working else "🔴 Not working"
            embed.add_field(name=name, value=status, inline=True)

        await interaction.followup.send(embed=embed)

    # ---------- /exploit <name> ----------

    @app_commands.command(name="exploit", description="Check the status of a specific exploit")
    @app_commands.describe(name="Exact exploit name")
    async def exploit(self, interaction: discord.Interaction, name: str):
        await interaction.response.defer()
        data, err = await self._get(f"/status/exploits/{name}")
        if err:
            await interaction.followup.send(f"Couldn't fetch status for **{name}**: {err}")
            return

        working = data.get("working")
        status = "🟢 Working" if working else "🔴 Not working"
        version = data.get("version", "n/a")

        embed = discord.Embed(title=name, color=discord.Color.green() if working else discord.Color.red())
        embed.add_field(name="Status", value=status, inline=True)
        embed.add_field(name="Version", value=version, inline=True)
        await interaction.followup.send(embed=embed)

    # ---------- /version <which> ----------

    @app_commands.command(name="version", description="Get Roblox version info")
    @app_commands.describe(which="current, past, or future")
    @app_commands.choices(which=[
        app_commands.Choice(name="current", value="current"),
        app_commands.Choice(name="past", value="past"),
        app_commands.Choice(name="future", value="future"),
    ])
    async def version(self, interaction: discord.Interaction, which: app_commands.Choice[str]):
        await interaction.response.defer()
        data, err = await self._get(f"/versions/{which.value}")
        if err:
            await interaction.followup.send(f"Couldn't fetch {which.value} version info: {err}")
            return

        embed = discord.Embed(title=f"Roblox — {which.value.capitalize()} Version", color=discord.Color.blurple())
        if isinstance(data, dict):
            for k, v in data.items():
                embed.add_field(name=str(k), value=str(v), inline=True)
        else:
            embed.description = str(data)

        await interaction.followup.send(embed=embed)

    # ---------- /setnotifychannel ----------

    @app_commands.command(name="setnotifychannel", description="Set this channel for exploit status change alerts")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def setnotifychannel(self, interaction: discord.Interaction, channel: discord.TextChannel | None = None):
        target = channel or interaction.channel
        self.notify_channels[str(interaction.guild_id)] = target.id
        self._save_config()
        await interaction.response.send_message(
            f"Exploit status change alerts will now be posted in {target.mention}."
        )

    @setnotifychannel.error
    async def setnotifychannel_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.MissingPermissions):
            await interaction.response.send_message(
                "You need the **Manage Server** permission to set the notify channel.", ephemeral=True
            )
        else:
            raise error

    # ---------- background poll loop ----------

    @tasks.loop(minutes=POLL_INTERVAL_MINUTES)
    async def poll_status(self):
        data, err = await self._get("/status/exploits")
        if err or not isinstance(data, list):
            return  # skip this tick silently; next poll will retry

        current_state: dict[str, bool] = {}
        changes: list[tuple[str, bool]] = []

        for item in data:
            name = item.get("title") or item.get("name")
            working = bool(item.get("working"))
            if not name:
                continue
            current_state[name] = working

            if self._seeded and name in self.last_state and self.last_state[name] != working:
                changes.append((name, working))

        self.last_state = current_state
        self._seeded = True  # first successful poll just seeds state, no alerts fired

        if not changes or not self.notify_channels:
            return

        embed = discord.Embed(title="Exploit Status Changes", color=discord.Color.orange())
        for name, working in changes:
            embed.add_field(
                name=name,
                value="🟢 Back online" if working else "🔴 Now offline",
                inline=False,
            )

        for guild_id, channel_id in self.notify_channels.items():
            channel = self.bot.get_channel(channel_id)
            if channel:
                try:
                    await channel.send(embed=embed)
                except discord.HTTPException:
                    pass  # e.g. missing permissions in that channel; skip and continue

    @poll_status.before_loop
    async def before_poll_status(self):
        await self.bot.wait_until_ready()


async def setup(bot: commands.Bot):
    await bot.add_cog(WeaoCog(bot))
