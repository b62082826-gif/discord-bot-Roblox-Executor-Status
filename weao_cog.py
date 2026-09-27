"""
weao_cog.py

Discord.py cog that exposes the WEAO (weao.xyz) exploit-status API
as slash commands: exploit status (all / single), Roblox version info
(current / past / future), and an auto-notification loop that posts
to a configured channel whenever an exploit's detected/updated state
changes.

Schema reference: WEAO API docs (Exploits + Roblox versions pages).

Usage:
    from weao_cog import WeaoCog
    await bot.add_cog(WeaoCog(bot))

Requires: discord.py >= 2.0, aiohttp (already a discord.py dependency)
"""

import json
import logging
import os
import urllib.parse

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands, tasks

log = logging.getLogger("weao_cog")

WEAO_BASE = "https://weao.xyz/api"
HEADERS = {
    "User-Agent": "WEAO-3PService",
    "Accept": "application/json",
}

# Per-guild notify-channel config, stored alongside your other JSON configs
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "weao_notify_config.json")

POLL_INTERVAL_MINUTES = 7  # anywhere in the 5-10 min range you mentioned
REQUEST_TIMEOUT_SECONDS = 10


def exploit_state_label(item: dict) -> str:
    """Combine updateStatus + detected into one human label."""
    if not item.get("updateStatus"):
        return "Outdated"
    if item.get("detected"):
        return "Updated but Detected"
    return "Updated & Undetected"


def exploit_state_emoji(label: str) -> str:
    return {
        "Outdated": "🔴",
        "Updated but Detected": "🟠",
        "Updated & Undetected": "🟢",
    }.get(label, "⚪")


def exploit_state_color(label: str) -> discord.Color:
    return {
        "Outdated": discord.Color.red(),
        "Updated but Detected": discord.Color.orange(),
        "Updated & Undetected": discord.Color.green(),
    }.get(label, discord.Color.greyple())


class WeaoCog(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.session: aiohttp.ClientSession | None = None
        self.notify_channels: dict[str, int] = self._load_config()
        # last known state label per exploit title, e.g. {"Potassium": "Updated & Undetected"}
        self.last_state: dict[str, str] = {}
        self._seeded = False  # avoid a notification storm on first poll after startup
        self._poll_fail_streak = 0

    async def cog_load(self):
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        self.session = aiohttp.ClientSession(headers=HEADERS, timeout=timeout)
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
            except (json.JSONDecodeError, OSError) as e:
                log.warning("Failed to load %s: %s", CONFIG_PATH, e)
                return {}
        return {}

    def _save_config(self):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self.notify_channels, f, ensure_ascii=False, indent=2)
        except OSError as e:
            log.error("Failed to save %s: %s", CONFIG_PATH, e)

    async def _get(self, path: str):
        """GET a WEAO endpoint, returning (data, error).

        WEAO returns 429 with a JSON body ({"error": ..., "rateLimitInfo": {...}})
        when you're rate limited, so that case gets its own message. Also treats
        a 200 response whose body itself contains an "error" key (e.g. an
        unknown exploit name) as an error rather than passing it through.
        """
        try:
            async with self.session.get(f"{WEAO_BASE}{path}") as resp:
                if resp.status == 429:
                    try:
                        body = await resp.json()
                        wait = body.get("rateLimitInfo", {}).get("remainingTime", "a bit")
                    except (aiohttp.ContentTypeError, json.JSONDecodeError):
                        wait = "a bit"
                    return None, f"Rate limited by WEAO, try again in ~{wait}s"

                if resp.status != 200:
                    return None, f"Upstream returned status {resp.status}"

                try:
                    data = await resp.json()
                except (aiohttp.ContentTypeError, json.JSONDecodeError):
                    return None, "Upstream returned an unreadable response"

                if isinstance(data, dict) and data.get("error"):
                    return None, str(data["error"])

                return data, None
        except aiohttp.ClientError as e:
            return None, f"Network error: {e}"
        except Exception as e:
            log.exception("Unexpected error fetching %s", path)
            return None, str(e)

    # ---------- /exploits ----------

    @app_commands.command(name="exploits", description="List all tracked Roblox exploit statuses")
    async def exploits(self, interaction: discord.Interaction):
        await interaction.response.defer()
        data, err = await self._get("/status/exploits")
        if err:
            await interaction.followup.send(f"Couldn't fetch exploit list: {err}")
            return
        if not isinstance(data, list) or not data:
            await interaction.followup.send("No exploit data available right now.")
            return

        embed = discord.Embed(title="Exploit Status", color=discord.Color.blurple())
        for item in data[:25]:  # embeds cap at 25 fields
            name = item.get("title", "Unknown")
            label = exploit_state_label(item)
            emoji = exploit_state_emoji(label)
            free_tag = "Free" if item.get("free") else "Paid"
            embed.add_field(name=name, value=f"{emoji} {label} · {free_tag}", inline=True)

        if len(data) > 25:
            embed.set_footer(text=f"Showing 25 of {len(data)} tracked exploits")

        await interaction.followup.send(embed=embed)

    # ---------- /exploit <name> ----------

    @app_commands.command(name="exploit", description="Check the status of a specific exploit")
    @app_commands.describe(name="Exact exploit name")
    async def exploit(self, interaction: discord.Interaction, name: str):
        await interaction.response.defer()
        safe_name = urllib.parse.quote(name, safe="")
        data, err = await self._get(f"/status/exploits/{safe_name}")
        if err:
            await interaction.followup.send(f"Couldn't fetch status for **{name}**: {err}")
            return
        if not isinstance(data, dict):
            await interaction.followup.send(f"No data found for **{name}**.")
            return

        label = exploit_state_label(data)
        emoji = exploit_state_emoji(label)

        embed = discord.Embed(
            title=data.get("title", name),
            color=exploit_state_color(label),
        )
        embed.add_field(name="Status", value=f"{emoji} {label}", inline=True)
        embed.add_field(name="Version", value=data.get("version", "n/a"), inline=True)
        embed.add_field(name="Platform", value=data.get("platform", "n/a"), inline=True)
        embed.add_field(name="Cost", value=data.get("cost", "Free" if data.get("free") else "Paid"), inline=True)
        embed.add_field(name="UNC Support", value="Yes" if data.get("uncStatus") else "No", inline=True)
        embed.add_field(name="Last Updated", value=data.get("updatedDate", "n/a"), inline=True)

        if data.get("websitelink"):
            embed.add_field(name="Website", value=data["websitelink"], inline=False)
        if data.get("purchaselink") and not data.get("free"):
            embed.add_field(name="Purchase", value=data["purchaselink"], inline=False)

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
        if not isinstance(data, dict):
            await interaction.followup.send(f"No {which.value} version data available.")
            return

        embed = discord.Embed(
            title=f"Roblox — {which.value.capitalize()} Version",
            color=discord.Color.blurple(),
        )
        # Android/iOS are only present on the "current" endpoint per the docs
        found_any = False
        for platform, ver_key, date_key in (
            ("Windows", "Windows", "WindowsDate"),
            ("Mac", "Mac", "MacDate"),
            ("Android", "Android", "AndroidDate"),
            ("iOS", "iOS", "iOSDate"),
        ):
            if ver_key in data:
                found_any = True
                embed.add_field(
                    name=platform,
                    value=f"{data[ver_key]}\n{data.get(date_key, '')}",
                    inline=True,
                )

        if not found_any:
            await interaction.followup.send(f"No recognizable version fields for **{which.value}**.")
            return

        await interaction.followup.send(embed=embed)

    # ---------- /setnotifychannel ----------

    @app_commands.command(name="setnotifychannel", description="Set this channel for exploit status change alerts")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def setnotifychannel(self, interaction: discord.Interaction, channel: discord.TextChannel | None = None):
        if interaction.guild_id is None:
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return
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
            log.exception("Unhandled error in setnotifychannel", exc_info=error)
            if interaction.response.is_done():
                await interaction.followup.send("Something went wrong running that command.", ephemeral=True)
            else:
                await interaction.response.send_message("Something went wrong running that command.", ephemeral=True)

    # ---------- background poll loop ----------

    @tasks.loop(minutes=POLL_INTERVAL_MINUTES)
    async def poll_status(self):
        data, err = await self._get("/status/exploits")
        if err or not isinstance(data, list):
            self._poll_fail_streak += 1
            if self._poll_fail_streak in (1, 5, 20) or self._poll_fail_streak % 50 == 0:
                # Log occasionally instead of on every failed tick, so a prolonged
                # outage doesn't spam the logs, but persistent failures are still visible.
                log.warning(
                    "poll_status failed (%s consecutive failures): %s",
                    self._poll_fail_streak, err or "unexpected response shape",
                )
            return  # skip this tick silently to Discord; next poll will retry

        self._poll_fail_streak = 0
        current_state: dict[str, str] = {}
        changes: list[tuple[str, str, str]] = []  # (name, old_label, new_label)

        for item in data:
            name = item.get("title")
            if not name:
                continue
            label = exploit_state_label(item)
            current_state[name] = label

            if self._seeded and name in self.last_state and self.last_state[name] != label:
                changes.append((name, self.last_state[name], label))

        self.last_state = current_state
        self._seeded = True  # first successful poll just seeds state, no alerts fired

        if not changes or not self.notify_channels:
            return

        embed = discord.Embed(title="Exploit Status Changes", color=discord.Color.orange())
        for name, old_label, new_label in changes:
            emoji = exploit_state_emoji(new_label)
            embed.add_field(
                name=name,
                value=f"{old_label} → {emoji} {new_label}",
                inline=False,
            )

        stale_guilds = []
        for guild_id, channel_id in self.notify_channels.items():
            channel = self.bot.get_channel(channel_id)
            if channel is None:
                continue
            try:
                await channel.send(embed=embed)
            except discord.Forbidden:
                log.warning("Missing permission to send in channel %s (guild %s)", channel_id, guild_id)
            except discord.HTTPException as e:
                log.warning("Failed to send alert in channel %s (guild %s): %s", channel_id, guild_id, e)

        if stale_guilds:
            for gid in stale_guilds:
                self.notify_channels.pop(gid, None)
            self._save_config()

    @poll_status.before_loop
    async def before_poll_status(self):
        await self.bot.wait_until_ready()

    @poll_status.error
    async def poll_status_error(self, error: BaseException):
        # tasks.loop stops the loop entirely if the wrapped coroutine raises
        # uncaught, so log it and restart rather than silently going dark.
        log.exception("poll_status crashed, restarting loop", exc_info=error)
        if not self.poll_status.is_running():
            self.poll_status.restart()


async def setup(bot: commands.Bot):
    await bot.add_cog(WeaoCog(bot))
