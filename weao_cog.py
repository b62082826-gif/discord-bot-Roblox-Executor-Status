"""
weao_cog.py

Discord.py cog สำหรับ WEAO exploit-status API
  - /exploits            รายการสถานะทั้งหมด
  - /exploit <name>      สถานะตัวเดียว (มี autocomplete)
  - /version <which>     เวอร์ชัน Roblox (current / past / future)
  - /setnotifychannel    ตั้งห้องแจ้งเตือนเมื่อสถานะเปลี่ยน
  - /clearnotifychannel  ปิดการแจ้งเตือนของเซิร์ฟเวอร์นี้

จุดเด่น
  - เรียก weao.xyz ก่อน แล้ว fallback ไปพร็อกซีอัตโนมัติเมื่อโดน 429 / เน็ตล่ม / 5xx
  - จำว่า primary ใช้ไม่ได้ชั่วคราว (circuit breaker) ไม่ยิงซ้ำรัว ๆ
  - cache ผลลัพธ์สั้น ๆ ลดโหลด + กัน rate limit
  - ข้อมูลจากพร็อกซี (HTTP ไม่เข้ารหัส) ถูก sanitize: ลิงก์ต้องเป็น https,
    escape markdown/mention, ตัดความยาว
  - poll loop ไม่ตายเงียบ, แจ้งเตือนแบ่ง embed ถ้าเปลี่ยนเยอะ, ล้าง config ห้องที่ถูกลบ

Env (ไม่บังคับ)
  WEAO_PRIMARY_BASE  default https://weao.xyz/api
  WEAO_PROXY_BASE    default http://farts.fadedis.xyz:25551/api  (ตั้งเป็นค่าว่างเพื่อปิด fallback)

Requires: discord.py >= 2.0, Python >= 3.10
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands, tasks

log = logging.getLogger("weao_cog")

PRIMARY_BASE = os.environ.get("WEAO_PRIMARY_BASE", "https://weao.xyz/api").rstrip("/")
PROXY_BASE = os.environ.get("WEAO_PROXY_BASE", "http://farts.fadedis.xyz:25551/api").rstrip("/")

HEADERS = {"User-Agent": "WEAO-3PService", "Accept": "application/json"}

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "weao_notify_config.json")

POLL_INTERVAL_MINUTES = 7
REQUEST_TIMEOUT_SECONDS = 10

CACHE_TTL_STATUS = 30      # วินาที
CACHE_TTL_VERSIONS = 120
DEFAULT_BLOCK_SECONDS = 60  # พัก primary เมื่อล้มเหลวโดยไม่รู้เวลา
MAX_BLOCK_SECONDS = 300

NO_MENTIONS = discord.AllowedMentions.none()

# ---------- helpers ----------

STATE_ORDER = {"Updated & Undetected": 0, "Updated but Detected": 1, "Outdated": 2}


def exploit_state_label(item: dict) -> str:
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


def clean(value: Any, limit: int = 200, default: str = "n/a") -> str:
    """แปลงเป็นข้อความปลอดภัย: escape markdown + mention และตัดความยาว"""
    if value is None or value == "":
        return default
    text = str(value)
    text = discord.utils.escape_mentions(discord.utils.escape_markdown(text))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def safe_link(url: Any) -> str | None:
    """อนุญาตเฉพาะ https:// เท่านั้น (กันลิงก์แปลก ๆ จากพร็อกซีที่ถูกแก้)"""
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url.startswith("https://") or len(url) > 1000 or any(c.isspace() for c in url):
        return None
    return url


def parse_retry_after(headers: Any, body: Any) -> float | None:
    """
    ดึงเวลารอ (หน่วย: วินาที) จาก 429 response

    ลำดับความสำคัญ:
      1. header Retry-After (มาตรฐาน หน่วยวินาที)
      2. body.rateLimitInfo.remainingTime
    เอกสาร WEAO ไม่ได้ระบุหน่วยของ remainingTime ชัดเจน จึงใช้ heuristic:
      ค่า >= 1000 ถือว่าเป็นมิลลิวินาที (รอเป็นพันวินาที = 16+ นาที ไม่สมเหตุสมผลกับ limiter รายนาที)
    ผลลัพธ์ถูก clamp ไว้ที่ 1..MAX_BLOCK_SECONDS
    """
    seconds: float | None = None

    try:
        header_val = headers.get("Retry-After") if headers is not None else None
        if header_val is not None:
            seconds = float(header_val)
    except (TypeError, ValueError):
        seconds = None  # Retry-After อาจเป็น HTTP-date ซึ่งเราไม่รองรับ → ไปใช้ body

    if seconds is None and isinstance(body, dict):
        info = body.get("rateLimitInfo")
        raw = info.get("remainingTime") if isinstance(info, dict) else None
        try:
            seconds = float(raw)
        except (TypeError, ValueError):
            return None
        if seconds >= 1000:
            seconds /= 1000.0

    if seconds is None or seconds != seconds or seconds <= 0:  # None / NaN / ค่าไม่บวก
        return None
    return min(max(seconds, 1.0), float(MAX_BLOCK_SECONDS))


def proxy_supports(path: str) -> bool:
    """พร็อกซีมีแค่ versions/current, versions/future และ status/exploits"""
    return not path.startswith("/versions/past")


@dataclass
class FetchResult:
    data: Any = None
    error: str | None = None
    source: str = "primary"  # "primary" | "proxy"

    @property
    def ok(self) -> bool:
        return self.error is None


def source_footer(result: FetchResult) -> str | None:
    return "ข้อมูลจากพร็อกซีสำรอง (fallback)" if result.source == "proxy" else None


# ---------- cog ----------

class WeaoCog(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.session: aiohttp.ClientSession | None = None
        self.notify_channels: dict[str, int] = self._load_config()

        self.last_state: dict[str, str] = {}
        self._seeded = False
        self._poll_fail_streak = 0

        self._cache: dict[str, tuple[float, Any, str]] = {}
        self._primary_blocked_until = 0.0

    async def cog_load(self):
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        self.session = aiohttp.ClientSession(headers=HEADERS, timeout=timeout)
        self.poll_status.start()

    async def cog_unload(self):
        self.poll_status.cancel()
        if self.session:
            await self.session.close()

    # ---------- config persistence ----------

    def _load_config(self) -> dict[str, int]:
        if not os.path.exists(CONFIG_PATH):
            return {}
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return {str(k): int(v) for k, v in raw.items()}
        except (json.JSONDecodeError, OSError, ValueError, AttributeError) as e:
            log.warning("Failed to load %s: %s", CONFIG_PATH, e)
            return {}

    def _save_config(self):
        """เขียนแบบ atomic กันไฟล์พังถ้าบอทดับกลางคัน"""
        directory = os.path.dirname(CONFIG_PATH) or "."
        try:
            fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".weao_", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.notify_channels, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, CONFIG_PATH)
        except OSError as e:
            log.error("Failed to save %s: %s", CONFIG_PATH, e)

    # ---------- HTTP layer ----------

    async def _request(self, base: str, path: str):
        """
        คืน (data, error, kind, retry_after)
        kind: None = สำเร็จ
              "retry" = ล้มเหลวแบบชั่วคราว ควรลอง source อื่น
              "fatal" = ปัญหาที่ลอง source อื่นก็ไม่ช่วย (เช่น ไม่รู้จักชื่อ exploit)
        """
        assert self.session is not None
        try:
            async with self.session.get(f"{base}{path}") as resp:
                if resp.status == 429:
                    body: Any = None
                    try:
                        body = await resp.json(content_type=None)
                    except (aiohttp.ClientError, json.JSONDecodeError):
                        pass
                    wait = parse_retry_after(resp.headers, body)
                    shown = f"~{int(wait + 0.999)} วินาที" if wait else "สักครู่"
                    return None, f"โดน rate limit ลองใหม่ใน {shown}", "retry", wait

                if resp.status == 404:
                    return None, "ไม่พบข้อมูลที่ขอ", "fatal", None

                if resp.status != 200:
                    return None, f"Upstream ตอบสถานะ {resp.status}", "retry", None

                try:
                    data = await resp.json(content_type=None)
                except (aiohttp.ClientError, json.JSONDecodeError):
                    return None, "Upstream ตอบกลับมาอ่านไม่ได้", "retry", None

                if isinstance(data, dict) and data.get("error"):
                    return None, clean(data["error"], 200), "fatal", None

                return data, None, None, None
        except aiohttp.ClientError as e:
            return None, f"Network error: {type(e).__name__}", "retry", None
        except TimeoutError:
            return None, "หมดเวลารอ upstream", "retry", None
        except Exception as e:  # noqa: BLE001
            log.exception("Unexpected error fetching %s%s", base, path)
            return None, f"Unexpected error: {type(e).__name__}", "retry", None

    async def _get(self, path: str, ttl: int = CACHE_TTL_STATUS) -> FetchResult:
        now = time.monotonic()

        cached = self._cache.get(path)
        if cached and cached[0] > now:
            return FetchResult(data=cached[1], source=cached[2])

        sources: list[tuple[str, str]] = []
        if now >= self._primary_blocked_until:
            sources.append(("primary", PRIMARY_BASE))
        if PROXY_BASE and proxy_supports(path):
            sources.append(("proxy", PROXY_BASE))
        if not sources:
            # primary ถูกพักอยู่และพร็อกซีไม่รองรับ path นี้ → ลอง primary ต่อดีกว่าไม่ทำอะไร
            sources.append(("primary", PRIMARY_BASE))

        last_error = "ไม่มี source ที่ใช้งานได้"
        for name, base in sources:
            data, err, kind, retry_after = await self._request(base, path)

            if kind is None:
                self._cache[path] = (time.monotonic() + ttl, data, name)
                if name == "primary":
                    self._primary_blocked_until = 0.0
                return FetchResult(data=data, source=name)

            last_error = err or last_error
            if name == "primary" and kind == "retry":
                block = min(retry_after or DEFAULT_BLOCK_SECONDS, MAX_BLOCK_SECONDS)
                self._primary_blocked_until = time.monotonic() + max(block, 5)
                log.info("primary WEAO blocked for %.0fs (%s)", block, last_error)
            if kind == "fatal":
                break

        # ถ้ามี cache เก่า (หมดอายุแล้ว) ยังดีกว่าไม่มีอะไรเลยเมื่อ upstream ล่ม
        if cached:
            return FetchResult(data=cached[1], source=cached[2])
        return FetchResult(error=last_error)

    # ---------- name helpers ----------

    def _resolve_name(self, name: str) -> str:
        """จับคู่ชื่อแบบไม่สนตัวพิมพ์ใหญ่เล็กกับรายการที่รู้จัก"""
        lowered = name.strip().lower()
        for known in self.last_state:
            if known.lower() == lowered:
                return known
        return name.strip()

    async def _exploit_autocomplete(self, interaction: discord.Interaction, current: str):
        current = current.lower()
        names = sorted(self.last_state, key=str.lower)
        return [
            app_commands.Choice(name=n[:100], value=n[:100])
            for n in names
            if current in n.lower()
        ][:25]

    # ---------- /exploits ----------

    @app_commands.command(name="exploits", description="List all tracked Roblox exploit statuses")
    async def exploits(self, interaction: discord.Interaction):
        await interaction.response.defer()
        result = await self._get("/status/exploits")
        if not result.ok:
            await interaction.followup.send(f"Couldn't fetch exploit list: {result.error}")
            return

        data = result.data
        if not isinstance(data, list) or not data:
            await interaction.followup.send("No exploit data available right now.")
            return

        items = [i for i in data if isinstance(i, dict)]
        for i in items:
            i["_label"] = exploit_state_label(i)
            if i.get("title"):
                self.last_state.setdefault(str(i["title"]), i["_label"])
        items.sort(key=lambda i: (STATE_ORDER.get(i["_label"], 9), str(i.get("title", "")).lower()))

        counts = {label: sum(1 for i in items if i["_label"] == label) for label in STATE_ORDER}
        summary = " · ".join(f"{exploit_state_emoji(k)} {v}" for k, v in counts.items())

        max_items = 100
        shown = items[:max_items]
        embeds: list[discord.Embed] = []
        for start in range(0, len(shown), 25):  # embed จำกัด 25 fields
            chunk = shown[start:start + 25]
            embed = discord.Embed(
                title="Exploit Status" if start == 0 else None,
                description=summary if start == 0 else None,
                color=discord.Color.blurple(),
            )
            for item in chunk:
                free_tag = "Free" if item.get("free") else "Paid"
                embed.add_field(
                    name=clean(item.get("title"), 100, "Unknown"),
                    value=f"{exploit_state_emoji(item['_label'])} {item['_label']} · {free_tag}",
                    inline=True,
                )
            embeds.append(embed)

        footer_parts = []
        if len(items) > max_items:
            footer_parts.append(f"แสดง {max_items} จาก {len(items)} รายการ")
        if (f := source_footer(result)):
            footer_parts.append(f)
        if footer_parts:
            embeds[-1].set_footer(text=" · ".join(footer_parts))

        await interaction.followup.send(embeds=embeds, allowed_mentions=NO_MENTIONS)

    # ---------- /exploit <name> ----------

    @app_commands.command(name="exploit", description="Check the status of a specific exploit")
    @app_commands.describe(name="Exploit name")
    @app_commands.autocomplete(name=_exploit_autocomplete)
    async def exploit(self, interaction: discord.Interaction, name: str):
        await interaction.response.defer()
        resolved = self._resolve_name(name)
        safe_name = urllib.parse.quote(resolved, safe="")
        result = await self._get(f"/status/exploits/{safe_name}")
        shown_name = clean(resolved, 100)

        if not result.ok:
            await interaction.followup.send(
                f"Couldn't fetch status for **{shown_name}**: {result.error}",
                allowed_mentions=NO_MENTIONS,
            )
            return
        data = result.data
        if not isinstance(data, dict):
            await interaction.followup.send(
                f"No data found for **{shown_name}**.", allowed_mentions=NO_MENTIONS
            )
            return

        label = exploit_state_label(data)
        emoji = exploit_state_emoji(label)

        embed = discord.Embed(
            title=clean(data.get("title", resolved), 250),
            color=exploit_state_color(label),
        )
        embed.add_field(name="Status", value=f"{emoji} {label}", inline=True)
        embed.add_field(name="Version", value=clean(data.get("version")), inline=True)
        embed.add_field(name="Platform", value=clean(data.get("platform")), inline=True)
        embed.add_field(
            name="Cost",
            value=clean(data.get("cost") or ("Free" if data.get("free") else "Paid")),
            inline=True,
        )
        embed.add_field(name="UNC Support", value="Yes" if data.get("uncStatus") else "No", inline=True)
        embed.add_field(name="Last Updated", value=clean(data.get("updatedDate")), inline=True)

        if (site := safe_link(data.get("websitelink"))):
            embed.add_field(name="Website", value=site, inline=False)
        if not data.get("free") and (buy := safe_link(data.get("purchaselink"))):
            embed.add_field(name="Purchase", value=buy, inline=False)

        if (f := source_footer(result)):
            embed.set_footer(text=f)

        await interaction.followup.send(embed=embed, allowed_mentions=NO_MENTIONS)

    # ---------- /version <which> ----------

    @app_commands.command(name="version", description="Get Roblox version info")
    @app_commands.describe(which="current, past (เฉพาะเมื่อ weao.xyz ใช้ได้) หรือ future")
    @app_commands.choices(which=[
        app_commands.Choice(name="current", value="current"),
        app_commands.Choice(name="past", value="past"),
        app_commands.Choice(name="future", value="future"),
    ])
    async def version(self, interaction: discord.Interaction, which: app_commands.Choice[str]):
        await interaction.response.defer()
        result = await self._get(f"/versions/{which.value}", ttl=CACHE_TTL_VERSIONS)
        if not result.ok:
            extra = ""
            if which.value == "past" and PROXY_BASE:
                extra = "\n(พร็อกซีสำรองไม่มีข้อมูล past)"
            await interaction.followup.send(
                f"Couldn't fetch {which.value} version info: {result.error}{extra}"
            )
            return

        data = result.data
        if not isinstance(data, dict):
            await interaction.followup.send(f"No {which.value} version data available.")
            return

        embed = discord.Embed(
            title=f"Roblox — {which.value.capitalize()} Version",
            color=discord.Color.blurple(),
        )
        found_any = False
        # Android/iOS มีเฉพาะ endpoint "current" ตามเอกสาร
        for platform, ver_key, date_key in (
            ("Windows", "Windows", "WindowsDate"),
            ("Mac", "Mac", "MacDate"),
            ("Android", "Android", "AndroidDate"),
            ("iOS", "iOS", "iOSDate"),
        ):
            if ver_key in data:
                found_any = True
                ver = clean(data[ver_key], 200)
                date = clean(data.get(date_key), 100, "")
                embed.add_field(name=platform, value=f"{ver}\n{date}".strip(), inline=True)

        if not found_any:
            await interaction.followup.send(f"No recognizable version fields for **{which.value}**.")
            return

        if (f := source_footer(result)):
            embed.set_footer(text=f)
        await interaction.followup.send(embed=embed, allowed_mentions=NO_MENTIONS)

    # ---------- notify channel config ----------

    @app_commands.command(name="setnotifychannel", description="Set a channel for exploit status change alerts")
    @app_commands.describe(channel="ห้องที่จะให้แจ้งเตือน (ไม่ใส่ = ห้องนี้)")
    @app_commands.guild_only()
    @app_commands.checks.has_permissions(manage_guild=True)
    async def setnotifychannel(
        self, interaction: discord.Interaction, channel: discord.TextChannel | None = None
    ):
        target = channel or interaction.channel
        if not isinstance(target, discord.TextChannel):
            await interaction.response.send_message("เลือกได้เฉพาะห้องข้อความปกติ", ephemeral=True)
            return

        me = interaction.guild.me if interaction.guild else None
        if me is not None:
            perms = target.permissions_for(me)
            if not (perms.view_channel and perms.send_messages and perms.embed_links):
                await interaction.response.send_message(
                    f"บอทต้องมีสิทธิ์ **View Channel / Send Messages / Embed Links** ใน {target.mention} ก่อน",
                    ephemeral=True,
                )
                return

        self.notify_channels[str(interaction.guild_id)] = target.id
        self._save_config()
        await interaction.response.send_message(
            f"Exploit status change alerts will now be posted in {target.mention}.",
            allowed_mentions=NO_MENTIONS,
        )

    @app_commands.command(name="clearnotifychannel", description="Turn off exploit alerts for this server")
    @app_commands.guild_only()
    @app_commands.checks.has_permissions(manage_guild=True)
    async def clearnotifychannel(self, interaction: discord.Interaction):
        removed = self.notify_channels.pop(str(interaction.guild_id), None)
        if removed is None:
            await interaction.response.send_message("เซิร์ฟเวอร์นี้ยังไม่ได้ตั้งห้องแจ้งเตือน", ephemeral=True)
            return
        self._save_config()
        await interaction.response.send_message("ปิดการแจ้งเตือนสถานะ exploit แล้ว")

    async def _config_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.MissingPermissions):
            msg = "You need the **Manage Server** permission to use this command."
        else:
            log.exception("Unhandled error in notify config command", exc_info=error)
            msg = "Something went wrong running that command."
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)

    @setnotifychannel.error
    async def setnotifychannel_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        await self._config_command_error(interaction, error)

    @clearnotifychannel.error
    async def clearnotifychannel_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        await self._config_command_error(interaction, error)

    @commands.Cog.listener()
    async def on_guild_remove(self, guild: discord.Guild):
        if self.notify_channels.pop(str(guild.id), None) is not None:
            self._save_config()

    # ---------- background poll loop ----------

    async def _resolve_channel(self, channel_id: int):
        """คืน (channel, is_stale) — stale เฉพาะเมื่อ Discord ยืนยันว่าห้องไม่มีอยู่แล้ว"""
        channel = self.bot.get_channel(channel_id)
        if channel is not None:
            return channel, False
        try:
            return await self.bot.fetch_channel(channel_id), False
        except discord.NotFound:
            return None, True
        except (discord.Forbidden, discord.HTTPException):
            return None, False  # ชั่วคราว/ไม่มีสิทธิ์ → เก็บ config ไว้ก่อน

    async def _poll_once(self):
        result = await self._get("/status/exploits", ttl=0)
        if not result.ok or not isinstance(result.data, list):
            self._poll_fail_streak += 1
            if self._poll_fail_streak in (1, 5, 20) or self._poll_fail_streak % 50 == 0:
                log.warning(
                    "poll_status failed (%s consecutive failures): %s",
                    self._poll_fail_streak, result.error or "unexpected response shape",
                )
            return

        self._poll_fail_streak = 0
        current_state: dict[str, str] = {}
        changes: list[tuple[str, str, str]] = []

        for item in result.data:
            if not isinstance(item, dict):
                continue
            name = item.get("title")
            if not name:
                continue
            name = str(name)
            label = exploit_state_label(item)
            current_state[name] = label
            if self._seeded and name in self.last_state and self.last_state[name] != label:
                changes.append((name, self.last_state[name], label))

        self.last_state = current_state
        self._seeded = True  # poll แรกแค่ seed ไม่แจ้งเตือน

        if not changes or not self.notify_channels:
            return

        embeds: list[discord.Embed] = []
        for start in range(0, len(changes), 25):
            embed = discord.Embed(
                title="Exploit Status Changes" if start == 0 else None,
                color=discord.Color.orange(),
            )
            for name, old_label, new_label in changes[start:start + 25]:
                embed.add_field(
                    name=clean(name, 100),
                    value=f"{old_label} → {exploit_state_emoji(new_label)} {new_label}",
                    inline=False,
                )
            embeds.append(embed)

        stale_guilds: list[str] = []
        for guild_id, channel_id in list(self.notify_channels.items()):
            channel, stale = await self._resolve_channel(channel_id)
            if stale:
                stale_guilds.append(guild_id)
                continue
            if channel is None or not hasattr(channel, "send"):
                continue
            try:
                await channel.send(embeds=embeds, allowed_mentions=NO_MENTIONS)
            except discord.Forbidden:
                log.warning("Missing permission to send in channel %s (guild %s)", channel_id, guild_id)
            except discord.HTTPException as e:
                log.warning("Failed to send alert in channel %s (guild %s): %s", channel_id, guild_id, e)

        if stale_guilds:
            for gid in stale_guilds:
                self.notify_channels.pop(gid, None)
            self._save_config()
            log.info("Removed %d stale notify channel config(s)", len(stale_guilds))

    @tasks.loop(minutes=POLL_INTERVAL_MINUTES)
    async def poll_status(self):
        # จับทุก exception ในนี้ เพื่อไม่ให้ loop หยุดเองเงียบ ๆ
        try:
            await self._poll_once()
        except Exception:  # noqa: BLE001
            log.exception("poll_status iteration crashed; will retry next tick")

    @poll_status.before_loop
    async def before_poll_status(self):
        await self.bot.wait_until_ready()


async def setup(bot: commands.Bot):
    await bot.add_cog(WeaoCog(bot))
