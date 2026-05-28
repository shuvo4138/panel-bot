import asyncio
import logging
import os
import re
import hashlib
from datetime import datetime, timezone, timedelta
import httpx
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    Application,
    MessageHandler,
    filters,
)

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════
#                    ENVIRONMENT CONFIG
# ══════════════════════════════════════════════════════════

SHARK_BASE_URL   = os.getenv("SHARK_BASE_URL", "http://65.109.111.158/ints").strip().rstrip("/")
SHARK_USERNAME   = os.getenv("SHARK_USERNAME", "").strip()
SHARK_PASSWORD   = os.getenv("SHARK_PASSWORD", "").strip()

SUPABASE_URL     = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY     = os.getenv("SUPABASE_KEY", "").strip()

BOT_TOKEN        = os.getenv("SHARK_BOT_TOKEN", "").strip()
ADMIN_ID         = int(os.getenv("ADMIN_ID", "0").strip())

POLL_INTERVAL    = int(os.getenv("POLL_INTERVAL", "10"))
SUPABASE_TABLE   = "shark_otps"

# ══════════════════════════════════════════════════════════
#                    SESSION STATE
# ══════════════════════════════════════════════════════════

session_cookies: dict = {}
is_logged_in: bool = False
_seen_hashes: set = set()
_bot_app: Application = None
_poll_task: asyncio.Task = None
_last_sms: dict = {}
_total_collected: int = 0
_poll_running: bool = False
_waiting_cookie: dict = {}
_settings: dict = {
    "poll_interval": POLL_INTERVAL,
}

# ══════════════════════════════════════════════════════════
#                    AUTO LOGIN
# ══════════════════════════════════════════════════════════

async def auto_login() -> bool:
    """Username/password দিয়ে auto login করো, CAPTCHA solve করো।"""
    global session_cookies, is_logged_in

    if not SHARK_USERNAME or not SHARK_PASSWORD:
        logger.warning("SHARK_USERNAME বা SHARK_PASSWORD সেট নেই! Manual cookie ব্যবহার করো।")
        return False

    try:
        async with httpx.AsyncClient(
            timeout=20,
            follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        ) as client:
            # Step 1: Login page GET করো — CAPTCHA নাও
            res = await client.get(f"{SHARK_BASE_URL}/login")
            if res.status_code != 200:
                logger.error(f"Login page GET failed: {res.status_code}")
                return False

            # PHPSESSID save করো
            phpsessid = res.cookies.get("PHPSESSID", "")

            # CAPTCHA solve করো
            match = re.search(r'What is (\d+)\s*\+\s*(\d+)', res.text)
            if not match:
                logger.error("CAPTCHA pattern not found in login page!")
                return False
            captcha_answer = int(match.group(1)) + int(match.group(2))
            logger.info(f"CAPTCHA solved: {match.group(1)} + {match.group(2)} = {captcha_answer}")

            # Step 2: POST করো signin endpoint এ
            login_data = {
                "username": SHARK_USERNAME,
                "password": SHARK_PASSWORD,
                "capt": str(captcha_answer),
                "crlf": "",
            }
            res2 = await client.post(
                f"{SHARK_BASE_URL}/signin",
                data=login_data,
                cookies={"PHPSESSID": phpsessid} if phpsessid else {},
            )

            # 302 মানে login সফল
            if res2.status_code == 302:
                # নতুন PHPSESSID নাও
                new_phpsessid = res2.cookies.get("PHPSESSID", phpsessid)
                if not new_phpsessid:
                    new_phpsessid = phpsessid

                # Step 3: SMSCDRStats page visit করে sesskey নাও
                res3 = await client.get(
                    f"{SHARK_BASE_URL}/agent/SMSCDRStats",
                    cookies={"PHPSESSID": new_phpsessid},
                )
                sesskey = ""
                sk_match = re.search(r'sesskey[=\s:\'\"]+([A-Za-z0-9+/=]{8,})', res3.text)
                if sk_match:
                    sesskey = sk_match.group(1)
                    logger.info(f"Sesskey extracted: {sesskey[:10]}...")

                session_cookies = {"PHPSESSID": new_phpsessid, "sesskey": sesskey}
                is_logged_in = True
                logger.info(f"Auto login successful! PHPSESSID={new_phpsessid[:10]}...")
                return True
            else:
                logger.error(f"Login POST failed: status={res2.status_code}")
                return False

    except Exception as e:
        logger.error(f"Auto login error: {e}")
        return False


async def ensure_logged_in() -> bool:
    """Login নিশ্চিত করো — না থাকলে auto login করো।"""
    global is_logged_in
    if is_logged_in and session_cookies.get("PHPSESSID"):
        return True
    logger.info("Not logged in. Attempting auto login...")
    success = await auto_login()
    if not success:
        logger.error("Auto login failed!")
    return success

# ══════════════════════════════════════════════════════════
#                    SUPABASE HELPERS
# ══════════════════════════════════════════════════════════

def _sb_headers() -> dict:
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
    }

async def supabase_insert(row: dict):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.post(
                f"{SUPABASE_URL}/rest/v1/{SUPABASE_TABLE}",
                headers=_sb_headers(),
                json=row,
            )
        if res.status_code not in (200, 201):
            logger.error(f"Supabase insert error {res.status_code}: {res.text}")
    except Exception as e:
        logger.error(f"Supabase insert exception: {e}")

async def supabase_load_seen():
    global _seen_hashes, _total_collected
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.get(
                f"{SUPABASE_URL}/rest/v1/{SUPABASE_TABLE}",
                headers=_sb_headers(),
                params={"select": "unique_id"},
            )
        rows = res.json()
        if isinstance(rows, list):
            for r in rows:
                _seen_hashes.add(r["unique_id"])
            _total_collected = len(rows)
            logger.info(f"Loaded {len(rows)} existing OTP hashes from Supabase")
    except Exception as e:
        logger.error(f"Supabase load_seen error: {e}")

async def supabase_count() -> int:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.get(
                f"{SUPABASE_URL}/rest/v1/{SUPABASE_TABLE}",
                headers={**_sb_headers(), "Prefer": "count=exact"},
                params={"select": "unique_id", "limit": "1"},
            )
        content_range = res.headers.get("content-range", "")
        if "/" in content_range:
            return int(content_range.split("/")[-1])
    except Exception:
        pass
    return len(_seen_hashes)

async def supabase_last_sms() -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.get(
                f"{SUPABASE_URL}/rest/v1/{SUPABASE_TABLE}",
                headers=_sb_headers(),
                params={
                    "select": "number,otp,message,app,dt",
                    "order": "created_at.desc",
                    "limit": "1",
                },
            )
        rows = res.json()
        if isinstance(rows, list) and rows:
            return rows[0]
    except Exception:
        pass
    return {}

async def supabase_delete_old():
    global _seen_hashes
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        async with httpx.AsyncClient(timeout=10) as client:
            fetch_res = await client.get(
                f"{SUPABASE_URL}/rest/v1/{SUPABASE_TABLE}",
                headers=_sb_headers(),
                params={"select": "unique_id", "created_at": f"lt.{cutoff}"},
            )
            old_ids = set()
            if fetch_res.status_code == 200:
                rows = fetch_res.json()
                if isinstance(rows, list):
                    old_ids = {r["unique_id"] for r in rows if "unique_id" in r}
            del_res = await client.delete(
                f"{SUPABASE_URL}/rest/v1/{SUPABASE_TABLE}",
                headers=_sb_headers(),
                params={"created_at": f"lt.{cutoff}"},
            )
        if del_res.status_code not in (200, 204):
            logger.error(f"Supabase delete_old error {del_res.status_code}: {del_res.text}")
        else:
            if old_ids:
                _seen_hashes -= old_ids
                logger.info(f"Old OTPs (>24h) deleted: {len(old_ids)} records removed from Supabase & memory")
            else:
                logger.info("Old OTPs (>24h): nothing to delete")
    except Exception as e:
        logger.error(f"Supabase delete_old exception: {e}")

# ══════════════════════════════════════════════════════════
#                    SHARK POLLING
# ══════════════════════════════════════════════════════════

def _make_poll_params(fnum: str = "") -> dict:
    bd_now = datetime.now(timezone(timedelta(hours=6)))
    fdate1 = bd_now.strftime("%Y-%m-%d 00:00:00")
    fdate2 = bd_now.strftime("%Y-%m-%d 23:59:59")
    sesskey_val = session_cookies.get("sesskey", "")
    return {
        "fdate1": fdate1, "fdate2": fdate2,
        "frange": "", "fclient": "", "fnum": fnum,
        "fcli": "", "fgdate": "", "fgmonth": "",
        "fgrange": "", "fgclient": "", "fgnumber": "",
        "fgcli": "", "fg": "0", "sesskey": sesskey_val,
        "sEcho": "1", "iColumns": "9",
        "sColumns": ",,,,,,,,",
        "iDisplayStart": "0", "iDisplayLength": "100",
        "mDataProp_0": "0", "mDataProp_1": "1",
        "mDataProp_2": "2", "mDataProp_3": "3",
        "mDataProp_4": "4", "mDataProp_5": "5",
        "mDataProp_6": "6", "mDataProp_7": "7",
        "mDataProp_8": "8", "sSearch": "",
        "bRegex": "false", "iSortCol_0": "0",
        "sSortDir_0": "desc", "iSortingCols": "1",
    }

def _parse_otp(message: str) -> str:
    message_clean = re.sub(r"#\s*", "", message)
    match = re.search(r"\b(\d[\d\s]{3,7}\d)\b", message_clean)
    if match:
        return re.sub(r"\s+", "", match.group(1))
    match2 = re.search(r"\b(\d{4,8})\b", message)
    if match2:
        return match2.group(1)
    return ""

async def shark_fetch_otps(fnum: str = "") -> list:
    global is_logged_in
    if not is_logged_in or not session_cookies.get("PHPSESSID"):
        return []
    try:
        params = _make_poll_params(fnum)
        async with httpx.AsyncClient(
            timeout=15,
            cookies={"PHPSESSID": session_cookies["PHPSESSID"]},
            follow_redirects=False,
            headers={
                "Referer": f"{SHARK_BASE_URL}/agent/SMSCDRStats",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json, text/javascript, */*; q=0.01",
            }
        ) as client:
            res = await client.get(
                f"{SHARK_BASE_URL}/agent/res/data_smscdr.php",
                params=params,
            )

        if res.status_code in (301, 302) or "signin" in res.text.lower():
            logger.warning("Cookie expired! Will re-login on next cycle.")
            is_logged_in = False
            return []

        if not res.text.strip() or res.text.strip()[0] not in ('{', '['):
            logger.warning(f"Non-JSON response (session likely expired): {res.text[:100]}")
            is_logged_in = False
            return []

        data = res.json()
        rows = data.get("aaData", [])
        results = []
        for row in rows:
            if not isinstance(row, list) or len(row) < 6:
                continue
            dt      = str(row[0]) if row[0] else ""
            number  = str(row[2]) if row[2] else ""
            app     = str(row[3]) if row[3] else ""
            message = str(row[5]) if row[5] else ""
            if not number or not message:
                continue
            otp = _parse_otp(message)
            results.append({
                "dt": dt, "number": number,
                "app": app, "message": message, "otp": otp,
            })
        return results

    except Exception as e:
        logger.error(f"Shark fetch error: {e}")
        return []

# ══════════════════════════════════════════════════════════
#                    MAIN POLL LOOP
# ══════════════════════════════════════════════════════════

async def keep_alive_ping() -> bool:
    if not session_cookies.get("PHPSESSID"):
        return False
    try:
        async with httpx.AsyncClient(
            timeout=10,
            cookies={"PHPSESSID": session_cookies["PHPSESSID"]},
            follow_redirects=False,
        ) as client:
            res = await client.get(f"{SHARK_BASE_URL}/agent/SMSCDRStats")
        if res.status_code in (301, 302):
            loc = res.headers.get("location", "")
            if "signin" in loc.lower():
                logger.warning("Keep-alive: session expired (redirect)!")
                return False
        # Body তেও check করো — অনেক সময় redirect ছাড়াই login page দেখায়
        if "signin" in res.text.lower() or 'name="username"' in res.text.lower():
            logger.warning("Keep-alive: login page detected in body — session expired!")
            return False
        return True
    except Exception as e:
        logger.warning(f"Keep-alive ping error: {e}")
        return False

async def poll_loop(bot: Bot):
    global is_logged_in, _last_sms, _total_collected, _poll_running
    _poll_running = True
    _ping_counter = 0
    _relogin_attempts = 0
    _cleanup_counter = 0
    KEEPALIVE_EVERY = max(1, 60 // max(_settings["poll_interval"], 1))  # প্রতি ~60 সেকেন্ডে ping
    logger.info("Poll loop started")

    while True:
        try:
            # Auto login যদি logged out থাকে
            if not is_logged_in:
                _relogin_attempts += 1
                logger.info(f"Auto re-login attempt #{_relogin_attempts}...")
                success = await auto_login()
                if success:
                    _relogin_attempts = 0
                    try:
                        await bot.send_message(
                            ADMIN_ID,
                            "🔄 *Auto Re-Login সফল!*\n\n"
                            f"🍪 PHPSESSID: `{session_cookies.get('PHPSESSID','')[:16]}...`\n"
                            "✅ Polling আবার চালু হয়েছে।",
                            parse_mode="Markdown",
                        )
                    except Exception:
                        pass
                else:
                    wait = min(60 * _relogin_attempts, 300)
                    logger.warning(f"Re-login failed. Waiting {wait}s before retry...")
                    await asyncio.sleep(wait)
                    continue

            # Keep-alive ping
            _ping_counter += 1
            if _ping_counter >= KEEPALIVE_EVERY:
                _ping_counter = 0
                alive = await keep_alive_ping()
                if not alive:
                    is_logged_in = False
                    continue

            otps = await shark_fetch_otps()

            if not is_logged_in:
                # Cookie expire হয়ে গেছে (shark_fetch_otps এ detect হয়েছে) — সাথে সাথে re-login
                try:
                    await bot.send_message(
                        ADMIN_ID,
                        "⚠️ *Cookie Expired!*\n\nAutomatic re-login চেষ্টা করছি...",
                        parse_mode="Markdown",
                    )
                except Exception:
                    pass
                await asyncio.sleep(_settings["poll_interval"])
                continue

            new_count = 0
            for item in otps:
                raw = f"{item['number']}:{item['dt']}:{item['message']}"
                uid = hashlib.md5(raw.encode()).hexdigest()

                if uid in _seen_hashes:
                    continue

                _seen_hashes.add(uid)
                _last_sms = item
                _total_collected += 1

                row = {
                    "unique_id":  uid,
                    "number":     item["number"],
                    "otp":        item["otp"],
                    "message":    item["message"],
                    "app":        item["app"],
                    "dt":         item["dt"],
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                await supabase_insert(row)
                new_count += 1
                logger.info(f"New OTP saved: {item['number']} -> {item['otp']}")

            if new_count:
                logger.info(f"{new_count} new OTP(s) saved to Supabase")

            _cleanup_counter += 1
            if _cleanup_counter >= 30:
                _cleanup_counter = 0
                await supabase_delete_old()

        except asyncio.CancelledError:
            _poll_running = False
            logger.info("Poll loop cancelled")
            raise
        except Exception as e:
            logger.error(f"Poll loop error: {e}")

        await asyncio.sleep(_settings["poll_interval"])

# ══════════════════════════════════════════════════════════
#                    KEYBOARD BUILDER
# ══════════════════════════════════════════════════════════

def main_menu_keyboard() -> InlineKeyboardMarkup:
    conn_icon = "🟢" if is_logged_in else "🔴"
    keyboard = [
        [
            InlineKeyboardButton(f"📡 Panel Status {conn_icon}", callback_data="status"),
            InlineKeyboardButton("🔄 Force Re-Login", callback_data="force_relogin"),
        ],
        [
            InlineKeyboardButton("🔄 Restart Polling", callback_data="restart_poll"),
            InlineKeyboardButton("🗑 Clear Cookie",    callback_data="clear_cookie"),
        ],
        [
            InlineKeyboardButton("📨 Last SMS",   callback_data="last_sms"),
            InlineKeyboardButton("📊 SMS Count",  callback_data="sms_count"),
        ],
        [
            InlineKeyboardButton("⚙️ Settings", callback_data="settings"),
        ],
    ]
    return InlineKeyboardMarkup(keyboard)

def settings_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [
            InlineKeyboardButton("⏱ 5s",  callback_data="interval_5"),
            InlineKeyboardButton("⏱ 10s", callback_data="interval_10"),
            InlineKeyboardButton("⏱ 30s", callback_data="interval_30"),
        ],
        [InlineKeyboardButton("◀️ Back", callback_data="back_main")],
    ]
    return InlineKeyboardMarkup(keyboard)

# ══════════════════════════════════════════════════════════
#                    ADMIN CHECK
# ══════════════════════════════════════════════════════════

def is_admin(update) -> bool:
    uid = update.effective_user.id if update.effective_user else None
    return uid == ADMIN_ID

# ══════════════════════════════════════════════════════════
#                    COMMAND HANDLERS
# ══════════════════════════════════════════════════════════

async def cmd_start(update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    conn_status = "✅ Logged In" if is_logged_in else "❌ Not Logged In"
    auto_status = "✅ সেট আছে" if (SHARK_USERNAME and SHARK_PASSWORD) else "❌ সেট নেই"
    await update.message.reply_text(
        "🦈 *Shark Panel Bot v3*\n\n"
        f"🔌 Status: {conn_status}\n"
        f"🤖 Auto Login: {auto_status}\n\n"
        "Panel থেকে SMS/OTP collect করে Supabase-এ save করে।\n"
        "Auto login সক্রিয় — cookie expire হলে নিজেই re-login করবে।\n\n"
        "নিচের buttons থেকে সব কাজ করো 👇",
        parse_mode="Markdown",
        reply_markup=main_menu_keyboard(),
    )

async def cmd_menu(update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    await update.message.reply_text(
        "🦈 *Shark Panel Bot — Menu*",
        parse_mode="Markdown",
        reply_markup=main_menu_keyboard(),
    )

async def cmd_setcookie(update, context: ContextTypes.DEFAULT_TYPE):
    """Manual cookie set — optional, auto login আছে।"""
    global session_cookies, is_logged_in
    if not is_admin(update):
        return
    if not context.args:
        await update.message.reply_text(
            "📋 *Manual Cookie (Optional)*\n\n"
            "`/setcookie <PHPSESSID>`\n\n"
            "💡 Auto login সক্রিয় থাকলে এটা দরকার নেই।",
            parse_mode="Markdown",
        )
        return
    phpsessid = context.args[0].strip()
    new_sesskey = context.args[1].strip() if len(context.args) > 1 else ""
    msg = await update.message.reply_text("🔍 Cookie set করছি...")
    extracted_sesskey = new_sesskey
    if not extracted_sesskey:
        # sesskey extract করার চেষ্টা
        try:
            async with httpx.AsyncClient(
                timeout=15,
                cookies={"PHPSESSID": phpsessid},
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            ) as client:
                res = await client.get(f"{SHARK_BASE_URL}/agent/SMSCDRStats")
            sk_match = re.search(r'sesskey[=\s:\'\"]+([A-Za-z0-9+/=]{8,})', res.text)
            if sk_match:
                extracted_sesskey = sk_match.group(1)
        except Exception:
            pass
    session_cookies = {"PHPSESSID": phpsessid, "sesskey": extracted_sesskey}
    is_logged_in = True
    await msg.edit_text(
        f"✅ *Cookie Set!*\n\n"
        f"🍪 PHPSESSID: `{phpsessid[:20]}...`\n"
        f"🔑 Sesskey: `{extracted_sesskey[:16] or 'N/A'}`",
        parse_mode="Markdown",
        reply_markup=main_menu_keyboard(),
    )

async def cmd_clearcookie(update, context: ContextTypes.DEFAULT_TYPE):
    global session_cookies, is_logged_in
    if not is_admin(update):
        return
    session_cookies = {}
    is_logged_in = False
    await update.message.reply_text(
        "🗑 *Cookie Cleared!*\n\nAuto re-login পরের cycle এ হবে।",
        parse_mode="Markdown",
        reply_markup=main_menu_keyboard(),
    )

# ══════════════════════════════════════════════════════════
#                    CALLBACK HANDLER
# ══════════════════════════════════════════════════════════

async def callback_handler(update, context: ContextTypes.DEFAULT_TYPE):
    global session_cookies, is_logged_in, _poll_task, _poll_running

    query = update.callback_query
    if not query or query.from_user.id != ADMIN_ID:
        return
    await query.answer()

    data = query.data

    if data == "status":
        status_icon = "✅ Logged In" if is_logged_in else "❌ Not Logged In"
        poll_icon   = "🟢 Running"   if _poll_running  else "🔴 Stopped"
        phpsessid   = session_cookies.get("PHPSESSID", "")
        sesskey_val = session_cookies.get("sesskey", "")
        sid_display = f"`{phpsessid[:16]}...`" if len(phpsessid) > 16 else f"`{phpsessid or 'N/A'}`"
        sk_display  = f"`{sesskey_val[:16]}...`" if len(sesskey_val) > 16 else f"`{sesskey_val or 'N/A'}`"
        auto_login_status = "✅ সক্রিয়" if (SHARK_USERNAME and SHARK_PASSWORD) else "❌ Credentials নেই"
        bd_now = datetime.now(timezone(timedelta(hours=6))).strftime("%Y-%m-%d %H:%M:%S")
        text = (
            f"📡 *Panel Status*\n\n"
            f"🔌 Login: {status_icon}\n"
            f"🤖 Auto Login: {auto_login_status}\n"
            f"🔄 Polling: {poll_icon}\n"
            f"⏱ Interval: {_settings['poll_interval']}s\n\n"
            f"🍪 PHPSESSID: {sid_display}\n"
            f"🔑 Sesskey: {sk_display}\n\n"
            f"📦 Seen (cache): `{len(_seen_hashes)}`\n"
            f"📊 Total collected: `{_total_collected}`\n"
            f"🕐 BD Time: `{bd_now}`"
        )
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard())

    elif data == "force_relogin":
        await query.edit_message_text("🔄 Manual re-login চেষ্টা করছি...", parse_mode="Markdown")
        session_cookies = {}
        is_logged_in = False
        success = await auto_login()
        if success:
            text = (
                "✅ *Re-Login সফল!*\n\n"
                f"🍪 PHPSESSID: `{session_cookies.get('PHPSESSID','')[:16]}...`\n"
                f"🔑 Sesskey: `{session_cookies.get('sesskey','')[:16] or 'N/A'}`\n\n"
                "🟢 Polling চলছে।"
            )
        else:
            text = "❌ *Re-Login ব্যর্থ!*\n\nCredentials চেক করো।"
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard())

    elif data == "clear_cookie":
        session_cookies = {}
        is_logged_in = False
        await query.edit_message_text(
            "🗑 *Cookie Cleared!*\n\nAuto re-login পরের cycle এ হবে।",
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(),
        )

    elif data == "restart_poll":
        await query.edit_message_text("🔄 Polling restart হচ্ছে...", parse_mode="Markdown")
        if _poll_task and not _poll_task.done():
            _poll_task.cancel()
            try:
                await _poll_task
            except asyncio.CancelledError:
                pass
        _poll_running = False
        _poll_task = context.application.create_task(
            poll_loop(context.bot), name="shark_poll_loop"
        )
        await asyncio.sleep(1)
        await query.edit_message_text(
            "✅ *Polling Restarted!*",
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(),
        )

    elif data == "last_sms":
        record = _last_sms if _last_sms else await supabase_last_sms()
        if record:
            text = (
                f"📨 *Last SMS*\n\n"
                f"📱 Number: `{record.get('number', 'N/A')}`\n"
                f"🔑 OTP: `{record.get('otp', 'N/A') or 'N/A'}`\n"
                f"📦 App: {record.get('app', 'Unknown') or 'Unknown'}\n"
                f"💬 Message:\n`{record.get('message', 'N/A')[:200]}`\n"
                f"🕐 Time: {record.get('dt', 'N/A')}"
            )
        else:
            text = "📨 *Last SMS*\n\nএখনো কোনো SMS collect হয়নি।"
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard())

    elif data == "sms_count":
        await query.edit_message_text("📊 Supabase থেকে count আনছি...", parse_mode="Markdown")
        total = await supabase_count()
        text = (
            f"📊 *SMS Count*\n\n"
            f"🗄 Supabase total: `{total}`\n"
            f"💾 Cache (seen): `{len(_seen_hashes)}`\n"
            f"✅ This session: `{_total_collected}`"
        )
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard())

    elif data == "settings":
        text = (
            f"⚙️ *Settings*\n\n"
            f"⏱ Poll Interval: *{_settings['poll_interval']}s*\n\n"
            f"নিচে পরিবর্তন করো 👇"
        )
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=settings_keyboard())

    elif data in ("interval_5", "interval_10", "interval_30"):
        val = int(data.split("_")[1])
        _settings["poll_interval"] = val
        text = (
            f"⚙️ *Settings*\n\n"
            f"⏱ Poll Interval: *{val}s* ✅"
        )
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=settings_keyboard())

    elif data == "back_main":
        await query.edit_message_text(
            "🦈 *Shark Panel Bot — Menu*",
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(),
        )

# ══════════════════════════════════════════════════════════
#                    MESSAGE HANDLER
# ══════════════════════════════════════════════════════════

async def message_handler(update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    # Manual cookie flow এখন নেই, auto login আছে
    pass

# ══════════════════════════════════════════════════════════
#                    STARTUP / SHUTDOWN
# ══════════════════════════════════════════════════════════

async def post_init(app: Application):
    global _bot_app, _poll_task
    _bot_app = app
    logger.info("Shark Panel Bot v3 starting...")

    try:
        await supabase_load_seen()

        # Auto login করো
        auto_ok = await auto_login()
        status_text = (
            "✅ Auto login সফল!" if auto_ok
            else "⚠️ Auto login ব্যর্থ — credentials চেক করো বা /setcookie দাও।"
        )

        _poll_task = asyncio.ensure_future(poll_loop(app.bot))
        logger.info("Shark Panel Bot v3 ready!")

        await app.bot.send_message(
            ADMIN_ID,
            f"🦈 *Shark Panel Bot v3 চালু হয়েছে!*\n\n"
            f"📊 Loaded: `{len(_seen_hashes)}` existing records\n"
            f"🤖 {status_text}\n\n"
            "📋 Menu দেখতে /menu চাপো 👇",
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(),
        )

    except Exception as e:
        logger.error(f"Error during post_init: {e}", exc_info=True)

async def post_shutdown(app: Application):
    global _poll_task, _poll_running
    logger.info("Shark Panel Bot shutting down...")
    _poll_running = False
    if _poll_task:
        _poll_task.cancel()
        try:
            await _poll_task
        except asyncio.CancelledError:
            logger.info("Poll task cancelled")
    logger.info("Shutdown complete.")

# ══════════════════════════════════════════════════════════
#                    MAIN
# ══════════════════════════════════════════════════════════

def main():
    try:
        app = (
            ApplicationBuilder()
            .token(BOT_TOKEN)
            .post_init(post_init)
            .post_shutdown(post_shutdown)
            .build()
        )

        app.add_handler(CommandHandler("start",       cmd_start))
        app.add_handler(CommandHandler("menu",        cmd_menu))
        app.add_handler(CommandHandler("setcookie",   cmd_setcookie))
        app.add_handler(CommandHandler("clearcookie", cmd_clearcookie))
        app.add_handler(CallbackQueryHandler(callback_handler))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))

        logger.info("Shark Panel Bot v3 starting polling...")
        app.run_polling(
            drop_pending_updates=True,
            timeout=30,
            allowed_updates=["message", "callback_query"],
        )

    except Exception as e:
        logger.error(f"Fatal error in main: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
