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

SHARK_BASE_URL = os.getenv("SHARK_BASE_URL", "http://65.109.111.158/ints").strip().rstrip("/")

SUPABASE_URL   = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY   = os.getenv("SUPABASE_KEY", "").strip()

BOT_TOKEN      = os.getenv("SHARK_BOT_TOKEN", "").strip()
ADMIN_ID       = int(os.getenv("ADMIN_ID", "0").strip())

POLL_INTERVAL  = int(os.getenv("POLL_INTERVAL", "10"))
SUPABASE_TABLE = "shark_otps"

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
    "notify_new_sms": True,
}

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

# ══════════════════════════════════════════════════════════
#                    COOKIE VERIFICATION
# ══════════════════════════════════════════════════════════

async def verify_cookie(phpsessid: str) -> bool:
    """Test the cookie against the panel. Returns True if valid."""
    try:
        bd_now = datetime.now(timezone(timedelta(hours=6)))
        params = {
            "fdate1": bd_now.strftime("%Y-%m-%d 00:00:00"),
            "fdate2": bd_now.strftime("%Y-%m-%d 23:59:59"),
            "frange": "", "fclient": "", "fnum": "",
            "fcli": "", "fgdate": "", "fgmonth": "",
            "fgrange": "", "fgclient": "", "fgnumber": "",
            "fgcli": "", "fg": "0", "sesskey": "",
            "sEcho": "1", "iColumns": "9",
            "sColumns": ",,,,,,,,",
            "iDisplayStart": "0", "iDisplayLength": "10",
            "mDataProp_0": "0", "mDataProp_1": "1",
            "mDataProp_2": "2", "mDataProp_3": "3",
            "mDataProp_4": "4", "mDataProp_5": "5",
            "mDataProp_6": "6", "mDataProp_7": "7",
            "mDataProp_8": "8", "sSearch": "",
            "bRegex": "false", "iSortCol_0": "0",
            "sSortDir_0": "desc", "iSortingCols": "1",
        }
        async with httpx.AsyncClient(
            timeout=15,
            cookies={"PHPSESSID": phpsessid},
            follow_redirects=False,
        ) as client:
            res = await client.get(
                f"{SHARK_BASE_URL}/agent/res/data_smscdr.php",
                params=params,
            )
        if res.status_code in (301, 302):
            return False
        if "signin" in res.text.lower():
            return False
        data = res.json()
        return "aaData" in data
    except Exception as e:
        logger.error(f"Cookie verification error: {e}")
    return False

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
        ) as client:
            res = await client.get(
                f"{SHARK_BASE_URL}/agent/res/data_smscdr.php",
                params=params,
            )

        if res.status_code in (301, 302) or "signin" in res.text.lower():
            logger.warning("Cookie expired or invalid!")
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

async def poll_loop(bot: Bot):
    global is_logged_in, _last_sms, _total_collected, _poll_running
    _poll_running = True
    logger.info("Poll loop started")

    while True:
        try:
            if not is_logged_in:
                await asyncio.sleep(_settings["poll_interval"])
                continue

            otps = await shark_fetch_otps()

            if not is_logged_in:
                # Cookie invalidated during fetch
                try:
                    await bot.send_message(
                        ADMIN_ID,
                        "⚠️ *Cookie Expired!*\n\n"
                        "Shark panel cookie মেয়াদ শেষ হয়েছে।\n"
                        "নতুন cookie দিতে /setcookie বা /menu ব্যবহার করো।",
                        parse_mode="Markdown",
                        reply_markup=main_menu_keyboard(),
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
                    "created_at": datetime.utcnow().isoformat(),
                }
                await supabase_insert(row)
                new_count += 1
                logger.info(f"New OTP saved: {item['number']} -> {item['otp']}")

                if _settings.get("notify_new_sms"):
                    try:
                        notif = (
                            f"📨 *New SMS Collected*\n\n"
                            f"📱 Number: `{item['number']}`\n"
                            f"🔑 OTP: `{item['otp'] or 'N/A'}`\n"
                            f"📦 App: {item['app'] or 'Unknown'}\n"
                            f"💬 Message: {item['message'][:100]}\n"
                            f"🕐 Time: {item['dt']}"
                        )
                        await bot.send_message(ADMIN_ID, notif, parse_mode="Markdown")
                    except Exception:
                        pass

            if new_count:
                logger.info(f"{new_count} new OTP(s) saved to Supabase")

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
            InlineKeyboardButton("🍪 Set Cookie",               callback_data="set_cookie_prompt"),
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
    notify_label = "🔔 Notify: ON" if _settings["notify_new_sms"] else "🔕 Notify: OFF"
    keyboard = [
        [InlineKeyboardButton(notify_label, callback_data="toggle_notify")],
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
    conn_status = "✅ Cookie সেট আছে" if is_logged_in else "❌ Cookie সেট নেই"
    await update.message.reply_text(
        "🦈 *Shark Panel Bot*\n\n"
        f"🔌 Status: {conn_status}\n\n"
        "Panel থেকে SMS/OTP collect করে Supabase-এ save করে।\n"
        "Cookie manually দিতে হবে — auto login নেই।\n\n"
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
    global session_cookies, is_logged_in
    if not is_admin(update):
        return

    if not context.args:
        await update.message.reply_text(
            "📋 *Cookie Set করার নিয়ম:*\n\n"
            "`/setcookie <PHPSESSID>`\n\n"
            "অথবা sesskey সহ:\n"
            "`/setcookie <PHPSESSID> <sesskey>`\n\n"
            "💡 Browser DevTools → Application → Cookies → PHPSESSID value কপি করো।",
            parse_mode="Markdown",
        )
        return

    phpsessid = context.args[0].strip()
    new_sesskey = context.args[1].strip() if len(context.args) > 1 else ""

    msg = await update.message.reply_text("🔍 Cookie verify করছি...")

    valid = await verify_cookie(phpsessid)
    if valid:
        session_cookies = {"PHPSESSID": phpsessid, "sesskey": new_sesskey}
        is_logged_in = True
        sid_display = f"`{phpsessid[:20]}...`" if len(phpsessid) > 20 else f"`{phpsessid}`"
        sk_display = f"`{new_sesskey[:16]}...`" if len(new_sesskey) > 16 else f"`{new_sesskey or 'N/A'}`"
        await msg.edit_text(
            f"✅ *Cookie Set Successfully!*\n\n"
            f"🍪 PHPSESSID: {sid_display}\n"
            f"🔑 Sesskey: {sk_display}\n\n"
            f"🟢 Polling চালু থাকবে এই cookie দিয়ে।",
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(),
        )
        logger.info(f"Cookie manually set and verified. PHPSESSID={phpsessid[:10]}...")
    else:
        await msg.edit_text(
            "❌ *Cookie Invalid বা Expired!*\n\n"
            "এই PHPSESSID দিয়ে panel-এ access হচ্ছে না।\n\n"
            "1. Browser-এ panel-এ login করো\n"
            "2. DevTools → Cookies → PHPSESSID কপি করো\n"
            "3. আবার `/setcookie <value>` দাও",
            parse_mode="Markdown",
        )

async def cmd_clearcookie(update, context: ContextTypes.DEFAULT_TYPE):
    global session_cookies, is_logged_in
    if not is_admin(update):
        return
    session_cookies = {}
    is_logged_in = False
    await update.message.reply_text(
        "🗑 *Cookie Cleared!*\n\nPolling বন্ধ হয়ে গেছে।\nনতুন cookie দিতে /setcookie ব্যবহার করো।",
        parse_mode="Markdown",
        reply_markup=main_menu_keyboard(),
    )

# ══════════════════════════════════════════════════════════
#              PLAIN MESSAGE HANDLER (button cookie flow)
# ══════════════════════════════════════════════════════════

async def message_handler(update, context: ContextTypes.DEFAULT_TYPE):
    global session_cookies, is_logged_in
    if not is_admin(update):
        return
    chat_id = update.effective_chat.id
    text = (update.message.text or "").strip()

    if not _waiting_cookie.get(chat_id):
        return

    parts = text.split()
    phpsessid = parts[0]
    new_sesskey = parts[1] if len(parts) > 1 else ""

    _waiting_cookie[chat_id] = False

    msg = await update.message.reply_text("🔍 Cookie verify করছি...")

    valid = await verify_cookie(phpsessid)
    if valid:
        session_cookies = {"PHPSESSID": phpsessid, "sesskey": new_sesskey}
        is_logged_in = True
        sid_display = f"`{phpsessid[:20]}...`" if len(phpsessid) > 20 else f"`{phpsessid}`"
        sk_display = f"`{new_sesskey[:16]}...`" if len(new_sesskey) > 16 else f"`{new_sesskey or 'N/A'}`"
        await msg.edit_text(
            f"✅ *Cookie Set Successfully!*\n\n"
            f"🍪 PHPSESSID: {sid_display}\n"
            f"🔑 Sesskey: {sk_display}\n\n"
            f"🟢 Polling চালু হয়েছে।",
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(),
        )
        logger.info(f"Cookie set via message flow. PHPSESSID={phpsessid[:10]}...")
    else:
        await msg.edit_text(
            "❌ *Cookie Invalid বা Expired!*\n\n"
            "আবার চেষ্টা করো অথবা `/setcookie <PHPSESSID>` ব্যবহার করো।",
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
    chat_id = query.message.chat_id

    if data == "status":
        status_icon = "✅ Connected" if is_logged_in else "❌ No Cookie Set"
        poll_icon   = "🟢 Running"   if _poll_running  else "🔴 Stopped"
        phpsessid   = session_cookies.get("PHPSESSID", "")
        sesskey_val = session_cookies.get("sesskey", "")
        sid_display = f"`{phpsessid[:16]}...`" if len(phpsessid) > 16 else f"`{phpsessid or 'N/A'}`"
        sk_display  = f"`{sesskey_val[:16]}...`" if len(sesskey_val) > 16 else f"`{sesskey_val or 'N/A'}`"
        bd_now = datetime.now(timezone(timedelta(hours=6))).strftime("%Y-%m-%d %H:%M:%S")

        text = (
            f"📡 *Panel Status*\n\n"
            f"🔌 Cookie: {status_icon}\n"
            f"🔄 Polling: {poll_icon}\n"
            f"⏱ Interval: {_settings['poll_interval']}s\n\n"
            f"🍪 PHPSESSID: {sid_display}\n"
            f"🔑 Sesskey: {sk_display}\n\n"
            f"📦 Seen (cache): `{len(_seen_hashes)}`\n"
            f"📊 Total collected: `{_total_collected}`\n"
            f"🕐 BD Time: `{bd_now}`"
        )
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard())

    elif data == "set_cookie_prompt":
        _waiting_cookie[chat_id] = True
        text = (
            "🍪 *Manual Cookie Entry*\n\n"
            "নিচের format-এ cookie পাঠাও:\n\n"
            "`PHPSESSID_VALUE`\n\n"
            "অথবা sesskey সহ:\n"
            "`PHPSESSID_VALUE sesskey_VALUE`\n\n"
            "📋 *Cookie কোথায় পাবে?*\n"
            "1. Browser-এ panel-এ login করো\n"
            "2. F12 → Application → Cookies\n"
            "3. PHPSESSID value কপি করো\n\n"
            "অথবা command দিয়ে:\n"
            "`/setcookie <PHPSESSID>`"
        )
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("◀️ Cancel", callback_data="back_main")]
        ]))

    elif data == "clear_cookie":
        session_cookies = {}
        is_logged_in = False
        _waiting_cookie[chat_id] = False
        await query.edit_message_text(
            "🗑 *Cookie Cleared!*\n\n"
            "Polling বন্ধ হয়েছে।\nনতুন cookie দিতে 🍪 Set Cookie বাটন চাপো।",
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(),
        )

    elif data == "restart_poll":
        if not is_logged_in:
            await query.answer("⚠️ আগে cookie সেট করো!", show_alert=True)
            return

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
            "✅ *Polling Restarted!*\n\nBackground loop নতুনভাবে চালু হয়েছে।",
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
        notify_status = "ON 🔔" if _settings["notify_new_sms"] else "OFF 🔕"
        text = (
            f"⚙️ *Settings*\n\n"
            f"🔔 New SMS Notify: *{notify_status}*\n"
            f"⏱ Poll Interval: *{_settings['poll_interval']}s*\n\n"
            f"নিচে পরিবর্তন করো 👇"
        )
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=settings_keyboard())

    elif data == "toggle_notify":
        _settings["notify_new_sms"] = not _settings["notify_new_sms"]
        notify_status = "ON 🔔" if _settings["notify_new_sms"] else "OFF 🔕"
        text = (
            f"⚙️ *Settings*\n\n"
            f"🔔 New SMS Notify: *{notify_status}*\n"
            f"⏱ Poll Interval: *{_settings['poll_interval']}s*"
        )
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=settings_keyboard())

    elif data in ("interval_5", "interval_10", "interval_30"):
        val = int(data.split("_")[1])
        _settings["poll_interval"] = val
        text = (
            f"⚙️ *Settings*\n\n"
            f"🔔 New SMS Notify: *{'ON 🔔' if _settings['notify_new_sms'] else 'OFF 🔕'}*\n"
            f"⏱ Poll Interval: *{val}s* ✅"
        )
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=settings_keyboard())

    elif data == "back_main":
        _waiting_cookie[chat_id] = False
        await query.edit_message_text(
            "🦈 *Shark Panel Bot — Menu*",
            parse_mode="Markdown",
            reply_markup=main_menu_keyboard(),
        )

# ══════════════════════════════════════════════════════════
#                    STARTUP / SHUTDOWN
# ══════════════════════════════════════════════════════════

async def post_init(app: Application):
    global _bot_app, _poll_task
    _bot_app = app
    logger.info("Shark Panel Bot starting...")

    try:
        await supabase_load_seen()
        _poll_task = app.create_task(poll_loop(app.bot), name="shark_poll_loop")
        logger.info("Shark Panel Bot ready!")

        await app.bot.send_message(
            ADMIN_ID,
            "🦈 *Shark Panel Bot চালু হয়েছে!*\n\n"
            f"📊 Loaded: `{len(_seen_hashes)}` existing records\n"
            f"🔌 Status: ❌ Cookie সেট নেই\n\n"
            "📋 শুরু করতে নিচে 🍪 *Set Cookie* চাপো 👇",
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
    logger.info("Shark Panel Bot shutdown complete.")

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

        logger.info("Shark Panel Bot starting polling...")
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
