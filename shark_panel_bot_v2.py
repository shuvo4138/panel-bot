import asyncio
import logging
import os
import re
import hashlib
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import httpx
from bs4 import BeautifulSoup
from telegram import Bot
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, Application

load_dotenv()

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

SHARK_BASE_URL  = os.getenv("SHARK_BASE_URL", "http://65.109.111.158/ints").strip().rstrip("/")
SHARK_USERNAME  = os.getenv("SHARK_USERNAME", "").strip()
SHARK_PASSWORD  = os.getenv("SHARK_PASSWORD", "").strip()

SUPABASE_URL    = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY    = os.getenv("SUPABASE_KEY", "").strip()

BOT_TOKEN       = os.getenv("SHARK_BOT_TOKEN", "").strip()
ADMIN_ID        = int(os.getenv("ADMIN_ID", "0").strip())

POLL_INTERVAL   = int(os.getenv("POLL_INTERVAL", "10"))   # seconds
SUPABASE_TABLE  = "shark_otps"

# ══════════════════════════════════════════════════════════
#                    SESSION STATE
# ══════════════════════════════════════════════════════════

session_cookies: dict = {}          # {"PHPSESSID": "..."}
sesskey: str = ""                   # base64 sesskey from panel
is_logged_in: bool = False
_seen_hashes: set = set()           # dedup cache
_bot_app: Application = None        # filled in main()

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
    """Insert one OTP row into Supabase."""
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
    """Load already-seen unique_ids from Supabase on startup."""
    global _seen_hashes
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
            logger.info(f"✅ Loaded {len(rows)} existing OTP hashes from Supabase")
    except Exception as e:
        logger.error(f"Supabase load_seen error: {e}")

# ══════════════════════════════════════════════════════════
#                    SHARK LOGIN
# ══════════════════════════════════════════════════════════

def _solve_math_captcha(question: str) -> int:
    """Parse math captcha like 'What is X + Y = ?' and return answer."""
    # Match: number, operator, number
    match = re.search(r"(\d+)\s*([+\-\*x×])\s*(\d+)", question)
    if match:
        a = int(match.group(1))
        op = match.group(2)
        b = int(match.group(3))
        if op == "+":
            return a + b
        elif op == "-":
            return a - b
        elif op in ("*", "x", "×"):
            return a * b
    # Fallback: just sum all digits found
    nums = re.findall(r"\d+", question)
    if len(nums) >= 2:
        return int(nums[0]) + int(nums[1])
    return 0

async def shark_login() -> bool:
    """Login to Shark Panel, store PHPSESSID and sesskey."""
    global session_cookies, sesskey, is_logged_in
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            # Step 1: GET login page to get captcha question
            res = await client.get(f"{SHARK_BASE_URL}/signin")
            soup = BeautifulSoup(res.text, "html.parser")

            # Find captcha question - search entire page
            capt_text = ""
            # Try common captcha patterns
            for tag in soup.find_all(["label", "div", "span", "p"]):
                text = tag.get_text()
                if re.search(r"\d+\s*[+\-\*x×]\s*\d+", text):
                    capt_text = text
                    break
            # Fallback: search raw HTML
            if not capt_text:
                raw_match = re.search(r"(\d+\s*[+\-\*x×]\s*\d+)", res.text)
                if raw_match:
                    capt_text = raw_match.group(1)
            capt_answer = _solve_math_captcha(capt_text)
            logger.info(f"Captcha: '{capt_text.strip()}' → answer: {capt_answer}")

            # Step 2: POST login
            payload = {
                "crlf": "",
                "username": SHARK_USERNAME,
                "password": SHARK_PASSWORD,
                "capt": str(capt_answer),
            }
            login_res = await client.post(
                f"{SHARK_BASE_URL}/signin",
                data=payload,
            )

            # Check if logged in (redirected to agent/)
            if "SMSDashboard" in login_res.text or "agent" in str(login_res.url):
                # Extract PHPSESSID
                phpsessid = client.cookies.get("PHPSESSID", "")
                if not phpsessid:
                    # Try from response cookies
                    for c in login_res.cookies.items():
                        if c[0] == "PHPSESSID":
                            phpsessid = c[1]

                session_cookies = {"PHPSESSID": phpsessid}

                # Extract sesskey from dashboard page
                soup2 = BeautifulSoup(login_res.text, "html.parser")
                sk_match = re.search(r"sesskey[=\s'\"]+([A-Za-z0-9+/=]+)", login_res.text)
                if sk_match:
                    sesskey = sk_match.group(1)
                else:
                    # Try URL params if redirected
                    sesskey = ""

                is_logged_in = True
                logger.info(f"✅ Shark login success! PHPSESSID={phpsessid[:10]}...")
                return True
            else:
                logger.error("❌ Shark login failed — check credentials or captcha solve")
                is_logged_in = False
                return False

    except Exception as e:
        logger.error(f"Shark login exception: {e}")
        is_logged_in = False
        return False

# ══════════════════════════════════════════════════════════
#                    SHARK POLLING
# ══════════════════════════════════════════════════════════

def _make_poll_params(fnum: str = "") -> dict:
    """Build the DataTable query params for Shark SMS CDR."""
    bd_now = datetime.now(timezone(timedelta(hours=6)))
    fdate1 = bd_now.strftime("%Y-%m-%d 00:00:00")
    fdate2 = bd_now.strftime("%Y-%m-%d 23:59:59")
    return {
        "fdate1": fdate1,
        "fdate2": fdate2,
        "frange": "",
        "fclient": "",
        "fnum": fnum,
        "fcli": "",
        "fgdate": "",
        "fgmonth": "",
        "fgrange": "",
        "fgclient": "",
        "fgnumber": "",
        "fgcli": "",
        "fg": "0",
        "sesskey": sesskey,
        "sEcho": "1",
        "iColumns": "9",
        "sColumns": ",,,,,,,,",
        "iDisplayStart": "0",
        "iDisplayLength": "100",
        "mDataProp_0": "0",
        "mDataProp_1": "1",
        "mDataProp_2": "2",
        "mDataProp_3": "3",
        "mDataProp_4": "4",
        "mDataProp_5": "5",
        "mDataProp_6": "6",
        "mDataProp_7": "7",
        "mDataProp_8": "8",
        "sSearch": "",
        "bRegex": "false",
        "iSortCol_0": "0",
        "sSortDir_0": "desc",
        "iSortingCols": "1",
    }

def _parse_otp(message: str) -> str:
    """Extract OTP digits from SMS message."""
    # Remove spaces between digits: "# 937 486" → "937486"
    message_clean = re.sub(r"#\s*", "", message)
    # Find 4-8 digit OTP
    match = re.search(r"\b(\d[\d\s]{3,7}\d)\b", message_clean)
    if match:
        return re.sub(r"\s+", "", match.group(1))
    # Fallback: any 4-8 digit number
    match2 = re.search(r"\b(\d{4,8})\b", message)
    if match2:
        return match2.group(1)
    return ""

async def shark_fetch_otps(fnum: str = "") -> list:
    """Fetch latest OTPs from Shark Panel."""
    global is_logged_in
    try:
        params = _make_poll_params(fnum)
        async with httpx.AsyncClient(
            timeout=15,
            cookies=session_cookies,
            follow_redirects=False,
        ) as client:
            res = await client.get(
                f"{SHARK_BASE_URL}/agent/res/data_smscdr.php",
                params=params,
            )

        # Session expired → redirect to signin
        if res.status_code in (301, 302) or "signin" in res.text.lower():
            logger.warning("⚠️ Session expired, re-logging in...")
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
                "dt": dt,
                "number": number,
                "app": app,
                "message": message,
                "otp": otp,
            })
        return results

    except Exception as e:
        logger.error(f"Shark fetch error: {e}")
        return []

# ══════════════════════════════════════════════════════════
#                    MAIN POLL LOOP
# ══════════════════════════════════════════════════════════

async def poll_loop(bot: Bot):
    """Main background loop: poll Shark → save new OTPs to Supabase."""
    global is_logged_in

    logger.info("🔄 Poll loop started")

    while True:
        try:
            # Re-login if needed
            if not is_logged_in:
                success = await shark_login()
                if not success:
                    logger.error("Login failed, retrying in 30s...")
                    # Alert admin
                    try:
                        await bot.send_message(
                            ADMIN_ID,
                            "❌ Shark Panel login failed!\nCredentials/captcha problem. Retrying in 30s."
                        )
                    except Exception:
                        pass
                    await asyncio.sleep(30)
                    continue

            # Fetch OTPs
            otps = await shark_fetch_otps()

            new_count = 0
            for item in otps:
                # Unique hash: number + datetime + message
                raw = f"{item['number']}:{item['dt']}:{item['message']}"
                uid = hashlib.md5(raw.encode()).hexdigest()

                if uid in _seen_hashes:
                    continue

                _seen_hashes.add(uid)

                # Save to Supabase
                row = {
                    "unique_id": uid,
                    "number":    item["number"],
                    "otp":       item["otp"],
                    "message":   item["message"],
                    "app":       item["app"],
                    "dt":        item["dt"],
                    "created_at": datetime.utcnow().isoformat(),
                }
                await supabase_insert(row)
                new_count += 1
                logger.info(f"✅ New OTP saved: {item['number']} → {item['otp']}")

            if new_count:
                logger.info(f"📥 {new_count} new OTP(s) saved to Supabase")

        except Exception as e:
            logger.error(f"Poll loop error: {e}")

        await asyncio.sleep(POLL_INTERVAL)

# ══════════════════════════════════════════════════════════
#                    ADMIN COMMANDS
# ══════════════════════════════════════════════════════════

async def cmd_start(update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(
        "🦈 Shark Panel Bot\n\n"
        "/status — Panel connection status\n"
        "/relogin — Force re-login\n"
        "/setsession <PHPSESSID> — Manually set session"
    )

async def cmd_status(update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    status = "✅ Connected" if is_logged_in else "❌ Disconnected"
    phpsessid = session_cookies.get("PHPSESSID", "N/A")
    await update.message.reply_text(
        f"🦈 Shark Panel Status\n\n"
        f"Status: {status}\n"
        f"PHPSESSID: {phpsessid[:12]}...\n"
        f"Seen OTPs: {len(_seen_hashes)}\n"
        f"Poll interval: {POLL_INTERVAL}s"
    )

async def cmd_relogin(update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    global is_logged_in
    is_logged_in = False
    await update.message.reply_text("🔄 Re-login triggered...")
    success = await shark_login()
    if success:
        await update.message.reply_text("✅ Re-login successful!")
    else:
        await update.message.reply_text("❌ Re-login failed! Check credentials.")

async def cmd_setsession(update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    global session_cookies, is_logged_in
    if not context.args:
        await update.message.reply_text("Usage: /setsession <PHPSESSID>")
        return
    new_sessid = context.args[0].strip()
    session_cookies = {"PHPSESSID": new_sessid}
    is_logged_in = True
    await update.message.reply_text(f"✅ Session updated!\nPHPSESSID: {new_sessid[:12]}...")

# ══════════════════════════════════════════════════════════
#                    STARTUP / SHUTDOWN
# ══════════════════════════════════════════════════════════

async def post_init(app: Application):
    global _bot_app
    _bot_app = app
    logger.info("🚀 Shark Panel Bot starting...")

    # Load seen hashes
    await supabase_load_seen()

    # Login
    await shark_login()

    # Start poll loop as background task
    asyncio.create_task(poll_loop(app.bot))

    logger.info("✅ Shark Panel Bot ready!")

async def post_shutdown(app: Application):
    logger.info("✅ Shark Panel Bot shutdown.")

# ══════════════════════════════════════════════════════════
#                    MAIN
# ══════════════════════════════════════════════════════════

def main():
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("relogin", cmd_relogin))
    app.add_handler(CommandHandler("setsession", cmd_setsession))

    logger.info("🦈 Shark Panel Bot running...")
    app.run_polling(drop_pending_updates=True, timeout=30)

if __name__ == "__main__":
    main()
