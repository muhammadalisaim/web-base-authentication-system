#!/usr/bin/env python3
"""
Number Trace & SMS Origin Analyzer — Offline Intelligence Engine
Web Base Authentication System — CAIPSD, The Islamia University of Bahawalpur

WHAT THIS DOES
--------------
Given a phone number, it answers three questions:
  1. Who is it?          -> country, operator network, line type, portability
  2. Where is it?        -> geographic location (honest answer: NOT derivable)
  3. What is it doing?   -> spam / smishing / OTP-fraud risk heuristics

Given an SMS body, it classifies the message and explains the origin channel.

DESIGN NOTE ON LOCATION (important, read before trusting the output)
---------------------------------------------------------------------
A phone number does not carry a GPS coordinate. What a prefix gives you is the
ALLOTTED OPERATOR, not a place. In Pakistan this is explicit: mobile codes are
four digits starting with 03 and they "denote the mobile provider on a
nationwide basis and not geographic location".

Real geographic tracing is only possible through one of these routes:
  * Device telemetry   - GPS/network location read from the target handset
  * Operator HLR/STD   - a live Home-Location-Register lookup. Pakistani mobile
                         operators (Jazz, Zong, Telenor, Ufone) do not expose
                         this to the public; it requires a PTA/Police request.
  * Carrier records    - subscriber identity + registered address, obtained by
                         the operator under PTA/FIA authority.
  * Network forensics  - lawful interception under the Telecommunications Act.

This module never fabricates a location. It reports the operator and the
legitimate escalation paths instead.

DATA SOURCES
------------
  * Offline carrier database (libphonenumber, Google's carrier dataset) —
    always available, no network, no API key.
  * Optional live HLR/spam provider (numverify / abstractapi / ipqualityscore)
    enabled by setting PHONE_LOOKUP_PROVIDER + PHONE_LOOKUP_API_KEY.
"""
import os
import re
import json
import datetime
import socket
import urllib.request
import urllib.error
import urllib.parse

try:  # Optional, but present in this deployment
    import phonenumbers
    from phonenumbers import carrier as _pn_carrier
    from phonenumbers import geocoder as _pn_geocoder
    from phonenumbers import timezone as _pn_timezone
    from phonenumbers import number_type as _pn_number_type
    _PHONENUMBERS_AVAILABLE = True
except Exception:  # pragma: no cover - graceful degradation
    _PHONENUMBERS_AVAILABLE = False


# ======================================================================
# PAKISTAN MOBILE PREFIX TABLE
# Source: libphonenumber carrier dataset (Google).
# Ranges are the ORIGINAL allocation. Mobile Number Portability (live in
# Pakistan since January 2018) means the number may now sit on a different
# operator's network. Only a live HLR lookup can confirm the current carrier.
# ======================================================================
PK_PREFIX_TABLE = [
    ("0300", "0309", "Mobilink",       "Jazz (MNC 01)",              "Jazz"),
    ("0310", "0319", "Zong",           "Zong (MNC 04)",              "Zong / China Mobile"),
    ("0320", "0329", "Warid",          "Jazz (MNC 01)",              "Jazz (Warid merged 2021)"),
    ("0330", "0337", "Ufone",          "Ufone (MNC 03)",             "Ufone / PTML"),
    ("0340", "0349", "Telenor",        "Telenor Pakistan (MNC 06)",  "Telenor Pakistan (Ufone/PTML since Jul 2026)"),
    ("0355", "0355", "SCO",            "SCO (MNC 09)",               "Special Communications Organization"),
    ("0364", "0364", "Instaphone",     "Instaphone (MNC 08)",        "Instaphone"),
]

# Legacy carrier name -> current consumer brand
CARRIER_BRAND_MAP = {
    "Mobilink": "Jazz",
    "Warid": "Jazz",
    "Zong": "Zong",
    "Ufone": "Ufone",
    "Telenor": "Telenor Pakistan",
    "SCO": "Special Communications Organization",
    "Instaphone": "Instaphone",
}

# Landline area codes (PK) — used to flag a landline vs mobile number.
PK_AREA_CODES = {
    "021": "Karachi", "022": "Hyderabad (Sindh)", "023": "Sukkur",
    "024": "Larkana", "025": "Nawabshah", "026": "Khairpur",
    "027": "Jacobabad", "028": "Gwadar", "029": "Rahim Yar Khan",
    "040": "Sahiwal", "041": "Faisalabad", "042": "Lahore",
    "043": "Sargodha", "044": "Okara", "045": "Mian Channu",
    "046": "Toba Tek Singh", "047": "Khushab", "048": "Sargodha",
    "049": "Kasur", "051": "Islamabad / Rawalpindi", "052": "Sialkot",
    "053": "Gujrat", "054": "Attock", "055": "Gujranwala",
    "056": "Sheikhupura", "057": "Attock", "061": "Multan",
    "062": "Bahawalpur", "063": "Rahim Yar Khan", "064": "Dera Ghazi Khan",
    "066": "Dera Ismail Khan", "067": "Dera Ghazi Khan",
    "068": "Sibi", "069": "Turbat", "071": "Karachi (Sindh)",
    "072": "Quetta", "073": "Gwadar", "074": "Khuzdar",
    "075": "Turbat", "076": "Sukkur", "077": "Gilgit", "078": "Zhob",
    "079": "Lashkar Gah", "080": "Chaman", "081": "Hub",
    "082": "Ziarat", "083": "Chaman", "084": "Panjgur",
    "086": "Larkana", "087": "Mansehra", "091": "Peshawar",
    "092": "Charsadda", "093": "Dera Ismail Khan", "094": "Malakand",
    "095": "Mardan", "096": "Swat", "098": "Kohat",
    "099": "Nowshera",
}

# Known bulk/service sender IDs seen on Pakistani networks.
KNOWN_SERVICE_SENDERS = {
    "JAZZ", "JAZZOFFICIAL", "ZONG", "UFONE", "TELENOR", "WARID",
    "SCO", "PTCL", "BANK", "HBL", "MEEZAN", "ABL", "UBL", "MCB",
    "HBLPAY", "EASYPAISA", "JAZZCASH", "SBP", "NBP", "FBR",
    "VERIFIED", "VERIFY", "ALERT", "INFO", "OTP", "SECURITY",
}

# Domains on short-URL services (used to hide the true destination)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
    "rebrand.ly", "s.id", "lnkd.in", "t.ly", "shorte.st", "bl.ink",
    "mcaf.ee", "qr.ae", "v.gd", "soo.gd", "clck.ru", "u.to",
}

# Top-level domains disproportionately used for throwaway phishing infrastructure
RISKY_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "loan",
    "men", "rest", "gdn", "work", "zip", "mov", "country", "kim", "science",
    "review", "stream", "cam", "quest", "cyou", "sbs", "fit", "monster",
    "cfd", "bond", "icu", "quest", "cfd", "beauty", "skin", "makeup",
}

# URL path / host tokens that betray a credential-harvesting page
CREDENTIAL_URL_TOKENS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "auth", "session", "recovery",
    "unlock", "suspend", "billing", "payment", "wallet", "bank",
    "password", "otp", "token", "reset", "validate", "activate",
]

# Message lexicon -> (weight, category, label)
SMS_SIGNAL_LEXICON = [
    # Credential / identity harvesting
    # Note: merely *delivering* a token is normal. *Asking the user to hand one
    # over* is the fraud. The high-weight entries below are the request forms.
    ("share your otp", 32, "Credential Theft", "Asks the user to share an OTP"),
    ("confirm your otp", 30, "Credential Theft", "Asks the user to confirm an OTP"),
    ("enter your otp", 30, "Credential Theft", "Asks the user to enter an OTP"),
    ("provide your otp", 30, "Credential Theft", "Asks the user to provide an OTP"),
    ("verify your otp", 30, "Credential Theft", "Asks the user to verify an OTP"),
    ("send your otp", 30, "Credential Theft", "Asks the user to send an OTP"),
    ("otp", 10, "Credential Theft", "Mentions an OTP / one-time-password"),
    ("one time password", 14, "Credential Theft", "Mentions a one-time password"),
    ("pin code", 12, "Credential Theft", "Mentions a PIN code"),
    ("cnic", 16, "Identity Theft", "Mentions CNIC (national ID)"),
    ("password", 18, "Credential Theft", "Mentions a password"),
    ("bank account number", 18, "Financial Fraud", "Mentions a bank account number"),
    ("atm card", 16, "Financial Fraud", "Mentions an ATM card"),
    ("cvv", 18, "Financial Fraud", "Mentions a CVV"),
    ("kyc", 10, "Identity Theft", "Mentions KYC verification"),
    ("verify your account", 20, "Credential Theft", "Account verification lure"),
    ("confirm your identity", 18, "Identity Theft", "Identity confirmation lure"),

    # Urgency / pressure
    ("urgent", 12, "Pressure Tactic", "Urgency language"),
    ("immediately", 10, "Pressure Tactic", "Urgency language"),
    ("within 24 hours", 16, "Pressure Tactic", "Artificial deadline"),
    ("within 48 hours", 16, "Pressure Tactic", "Artificial deadline"),
    ("last warning", 18, "Pressure Tactic", "Threatening tone"),
    ("will be blocked", 16, "Pressure Tactic", "Threat of suspension"),
    ("will be suspended", 16, "Pressure Tactic", "Threat of suspension"),
    ("account will be closed", 18, "Pressure Tactic", "Threat of closure"),
    ("final notice", 14, "Pressure Tactic", "Threatening tone"),
    ("act now", 10, "Pressure Tactic", "Call to immediate action"),

    # Prize / lottery
    ("you have won", 24, "Prize Scam", "Prize-winner claim"),
    ("you won", 20, "Prize Scam", "Prize-winner claim"),
    ("congratulations", 12, "Prize Scam", "Congratulations lure"),
    ("claim your prize", 24, "Prize Scam", "Prize claim"),
    ("lucky winner", 22, "Prize Scam", "Lottery lure"),
    ("lottery", 16, "Prize Scam", "Lottery reference"),
    ("prize money", 20, "Prize Scam", "Prize money lure"),
    ("gift card", 18, "Financial Fraud", "Gift-card redemption request"),

    # Job / recruitment
    ("you have been selected", 20, "Job Scam", "Recruitment lure"),
    ("recruited", 14, "Job Scam", "Recruitment lure"),
    ("interview", 10, "Job Scam", "Recruitment lure"),
    ("registration fee", 22, "Job Scam", "Upfront fee request"),
    ("work from home", 14, "Job Scam", "Work-from-home lure"),
    ("part time job", 12, "Job Scam", "Part-time job lure"),

    # Crypto / investment
    ("btc", 14, "Investment Scam", "Bitcoin reference"),
    ("usdt", 14, "Investment Scam", "USDT reference"),
    ("crypto", 12, "Investment Scam", "Cryptocurrency reference"),
    ("investment", 8, "Investment Scam", "Investment lure"),
    ("double your", 24, "Investment Scam", "Doubling-money scam"),
    ("mining", 10, "Investment Scam", "Mining lure"),

    # Payment redirect
    ("send money", 22, "Financial Fraud", "Money transfer request"),
    ("transfer the amount", 22, "Financial Fraud", "Money transfer request"),
    ("easypaisa", 8, "Financial Fraud", "Wallet transfer reference"),
    ("jazzcash", 8, "Financial Fraud", "Wallet transfer reference"),
    ("western union", 14, "Financial Fraud", "Money transfer service"),
    ("moneygram", 14, "Financial Fraud", "Money transfer service"),

    # Support impersonation
    ("customer care", 10, "Impersonation", "Customer-support impersonation"),
    ("helpline", 10, "Impersonation", "Fake helpline"),
    ("support team", 10, "Impersonation", "Support-team impersonation"),
    ("official website", 8, "Impersonation", "Claims to be an official site"),
]

# Genuine institutional senders — used to soften risk when the message
# matches a known sender AND contains no URLs.
LEGIT_CONTEXT_KEYWORDS = [
    "your parcel", "delivered", "shipment", "tracking", "appointment",
    "your order", "invoice attached", "payroll", "salary",
    "class schedule", "exam result", "assignment",
]


# ======================================================================
# NORMALIZATION
# ======================================================================
def normalize_number(raw):
    """
    Turn messy user input into an E.164 string when possible.

    Handles: '+92 341-2107586', '92-3412107586', '03412107586',
             '0341 2107586', '(0341) 2107586', '3412107586'
    """
    if raw is None:
        return None, None
    text = str(raw).strip()
    if not text:
        return None, None

    # Strip common separators but keep a leading + so E.164 survives
    cleaned = re.sub(r"[\s()\-.\u2013\u2014]", "", text)

    has_plus = cleaned.startswith("+")
    digits = re.sub(r"\D", "", cleaned)
    if not digits:
        return None, None

    if has_plus:
        return "+" + digits, None
    if digits.startswith("0092"):
        return "+" + digits[2:], None
    if digits.startswith("92") and len(digits) == 12:
        return "+" + digits, None
    if digits.startswith("0") and len(digits) == 11:
        return "+92" + digits[1:], None
    if digits.startswith("92") and len(digits) == 11:
        return "+" + digits, None
    if len(digits) == 10 and digits.startswith("3"):
        return "+92" + digits, None
    return "+" + digits, "Unrecognised national format — treated as international"


# ======================================================================
# OFFLINE LOOKUP
# ======================================================================
def _pk_prefix_info(national_number):
    """Resolve a Pakistani national number against the prefix tables."""
    digits = str(national_number)
    # libphonenumber strips the national trunk '0' (3412107586 -> 03412107586)
    if not digits.startswith("0"):
        digits = "0" + digits
    info = {"operator": None, "brand": None, "mcc_mnc": None, "lineScope": None}

    for lo, hi, legacy, mnc_label, brand in PK_PREFIX_TABLE:
        # Compare the 4-digit mobile code, not the whole number.
        if lo <= digits[:4] <= hi:
            info["operator"] = legacy
            info["brand"] = brand
            info["mcc_mnc"] = mnc_label
            info["lineScope"] = "Mobile"
            return info

    if digits[:3] in PK_AREA_CODES:
        info["operator"] = "Fixed Line (PTA licensed)"
        info["brand"] = PK_AREA_CODES[digits[:3]]
        info["mcc_mnc"] = "Area code %s" % digits[:3]
        info["lineScope"] = "Landline"
        info["geographicArea"] = PK_AREA_CODES[digits[:3]]
    elif digits[:2] in PK_AREA_CODES:
        info["operator"] = "Fixed Line (PTA licensed)"
        info["brand"] = PK_AREA_CODES[digits[:2]]
        info["mcc_mnc"] = "Area code %s" % digits[:2]
        info["lineScope"] = "Landline"
        info["geographicArea"] = PK_AREA_CODES[digits[:2]]
    return info


def lookup_offline(e164):
    """Country / carrier / line type / timezone lookup with no network access."""
    result = {
        "resolved": False,
        "e164": e164,
        "country": None,
        "countryCode": None,
        "region": None,
        "operator": None,
        "brand": None,
        "mccMnc": None,
        "lineType": None,
        "timezones": [],
        "valid": False,
        "possible": False,
        "nationalNumber": None,
        "internationalFormat": None,
        "nationalFormat": None,
        "source": "Offline libphonenumber carrier dataset",
    }
    if not e164 or not _PHONENUMBERS_AVAILABLE:
        return result

    try:
        parsed = phonenumbers.parse(e164, None)
    except Exception:
        return result

    result["resolved"] = True
    result["valid"] = phonenumbers.is_valid_number(parsed)
    result["possible"] = phonenumbers.is_possible_number(parsed)
    result["nationalNumber"] = parsed.national_number
    result["countryCode"] = parsed.country_code
    result["internationalFormat"] = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    result["nationalFormat"] = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

    try:
        result["region"] = phonenumbers.region_code_for_number(parsed)
    except Exception:
        result["region"] = None

    try:
        result["country"] = _pn_geocoder.description_for_number(parsed, "en")
    except Exception:
        result["country"] = None

    try:
        carrier_name = _pn_carrier.name_for_number(parsed, "en") or None
    except Exception:
        carrier_name = None

    try:
        tz_list = list(_pn_timezone.time_zones_for_number(parsed))
    except Exception:
        tz_list = []
    result["timezones"] = tz_list

    type_map = {
        0: "Fixed Line", 1: "Mobile", 2: "Fixed Line or Mobile",
        3: "Toll Free", 4: "Premium Rate", 5: "Shared Cost",
        6: "VoIP", 7: "Personal Number", 8: "Pager",
        9: "UAN", 10: "Voicemail", -1: "Unknown",
    }
    try:
        result["lineType"] = type_map.get(int(_pn_number_type(parsed)), "Unknown")
    except Exception:
        result["lineType"] = "Unknown"

    # Country-specific enrichment
    if result["region"] == "PK":
        pk = _pk_prefix_info(parsed.national_number)
        result["operator"] = pk["operator"] or carrier_name
        result["brand"] = pk["brand"]
        result["mccMnc"] = pk["mcc_mnc"]
        result["lineType"] = pk["lineScope"] or result["lineType"]
        if pk.get("geographicArea"):
            result["geographicArea"] = pk["geographicArea"]
    else:
        result["operator"] = carrier_name
        result["brand"] = CARRIER_BRAND_MAP.get(carrier_name or "", carrier_name)

    return result


# ======================================================================
# OPTIONAL LIVE HLR / SPAM PROVIDER
# ======================================================================
def _utc_now_iso():
    """Timezone-aware UTC timestamp (avoids the deprecated utcnow())."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _http_get_json(url, timeout=8.0):
    req = urllib.request.Request(url, headers={
        "User-Agent": "CAIPSD-NumberTrace/2.8",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception:
        return None


def lookup_live(e164):
    """
    Optional live lookup: current carrier after porting + spam reputation.
    Requires PHONE_LOOKUP_PROVIDER and PHONE_LOOKUP_API_KEY in the environment.
    Returns {'enabled': bool, 'data': {...} | None, 'provider': str, 'reason': str}
    """
    provider = (os.getenv("PHONE_LOOKUP_PROVIDER") or "").strip().lower()
    api_key = (os.getenv("PHONE_LOOKUP_API_KEY") or "").strip()

    if not provider or not api_key:
        return {
            "enabled": False,
            "provider": None,
            "data": None,
            "reason": "Set PHONE_LOOKUP_PROVIDER and PHONE_LOOKUP_API_KEY to enable "
                      "live HLR / spam-reputation lookup (current carrier after "
                      "porting, spam score, line type).",
        }

    digits = re.sub(r"\D", "", e164)
    data = None

    if provider == "numverify":
        data = _http_get_json(
            "http://apilayer.net/api/validate?access_key=%s&number=%s&format=json"
            % (api_key, digits))
    elif provider == "abstractapi":
        data = _http_get_json(
            "https://phoneintelligence.abstractapi.com/v1/?api_key=%s&phone=%s"
            % (api_key, e164))
    elif provider == "ipqualityscore":
        data = _http_get_json(
            "https://ipqualityscore.com/api/json/phone/%s?key=%s" % (digits, api_key))

    if not data:
        return {"enabled": True, "provider": provider, "data": None,
                "reason": "Live provider did not respond. Offline analysis still valid."}

    payload = {}
    if provider == "numverify" and data.get("success"):
        payload = {
            "currentCarrier": data.get("carrier"),
            "currentLineType": data.get("line_type"),
            "location": data.get("location"),
            "portable": data.get("portable"),
            "valid": data.get("valid"),
        }
    elif provider == "abstractapi":
        payload = {
            "currentCarrier": data.get("carrier"),
            "currentLineType": data.get("type"),
            "location": data.get("location"),
            "portable": data.get("portable"),
            "spamScore": data.get("spam_score"),
        }
    elif provider == "ipqualityscore":
        payload = {
            "currentCarrier": data.get("carrier"),
            "currentLineType": data.get("line_type"),
            "location": data.get("location"),
            "portable": data.get("portable"),
            "fraudScore": data.get("fraud_score"),
            "recentAbuse": data.get("recent_abuse"),
            "activeStatus": data.get("active"),
        }

    return {"enabled": True, "provider": provider, "data": payload or data,
            "reason": "Live lookup completed."}


# ======================================================================
# WHATSAPP PROFILE LOOKUP
# The public wa.me landing page resolves a number's WhatsApp profile:
# display name, Business Account status, profile photo and verified badge.
# No key, no login. A number that is not on WhatsApp renders a generic
# "Share on WhatsApp" page instead of a profile.
# ======================================================================
_WA_GENERIC_TITLE = "Share on WhatsApp"

# Keyboards mash: "fhdjghjj", "asdfgh", "qwerty" etc. Sign of a bulk-created
# throwaway account rather than a human choosing a display name.
_GENERATED_NAME_RE = re.compile(
    r"^(?:[a-z]{1,3}(?:[0-9]{1,3})?)+$", re.IGNORECASE)


def _looks_generated_name(name):
    """Heuristic: keyboard-mash style display name."""
    if not name:
        return False
    n = name.strip()
    if not n or len(n) < 4:
        return False
    if " " in n:
        return False
    # A real name is not a single unbroken consonant run of this shape.
    if _GENERATED_NAME_RE.match(n) and not re.search(r"\d", n):
        vowels = sum(1 for c in n.lower() if c in "aeiou")
        return vowels == 0
    return False


def lookup_whatsapp(e164):
    """
    Resolve the public WhatsApp profile attached to a phone number.

    Returns registration state, display name, whether it is a Business
    Account, and whether a profile photo / verified badge is exposed.
    """
    result = {
        "checked": False,
        "registered": None,
        "displayName": None,
        "accountType": None,
        "profilePhoto": None,
        "hasProfilePhoto": False,
        "verifiedBadge": False,
        "nameLooksGenerated": False,
        "publicUrl": None,
        "note": None,
    }
    if not e164:
        return result

    digits = re.sub(r"\D", "", str(e164))
    if len(digits) < 8:
        return result

    url = "https://wa.me/%s" % digits
    result["publicUrl"] = url

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
            "Accept": "text/html,application/xhtml+xml",
        })
        with urllib.request.urlopen(req, timeout=12) as resp:
            html = resp.read().decode("utf-8", "ignore")
    except Exception as exc:
        result["checked"] = True
        result["note"] = "WhatsApp profile lookup failed: %s" % exc
        return result

    result["checked"] = True

    def meta(prop):
        m = re.search(r'<meta[^>]+property="%s"[^>]+content="([^"]*)"' % re.escape(prop),
                      html, re.IGNORECASE)
        if not m:
            m = re.search(r'<meta[^>]+content="([^"]*)"[^>]+property="%s"' % re.escape(prop),
                          html, re.IGNORECASE)
        return re.sub(r"\s+", " ", m.group(1)).strip() if m else None

    title = meta("og:title")
    desc = meta("og:description")
    image = meta("og:image")

    if not title or title == _WA_GENERIC_TITLE:
        result["registered"] = False
        result["note"] = ("This number does not have a public WhatsApp profile. It is either "
                          "not registered on WhatsApp, or the profile is fully private.")
        return result

    result["registered"] = True
    result["displayName"] = title

    if desc:
        low = desc.lower()
        if "business account" in low:
            result["accountType"] = "WhatsApp Business Account"
        elif "business" in low:
            result["accountType"] = "WhatsApp Business Account"
        else:
            result["accountType"] = "WhatsApp Account"

    photo = re.search(r"https://pps\.whatsapp\.net/[^\s\"\\']+", html)
    if photo:
        result["hasProfilePhoto"] = True
        result["profilePhoto"] = photo.group(0)
    elif image and "static.whatsapp.net" not in image:
        result["hasProfilePhoto"] = True
        result["profilePhoto"] = image

    result["verifiedBadge"] = bool(re.search(r"verifiedBadge|isVerifiedBusiness|verified_business",
                                              html, re.IGNORECASE))
    result["nameLooksGenerated"] = _looks_generated_name(title)

    return result


# ======================================================================
# LINK DEEP ANALYSIS
# A link that arrived with a scam message is the only artifact that can be
# traced technically:
#     redirect chain -> real host -> DNS -> hosting IP -> hosting provider
#     -> domain registrant, plus reputation blocklists (OTX, URLhaus,
#     OpenPhish, Google Safe Browsing).
#
# IMPORTANT: this resolves the SERVER, never the person. Attributing a
# subscriber to a physical address is only possible through the mobile
# operator (PTA complaint / police FIR + court order). The output here is
# shaped so it can be pasted straight into a PTA/NCCIA complaint as a
# technical annexure - it names hosts, IPs, providers, dates and verdicts.
#
# Everything below uses public, keyless endpoints. Nothing here touches
# leaked identity databases.
# ======================================================================

# OTX validation sources that only mean "this host exists in an
# infrastructure database" - not a security verdict.
_BENIGN_VALIDATION_SOURCES = {
    "akamai", "whitelist", "majestic", "whoisxml", "cloudflare",
    "certspotter", "domain_whois", "whois", "google",
}

# OTX validation sources that ARE a security verdict.
_SECURITY_VALIDATION_SOURCES = {
    "virustotal", "urlscan", "phishtank", "abuse.ch", "urlhaus",
    "malwarebazaar", "threatfox", "criminalip", "hybrid-analysis",
    "any.run", "urlquery", "metadefender", "cyren", "surbl",
    "openphish", "phishtank_scan", "maltiverse", "crimcheck",
}

# Pulse tags worth surfacing - raw OTX tag lists are extremely noisy.
_RELEVANT_TAGS = {
    "phishing", "phish", "malware", "scam", "fraud", "credential",
    "spoof", "c2", "exploit", "otp", "banking", "bank", "social-engineering",
    "spam", "trojan", "pharming", "fake", "impersonation", "money",
    "stealer", "ransomware", "botnet", "ddos", "smishing", "vishing",
    "atm", "kyc", "whatsapp", "telegram", "free", "gift",
}

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

# Cached blocklist feeds: name -> {"ts": epoch, "urls": set, "hosts": set}
_FEED_CACHE = {}
_FEED_TTL = 6 * 3600  # 6 hours

# How many links in one message get the full network-level analysis.
DEEP_LINK_LIMIT = 3

# Set PHONE_DEEP_LINK_ANALYSIS=0 to disable outbound lookups entirely.
DEEP_LINK_ANALYSIS_ENABLED = os.environ.get("PHONE_DEEP_LINK_ANALYSIS", "1") != "0"

# Link-in-bio / shortener / messaging hosts that are commonly abused to
# hide the real destination of a phishing page.
LINK_ABUSE_HOSTS = {
    "chat.whatsapp.com", "wa.me", "api.whatsapp.com", "t.me", "telegram.me",
    "linktr.ee", "lnk.bio", "beacons.ai", "bio.link", "linkin.bio",
    "tinyurl.com", "bit.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
    "s.id", "tiny.cc", "t.ly", "bl.ink", "shorturl.gg", "urlz.fr", "adf.ly",
    "shorte.st", "is.gd", "v.gd", "soo.gd", "clck.ru", "u.to", "x.co",
    "1url.com", "shorturl.com", "l.ead.me", "vzturl.com", "shrinkme.io",
    "ow.ly", "trib.al", "mcaf.ee", "su.pr", "qr.ae", "tr.im", "clicky.me",
}


class _RedirectTracker(urllib.request.HTTPRedirectHandler):
    """Follows redirects while recording the chain (needed as evidence)."""

    def __init__(self):
        super().__init__()
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({
            "from": req.full_url,
            "to": newurl,
            "status": code,
        })
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _http_get_text(url, timeout=12.0, headers=None):
    """
    GET a URL, follow redirects, return (status, body, final_url, chain).
    Never raises - network trouble comes back as (None, "", url, []).
    """
    tracker = _RedirectTracker()
    opener = urllib.request.build_opener(tracker)
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(400000)
            return (resp.status, raw.decode("utf-8", "ignore"),
                    resp.geturl(), tracker.chain)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(200000).decode("utf-8", "ignore")
        except Exception:
            pass
        return exc.code, body, getattr(exc, "url", url) or url, tracker.chain
    except Exception:
        return None, "", url, tracker.chain


def _host_of(url):
    """Extract the lowercase hostname from a URL (no scheme assumed)."""
    if not url:
        return ""
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        host = urllib.parse.urlparse(raw).netloc
    except Exception:
        return ""
    host = host.split("@")[-1].split(":")[0].strip().lower()
    return host


def expand_short_link(url, timeout=12.0):
    """
    Resolve a shortened / redirecting link to its real destination.
    Returns the redirect chain plus the final URL.
    """
    out = {
        "original": url,
        "final": url,
        "chain": [],
        "hops": 0,
        "isAbusiveHost": False,
        "error": None,
    }
    status, _body, final, chain = _http_get_text(url, timeout=timeout)
    out["final"] = final or url
    out["chain"] = chain
    out["hops"] = len(chain)
    out["isAbusiveHost"] = _host_of(out["final"]) in LINK_ABUSE_HOSTS
    if status is None:
        out["error"] = "no HTTP response from the host (site may be offline or blocking this network)"
    return out


def resolve_host_ips(host, limit=6):
    """DNS A/AAAA resolution -> list of IPs. Never raises."""
    ips = []
    if not host:
        return ips
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
            if len(ips) >= limit:
                break
    except Exception:
        pass
    return ips


def ip_intel(ip, timeout=10.0):
    """Geolocation + network ownership for an IP (ipwho.is). Never raises."""
    out = {
        "ip": ip,
        "country": None,
        "region": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "org": None,
        "isp": None,
        "error": None,
    }
    status, body, _f, _c = _http_get_text(
        "https://ipwho.is/%s" % urllib.parse.quote(ip), timeout=timeout)
    if status is None:
        out["error"] = "ip intelligence unreachable"
        return out
    try:
        data = json.loads(body)
    except Exception:
        out["error"] = "unparseable ip intelligence response"
        return out
    if not data.get("success", True):
        out["error"] = data.get("message") or "lookup failed"
        return out
    out["country"] = data.get("country")
    out["region"] = data.get("region")
    out["city"] = data.get("city")
    out["latitude"] = data.get("latitude")
    out["longitude"] = data.get("longitude")
    conn = data.get("connection") or {}
    out["asn"] = conn.get("asn")
    out["org"] = conn.get("org")
    out["isp"] = conn.get("isp")
    return out


def rdap_domain(domain, timeout=12.0):
    """Registration data via RDAP (rdap.org). Never raises."""
    out = {
        "domain": domain,
        "registrar": None,
        "registrantName": None,
        "registrantEmail": None,
        "created": None,
        "updated": None,
        "nameservers": [],
        "error": None,
    }
    status, body, _f, _c = _http_get_text(
        "https://rdap.org/domain/%s" % urllib.parse.quote(domain), timeout=timeout)
    if status is None:
        out["error"] = "rdap unreachable"
        return out
    try:
        data = json.loads(body)
    except Exception:
        out["error"] = "unparseable rdap response"
        return out
    if data.get("errorCode") or data.get("error"):
        out["error"] = "rdap: %s" % (data.get("title") or data.get("errorCode")
                                     or data.get("error"))
        return out

    def _date(value):
        if isinstance(value, list):
            value = value[0] if value else None
        return value

    for event in data.get("events") or []:
        action = (event.get("eventAction") or "").lower()
        if action == "registration":
            out["created"] = _date(event.get("eventDate"))
        elif action in ("last changed", "last update of rdap database"):
            out["updated"] = _date(event.get("eventDate"))
    for ns in data.get("nameservers") or []:
        name = ns.get("ldhName")
        if name:
            out["nameservers"].append(name.lower())
    for entity in data.get("entities") or []:
        roles = entity.get("roles") or []
        vcard = entity.get("vcardArray") or []
        fields = {}
        for item in (vcard[1] if len(vcard) > 1 else []):
            if len(item) >= 4 and isinstance(item[0], str):
                fields[item[0]] = item[3]
        if "registrar" in roles:
            out["registrar"] = fields.get("fn") or out["registrar"]
        if "registrant" in roles:
            out["registrantName"] = fields.get("fn") or out["registrantName"]
            out["registrantEmail"] = fields.get("email") or out["registrantEmail"]
    if not out["registrantName"] and not out["registrar"]:
        out["error"] = "no registration data exposed"
    return out


def otx_lookup(url, timeout=15.0):
    """AlienVault OTX reputation for a URL. Never raises."""
    out = {
        "pulseCount": 0,
        "flaggedBy": [],
        "validationSources": [],
        "pulses": [],
        "reputation": None,
        "error": None,
    }
    endpoint = ("https://otx.alienvault.com/api/v1/indicators/url/%s/general"
                % urllib.parse.quote(url, safe=""))
    status, body, _f, _c = _http_get_text(endpoint, timeout=timeout)
    if status is None:
        out["error"] = "otx unreachable"
        return out
    try:
        data = json.loads(body)
    except Exception:
        out["error"] = "unparseable otx response"
        return out

    pulse_info = data.get("pulse_info") or {}
    out["pulseCount"] = pulse_info.get("count") or 0
    out["reputation"] = data.get("reputation")
    for validation in data.get("validation") or []:
        source = (validation.get("source") or "").strip().lower()
        if not source:
            continue
        out["validationSources"].append(source)
        if source not in _BENIGN_VALIDATION_SOURCES:
            out["flaggedBy"].append(source)
    out["flaggedBy"] = sorted(set(out["flaggedBy"]))
    for pulse in (pulse_info.get("pulses") or [])[:8]:
        tags = [t for t in (pulse.get("tags") or [])
                if isinstance(t, str) and t.lower() in _RELEVANT_TAGS]
        out["pulses"].append({
            "name": (pulse.get("name") or "")[:120],
            "tags": sorted(set(tags))[:8],
            "created": pulse.get("created"),
        })
    return out


def _parse_urlhaus(body):
    """URLhaus hostfile lines look like: 127.0.0.1<TAB>host"""
    urls, hosts = set(), set()
    for line in (body or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\s\t]+", line)
        if not parts:
            continue
        value = parts[-1].lower()
        if value.startswith("http://") or value.startswith("https://"):
            urls.add(value)
            host = _host_of(value)
            if host:
                hosts.add(host)
        else:
            hosts.add(value)
    return urls, hosts


def _parse_url_list(body):
    """One URL per line."""
    urls, hosts = set(), set()
    for line in (body or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.add(line)
        host = _host_of(line)
        if host:
            hosts.add(host)
    return urls, hosts


def _load_feed(name, url, parser):
    """Download + cache a blocklist feed. Returns (urls, hosts)."""
    now = datetime.datetime.now().timestamp()
    cached = _FEED_CACHE.get(name)
    if cached and (now - cached["ts"]) < _FEED_TTL:
        return cached["urls"], cached["hosts"]
    status, body, _f, _c = _http_get_text(url, timeout=30.0)
    if status is None:
        if cached:
            return cached["urls"], cached["hosts"]
        return set(), set()
    urls, hosts = parser(body)
    _FEED_CACHE[name] = {"ts": now, "urls": urls, "hosts": hosts}
    return urls, hosts


def urlhaus_check(url, host, timeout=30.0):
    """Check a URL/host against the URLhaus malware blocklist."""
    out = {"listed": False, "exactUrl": False, "host": False,
           "feedSize": 0, "error": None}
    try:
        urls, hosts = _load_feed(
            "urlhaus",
            "https://urlhaus.abuse.ch/downloads/hostfile/",
            _parse_urlhaus)
    except Exception as exc:
        out["error"] = str(exc)
        return out
    out["feedSize"] = len(hosts)
    low_url = url.lower().strip()
    if low_url in urls:
        out["listed"] = True
        out["exactUrl"] = True
    if host and host.lower() in hosts:
        out["listed"] = True
        out["host"] = True
    return out


def openphish_check(url, host, timeout=30.0):
    """Check a URL/host against the OpenPhish live phishing feed."""
    out = {"listed": False, "exactUrl": False, "host": False,
           "feedSize": 0, "error": None}
    try:
        urls, hosts = _load_feed(
            "openphish",
            "https://openphish.com/feed.txt",
            _parse_url_list)
    except Exception as exc:
        out["error"] = str(exc)
        return out
    out["feedSize"] = len(urls)
    low_url = url.lower().strip()
    if low_url in urls:
        out["listed"] = True
        out["exactUrl"] = True
    if host and host.lower() in hosts:
        out["listed"] = True
        out["host"] = True
    return out


def safebrowsing_check(url, timeout=15.0):
    """
    Google Safe Browsing report page. Best-effort - the endpoint is
    JS-rendered and is often unreachable from datacenter networks.
    """
    out = {"available": False, "verdict": None, "detail": None, "error": None}
    endpoint = ("https://safebrowsing.google.com/safebrowsing/report?url=%s"
                % urllib.parse.quote(url, safe=""))
    status, body, _f, _c = _http_get_text(endpoint, timeout=timeout)
    if status is None or not body:
        out["error"] = "safe browsing endpoint unreachable"
        return out
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", body)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).lower()
    out["available"] = True
    if "no unsafe content found" in text or "no unsafe" in text:
        out["verdict"] = "clean"
    elif "has been reported" in text or "reported as unsafe" in text:
        out["verdict"] = "flagged"
    elif "malware" in text or "phishing" in text or "dangerous" in text:
        out["verdict"] = "flagged"
    else:
        out["verdict"] = "unknown"
    return out


def _is_internal_host(host):
    """
    True when a hostname resolves to a private / loopback / link-local
    address. The server fetches attacker-supplied URLs, so anything that
    points back into the server's own network must be refused.
    """
    if not host:
        return True
    host = host.lower().strip("[]")
    if host in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    if host in ("metadata.google.internal", "metadata.goog"):
        return True
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        octets = [int(o) for o in host.split(".")]
        if len(octets) != 4 or any(o > 255 for o in octets):
            return True
        first, second = octets[0], octets[1]
        if first == 10 or first == 127 or first == 0:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 169 and second == 254:
            return True
        if first >= 224:
            return True
    if ":" in host:  # IPv6 literal
        if host in ("::1", "::", "0:0:0:0:0:0:0:1"):
            return True
        if host.startswith("fc") or host.startswith("fd") or host.startswith("fe80"):
            return True
    return False


def analyze_link(url, deep=True):
    """
    Full technical analysis of a single link.

    Returns a dict with the redirect chain, DNS, hosting IP + provider,
    domain registration and reputation verdicts. Safe to call on any URL;
    every network call is failure-tolerant.
    """
    result = {
        "url": url,
        "host": None,
        "finalUrl": url,
        "finalHost": None,
        "shortener": False,
        "abusiveHost": False,
        "redirectChain": [],
        "hops": 0,
        "dnsIps": [],
        "ipIntel": [],
        "serverLocation": None,
        "hostingProvider": None,
        "domainRegistration": None,
        "reputation": {
            "otx": None,
            "urlhaus": None,
            "openphish": None,
            "googleSafeBrowsing": None,
            "listedAnywhere": False,
        },
        "riskScore": 0,
        "signals": [],
        "verdict": "Not analysed",
        "verdictCode": "info",
        "notes": [],
        "limitations": (
            "This resolves the hosting server, not the person behind the account. "
            "Only the mobile operator (via PTA complaint or police FIR + court "
            "order) can attribute a subscriber to a phone number and address."
        ),
    }

    if not url:
        return result

    if not re.match(r"^https?://", url.strip(), re.IGNORECASE):
        result["notes"].append("Only http:// and https:// links can be analysed.")
        result["verdict"] = "Unsupported scheme"
        return result

    initial_host = _host_of(url)
    if _is_internal_host(initial_host):
        result["notes"].append(
            "Refused: this target points inside the local network, not a public site.")
        result["verdict"] = "Refused — internal target"
        return result

    result["host"] = initial_host
    result["finalHost"] = result["host"]
    result["shortener"] = result["host"] in LINK_ABUSE_HOSTS
    result["abusiveHost"] = result["shortener"]

    # Local heuristics (reuse the SMS scanner's URL rules)
    try:
        _h, local_score, local_signals = _analyze_url(url)
    except Exception:
        local_score, local_signals = 0, []
    result["riskScore"] += local_score
    result["signals"].extend([
        {"category": cat, "label": label, "weight": weight, "evidence": url}
        for cat, label, weight in local_signals
    ])

    if not deep:
        result["verdict"] = "Local heuristics only"
        return result

    # 1. Redirect expansion
    expansion = expand_short_link(url)
    result["finalUrl"] = expansion["final"]
    result["finalHost"] = _host_of(expansion["final"])
    result["redirectChain"] = expansion["chain"]
    result["hops"] = expansion["hops"]
    if _is_internal_host(result["finalHost"]):
        result["notes"].append(
            "Refused: the link redirects into the local network, not a public site.")
        result["verdict"] = "Refused — internal redirect target"
        return result
    if expansion["error"]:
        result["notes"].append(expansion["error"] + " (the host still resolved; "
                           "the page itself did not answer)")
    if expansion["isAbusiveHost"]:
        result["abusiveHost"] = True
        result["signals"].append({
            "category": "Evasion",
            "label": "Destination is a link-shortener / messaging redirect host",
            "weight": 10,
            "evidence": expansion["final"],
        })
        result["riskScore"] += 10
    if expansion["hops"] >= 3:
        result["signals"].append({
            "category": "Evasion",
            "label": "Long redirect chain (%d hops)" % expansion["hops"],
            "weight": 10,
            "evidence": " -> ".join(
                [c["from"] for c in expansion["chain"][:3]] + [expansion["final"]]
            )[:200],
        })
        result["riskScore"] += 10

    final_host = result["finalHost"] or result["host"]

    # 2. DNS + hosting + registration + reputation all run in parallel -
    #    once the redirect is resolved none of them depend on each other.
    from concurrent.futures import ThreadPoolExecutor

    def _ip_job(ip):
        try:
            return ip_intel(ip)
        except Exception as exc:
            return {"ip": ip, "error": str(exc)}

    def _reg_job():
        if not final_host or "." not in final_host:
            return None
        try:
            return rdap_domain(final_host)
        except Exception:
            return None

    def _otx_job():
        try:
            return otx_lookup(expansion["final"])
        except Exception:
            return None

    def _urlhaus_job():
        try:
            return urlhaus_check(expansion["final"], final_host)
        except Exception:
            return None

    def _openphish_job():
        try:
            return openphish_check(expansion["final"], final_host)
        except Exception:
            return None

    def _sb_job():
        try:
            return safebrowsing_check(expansion["final"])
        except Exception:
            return None

    ips = resolve_host_ips(final_host)
    result["dnsIps"] = ips

    with ThreadPoolExecutor(max_workers=8) as pool:
        ip_jobs = [pool.submit(_ip_job, ip) for ip in ips[:3]]
        reg_job = pool.submit(_reg_job)
        otx_job = pool.submit(_otx_job)
        uh_job = pool.submit(_urlhaus_job)
        op_job = pool.submit(_openphish_job)
        sb_job = pool.submit(_sb_job)

        for future in ip_jobs:
            try:
                result["ipIntel"].append(future.result())
            except Exception:
                pass
        for job, key in ((reg_job, "domainRegistration"),
                         (otx_job, "otx"),
                         (uh_job, "urlhaus"),
                         (op_job, "openphish"),
                         (sb_job, "googleSafeBrowsing")):
            try:
                value = job.result()
            except Exception:
                value = None
            if key == "domainRegistration":
                result["domainRegistration"] = value
            else:
                result["reputation"][key] = value

    for intel in result["ipIntel"]:
        if intel.get("error"):
            continue
        if not result["serverLocation"]:
            result["serverLocation"] = {
                "country": intel.get("country"),
                "region": intel.get("region"),
                "city": intel.get("city"),
                "latitude": intel.get("latitude"),
                "longitude": intel.get("longitude"),
            }
        if intel.get("org") and not result["hostingProvider"]:
            result["hostingProvider"] = {
                "asn": intel.get("asn"),
                "org": intel.get("org"),
                "isp": intel.get("isp"),
            }

    # 3. Reputation verdicts (already fetched above, in parallel)

    otx = result["reputation"].get("otx") or {}
    uh = result["reputation"].get("urlhaus") or {}
    op = result["reputation"].get("openphish") or {}
    sb = result["reputation"].get("googleSafeBrowsing") or {}

    listed = bool(uh.get("listed")) or bool(op.get("listed")) or \
        bool(otx.get("flaggedBy")) or sb.get("verdict") == "flagged"
    result["reputation"]["listedAnywhere"] = listed

    if uh.get("listed"):
        result["signals"].append({
            "category": "Malware Infrastructure",
            "label": "Host appears in the URLhaus malware blocklist",
            "weight": 45,
            "evidence": final_host,
        })
        result["riskScore"] += 45
    if op.get("listed"):
        result["signals"].append({
            "category": "Phishing Infrastructure",
            "label": "Host appears in the OpenPhish live phishing feed",
            "weight": 45,
            "evidence": final_host,
        })
        result["riskScore"] += 45
    security_sources = [s for s in (otx.get("flaggedBy") or [])
                        if s in _SECURITY_VALIDATION_SOURCES]
    if security_sources:
        result["signals"].append({
            "category": "Threat Intelligence",
            "label": "Flagged by %s" % ", ".join(security_sources[:4]),
            "weight": 30,
            "evidence": final_host,
        })
        result["riskScore"] += 30
    if sb.get("verdict") == "flagged":
        result["signals"].append({
            "category": "Threat Intelligence",
            "label": "Google Safe Browsing reports this URL as unsafe",
            "weight": 35,
            "evidence": final_host,
        })
        result["riskScore"] += 35

    # Freshly registered domain around a scam page is a strong signal.
    reg = result.get("domainRegistration") or {}
    created = reg.get("created")
    if created:
        try:
            created_dt = datetime.datetime.strptime(created[:19], "%Y-%m-%dT%H:%M:%S")
            age_days = (datetime.datetime.now() - created_dt).days
            if 0 <= age_days <= 45:
                result["signals"].append({
                    "category": "Infrastructure Age",
                    "label": "Domain is only %d day(s) old (registered %s)"
                             % (age_days, created[:10]),
                    "weight": 30,
                    "evidence": final_host,
                })
                result["riskScore"] += 30
            result["notes"].append("Domain registered %s (age %d days)"
                                   % (created[:10], age_days))
        except Exception:
            pass

    result["riskScore"] = min(100, result["riskScore"])
    if result["riskScore"] >= 70:
        result["verdict"] = "High Risk — Known malicious / phishing infrastructure"
        result["verdictCode"] = "high"
    elif result["riskScore"] >= 40:
        result["verdict"] = "Suspicious — Treat With Caution"
        result["verdictCode"] = "medium"
    elif result["riskScore"] >= 20:
        result["verdict"] = "Low Risk — Minor Indicators"
        result["verdictCode"] = "low"
    else:
        result["verdict"] = "No Strong Indicators Detected"
        result["verdictCode"] = "info"

    return result


def build_complaint_annex(analysis):
    """
    Render a link analysis as a paste-ready technical annexure for a
    PTA / NCCIA / police complaint.
    """
    if not analysis:
        return ""
    lines = []
    lines.append("TECHNICAL ANNEXURE - MALICIOUS LINK")
    lines.append("=" * 60)
    lines.append("Original URL      : %s" % analysis.get("url"))
    lines.append("Resolved URL      : %s" % analysis.get("finalUrl"))
    if analysis.get("redirectChain"):
        lines.append("Redirect chain    :")
        for hop in analysis["redirectChain"]:
            lines.append("    %s  ->  %s" % (hop.get("status"), hop.get("to")))
    lines.append("Host              : %s" % (analysis.get("finalHost") or analysis.get("host")))
    lines.append("DNS A records     : %s" % (", ".join(analysis.get("dnsIps") or []) or "n/a"))

    intel = (analysis.get("ipIntel") or [{}])[0]
    if intel:
        lines.append("Hosting IP        : %s" % intel.get("ip"))
        lines.append("Server location   : %s / %s / %s (approx, server not person)"
                     % (intel.get("city"), intel.get("region"), intel.get("country")))
        provider = analysis.get("hostingProvider") or {}
        lines.append("Hosting provider  : %s (AS%s) / %s"
                     % (provider.get("org"), provider.get("asn"), provider.get("isp")))

    reg = analysis.get("domainRegistration") or {}
    if reg:
        lines.append("Domain registrar  : %s" % (reg.get("registrar") or "not disclosed"))
        lines.append("Registered on     : %s" % (reg.get("created") or "not disclosed"))
        if reg.get("registrantName"):
            lines.append("Registrant        : %s <%s>"
                         % (reg["registrantName"], reg.get("registrantEmail") or ""))

    rep = analysis.get("reputation") or {}
    otx = rep.get("otx") or {}
    lines.append("Threat intel      : OTX pulses=%s flagged_by=%s"
                 % (otx.get("pulseCount"), ", ".join(otx.get("flaggedBy") or []) or "none"))
    uh = rep.get("urlhaus") or {}
    op = rep.get("openphish") or {}
    sb = rep.get("googleSafeBrowsing") or {}
    lines.append("Blocklists        : URLhaus=%s OpenPhish=%s SafeBrowsing=%s"
                 % (uh.get("listed"), op.get("listed"), sb.get("verdict")))

    lines.append("Verdict           : %s (score %s/100)"
                 % (analysis.get("verdict"), analysis.get("riskScore")))
    lines.append("")
    lines.append("Note: the above identifies the hosting infrastructure only. Subscriber")
    lines.append("identity and location can only be attributed by the mobile operator on")
    lines.append("the basis of a PTA complaint or a court order.")
    return "\n".join(lines)


# ======================================================================
# SMS BODY ANALYSIS
# ======================================================================
def _extract_urls(text):
    urls = []
    for match in re.finditer(r"(?:https?://|www\.)[^\s<>\"']+", text, re.IGNORECASE):
        urls.append(match.group(0).rstrip(".,);:!?"))
    return urls


def _analyze_url(url):
    """Per-URL risk signals."""
    signals = []
    score = 0
    raw = url.lower()

    # Strip the scheme first, otherwise splitting on "/" yields "http:" as the host
    is_plain_http = raw.startswith("http://")
    without_scheme = re.sub(r"^[a-z]+://", "", raw)
    if without_scheme.startswith("www."):
        without_scheme = without_scheme[4:]

    host = without_scheme.split("/")[0].split("?")[0].split("#")[0]
    path = without_scheme.split("/", 1)[1] if "/" in without_scheme else ""

    if "xn--" in host:
        signals.append(("Homograph Attack", "Punycode/IDN domain can imitate a real brand", 30))
        score += 30
    if is_plain_http:
        signals.append(("No TLS", "Link is plain HTTP", 12))
        score += 12
    if host in URL_SHORTENERS:
        signals.append(("Shortened Link", "Link hides its real destination", 22))
        score += 22
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        signals.append(("High-Risk TLD", ".%s is heavily abused for throwaway phishing pages" % tld, 14))
        score += 14
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host.split(":")[0]):
        signals.append(("Raw IP in URL", "Links to a bare IP address instead of a domain", 26))
        score += 26
    if re.search(r":\d{2,5}/", without_scheme):
        signals.append(("Non-Standard Port", "Link uses a non-standard port", 18))
        score += 18
    for token in CREDENTIAL_URL_TOKENS:
        if token in host or token in path:
            signals.append(("Credential Lure", "URL path references '%s'" % token, 12))
            score += 12
            break
    if len(host.split(".")[0]) <= 3 and host.count(".") >= 2 and host not in URL_SHORTENERS:
        signals.append(("Look-alike Brand", "Short, brand-like domain name", 10))
        score += 10
    return host, score, signals


def analyze_sms_body(text, sender=None):
    """Heuristic classification of an SMS body. Returns a structured report."""
    body = text or ""
    lower = body.lower()

    categories = {}
    signals = []
    score = 0

    for needle, weight, category, label in SMS_SIGNAL_LEXICON:
        if needle in lower:
            score += weight
            categories[category] = categories.get(category, 0) + weight
            signals.append({
                "category": category,
                "label": label,
                "weight": weight,
                "evidence": needle,
            })

    # URL analysis
    urls = _extract_urls(body)
    url_reports = []
    for index, url in enumerate(urls[:12]):
        host, u_score, u_signals = _analyze_url(url)
        score += u_score
        report = {"url": url, "host": host, "risk": u_score, "signals": u_signals}

        # Full network-level analysis on the first few links only - each
        # one costs several outbound requests.
        if (DEEP_LINK_ANALYSIS_ENABLED and index < DEEP_LINK_LIMIT
                and u_score >= 10):
            try:
                deep = analyze_link(url)
            except Exception as exc:
                deep = {"error": str(exc)}
            report["deep"] = deep
            deep_score = deep.get("riskScore") or 0
            report["risk"] = u_score + deep_score
            score += deep_score
            for entry in (deep.get("signals") or []):
                categories[entry["category"]] = categories.get(entry["category"], 0) + entry["weight"]
                signals.append(entry)

        url_reports.append(report)
        for cat, label, weight in u_signals:
            categories[cat] = categories.get(cat, 0) + weight
            signals.append({"category": cat, "label": label,
                            "weight": weight, "evidence": url})

    # Structural anomalies
    if re.search(r"[\u200b\u200c\u200d\ufeff]", body):
        score += 20
        categories.setdefault("Evasion", 0)
        categories["Evasion"] += 20
        signals.append({"category": "Evasion", "label": "Contains invisible/zero-width characters",
                        "weight": 20, "evidence": "Unicode control characters"})

    # Mixed-script homoglyph (Latin + Cyrillic/Greek mix inside words)
    if re.search(r"(?i)[a-z][\u0400-\u04ff\u0370-\u03ff]", body):
        score += 18
        categories["Evasion"] = categories.get("Evasion", 0) + 18
        signals.append({"category": "Evasion", "label": "Mixed-script text (possible homoglyph spoofing)",
                        "weight": 18, "evidence": "Cyrillic/Greek characters mixed with Latin"})

    if len(urls) >= 3:
        score += 14
        categories.setdefault("Bulk Link Dump", 0)
        categories["Bulk Link Dump"] += 14
        signals.append({"category": "Bulk Link Dump", "label": "Contains 3 or more links",
                        "weight": 14, "evidence": "%d URLs" % len(urls)})

    if len(body) > 600:
        score += 8
        categories.setdefault("Obfuscation", 0)
        categories["Obfuscation"] += 8
        signals.append({"category": "Obfuscation", "label": "Unusually long message",
                        "weight": 8, "evidence": "%d characters" % len(body)})

    caps_ratio = sum(1 for c in body if c.isupper()) / max(len(body), 1)
    if caps_ratio > 0.6 and len(body) > 25:
        score += 6
        categories.setdefault("Pressure Tactic", 0)
        categories["Pressure Tactic"] += 6
        signals.append({"category": "Pressure Tactic", "label": "Mostly capital letters",
                        "weight": 6, "evidence": "%.0f%% uppercase" % (caps_ratio * 100)})

    # A genuine institutional message with no links and no credential ask
    legit_hit = [k for k in LEGIT_CONTEXT_KEYWORDS if k in lower]
    if legit_hit and not urls and "Credential Theft" not in categories:
        score = max(0, score - 25)

    # "Do not share this OTP" is the sender protecting the user, not asking for it.
    if re.search(r"(do not|don't|never) (share|disclose)", lower):
        score = max(0, score - 18)
        signals.append({
            "category": "Benign Context",
            "label": "Sender explicitly warns against sharing the code",
            "weight": -18,
            "evidence": "contains a 'do not share' advisory",
        })

    score = min(100, score)

    if score >= 70:
        verdict, verdict_code = "High Risk — Likely Fraud / Phishing", "high"
    elif score >= 40:
        verdict, verdict_code = "Suspicious — Treat With Caution", "medium"
    elif score >= 20:
        verdict, verdict_code = "Low Risk — Minor Indicators", "low"
    else:
        verdict, verdict_code = "No Strong Indicators Detected", "info"

    ranked = sorted(categories.items(), key=lambda kv: kv[1], reverse=True)
    return {
        "riskScore": score,
        "verdict": verdict,
        "verdictCode": verdict_code,
        "categories": [{"name": name, "weight": weight} for name, weight in ranked],
        "signals": sorted(signals, key=lambda s: s["weight"], reverse=True),
        "urls": url_reports,
        "legitContextHits": legit_hit,
    }


def classify_sender(sender_raw):
    """
    Work out what KIND of entity sent the message. This is the closest thing
    to 'where did it come from' that the data actually supports.
    """
    raw = (sender_raw or "").strip()
    info = {
        "raw": raw,
        "senderType": "Unknown",
        "senderClass": "unknown",
        "origin": "Unknown",
        "originDetail": "",
        "isShortCode": False,
        "isAlphanumeric": False,
        "isInternational": False,
    }
    if not raw:
        return info

    if re.match(r"^[A-Za-z][A-Za-z0-9 &.\-_]{1,11}$", raw):
        info["isAlphanumeric"] = True
        info["senderType"] = "Alphanumeric Sender ID"
        info["senderClass"] = "service"
        if raw.upper() in KNOWN_SERVICE_SENDERS:
            info["origin"] = "Known Institutional Sender"
            info["originDetail"] = "'%s' matches a known institutional sender ID on Pakistani networks." % raw.upper()
        else:
            info["origin"] = "Service / Brand Sender ID"
            info["originDetail"] = ("Alphanumeric IDs are assigned to brands and services by their SMS "
                                     "provider, so the message came from a company's SMS platform, "
                                     "not from a person.")
        return info

    digits = re.sub(r"\D", "", raw)
    if not digits:
        return info

    if len(digits) <= 6:
        info["isShortCode"] = True
        info["senderType"] = "Short Code"
        info["senderClass"] = "service"
        info["origin"] = "Operator Short Code"
        info["originDetail"] = ("Short codes are operated by the network or by a company "
                                 "subscribed to an enterprise SMS plan. The message was sent "
                                 "through an operator SMSC, so it carries no geographic data.")
        return info

    e164, note = normalize_number(raw)
    info["e164"] = e164
    offline = lookup_offline(e164) if e164 else {"resolved": False}
    if not offline.get("resolved"):
        info["senderType"] = "Unrecognised Sender ID"
        return info

    country_code = offline.get("countryCode")
    if country_code and country_code != 92:
        info["isInternational"] = True
        info["senderType"] = "International Number"
        info["senderClass"] = "external"
        info["origin"] = "International Origin (%s)" % (offline.get("country") or country_code)
        info["originDetail"] = ("The sender is outside Pakistan. The message reached you through "
                                "your own operator's international gateway (A2P SMS).")
    elif offline.get("lineType") == "Landline":
        info["senderType"] = "Landline"
        info["senderClass"] = "external"
        info["origin"] = "Landline — %s" % (offline.get("brand") or "Fixed Line")
        info["originDetail"] = "Landline area codes in Pakistan do map to a city; mobile codes do not."
    else:
        info["senderType"] = "Mobile Number"
        info["senderClass"] = "individual"
        info["origin"] = "Mobile Network — %s" % (offline.get("brand") or offline.get("operator") or "Unknown")
        info["originDetail"] = ("Sent from a mobile SIM on %s. The message was handed to the "
                                 "operator's SMSC, so it carries no location information."
                                 % (offline.get("brand") or offline.get("operator") or "the assigned network"))

    info["operator"] = offline.get("brand") or offline.get("operator")
    return info


# ======================================================================
# ACTION GUIDANCE
# ======================================================================
def _guidance_for(sender_class, verdict_code, country_code):
    actions = []

    if sender_class == "service":
        actions.append({
            "priority": "low",
            "title": "Do not reply to short codes or brand IDs",
            "detail": ("Short codes and alphanumeric IDs belong to automated platforms. Replying "
                       "confirms your number is live and hands you to a human agent who will "
                       "pressure you."),
        })
        actions.append({
            "priority": "low",
            "title": "Verify independently",
            "detail": ("Open the company's official app or type its URL yourself. Never use a link "
                       "or number supplied by the message."),
        })
    elif sender_class == "individual":
        actions.append({
            "priority": "medium",
            "title": "Do not share OTPs, PINs, or CNIC on request",
            "detail": ("No legitimate operator, bank, or government department asks for an OTP, "
                       "PIN, password, or CNIC over SMS."),
        })
        actions.append({
            "priority": "medium",
            "title": "Block the sender if the message repeats",
            "detail": ("Android: Phone app -> number -> Block. iPhone: Phone -> info -> Block. "
                       "Also enable 'Caller ID & spam' so Google can label repeat senders."),
        })

    if verdict_code in ("high", "medium"):
        actions.append({
            "priority": "high",
            "title": "Report to PTA",
            "detail": ("Pakistan Telecommunication Authority complaint line 0800-55055, or the "
                       "online complaint portal at https://complaint.pta.gov.pk. PTA can trace "
                       "the SIM owner through the operator — this is the official route to a "
                       "real identity."),
        })
        actions.append({
            "priority": "high",
            "title": "Report to FIA Cyber Crime if money was involved",
            "detail": ("https://complaint.digitalcrime.gov.pk — include the sender number and a "
                       "screenshot of the message and any transaction reference."),
        })
        actions.append({
            "priority": "medium",
            "title": "Call your bank's official fraud line",
            "detail": ("Use the number printed on the back of your card or on the bank's official "
                       "website. If you shared an OTP, freeze the account immediately."),
        })
        actions.append({
            "priority": "low",
            "title": "Never click the link",
            "detail": ("A link in a message is the payload. If you must inspect it, copy it into a "
                       "text editor first so it cannot auto-open, and check it on a URL reputation "
                       "service such as VirusTotal."),
        })

    if country_code and country_code != 92:
        actions.append({
            "priority": "medium",
            "title": "International sender — treat as higher risk",
            "detail": ("Messages from outside Pakistan are a standard pattern for international "
                       "smishing campaigns, because the sender hides behind cheap SMS gateways."),
        })

    if country_code == 92:
        actions.append({
            "priority": "high",
            "title": "Report the spam SMS to PTA by SMS to 9000",
            "detail": ("PTA's official reporting short code. Send: sender's cell number, a space, "
                       "then the full received message text, to 9000. This registers the complaint "
                       "against the sending SIM and is the fastest route to action."),
        })
        actions.append({
            "priority": "medium",
            "title": "Check the number's current network with 76367",
            "detail": ("Send 'N' + a space + the full number (e.g. N 03412107586) to 76367 to learn "
                       "which operator serves the number TODAY. The prefix only shows the original "
                       "allocation — Mobile Number Portability can move the number to another "
                       "network while the owner stays the same."),
        })
        actions.append({
            "priority": "medium",
            "title": "File a formal complaint with PTA",
            "detail": ("Helpline 0800-55055, complaint@pta.gov.pk, or the Complaint Management "
                       "System at https://complaint.pta.gov.pk/RegisterComplaint (or the PTA CMS "
                       "app). PTA can compel the operator to disclose the SIM owner's verified "
                       "identity — this is the only lawful route to a real name."),
        })
        actions.append({
            "priority": "medium",
            "title": "Escalate to NCCIA / FIA if money, links, or fraud are involved",
            "detail": ("File at https://complaint.nccia.gov.pk or https://complaint.fia.gov.pk "
                       "(both free, no payment at any step); cyber crime helpline 9911. The "
                       "National Cyber Crime Investigation Agency absorbed the FIA's Cyber "
                       "Crime Wing in April 2025. Include screenshots of the messages and any "
                       "transaction reference. If money moved, also inform the State Bank "
                       "helpdesk at cpd.helpdesk@sbp.org.pk and your bank immediately — a recall "
                       "is only realistic within the first 24 hours. If messages are "
                       "threatening or stalking, also file an FIR with your local police."),
        })
        actions.append({
            "priority": "high",
            "title": "If the contact was on WhatsApp, report the account in-app",
            "detail": ("Open the chat -> tap the contact name -> scroll to the bottom -> "
                       "'Report' -> choose 'Fraud or Scam' (then 'Block and report'). This "
                       "escalates the account to WhatsApp for review and is the only route "
                       "that gets a bulk Business Account taken down. Also email "
                       "support@whatsapp.com with the profile name, number and screenshots. "
                       "Screenshot the profile FIRST - the account can be deleted within hours "
                       "and the evidence goes with it."),
        })
        actions.append({
            "priority": "medium",
            "title": "Never confirm anything on a WhatsApp call",
            "detail": ("No telecom operator, bank, PTA or NCCIA calls you on WhatsApp. A "
                       "caller claiming to be any of them is impersonating them. Hang up and "
                       "call the official number from the company's website or your card. "
                       "WhatsApp calls carry no verifiable caller identity: the number shown "
                       "can be spoofed or forwarded, so do not treat it as proof of who called."),
        })
        actions.append({
            "priority": "low",
            "title": "Do not expect a public owner lookup to work — and do not buy one",
            "detail": ("PTA, NADRA and the operators expose NO public service that returns the "
                       "owner name, CNIC or address of someone else's number. Sites and apps that "
                       "offer this rely on leaked or stale data. Using another person's identity "
                       "information without permission is an offence under Section 16 of PECA "
                       "2016 (up to 3 years' imprisonment and/or a fine up to Rs 5 million)."),
        })

    if not actions:
        actions.append({
            "priority": "low",
            "title": "No immediate action required",
            "detail": "Keep the message for your records and stay alert for follow-ups.",
        })
    return actions


# ======================================================================
# TOP-LEVEL PUBLIC API
# ======================================================================
def trace_number(raw_number, sender_hint=None):
    """
    Full trace report for a phone number.

    Returns: identity, network, location-intelligence (honest), risk,
             live-lookup status and recommended actions.
    """
    e164, format_note = normalize_number(raw_number)
    offline = lookup_offline(e164) if e164 else {"resolved": False}

    if not offline.get("resolved"):
        return {
            "status": "error",
            "input": raw_number,
            "message": ("Could not parse '%s' as a phone number. Enter it in international "
                        "format, e.g. +923412107586 or 03412107586." % raw_number),
            "suggestions": [
                "International format: +92 341 2107586",
                "National format:      0341-2107586",
            ],
        }

    live = lookup_live(e164)
    live_data = live.get("data") or {}

    operator = offline.get("brand") or offline.get("operator")
    current_operator = live_data.get("currentCarrier") or operator

    # ---- Risk assessment -------------------------------------------------
    signals = []
    risk_score = 0

    if not offline.get("valid"):
        risk_score += 35
        signals.append({"label": "Number fails validity check",
                        "detail": "The number is not a valid subscriber number for this country."})
    if not offline.get("possible"):
        risk_score += 25
        signals.append({"label": "Number fails plausibility check",
                        "detail": "Length does not match any allocated range."})
    if offline.get("valid") and offline.get("possible"):
        risk_score = max(0, risk_score - 15)
        signals.append({"label": "Valid, allocatable subscriber number",
                        "detail": "The number matches a real, active allocation range."})

    if offline.get("region") == "PK":
        signals.append({
            "label": "Pakistani mobile allocation",
            "detail": ("Allocated to %s. Mobile prefixes in Pakistan identify the OPERATOR "
                       "nationwide, not a city or area." % operator),
        })
    if offline.get("lineType") == "Landline":
        signals.append({"label": "Fixed-line allocation",
                        "detail": "Landline area codes do resolve to a city in Pakistan."})

    # Portability caveat
    portability_note = None
    if live_data.get("portable") is True:
        portability_note = ("This number is portable, so it may have been migrated to a "
                            "different operator since the %s allocation." % operator)
    elif offline.get("region") == "PK":
        portability_note = ("Mobile Number Portability is live in Pakistan, so the ORIGINAL "
                            "allocation shown (%s) may differ from the operator currently "
                            "serving this number." % operator)

    spam_score = live_data.get("spamScore") or live_data.get("fraudScore")
    if isinstance(spam_score, (int, float)) and spam_score > 0:
        normalized_spam = min(100, spam_score if spam_score <= 1 else spam_score / 100 * 100)
        risk_score += int(normalized_spam * 0.5)
        signals.append({"label": "Community spam/fraud score: %s" % spam_score,
                        "detail": "Reported by the live lookup provider."})
    if live_data.get("recentAbuse"):
        risk_score += 25
        signals.append({"label": "Flagged for recent abuse",
                        "detail": "The live provider lists this number in recent-abuse records."})

    # ---- WhatsApp profile (public) ----------------------------------------
    whatsapp = lookup_whatsapp(e164)
    if whatsapp.get("registered"):
        if whatsapp.get("accountType") == "WhatsApp Business Account":
            risk_score += 15
            signals.append({
                "label": "Registered as a WhatsApp Business Account",
                "detail": ("Business Accounts can be provisioned in bulk through the WhatsApp "
                           "Business API and are the account type most often used for mass "
                           "scam outreach. Legitimate consumer accounts are ordinary accounts."),
            })
        if whatsapp.get("nameLooksGenerated"):
            risk_score += 20
            signals.append({
                "label": "Display name looks machine-generated",
                "detail": ("The public display name '%s' has the pattern of a keyboard-mash "
                           "placeholder, which is typical of a throwaway account created in a "
                           "bulk batch rather than a real person."
                           % whatsapp.get("displayName")),
            })
        if not whatsapp.get("hasProfilePhoto"):
            signals.append({
                "label": "No public profile photo",
                "detail": "A genuine personal account almost always has a profile picture.",
            })
    elif whatsapp.get("checked") and whatsapp.get("registered") is False:
        signals.append({
            "label": "No public WhatsApp profile",
            "detail": ("The number is either not on WhatsApp or the profile is fully private. "
                       "If the caller reached you on WhatsApp, the number you were shown may "
                       "have been a forwarded or spoofed caller ID."),
        })

    risk_score = min(100, risk_score)
    if risk_score >= 60:
        risk_level, risk_code = "Elevated", "elevated"
    elif risk_score >= 30:
        risk_level, risk_code = "Moderate", "moderate"
    else:
        risk_level, risk_code = "Low", "low"

    # ---- Location intelligence (honest) ----------------------------------
    location_intelligence = {
        "geographicLocation": None,
        "geographicStatus": "Not derivable from the number",
        "explanation": (
            "A phone number contains no coordinates. What the prefix identifies is the "
            "operator the number was originally allocated to — in Pakistan the mobile codes "
            "are four digits starting with 03 and denote the provider 'on a nationwide basis "
            "and not geographic location'. No prefix-to-city mapping exists for Pakistani "
            "mobile numbers."
        ),
        "whatIsDeterminable": [
            "Country of allocation (country calling code +92)",
            "Allocated operator network (%s)" % operator,
            "Line type (mobile / landline)",
            "Time zone of the allocation (Asia/Karachi)",
        ] + (["Registered area for landline: %s" % offline.get("geographicArea")]
             if offline.get("geographicArea") else []),
        "legalRoutes": [
            {
                "route": "PTA complaint (0800-55055 / complaint.pta.gov.pk)",
                "detail": ("PTA can order the operator to disclose the SIM owner's verified "
                           "identity and registered address. This is the standard civil route "
                           "for spam and harassment in Pakistan."),
            },
            {
                "route": "NCCIA / FIA Cyber Crime (complaint.nccia.gov.pk)",
                "detail": ("Required when there is fraud, extortion, or a financial transaction. "
                           "The National Cyber Crime Investigation Agency absorbed the FIA's "
                           "Cyber Crime Wing in April 2025, so complaint.nccia.gov.pk is the "
                           "current portal; the older complaint.fia.gov.pk still exists. "
                           "Helpline 9911."),
            },
            {
                "route": "Police First Information Report (FIR)",
                "detail": ("An FIR plus a court order lets police request subscriber location "
                           "and call-detail records from the operator."),
            },
            {
                "route": "Operator HLR/STD request",
                "detail": ("A live Home-Location-Register query returns the network cell serving "
                           "the SIM. Pakistani operators do not expose this to the public — "
                           "it requires PTA or Police authority."),
            },
            {
                "route": "Device-level (target handset access)",
                "detail": ("GPS/network location read directly from the device. This is the only "
                           "true real-time location method and it requires access to the phone."),
            },
        ],
        "smsOriginModel": (
            "Every SMS from a mobile number is delivered by the ORIGINATING operator's SMSC "
            "(Short Message Service Centre) in Pakistan. The message therefore physically "
            "entered the network at %s's SMS gateway — a national facility — and the routing "
            "path contains no street-level location. The only location-bearing data would be "
            "the cell ID at the moment of sending, and that is held by the operator, not by "
            "the message." % (current_operator or operator)
        ),
    }

    sender_info = classify_sender(sender_hint) if sender_hint else None
    actions = _guidance_for(
        sender_info["senderClass"] if sender_info else "individual",
        risk_code,
        offline.get("countryCode"),
    )

    return {
        "status": "success",
        "input": raw_number,
        "e164": e164,
        "formatNote": format_note,
        "timestamp": _utc_now_iso(),
        "identity": {
            "country": offline.get("country"),
            "countryCode": offline.get("countryCode"),
            "region": offline.get("region"),
            "operator": operator,
            "currentOperator": current_operator,
            "mccMnc": offline.get("mccMnc"),
            "lineType": offline.get("lineType"),
            "timezones": offline.get("timezones"),
            "internationalFormat": offline.get("internationalFormat"),
            "nationalFormat": offline.get("nationalFormat"),
            "valid": offline.get("valid"),
            "possible": offline.get("possible"),
            "source": offline.get("source"),
        },
        "portabilityNote": portability_note,
        "locationIntelligence": location_intelligence,
        "whatsapp": whatsapp,
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "code": risk_code,
            "signals": signals,
        },
        "liveLookup": {
            "enabled": live.get("enabled"),
            "provider": live.get("provider"),
            "status": live.get("reason"),
            "data": live_data or None,
        },
        "senderOrigin": sender_info,
        "recommendedActions": actions,
    }


def analyze_message(raw_text, sender=None):
    """Combined SMS report: who sent it, where it came from, and what it wants."""
    sender_info = classify_sender(sender)
    body_analysis = analyze_sms_body(raw_text, sender)

    combined_score = body_analysis["riskScore"]
    if sender_info["senderClass"] == "service" and body_analysis["riskScore"] < 40:
        combined_score = max(0, combined_score - 10)

    if combined_score >= 70:
        verdict, verdict_code = "High Risk — Likely Fraud / Phishing", "high"
    elif combined_score >= 40:
        verdict, verdict_code = "Suspicious — Treat With Caution", "medium"
    elif combined_score >= 20:
        verdict, verdict_code = "Low Risk — Minor Indicators", "low"
    else:
        verdict, verdict_code = "No Strong Indicators Detected", "info"

    offline = lookup_offline(sender_info.get("e164")) if sender_info.get("e164") else {"resolved": False}
    actions = _guidance_for(sender_info["senderClass"], verdict_code,
                            offline.get("countryCode"))

    return {
        "status": "success",
        "timestamp": _utc_now_iso(),
        "senderOrigin": sender_info,
        "messageAnalysis": body_analysis,
        "risk": {
            "score": combined_score,
            "level": verdict,
            "code": verdict_code,
        },
        "originExplanation": {
            "channel": sender_info["origin"],
            "detail": sender_info["originDetail"],
            "smscRoute": (
                "Sender number -> originating operator SMSC -> your operator's SMSC -> "
                "your handset. Only the operator's records can break this chain down to a cell."
            ),
            "geographicNote": (
                "No geographic origin is recoverable from an SMS. The sender ID gives operator "
                "and country only."
            ),
        },
        "recommendedActions": actions,
    }


if __name__ == "__main__":
    import sys
    argv = sys.argv[1:]
    if argv and argv[0] in ("number", "link", "message"):
        mode = argv[0]
        rest = argv[1:]
    else:
        mode = "number"
        rest = argv
    if mode == "link":
        if not rest:
            print("usage: python3 phone_trace.py link <url>")
            raise SystemExit(1)
        target_url = rest[0]
        if not re.match(r"^(https?://|www\.)", target_url, re.IGNORECASE):
            target_url = "http://" + target_url
        analysis = analyze_link(target_url)
        print(json.dumps(analysis, indent=2, ensure_ascii=False))
        print()
        print(build_complaint_annex(analysis))
    elif mode == "message":
        if not rest:
            print("usage: python3 phone_trace.py message \"<text>\" [sender]")
            raise SystemExit(1)
        sender_arg = rest[1] if len(rest) > 1 else None
        print(json.dumps(analyze_message(rest[0], sender_arg), indent=2, ensure_ascii=False))
    else:
        target = rest[0] if rest else "+923412107586"
        print(json.dumps(trace_number(target), indent=2, ensure_ascii=False))
