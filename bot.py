# language: Python 3.11, file: bot.py
# /neko <number> | /gmail <email> | /tek <tiktok_username>

import os
import re
import ssl
import json
import time
import hashlib
import urllib.request
import urllib.parse
import urllib.error

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
CHAT_ID   = os.getenv("CHAT_ID", "")
DEFAULT_REGION = os.getenv("DEFAULT_REGION", "EG")
SERPER_API_KEY = os.getenv("SERPER_API_KEY", "")
EPIEOS_API_KEY = os.getenv("EPIEOS_API_KEY", "")
FB_COOKIE = os.getenv("FB_COOKIE", "")

UA_MOBILE = ("Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36")
UA_DESKTOP = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")

COUNTRY_CODES = {
    "20": ("EG", "Egypt"), "966": ("SA", "Saudi Arabia"),
    "971": ("AE", "UAE"), "965": ("KW", "Kuwait"), "974": ("QA", "Qatar"),
    "973": ("BH", "Bahrain"), "968": ("OM", "Oman"), "962": ("JO", "Jordan"),
    "961": ("LB", "Lebanon"), "963": ("SY", "Syria"), "964": ("IQ", "Iraq"),
    "218": ("LY", "Libya"), "216": ("TN", "Tunisia"), "213": ("DZ", "Algeria"),
    "212": ("MA", "Morocco"), "249": ("SD", "Sudan"), "967": ("YE", "Yemen"),
    "970": ("PS", "Palestine"), "1": ("US", "USA/Canada"),
    "44": ("GB", "UK"), "49": ("DE", "Germany"), "33": ("FR", "France"),
    "39": ("IT", "Italy"), "34": ("ES", "Spain"), "90": ("TR", "Turkey"),
    "7": ("RU", "Russia"), "86": ("CN", "China"), "91": ("IN", "India"),
    "92": ("PK", "Pakistan"), "880": ("BD", "Bangladesh"),
    "62": ("ID", "Indonesia"), "60": ("MY", "Malaysia"),
    "65": ("SG", "Singapore"), "81": ("JP", "Japan"), "82": ("KR", "Korea"),
    "234": ("NG", "Nigeria"), "254": ("KE", "Kenya"), "27": ("ZA", "S.Africa"),
}

EG_CARRIERS = {"010": "Vodafone", "011": "Etisalat", "012": "Orange", "015": "WE"}
EG_LINE_TYPES = {"02": "landline-Cairo", "03": "landline-Alexandria",
                 "04": "landline", "05": "landline", "06": "landline",
                 "07": "landline", "08": "landline", "09": "landline"}


def normalize_number(raw, region=DEFAULT_REGION):
    s = "".join(c for c in raw if c.isdigit() or c == "+")
    if not s:
        return None
    if not s.startswith("+"):
        if region == "EG":
            s = ("+20" + s[1:]) if s.startswith("0") else \
                ("+20" + s) if s.startswith("1") else ("+" + s)
        else:
            s = "+" + s
    digits = s.lstrip("+")
    cc = None
    for ln in (3, 2, 1):
        if digits[:ln] in COUNTRY_CODES:
            cc = digits[:ln]
            break
    if not cc:
        return None
    iso, name = COUNTRY_CODES[cc]
    national = digits[len(cc):]
    carrier = None
    line_type = "mobile"
    if iso == "EG":
        local = "0" + national if not national.startswith("0") else national
        for prefix, c in EG_CARRIERS.items():
            if local.startswith(prefix):
                carrier = c
                break
        for prefix, lt in EG_LINE_TYPES.items():
            if local.startswith(prefix):
                line_type = lt
                break
    return {"e164": "+" + digits, "country_iso": iso, "country_name": name,
            "national": national, "carrier": carrier, "line_type": line_type,
            "country_code": cc}


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_get(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": UA_MOBILE})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return None, str(e)


def http_post_json(url, payload, headers=None, timeout=15):
    data = json.dumps(payload).encode()
    h = {"Content-Type": "application/json", "User-Agent": UA_DESKTOP}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return None, str(e)


def check_pgp(email):
    result = {"status": "unknown", "email": email, "name": None,
              "fingerprint": None,
              "url": "https://keys.openpgp.org/search?q=" + urllib.parse.quote(email)}
    if not email or "@" not in email:
        result["status"] = "bad_email"; return result
    url = "https://keys.openpgp.org/vks/v1/by-email/" + urllib.parse.quote(email)
    status, body = http_get(url, headers={"User-Agent": UA_DESKTOP,
                                          "Accept": "application/pgp-keys"}, timeout=15)
    if status is None:
        result["status"] = "no_net"; return result
    if status == 404:
        result["status"] = "not_found"; return result
    if status == 429:
        result["status"] = "rate_limit"; return result
    if status != 200:
        result["status"] = "http_" + str(status); return result
    if "BEGIN PGP PUBLIC KEY BLOCK" not in body:
        result["status"] = "bad_response"; return result
    result["status"] = "found"
    fp = re.search(r'([0-9A-Fa-f]{40})', body)
    if fp:
        result["fingerprint"] = fp.group(1).upper()
    m = re.search(r'([A-Z\u0600-\u06FF][^\n<>]{1,80})\s*<[^>]+>', body)
    if m:
        result["name"] = m.group(1).strip()[:80]
    return result


def check_gravatar(email):
    email = email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        return {"status": "bad_email", "email": email}
    h = hashlib.md5(email.encode("utf-8")).hexdigest()
    img_url = "https://www.gravatar.com/avatar/" + h + "?d=404&s=400"
    status, _ = http_get(img_url, headers={"User-Agent": UA_DESKTOP}, timeout=10)
    has_avatar = (status == 200)
    prof = None
    status, body = http_get(
        "https://gravatar.com/" + h + ".json",
        headers={"User-Agent": UA_DESKTOP, "Accept": "application/json"}, timeout=10)
    if status == 200:
        try:
            j = json.loads(body)
            entry = (j.get("entry") or [{}])[0]
            nb = entry.get("name") or {}
            prof = {"display_name": entry.get("displayName"),
                    "full_name": nb.get("formatted"),
                    "about": entry.get("aboutMe"),
                    "location": entry.get("currentLocation"),
                    "job": entry.get("jobTitle"),
                    "urls": [u.get("value") for u in (entry.get("urls") or [])
                             if u.get("value")],
                    "accounts": [{"shortname": a.get("shortname"),
                                  "url": a.get("url"),
                                  "username": a.get("username")}
                                 for a in (entry.get("accounts") or [])],
                    "emails": [e.get("value") for e in (entry.get("emails") or [])
                               if e.get("value")]}
        except Exception:
            prof = None
    return {"status": "ok", "email": email, "md5": h,
            "has_avatar": has_avatar,
            "avatar_url": img_url if has_avatar else None,
            "profile_url": "https://gravatar.com/" + h, "profile": prof}


def check_github_avatar(username):
    if not username:
        return {"status": "no_username"}
    status, body = http_get(
        "https://api.github.com/users/" + urllib.parse.quote(username),
        headers={"User-Agent": UA_DESKTOP,
                 "Accept": "application/vnd.github+json"}, timeout=10)
    if status is None:
        return {"status": "no_net"}
    if status == 404:
        return {"status": "not_found"}
    if status != 200:
        return {"status": "http_" + str(status)}
    try:
        j = json.loads(body)
        return {"status": "ok", "name": j.get("name"),
                "avatar": j.get("avatar_url"), "url": j.get("html_url")}
    except Exception:
        return {"status": "bad_json"}


def check_instagram(username):
    if not username:
        return {"status": "no_username"}
    url = "https://www.instagram.com/" + urllib.parse.quote(username) + "/"
    status, body = http_get(url, headers={"User-Agent": UA_MOBILE,
                                          "Accept-Language": "en;q=0.9"}, timeout=12)
    if status is None:
        return {"status": "no_net"}
    if status == 404:
        return {"status": "not_found"}
    if status != 200:
        return {"status": "http_" + str(status)}
    if "login" in body[:2000].lower() and "og:image" not in body[:3000]:
        return {"status": "blocked_login"}
    result = {"status": "unknown", "name": None, "image": None, "url": url}
    m = re.search(r'property="og:image"\s+content="([^"]+)"', body)
    if m:
        result["image"] = m.group(1).replace("&amp;", "&")
    m = re.search(r'property="og:title"\s+content="([^"]+)"', body)
    if m:
        t = m.group(1).strip()
        if t and "Instagram" not in t and "Login" not in t:
            result["name"] = t
    result["status"] = ("found" if (result["image"] or result["name"]) else "no_results")
    return result


def check_twitter(username):
    if not username:
        return {"status": "no_username"}
    url = "https://nitter.net/" + urllib.parse.quote(username)
    status, body = http_get(url, headers={"User-Agent": UA_DESKTOP}, timeout=12)
    if status == 200:
        result = {"status": "ok", "name": None, "image": None, "url": url}
        m = re.search(r'<img class="profile-card-avatar"\s+src="([^"]+)"', body)
        if m:
            result["image"] = m.group(1)
        m = re.search(r'<a class="profile-card-fullname"[^>]*>([^<]+)</a>', body)
        if m:
            result["name"] = m.group(1).strip()
        if result["image"] or result["name"]:
            return result
    url = "https://twitter.com/" + urllib.parse.quote(username)
    status, body = http_get(url, headers={"User-Agent": UA_MOBILE}, timeout=12)
    if status == 200:
        result = {"status": "ok", "name": None, "image": None, "url": url}
        m = re.search(r'property="og:image"\s+content="([^"]+)"', body)
        if m:
            result["image"] = m.group(1)
        m = re.search(r'property="og:title"\s+content="([^"]+)"', body)
        if m:
            result["name"] = m.group(1)
        if result["image"]:
            return result
    return {"status": "not_found", "url": url}


def check_facebook_by_username(username):
    if not username:
        return {"status": "no_username"}
    url = "https://www.facebook.com/" + urllib.parse.quote(username)
    headers = {"User-Agent": UA_MOBILE, "Accept-Language": "en;q=0.9"}
    if FB_COOKIE:
        headers["Cookie"] = FB_COOKIE
    status, body = http_get(url, headers=headers, timeout=12)
    if status is None:
        return {"status": "no_net"}
    if status == 404:
        return {"status": "not_found"}
    if status != 200:
        return {"status": "http_" + str(status)}
    if "login" in body[:2000].lower() and "og:image" not in body[:3000]:
        return {"status": "blocked_login", "url": url}
    result = {"status": "unknown", "name": None, "image": None, "url": url}
    m = re.search(r'property="og:image"\s+content="([^"]+)"', body)
    if m:
        result["image"] = m.group(1).replace("&amp;", "&")
    m = re.search(r'property="og:title"\s+content="([^"]+)"', body)
    if m:
        t = m.group(1).strip()
        if t and "Facebook" not in t and "Log" not in t:
            result["name"] = t
    result["status"] = ("found" if (result["image"] or result["name"]) else "no_results")
    return result


def check_email_on_facebook(email):
    encoded = urllib.parse.quote(email)
    result = {"status": "unknown", "name": None, "profile_url": None, "image": None,
              "search_url": "https://www.facebook.com/search/top?q=" + encoded}
    headers = {"User-Agent": UA_MOBILE, "Accept-Language": "en;q=0.9"}
    if FB_COOKIE:
        headers["Cookie"] = FB_COOKIE
    status, body = http_get(
        "https://www.facebook.com/search/top?q=" + encoded,
        headers=headers, timeout=12)
    if status is None:
        result["status"] = "no_net"; return result
    if status != 200:
        result["status"] = "http_" + str(status); return result
    if "login" in body[:2000].lower() and "search" not in body[:2000].lower():
        result["status"] = "blocked_login"; return result
    m = re.search(r'property="og:image"\s+content="([^"]+)"', body)
    if m:
        result["image"] = m.group(1)
    urls = re.findall(r'href="(https://www\.facebook\.com/[^"?]+(?:\?id=\d+)?)"', body)
    urls = [u for u in urls if "/search/" not in u and "/login" not in u
            and "/help" not in u and "/policies" not in u
            and "/privacy" not in u and "/terms" not in u]
    if urls:
        result["profile_url"] = urls[0]
    m = re.search(r'<title[^>]*>([^<]+)</title>', body)
    if m:
        title = m.group(1).split("|")[0].strip()
        if len(title) > 2 and "Facebook" not in title and "log in" not in title.lower():
            result["name"] = title
    result["status"] = ("found" if (result["image"] or result["profile_url"]
                                     or result["name"]) else "no_results")
    return result


def check_facebook(e164):
    digits = e164.lstrip("+")
    result = {"status": "unknown", "name": None, "profile_url": None, "image": None,
              "search_url": "https://www.facebook.com/search/top?q=" + digits}
    headers = {"User-Agent": UA_MOBILE, "Accept-Language": "en;q=0.9"}
    if FB_COOKIE:
        headers["Cookie"] = FB_COOKIE
    status, body = http_get(
        "https://www.facebook.com/search/top?q=" + digits,
        headers=headers, timeout=12)
    if status is None:
        result["status"] = "no_net"
    elif status == 200:
        if "login" in body[:2000].lower() and "search" not in body[:2000].lower():
            result["status"] = "blocked_login"
        else:
            m = re.search(r'property="og:image"\s+content="([^"]+)"', body)
            if m:
                result["image"] = m.group(1)
            urls = re.findall(r'href="(https://www\.facebook\.com/[^"?]+(?:\?id=\d+)?)"', body)
            urls = [u for u in urls if "/search/" not in u and "/login" not in u
                    and "/help" not in u and "/policies" not in u
                    and "/privacy" not in u and "/terms" not in u]
            if urls:
                result["profile_url"] = urls[0]
            m = re.search(r'<title[^>]*>([^<]+)</title>', body)
            if m:
                title = m.group(1).split("|")[0].strip()
                if len(title) > 2 and "Facebook" not in title and "log in" not in title.lower():
                    result["name"] = title
            result["status"] = ("found" if (result["name"] or result["profile_url"]
                                             or result["image"]) else "no_results")
    else:
        result["status"] = "http_" + str(status)
    return result


def check_getcontact(e164):
    digits = e164.lstrip("+")
    result = {"status": "unknown", "name": None, "image": None, "tags": [],
              "search_url": "https://www.getcontact.com/en/search?q=" + digits}
    status, body = http_get(
        "https://www.getcontact.com/en/search?q=" + digits,
        headers={"User-Agent": UA_MOBILE, "Accept-Language": "en;q=0.9",
                 "Accept": "text/html"}, timeout=15)
    if status is None:
        result["status"] = "no_net"; return result
    if status != 200:
        result["status"] = "http_" + str(status); return result
    m = re.search(r'property="og:title"\s+content="([^"]+)"', body)
    if m:
        t = m.group(1).strip()
        if t and "GetContact" not in t:
            result["name"] = t
    m = re.search(r'property="og:image"\s+content="([^"]+)"', body)
    if m:
        result["image"] = m.group(1)
    tags = re.findall(r'"tagName"\s*:\s*"([^"]+)"', body)
    if tags:
        result["tags"] = tags[:5]
    result["status"] = ("found" if (result["name"] or result["image"]
                                     or result["tags"]) else "no_results")
    return result


def check_syncme(e164):
    result = {"status": "unknown", "name": None, "carrier": None,
              "tags": [], "spam": False, "image": None,
              "url": "https://sync.me/search/?number=" + e164}
    status, body = http_get(
        "https://sync.me/api/search?number=" + urllib.parse.quote(e164),
        headers={"Referer": "https://sync.me/", "User-Agent": UA_MOBILE,
                 "Accept": "application/json"}, timeout=12)
    if status is None:
        result["status"] = "no_net"; return result
    if status != 200:
        result["status"] = "http_" + str(status); return result
    try:
        j = json.loads(body)
    except Exception:
        result["status"] = "bad_json"; return result
    result["status"] = "ok"
    result["name"] = j.get("name")
    result["carrier"] = j.get("carrier")
    result["spam"] = bool(j.get("spam", False))
    tags = j.get("tags") or []
    if isinstance(tags, list):
        result["tags"] = [str(t) for t in tags if t][:8]
    for k in ("image", "avatar", "photo", "picture"):
        if j.get(k):
            result["image"] = j[k]; break
    if not (result["name"] or result["image"]):
        result["status"] = "no_results"
    return result


def check_serper(query):
    if not SERPER_API_KEY:
        return {"status": "no_key"}
    status, body = http_post_json(
        "https://google.serper.dev/search",
        {"q": query, "gl": "eg", "hl": "en"},
        headers={"X-API-KEY": SERPER_API_KEY})
    if status is None:
        return {"status": "no_net"}
    if status != 200:
        return {"status": "http_" + str(status)}
    try:
        j = json.loads(body)
    except Exception:
        return {"status": "bad_json"}
    organic = j.get("organic") or []
    kg = j.get("knowledgeGraph") or {}
    return {"status": "ok",
            "results": [{"title": r.get("title"), "link": r.get("link"),
                         "snippet": r.get("snippet")} for r in organic[:5]],
            "knowledge": {"title": kg.get("title"),
                          "description": kg.get("description"),
                          "image": (kg.get("imageUrl")
                                    or (kg.get("attributes") or {}).get("Image"))}
                         if kg else None}


def check_whatsapp(e164):
    digits = e164.lstrip("+")
    status, body = http_get("https://wa.me/" + digits,
                            headers={"User-Agent": UA_MOBILE}, timeout=10)
    if status is None:
        return {"status": "no_net", "exists": None}
    if status != 200:
        return {"status": "http_" + str(status), "exists": None}
    invalid = any(m.lower() in body.lower() for m in
                  ["Phone number shared via url is invalid",
                   "Invalid phone number", "isn't on WhatsApp"])
    exists = not invalid and "whatsapp" in body.lower()
    return {"status": "ok", "exists": exists}


def check_epieos_email(email):
    result = {"status": "no_key", "email": email,
              "search_url": "https://epieos.com/?q=" + urllib.parse.quote(email) + "&t=email",
              "google_account": None, "skype": None}
    if not EPIEOS_API_KEY:
        return result
    status, body = http_post_json(
        "https://api.epieos.com/v1/email",
        {"email": email, "key": EPIEOS_API_KEY},
        headers={"User-Agent": UA_DESKTOP, "Accept": "application/json"}, timeout=20)
    if status is None:
        result["status"] = "no_net"; return result
    if status in (401, 403):
        result["status"] = "unauth"; return result
    if status != 200:
        result["status"] = "http_" + str(status); return result
    try:
        j = json.loads(body)
    except Exception:
        result["status"] = "bad_json"; return result
    result["status"] = "ok"
    g = j.get("google") or j.get("google_account") or {}
    if g:
        result["google_account"] = {
            "name": g.get("name") or g.get("full_name"),
            "picture": g.get("picture") or g.get("image"),
            "gaia_id": g.get("gaia_id") or g.get("id")}
    sk = j.get("skype") or {}
    if sk:
        result["skype"] = {"name": sk.get("name") or sk.get("display_name"),
                           "id": sk.get("id") or sk.get("skype_id"),
                           "image": sk.get("image") or sk.get("avatar")}
    return result


def check_epieos_phone(e164):
    result = {"status": "no_key", "phone": e164,
              "search_url": "https://epieos.com/?q=" + urllib.parse.quote(e164.lstrip("+")) + "&t=phone",
              "google_account": None}
    if not EPIEOS_API_KEY:
        return result
    status, body = http_post_json(
        "https://api.epieos.com/v1/phone",
        {"phone": e164, "key": EPIEOS_API_KEY},
        headers={"User-Agent": UA_DESKTOP, "Accept": "application/json"}, timeout=20)
    if status is None:
        result["status"] = "no_net"; return result
    if status in (401, 403):
        result["status"] = "unauth"; return result
    if status != 200:
        result["status"] = "http_" + str(status); return result
    try:
        j = json.loads(body)
        result["status"] = "ok"
        g = j.get("google") or j.get("google_account") or {}
        if g:
            result["google_account"] = {
                "name": g.get("name") or g.get("full_name"),
                "picture": g.get("picture") or g.get("image"),
                "gaia_id": g.get("gaia_id")}
    except Exception:
        result["status"] = "bad_json"
    return result


def check_tiktok_full(username):
    if not username:
        return {"status": "no_username"}
    username = username.lstrip("@")
    url = "https://www.tiktok.com/@" + urllib.parse.quote(username)
    status, body = http_get(url, headers={"User-Agent": UA_MOBILE,
                                          "Accept-Language": "en;q=0.9"}, timeout=15)
    if status is None:
        return {"status": "no_net", "url": url, "username": username}
    if status == 404:
        return {"status": "not_found", "url": url, "username": username}
    if status != 200:
        return {"status": "http_" + str(status), "url": url, "username": username}
    result = {"status": "unknown", "url": url, "username": username,
              "name": None, "image": None, "bio": None,
              "followers": None, "following": None, "likes": None,
              "videos": None, "verified": False, "external_links": []}
    m = re.search(r'property="og:title"\s+content="([^"]+)"', body)
    if m:
        t = m.group(1)
        nm = re.match(r'^([^(]+)\s*\(@', t)
        if nm:
            result["name"] = nm.group(1).strip()
    m = re.search(r'property="og:image"\s+content="([^"]+)"', body)
    if m:
        result["image"] = m.group(1).replace("&amp;", "&")
    m = re.search(r'property="og:description"\s+content="([^"]+)"', body)
    if m:
        result["bio"] = m.group(1).replace("&amp;", "&")[:500]
    m = re.search(r'__UNIVERSAL_DATA_FOR_REHYDRATION__[^>]*>(\{.*?\})</script>', body, re.S)
    if m:
        try:
            data = json.loads(m.group(1))
            scope = data.get("__DEFAULT_SCOPE__") or {}
            ud = scope.get("webapp.user-detail") or {}
            stats = (ud.get("userInfo") or {}).get("stats") or {}
            user = (ud.get("userInfo") or {}).get("user") or {}
            if stats:
                result["followers"] = stats.get("followerCount")
                result["following"] = stats.get("followingCount")
                result["likes"] = stats.get("heartCount")
                result["videos"] = stats.get("videoCount")
            if user:
                result["verified"] = bool(user.get("verified"))
                if not result["name"] and user.get("nickname"):
                    result["name"] = user["nickname"]
                bio_link = user.get("bioLink") or {}
                if bio_link.get("link"):
                    result["external_links"].append(bio_link["link"])
        except Exception:
            pass
    result["status"] = ("found" if (result["name"] or result["image"]
                                     or result["followers"]) else "no_results")
    return result


def build_social_links(e164):
    digits = e164.lstrip("+")
    gq = "https://www.google.com/search?q=site%3A{site}+%22{d}%22"
    return {
        "instagram": {"profile": "https://www.instagram.com/" + digits + "/",
                      "dork": gq.format(site="instagram.com", d=digits)},
        "tiktok": {"profile": "https://www.tiktok.com/@" + digits,
                   "dork": gq.format(site="tiktok.com", d=digits)},
        "twitter": {"search": "https://twitter.com/search?q=" + digits + "&f=user",
                    "dork": gq.format(site="twitter.com", d=digits)},
        "linkedin": {"search": "https://www.linkedin.com/search/results/all/?keywords=" + digits,
                     "dork": gq.format(site="linkedin.com", d=digits)},
        "snapchat": {"add": "https://www.snapchat.com/add/" + digits,
                     "dork": gq.format(site="snapchat.com", d=digits)},
        "telegram": {"search": "https://t.me/+" + digits,
                     "dork": gq.format(site="t.me", d=digits)},
        "facebook": {"search": "https://www.facebook.com/search/top?q=" + digits,
                     "dork": gq.format(site="facebook.com", d=digits)},
        "github": {"search": "https://github.com/search?q=" + digits + "&type=users",
                   "dork": gq.format(site="github.com", d=digits)},
        "youtube": {"search": "https://www.youtube.com/results?search_query=" + digits,
                    "dork": gq.format(site="youtube.com", d=digits)},
        "pinterest": {"search": "https://www.pinterest.com/search/pins/?q=" + digits,
                      "dork": gq.format(site="pinterest.com", d=digits)},
    }


def scan_number(raw):
    info = normalize_number(raw)
    if not info:
        return {"raw": raw, "valid": False}
    info["raw"] = raw
    info["valid"] = True
    info["social_links"] = build_social_links(info["e164"])
    info["whatsapp"] = check_whatsapp(info["e164"])
    info["sync_me"] = check_syncme(info["e164"])
    info["getcontact"] = check_getcontact(info["e164"])
    info["facebook"] = check_facebook(info["e164"])
    info["epieos"] = check_epieos_phone(info["e164"])
    if SERPER_API_KEY:
        info["serper"] = check_serper('"' + info["e164"] + '"')
    else:
        info["serper"] = {"status": "no_key"}
    return info
    
    def collect_images_from_number(info):
        images = []
    sm = info.get("sync_me") or {}
    if sm.get("image"):
        images.append(("Sync.me", sm["image"]))
    gc = info.get("getcontact") or {}
    if gc.get("image"):
        images.append(("GetContact", gc["image"]))
    fb = info.get("facebook") or {}
    if fb.get("image"):
        images.append(("Facebook", fb["image"]))
    ep = info.get("epieos") or {}
    ga = ep.get("google_account") or {}
    if ga.get("picture"):
        images.append(("Epieos (Google)", ga["picture"]))
    sp = info.get("serper") or {}
    if sp.get("status") == "ok":
        kg = sp.get("knowledge") or {}
        if kg.get("image"):
            images.append(("Google KG", kg["image"]))
    return images


def collect_images_from_email(g, fb_res, serper_res, username, epieos_res=None):
    images = []
    if epieos_res:
        ga = epieos_res.get("google_account") or {}
        if ga.get("picture"):
            images.append(("Epieos (Google)", ga["picture"]))
        sk = epieos_res.get("skype") or {}
        if sk.get("image"):
            images.append(("Epieos (Skype)", sk["image"]))
    if g.get("has_avatar") and g.get("avatar_url"):
        images.append(("Gravatar", g["avatar_url"]))
    if fb_res and fb_res.get("image"):
        images.append(("Facebook (email)", fb_res["image"]))
    if serper_res and (serper_res.get("knowledge") or {}).get("image"):
        images.append(("Google KG", serper_res["knowledge"]["image"]))
    if username:
        gh = check_github_avatar(username)
        if gh.get("status") == "ok" and gh.get("avatar"):
            images.append(("GitHub", gh["avatar"]))
        ig = check_instagram(username)
        if ig.get("image"):
            images.append(("Instagram", ig["image"]))
        tk = check_tiktok_full(username)
        if tk.get("image"):
            images.append(("TikTok", tk["image"]))
        tw = check_twitter(username)
        if tw.get("image"):
            images.append(("Twitter", tw["image"]))
        fbu = check_facebook_by_username(username)
        if fbu.get("image"):
            images.append(("Facebook (username)", fbu["image"]))
    seen = set()
    unique = []
    for src, url in images:
        if url in seen:
            continue
        seen.add(url); unique.append((src, url))
    return unique


def pretty_main(info):
    if not info.get("valid"):
        return "Invalid number."
    lines = ["<code>" + info["raw"] + "</code>", ""]
    lines.append("🌍 " + info["country_name"] + " (" + info["country_iso"] + ")")
    lines.append("🔢 <code>" + info["e164"] + "</code>")
    if info.get("carrier"):
        lines.append("📡 " + info["carrier"])
    lt = info.get("line_type", "")
    lines.append("📞 " + ("Landline" if lt.startswith("landline") else "Mobile"))
    wa = info.get("whatsapp") or {}
    if wa.get("exists") is True:
        lines.append("💬 WhatsApp: ✅")
    elif wa.get("exists") is False:
        lines.append("💬 WhatsApp: ❌")
    return "\n".join(lines)


def pretty_info_details(info):
    lines = ["<b>📋 Info Details</b>",
             "<code>" + info["raw"] + "</code>", ""]
    sm = info.get("sync_me") or {}
    if sm.get("name") or sm.get("tags") or sm.get("spam"):
        lines.append("<b>🔄 Sync.me</b>")
        if sm.get("name"):
            lines.append("👤 " + sm["name"])
        if sm.get("carrier"):
            lines.append("📡 " + sm["carrier"])
        if sm.get("tags"):
            lines.append("🏷 " + ", ".join(sm["tags"]))
        if sm.get("spam"):
            lines.append("⚠️ spam")
    gc = info.get("getcontact") or {}
    if gc.get("name") or gc.get("tags"):
        lines.append("")
        lines.append("<b>📇 GetContact</b>")
        if gc.get("name"):
            lines.append("👤 " + gc["name"])
        if gc.get("tags"):
            lines.append("🏷 " + ", ".join(gc["tags"]))
    fb = info.get("facebook") or {}
    if fb.get("name") or fb.get("profile_url"):
        lines.append("")
        lines.append("<b>📘 Facebook</b>")
        if fb.get("name"):
            lines.append("👤 " + fb["name"])
        if fb.get("profile_url"):
            lines.append("🔗 <a href=\"" + fb["profile_url"] + "\">Profile</a>")
    ep = info.get("epieos") or {}
    if ep.get("google_account") or ep.get("status") != "no_key":
        lines.append("")
        lines.append("<b>🔍 Epieos</b>: " + ep.get("status", "?"))
        ga = ep.get("google_account") or {}
        if ga.get("name"):
            lines.append("👤 " + ga["name"])
        if ga.get("gaia_id"):
            lines.append("🆔 <code>" + ga["gaia_id"] + "</code>")
    sp = info.get("serper") or {}
    if sp.get("status") == "ok":
        results = sp.get("results") or []
        if results:
            lines.append("")
            lines.append("<b>🔵 Google</b>")
            for r in results[:4]:
                t = (r.get("title") or "")[:60]
                l = r.get("link") or ""
                lines.append("• <a href=\"" + l + "\">" + t + "</a>")
    return "\n".join(lines)


def pretty_social(info):
    if not info.get("valid"):
        return "Invalid."
    digits = info["e164"].lstrip("+")
    lines = ["<b>🔗 Social Links</b>",
             "<code>" + info["raw"] + "</code>", ""]
    social = info.get("social_links") or {}
    emoji = {"instagram": "📷", "tiktok": "🎵", "twitter": "🐦",
             "linkedin": "💼", "snapchat": "👻", "telegram": "✈️",
             "facebook": "📘", "github": "🐙", "youtube": "▶️", "pinterest": "📌"}
    lines.append("<b>🌐 Social search</b>")
    for name, urls in social.items():
        e = emoji.get(name, "•")
        main = (urls.get("profile") or urls.get("search") or urls.get("add") or "")
        dork = urls.get("dork") or ""
        lines.append(e + " <a href=\"" + main + "\">" + name + "</a>  "
                     "<a href=\"" + dork + "\">🔍</a>")
    lines.append("")
    lines.append("<b>🔎 Search engines</b>")
    q_digits = urllib.parse.quote('"' + digits + '"')
    lines.append("<a href=\"https://www.google.com/search?q=" + q_digits + "\">Google</a>  "
                 "<a href=\"https://www.bing.com/search?q=" + q_digits + "\">Bing</a>  "
                 "<a href=\"https://duckduckgo.com/?q=" + q_digits + "\">DDG</a>")
    lines.append("")
    lines.append("<b>📞 Phone services</b>")
    cc = info["country_iso"].lower()
    lines.append("<a href=\"https://wa.me/" + digits + "\">WhatsApp</a>  "
                 "<a href=\"https://t.me/+" + digits + "\">Telegram</a>")
    lines.append("<a href=\"https://www.truecaller.com/search/" + cc + "/" + digits + "\">Truecaller</a>  "
                 "<a href=\"https://sync.me/search/?number=" + info["e164"] + "\">Sync.me</a>")
    lines.append("<a href=\"https://www.getcontact.com/en/search?q=" + digits + "\">GetContact</a>  "
                 "<a href=\"https://epieos.com/?q=" + digits + "&t=phone\">Epieos</a>")
    return "\n".join(lines)


def pretty_gravatar(g, fb_result=None, serper_result=None, epieos_result=None, pgp_result=None):
    if g.get("status") == "bad_email":
        return "Bad email."
    email = g["email"]
    local = email.split("@")[0]
    username = re.sub(r"[^a-zA-Z0-9._]", "", local)
    encoded = urllib.parse.quote(email)
    lines = ["Email: <code>" + email + "</code>", ""]

    name = None
    if epieos_result:
        ga = epieos_result.get("google_account") or {}
        name = ga.get("name")
    if not name and g.get("profile"):
        p = g["profile"]
        name = p.get("display_name") or p.get("full_name")
    if not name and fb_result and fb_result.get("name"):
        name = fb_result["name"]
    if not name and serper_result:
        kg = serper_result.get("knowledge") or {}
        if kg.get("title"):
            name = kg["title"]
    if name:
        lines.append("👤 Name: <b>" + name + "</b>")

    if g.get("has_avatar"):
        lines.append("🖼 Gravatar: avatar")
    lines.append("<a href=\"" + g["profile_url"] + "\">Gravatar profile</a>")

    prof = g.get("profile")
    if prof:
        if prof.get("job"):
            lines.append("💼 " + prof["job"])
        if prof.get("location"):
            lines.append("📍 " + prof["location"])
        if prof.get("accounts"):
            lines.append("<b>Linked accounts</b>")
            for a in prof["accounts"][:10]:
                sn = a.get("shortname") or "?"
                url = a.get("url") or ""
                lines.append("• " + sn + ": <a href=\"" + url + "\">link</a>")

    if pgp_result and pgp_result.get("status") == "found":
        lines.append("")
        lines.append("<b>🔐 PGP Key</b>")
        if pgp_result.get("name"):
            lines.append("👤 " + pgp_result["name"])
        if pgp_result.get("fingerprint"):
            lines.append("🔑 <code>" + pgp_result["fingerprint"] + "</code>")
        lines.append("<a href=\"" + pgp_result["url"] + "\">keys.openpgp.org</a>")

    if epieos_result:
        lines.append("")
        lines.append("<b>🔍 Epieos</b>: " + epieos_result.get("status", "?"))
        ga = epieos_result.get("google_account") or {}
        if ga.get("name"):
            lines.append("👤 Google: " + ga["name"])
        if ga.get("gaia_id"):
            lines.append("🆔 <code>" + ga["gaia_id"] + "</code>")

    if fb_result and fb_result.get("status") != "no_net":
        lines.append("")
        lines.append("<b>📘 Facebook</b>: " + str(fb_result.get("status")))
        if fb_result.get("name"):
            lines.append("👤 " + fb_result["name"])
        if fb_result.get("profile_url"):
            lines.append("🔗 " + fb_result["profile_url"])

    if serper_result and serper_result.get("status") == "ok":
        results = serper_result.get("results") or []
        if results:
            lines.append("")
            lines.append("<b>🔵 Google</b>")
            for r in results[:4]:
                t = (r.get("title") or "")[:60]
                l = r.get("link") or ""
                lines.append("• <a href=\"" + l + "\">" + t + "</a>")

    if username:
        lines.append("")
        lines.append("<b>🔍 Social by username</b>")
        lines.append("<a href=\"https://www.instagram.com/" + username + "/\">Instagram</a> "
                     "<a href=\"https://www.tiktok.com/@" + username + "\">TikTok</a>")
        lines.append("<a href=\"https://www.facebook.com/" + username + "\">Facebook</a> "
                     "<a href=\"https://twitter.com/" + username + "\">Twitter</a>")
        lines.append("<a href=\"https://github.com/" + username + "\">GitHub</a>")

    lines.append("")
    lines.append("<a href=\"https://www.google.com/search?q=" + encoded + "\">Google</a> "
                 "<a href=\"https://www.bing.com/search?q=" + encoded + "\">Bing</a>")
    lines.append("<a href=\"https://haveibeenpwned.com/account/" + encoded + "\">HIBP (manual)</a>")
    return "\n".join(lines)


def pretty_tiktok(r):
    if r.get("status") == "no_username":
        return "Usage: /tek username"
    if r.get("status") == "not_found":
        return "TikTok: <b>@" + r["username"] + "</b> — not found"
    if r.get("status") == "no_net":
        return "TikTok: no net"
    if r.get("status", "").startswith("http_"):
        return "TikTok: " + r["status"]
    lines = ["<b>TikTok Profile</b>",
             "Username: <code>@" + r["username"] + "</code>",
             "URL: " + r["url"], ""]
    if r.get("name"):
        v = " ✓" if r.get("verified") else ""
        lines.append("Name: <b>" + r["name"] + v + "</b>")
    if r.get("bio"):
        lines.append("Bio: " + r["bio"])
    lines.append("")
    if r.get("followers") is not None:
        lines.append("Followers: <b>" + str(r["followers"]) + "</b>")
    if r.get("following") is not None:
        lines.append("Following: " + str(r["following"]))
    if r.get("likes") is not None:
        lines.append("Likes: " + str(r["likes"]))
    if r.get("videos") is not None:
        lines.append("Videos: " + str(r["videos"]))
    if r.get("external_links"):
        lines.append("")
        lines.append("<b>Links</b>")
        for u in r["external_links"][:5]:
            lines.append("• " + u)
    return "\n".join(lines)


class Bot:
    def __init__(self, token, chat_id=""):
        self.token = token
        self.chat_id = chat_id
        self.api = "https://api.telegram.org/bot" + token
        self.pending_photos = {}

    def _post_json(self, method, payload, timeout=40):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.api + "/" + method, data=data,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=_ssl_ctx()) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def send(self, text, chat_id=None, buttons=None):
        payload = {"chat_id": chat_id or self.chat_id, "text": text,
                   "parse_mode": "HTML", "disable_web_page_preview": True}
        if buttons is not None:
            payload["reply_markup"] = {"inline_keyboard": buttons}
        return self._post_json("sendMessage", payload)

    def edit(self, chat_id, message_id, text, buttons=None):
        payload = {"chat_id": chat_id, "message_id": message_id,
                   "text": text, "parse_mode": "HTML",
                   "disable_web_page_preview": True}
        if buttons is not None:
            payload["reply_markup"] = {"inline_keyboard": buttons}
        return self._post_json("editMessageText", payload)

    def send_photo(self, photo_url, caption="", chat_id=None):
        return self._post_json("sendPhoto", {
            "chat_id": chat_id or self.chat_id, "photo": photo_url,
            "caption": caption[:1024] if caption else "",
            "parse_mode": "HTML"}, timeout=30)

    def answer_callback(self, callback_id, text=""):
        return self._post_json("answerCallbackQuery",
                               {"callback_query_id": callback_id, "text": text})

    def get_updates(self, offset=None, timeout=25):
        url = self.api + "/getUpdates?timeout=" + str(timeout)
        if offset:
            url += "&offset=" + str(offset)
        try:
            with urllib.request.urlopen(url, timeout=timeout + 10,
                                        context=_ssl_ctx()) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def run(self):
        if not self.token:
            print("[bot] ERROR: no BOT_TOKEN")
            return
        print("[bot] started")
        offset = None
        while True:
            data = self.get_updates(offset)
            if not data.get("ok"):
                print("[bot] err: " + str(data.get("error")))
                time.sleep(3)
                continue
            for upd in data.get("result", []):
                offset = upd["update_id"] + 1

                if "callback_query" in upd:
                    cq = upd["callback_query"]
                    cb_data = cq.get("data", "")
                    cb_id = cq.get("id")
                    cb_msg = cq.get("message") or {}
                    cb_chat = str(cb_msg.get("chat", {}).get("id", self.chat_id))
                    cb_mid = cb_msg.get("message_id")
                    uid = cq.get("from", {}).get("id", cb_chat)

                    if cb_data == "imgs_yes":
                        self.answer_callback(cb_id, "Sending...")
                        imgs = self.pending_photos.pop(uid, [])
                        self.edit(cb_chat, cb_mid, "Sending " + str(len(imgs)) + "...")
                        for src, url in imgs:
                            self.send_photo(url, "Source: <b>" + src + "</b>", cb_chat)
                    elif cb_data == "imgs_no":
                        self.answer_callback(cb_id, "Skipped")
                        self.pending_photos.pop(uid, None)
                        self.edit(cb_chat, cb_mid, "Skipped.")
                    elif cb_data.startswith("back:"):
                        raw = cb_data.split(":", 1)[1]
                        info = scan_number(raw)
                        if not info.get("valid"):
                            self.edit(cb_chat, cb_mid, "Invalid")
                            continue
                        self.answer_callback(cb_id)
                        self.edit(cb_chat, cb_mid, pretty_main(info),
                                  [[{"text": "Info Details", "callback_data": "info:" + raw},
                                    {"text": "Social", "callback_data": "social:" + raw}]])
                    elif cb_data.startswith("info:"):
                        raw = cb_data.split(":", 1)[1]
                        info = scan_number(raw)
                        if not info.get("valid"):
                            self.answer_callback(cb_id, "Invalid")
                            continue
                        self.answer_callback(cb_id)
                        self.edit(cb_chat, cb_mid, pretty_info_details(info),
                                  [[{"text": "← Back", "callback_data": "back:" + raw}]])
                    elif cb_data.startswith("social:"):
                        raw = cb_data.split(":", 1)[1]
                        info = scan_number(raw)
                        if not info.get("valid"):
                            self.answer_callback(cb_id, "Invalid")
                            continue
                        self.answer_callback(cb_id)
                        self.edit(cb_chat, cb_mid, pretty_social(info),
                                  [[{"text": "← Back", "callback_data": "back:" + raw}]])
                    continue

                msg = upd.get("message") or {}
                text = (msg.get("text") or "").strip()
                chat_id = str(msg.get("chat", {}).get("id", self.chat_id))
                uid = msg.get("from", {}).get("id", chat_id)

                if text.startswith("/neko"):
                    parts = text.split()
                    if len(parts) < 2:
                        self.send("Usage: /neko 01012345678", chat_id)
                        continue
                    raw = parts[1]
                    self.send("Scanning <code>" + raw + "</code>...", chat_id)
                    try:
                        info = scan_number(raw)
                        if not info.get("valid"):
                            self.send("Invalid number.", chat_id)
                            continue
                        images = collect_images_from_number(info)
                        if images:
                            self.pending_photos[uid] = images
                            self.send("Found <b>" + str(len(images)) + "</b> image(s).",
                                      chat_id,
                                      [[{"text": "Yes", "callback_data": "imgs_yes"},
                                        {"text": "No", "callback_data": "imgs_no"}]])
                        self.send(pretty_main(info), chat_id,
                                  [[{"text": "Info Details", "callback_data": "info:" + raw},
                                    {"text": "Social", "callback_data": "social:" + raw}]])
                    except Exception as e:
                        self.send("Error: <code>" + str(e) + "</code>", chat_id)

                elif text.startswith("/gmail"):
                    parts = text.split()
                    if len(parts) < 2:
                        self.send("Usage: /gmail user@gmail.com", chat_id)
                        continue
                    email = parts[1]
                    self.send("Searching <code>" + email + "</code>...", chat_id)
                    try:
                        g = check_gravatar(email)
                        fb_res = check_email_on_facebook(email)
                        serper_res = (check_serper('"' + email + '"')
                                      if SERPER_API_KEY
                                      else {"status": "no_key"})
                        ep_res = check_epieos_email(email)
                        pgp_res = check_pgp(email)
                        username = re.sub(r"[^a-zA-Z0-9._]", "", email.split("@")[0])
                        self.send(pretty_gravatar(g, fb_res, serper_res, ep_res, pgp_res),
                                  chat_id)
                        images = collect_images_from_email(g, fb_res, serper_res,
                                                           username, ep_res)
                        if images:
                            self.pending_photos[uid] = images
                            self.send("Found <b>" + str(len(images)) + "</b> image(s).",
                                      chat_id,
                                      [[{"text": "Yes", "callback_data": "imgs_yes"},
                                        {"text": "No", "callback_data": "imgs_no"}]])
                    except Exception as e:
                        self.send("Error: <code>" + str(e) + "</code>", chat_id)

                elif text.startswith("/tek"):
                    parts = text.split()
                    if len(parts) < 2:
                        self.send("Usage: /tek username", chat_id)
                        continue
                    username = parts[1].lstrip("@")
                    self.send("Looking up <code>@" + username + "</code>...", chat_id)
                    try:
                        r = check_tiktok_full(username)
                        self.send(pretty_tiktok(r), chat_id)
                        if r.get("image"):
                            self.send_photo(r["image"], "Profile: <b>@" + username + "</b>", chat_id)
                    except Exception as e:
                        self.send("Error: <code>" + str(e) + "</code>", chat_id)

                elif text == "/start":
                    self.send("Commands:\n"
                              "/neko &lt;number&gt;\n"
                              "/gmail &lt;email&gt;\n"
                              "/tek &lt;tiktok_username&gt;\n"
                              "/id", chat_id)
                elif text == "/id":
                    self.send("chat_id: <code>" + chat_id + "</code>", chat_id)


if __name__ == "__main__":
    Bot(BOT_TOKEN, CHAT_ID).run()
