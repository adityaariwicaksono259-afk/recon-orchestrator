import re, json, urllib.parse
from bs4 import BeautifulSoup

def fetch(url, timeout=10):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0 (Recon/5.0)"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8","ignore"), r.status, dict(r.headers)
    except Exception as e:
        return None, 0, {"error":str(e)}

# ============================================
# EXTRACT ASSET URLs FROM HTML (js/css/json/map)
# ============================================
def extract_assets(html, base):
    assets = {"js": set(), "css": set(), "json": set(), "map": set(), "manifest": set()}
    soup = BeautifulSoup(html, "html.parser")

    # <script src>
    for s in soup.find_all("script", src=True):
        full = urllib.parse.urljoin(base, s["src"])
        if full.endswith(".js") or ".js?" in full:
            assets["js"].add(full)
        elif full.endswith(".json") or ".json?" in full:
            assets["json"].add(full)

    # <link rel=stylesheet>
    for l in soup.find_all("link", href=True):
        full = urllib.parse.urljoin(base, l["href"])
        if full.endswith(".css") or ".css?" in full:
            assets["css"].add(full)
        elif full.endswith(".map") or ".map?" in full:
            assets["map"].add(full)
        elif "manifest" in full.lower():
            assets["manifest"].add(full)
        elif full.endswith(".json") or ".json?" in full:
            assets["json"].add(full)

    # <link rel=manifest>
    for m in soup.find_all("link", rel=lambda r: r and "manifest" in r):
        if m.get("href"):
            assets["manifest"].add(urllib.parse.urljoin(base, m["href"]))

    # Regex di HTML: semua .js/.css/.json/.map string
    for pat, key in [
        (r'["\']([^"\']+\.js[^"\']*)["\']', "js"),
        (r'["\']([^"\']+\.css[^"\']*)["\']', "css"),
        (r'["\']([^"\']+\.json[^"\']*)["\']', "json"),
        (r'["\']([^"\']+\.map[^"\']*)["\']', "map"),
    ]:
        for m in re.findall(pat, html):
            full = urllib.parse.urljoin(base, m)
            assets[key].add(full)

    # Convert to sorted list, limit
    return {k: sorted(v)[:30] for k,v in assets.items()}

# ============================================
# PARSE JS FILE — extract endpoints, secrets, paths
# ============================================
def parse_js(content, base):
    result = {"endpoints": set(), "secrets": [], "api_calls": set()}

    # Endpoint patterns
    patterns = [
        r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/]+)["\']',
        r'["\'](/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-/]+)["\']',
        r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["`\']([^"`\']+)["`\']',
        r'(?:url|endpoint|path|api)\s*:\s*["\']([^"\']+)["\']',
        r'["\']https?://[a-zA-Z0-9._\-]+/[a-zA-Z0-9_\-/]+["\']',
    ]
    for pat in patterns:
        for m in re.findall(pat, content):
            if m.startswith("http"):
                result["api_calls"].add(m)
            elif m.startswith("/"):
                result["endpoints"].add(base.rsplit("/",1)[0] + m)

    # Secret patterns (lebih agresif)
    secrets_pat = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret": r"aws_secret_access_key[^a-zA-Z0-9]*([A-Za-z0-9/+=]{40})",
        "Google API": r"AIza[0-9A-Za-z\-_]{35}",
        "Firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{36}",
        "GitLab Token": r"glpat-[A-Za-z0-9\-_]{20}",
        "Stripe Live": r"sk_live_[0-9a-zA-Z]{24}",
        "Stripe Test": r"sk_test_[0-9a-zA-Z]{24}",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
        "Discord Bot": r"[A-Za-z0-9]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
        "JWT": r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
        "Supabase": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "Mapbox": r"pk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9]{20,}",
        "SendGrid": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    }
    for name, pat in secrets_pat.items():
        for m in re.findall(pat, content):
            val = m if isinstance(m, str) else m[0] if m else ""
            if val:
                result["secrets"].append({"type":name, "value": val[:60] + ("..." if len(val) > 60 else "")})

    return {
        "endpoints": sorted(result["endpoints"])[:100],
        "api_calls": sorted(result["api_calls"])[:50],
        "secrets": result["secrets"][:20],
    }

# ============================================
# PARSE CSS FILE — extract url(), font, sourcemap
# ============================================
def parse_css(content):
    urls = set()
    for m in re.findall(r'url\(["\']?([^)"\']+)["\']?\)', content):
        if not m.startswith("data:"):
            urls.add(m)
    sourcemap = re.findall(r'/\*#\s*sourceMappingURL=(\S+)\s*\*/', content)
    return {"urls": sorted(urls)[:30], "sourcemap": sourcemap[:5]}

# ============================================
# PARSE JSON FILE — extract strings/keys
# ============================================
def parse_json(content, base):
    try:
        data = json.loads(content)
    except:
        return {"error": "invalid json"}
    result = {"keys": [], "endpoints": [], "sensitive": []}
    sensitive_keys = ["password","secret","token","key","api_key","apikey","auth","private"]

    def walk(obj, depth=0):
        if depth > 4: return
        if isinstance(obj, dict):
            for k, v in obj.items():
                result["keys"].append(k)
                if any(s in k.lower() for s in sensitive_keys):
                    result["sensitive"].append({"key": k, "value": str(v)[:60]})
                if isinstance(v, str) and (v.startswith("/api") or v.startswith("http")):
                    result["endpoints"].append(v)
                walk(v, depth+1)
        elif isinstance(obj, list):
            for item in obj[:5]:
                walk(item, depth+1)

    walk(data)
    return {
        "keys": sorted(set(result["keys"]))[:50],
        "endpoints": sorted(set(result["endpoints"]))[:50],
        "sensitive": result["sensitive"][:15],
    }

# ============================================
# PARSE SOURCEMAP — original source code
# ============================================
def parse_sourcemap(content):
    try:
        data = json.loads(content)
    except:
        return {"error": "invalid sourcemap"}
    return {
        "version": data.get("version"),
        "sources": data.get("sources", [])[:30],
        "sourcesContent_count": len(data.get("sourcesContent", [])),
        "file": data.get("file"),
    }

# ============================================
# PARSE MANIFEST.JSON (PWA)
# ============================================
def parse_manifest(content):
    try:
        data = json.loads(content)
    except:
        return {"error": "invalid manifest"}
    return {
        "name": data.get("name"),
        "short_name": data.get("short_name"),
        "start_url": data.get("start_url"),
        "scope": data.get("scope"),
        "icons": [i.get("src") for i in data.get("icons", [])][:10],
        "display": data.get("display"),
    }

# ============================================
# MASTER PARSER — parse all assets
# ============================================
def parse_all_assets(html, base):
    assets = extract_assets(html, base)
    result = {
        "assets_found": {k: len(v) for k,v in assets.items()},
        "js_parsed": [],
        "css_parsed": [],
        "json_parsed": [],
        "sourcemap_parsed": [],
        "manifest_parsed": None,
        "all_endpoints": set(),
        "all_secrets": [],
    }

    # Parse JS (max 10 file)
    for js_url in assets["js"][:10]:
        content, status, _ = fetch(js_url, timeout=10)
        if content and status == 200:
            parsed = parse_js(content, base)
            parsed["url"] = js_url
            parsed["size"] = len(content)
            result["js_parsed"].append(parsed)
            result["all_endpoints"].update(parsed["endpoints"])
            result["all_endpoints"].update(parsed["api_calls"])
            result["all_secrets"].extend(parsed["secrets"])
            # Cek sourcemap dari JS
            sm = re.findall(r'//#\s*sourceMappingURL=(\S+)', content)
            for s in sm[:2]:
                assets["map"].append(urllib.parse.urljoin(js_url, s))

    # Parse CSS (max 5 file)
    for css_url in assets["css"][:5]:
        content, status, _ = fetch(css_url, timeout=10)
        if content and status == 200:
            parsed = parse_css(content)
            parsed["url"] = css_url
            result["css_parsed"].append(parsed)

    # Parse JSON (max 5 file)
    for json_url in assets["json"][:5]:
        content, status, _ = fetch(json_url, timeout=10)
        if content and status == 200:
            parsed = parse_json(content, base)
            parsed["url"] = json_url
            result["json_parsed"].append(parsed)
            if "endpoints" in parsed:
                result["all_endpoints"].update(parsed["endpoints"])

    # Parse sourcemap (max 3 file)
    for sm_url in assets["map"][:3]:
        content, status, _ = fetch(sm_url, timeout=15)
        if content and status == 200:
            parsed = parse_sourcemap(content)
            parsed["url"] = sm_url
            result["sourcemap_parsed"].append(parsed)

    # Parse manifest
    if assets["manifest"]:
        content, status, _ = fetch(assets["manifest"][0], timeout=5)
        if content and status == 200:
            result["manifest_parsed"] = parse_manifest(content)

    result["all_endpoints"] = sorted(result["all_endpoints"])[:200]
    result["total_unique_secrets"] = len(set(s["type"]+s["value"] for s in result["all_secrets"]))

    return result
