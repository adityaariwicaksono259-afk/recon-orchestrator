from fastapi import FastAPI
from pydantic import BaseModel
import subprocess, json, os, re, time
import urllib.request
import urllib.parse
from bs4 import BeautifulSoup

app = FastAPI(title="Recon Orchestrator", version="2.0.0")

class ScanRequest(BaseModel):
    target: str

# ============================================
# HELPERS
# ============================================
def fetch(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (ReconOrchestrator/2.0)"
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore"), r.status, dict(r.headers)
    except Exception as e:
        return None, 0, {"error": str(e)}

# ============================================
# TOOL 1: ENDPOINT EXTRACTOR (HTML + JS)
# ============================================
def extract_endpoints(html, base):
    endpoints = set()
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(["a", "link", "script", "img", "form", "iframe"]):
        attr = tag.get("href") or tag.get("src") or tag.get("action")
        if attr:
            full = urllib.parse.urljoin(base, attr)
            if base.split("/")[2] in full:
                endpoints.add(full)
    for m in re.findall(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', html):
        endpoints.add(base.rsplit("/", 1)[0] + m)
    for m in re.findall(r'["\'](/api/[^"\']+)["\']', html):
        endpoints.add(base.rsplit("/", 1)[0] + m)
    for m in re.findall(r'(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["\']([^"\']+)["\']', html):
        if m.startswith("http"):
            endpoints.add(m)
        elif m.startswith("/"):
            endpoints.add(base.rsplit("/", 1)[0] + m)
    return sorted(endpoints)[:200]

# ============================================
# TOOL 2: PARAMETER DISCOVERY
# ============================================
def extract_params(urls):
    params = set()
    for u in urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.query:
            for k, v in urllib.parse.parse_qsl(parsed.query):
                params.add(k)
    return sorted(params)

def extract_forms(html):
    forms = []
    soup = BeautifulSoup(html, "html.parser")
    for f in soup.find_all("form"):
        forms.append({
            "action": f.get("action", ""),
            "method": f.get("method", "GET").upper(),
            "inputs": [i.get("name") for i in f.find_all("input") if i.get("name")],
        })
    return forms[:20]

# ============================================
# TOOL 3: SECURITY HEADERS SCAN
# ============================================
def security_headers_scan(headers):
    required = [
        "content-security-policy", "x-frame-options", "x-content-type-options",
        "strict-transport-security", "referrer-policy", "permissions-policy"
    ]
    present_lower = [k.lower() for k in headers.keys()]
    missing = [h for h in required if h not in present_lower]
    return {"missing": missing, "present": [h for h in required if h not in missing]}

# ============================================
# TOOL 4: SUBDOMAIN ENUM (crt.sh)
# ============================================
def subdomain_enum(domain):
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and "*" not in name:
                    subs.add(name)
        return sorted(subs)[:200]
    except Exception as e:
        return {"error": str(e)}

# ============================================
# TOOL 5: TECHNOLOGY DETECTION
# ============================================
def detect_tech(html, headers):
    tech = []
    server = headers.get("Server", "")
    if server: tech.append({"category": "server", "name": server})
    powered = headers.get("X-Powered-By", "")
    if powered: tech.append({"category": "backend", "name": powered})
    lower = html.lower()
    signatures = {
        "react": "React", "next.js": "Next.js", "vue": "Vue.js",
        "angular": "Angular", "jquery": "jQuery", "bootstrap": "Bootstrap",
        "tailwind": "TailwindCSS", "wordpress": "WordPress", "wp-content": "WordPress",
        "shopify": "Shopify", "cloudflare": "Cloudflare", "google-analytics": "Google Analytics",
        "gtag": "Google Tag Manager", "hotjar": "Hotjar", "sentry": "Sentry",
        "stripe": "Stripe", "razorpay": "Razorpay", "recaptcha": "reCAPTCHA",
        "laravel": "Laravel", "django": "Django", "express": "Express.js",
        "firebase": "Firebase", "supabase": "Supabase", "vercel": "Vercel",
        "netlify": "Netlify", "pages.dev": "Cloudflare Pages", "github.io": "GitHub Pages"
    }
    for sig, name in signatures.items():
        if sig in lower:
            tech.append({"category": "framework/service", "name": name})
    return tech

# ============================================
# ORCHESTRATOR
# ============================================
@app.get("/")
def root():
    return {
        "name": "Recon Orchestrator",
        "version": "2.0.0",
        "tools": [
            "endpoint_extractor",
            "parameter_discovery",
            "security_headers_scan",
            "subdomain_enum",
            "technology_detection"
        ],
        "endpoints": ["POST /scan"],
        "note": "Passive recon only. Gunakan hanya untuk web milik sendiri."
    }

@app.post("/scan")
async def scan(req: ScanRequest):
    target = req.target.rstrip("/")
    domain = urllib.parse.urlparse(target).netloc
    
    result = {
        "target": target,
        "domain": domain,
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tools": {}
    }

    # TOOL 1 + 2 + 3 + 5: Fetch HTML dulu
    html, status, headers = fetch(target)
    if html is None:
        return {"ok": False, "error": "Gagal fetch target: " + headers.get("error", "")}
    
    result["tools"]["http_status"] = {
        "status": status,
        "content_length": len(html),
        "server": headers.get("Server", "unknown")
    }
    
    result["tools"]["security_headers"] = security_headers_scan(headers)
    result["tools"]["technology"] = detect_tech(html, headers)
    
    endpoints = extract_endpoints(html, target)
    result["tools"]["endpoints"] = {"count": len(endpoints), "list": endpoints[:100]}
    
    params = extract_params(endpoints)
    result["tools"]["parameters"] = {"count": len(params), "list": params}
    result["tools"]["forms"] = extract_forms(html)
    
    # TOOL 4: Subdomain (via crt.sh)
    subs = subdomain_enum(domain)
    if isinstance(subs, dict):
        result["tools"]["subdomains"] = subs
    else:
        result["tools"]["subdomains"] = {"count": len(subs), "list": subs}

    # SUMMARY
    missing_h = len(result["tools"]["security_headers"]["missing"])
    result["summary"] = {
        "total_endpoints": len(endpoints),
        "total_params": len(params),
        "total_forms": len(result["tools"]["forms"]),
        "total_subdomains": len(subs) if isinstance(subs, list) else 0,
        "tech_detected": len(result["tools"]["technology"]),
        "missing_security_headers": missing_h,
        "risk_hint": "High" if missing_h > 3 else "Medium" if missing_h > 1 else "Low"
    }

    return {"ok": True, "data": result}
