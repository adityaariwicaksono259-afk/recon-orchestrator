from fastapi import FastAPI
from pydantic import BaseModel
import subprocess, json, os, re, time
import urllib.request
import urllib.parse
from bs4 import BeautifulSoup

app = FastAPI(title="Recon Orchestrator", version="1.0.0")

class ScanRequest(BaseModel):
    target: str

def fetch(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (ReconOrchestrator/1.0)"
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore"), r.status, dict(r.headers)
    except Exception as e:
        return None, 0, {"error": str(e)}

def extract_endpoints(html, base):
    """Extract endpoints from HTML (links, forms, scripts)"""
    endpoints = set()
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(["a", "link", "script", "img", "form"]):
        attr = tag.get("href") or tag.get("src") or tag.get("action")
        if attr:
            full = urllib.parse.urljoin(base, attr)
            if full.startswith(base.rsplit("/", 1)[0]):
                endpoints.add(full)
    # Also regex all URLs in HTML
    for m in re.findall(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', html):
        endpoints.add(base.rsplit("/", 1)[0] + m)
    return sorted(endpoints)[:200]

def extract_js_endpoints(html, base):
    """Extract endpoints from inline JS"""
    endpoints = set()
    # API calls
    for m in re.findall(r'["\'](/api/[^"\']+)["\']', html):
        endpoints.add(base.rsplit("/", 1)[0] + m)
    # fetch/axios URLs
    for m in re.findall(r'(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["\']([^"\']+)["\']', html):
        if m.startswith("http"):
            endpoints.add(m)
        elif m.startswith("/"):
            endpoints.add(base.rsplit("/", 1)[0] + m)
    return sorted(endpoints)[:200]

def extract_forms(html):
    """Extract forms (login, search, upload)"""
    forms = []
    soup = BeautifulSoup(html, "html.parser")
    for f in soup.find_all("form"):
        forms.append({
            "action": f.get("action", ""),
            "method": f.get("method", "GET").upper(),
            "inputs": [i.get("name") for i in f.find_all("input") if i.get("name")],
        })
    return forms[:20]

def extract_params(urls):
    """Extract unique parameters from URLs"""
    params = set()
    for u in urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.query:
            for k, v in urllib.parse.parse_qsl(parsed.query):
                params.add(k)
    return sorted(params)

def run_deepvex(target):
    """Run DeepVex if available"""
    try:
        out = "/tmp/deepvex_result.json"
        if os.path.exists(out): os.remove(out)
        subprocess.run(
            ["deepvex", "-u", target, "-d", "2", "-t", "15", "--stealth", "-o", out, "--json"],
            capture_output=True, text=True, timeout=120
        )
        if os.path.exists(out):
            with open(out) as f:
                return json.load(f)
        return {"error": "DeepVex tidak menghasilkan output"}
    except FileNotFoundError:
        return {"error": "DeepVex tidak terinstall"}
    except subprocess.TimeoutExpired:
        return {"error": "DeepVex timeout"}
    except Exception as e:
        return {"error": str(e)}

def security_headers_scan(headers):
    """Check missing security headers"""
    required = [
        "content-security-policy", "x-frame-options", "x-content-type-options",
        "strict-transport-security", "referrer-policy", "permissions-policy"
    ]
    missing = [h for h in required if h not in [k.lower() for k in headers.keys()]]
    return {"missing": missing, "present": [h for h in required if h not in missing]}

@app.get("/")
def root():
    return {
        "name": "Recon Orchestrator",
        "version": "1.0.0",
        "endpoints": ["POST /scan"],
        "note": "Passive recon only. Gunakan hanya untuk web milik sendiri."
    }

@app.post("/scan")
async def scan(req: ScanRequest):
    target = req.target.rstrip("/")
    result = {
        "target": target,
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "steps": {}
    }

    # ========== Step 1: Fetch HTML ==========
    html, status, headers = fetch(target)
    if html is None:
        return {"ok": False, "error": "Gagal fetch target: " + headers.get("error", "")}
    
    result["steps"]["http"] = {
        "status": status,
        "content_length": len(html),
        "server": headers.get("Server", "unknown")
    }

    # ========== Step 2: Security Headers ==========
    result["steps"]["security_headers"] = security_headers_scan(headers)

    # ========== Step 3: Extract Endpoints ==========
    endpoints = extract_endpoints(html, target)
    js_endpoints = extract_js_endpoints(html, target)
    all_endpoints = sorted(set(endpoints + js_endpoints))
    
    result["steps"]["endpoints"] = {
        "count": len(all_endpoints),
        "list": all_endpoints[:100]
    }

    # ========== Step 4: Extract Forms ==========
    result["steps"]["forms"] = extract_forms(html)

    # ========== Step 5: Extract Parameters ==========
    params = extract_params(all_endpoints)
    result["steps"]["parameters"] = {
        "count": len(params),
        "list": params[:100]
    }

    # ========== Step 6: DeepVex (if available) ==========
    deepvex_result = run_deepvex(target)
    result["steps"]["deepvex"] = deepvex_result if "error" not in deepvex_result else {"skipped": deepvex_result["error"]}

    # ========== Step 7: Summary ==========
    result["summary"] = {
        "total_endpoints": len(all_endpoints),
        "total_forms": len(result["steps"]["forms"]),
        "total_params": len(params),
        "missing_headers": len(result["steps"]["security_headers"]["missing"]),
        "risk_hint": "High" if len(result["steps"]["security_headers"]["missing"]) > 3 else "Medium" if len(result["steps"]["security_headers"]["missing"]) > 1 else "Low"
    }

    return {"ok": True, "data": result}
