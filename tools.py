import re, json, socket, ssl, subprocess, urllib.parse, urllib.request
from bs4 import BeautifulSoup
import concurrent.futures
import tools_assets as TA

# ============================================
# TOOLS: PASSIVE RECON
# ============================================

def fetch(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0 (Recon/4.0)"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8","ignore"), r.status, dict(r.headers)
    except Exception as e:
        return None, 0, {"error":str(e)}

def tool_endpoints(html, base):
    eps = set()
    soup = BeautifulSoup(html,"html.parser")
    for t in soup.find_all(["a","link","script","img","form","iframe"]):
        attr = t.get("href") or t.get("src") or t.get("action")
        if attr:
            full = urllib.parse.urljoin(base, attr)
            if base.split("/")[2] in full: eps.add(full)
    for m in re.findall(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', html):
        eps.add(base.rsplit("/",1)[0]+m)
    return sorted(eps)[:200]

def tool_params(urls):
    p = set()
    for u in urls:
        for k,_ in urllib.parse.parse_qsl(urllib.parse.urlparse(u).query):
            p.add(k)
    return sorted(p)

def tool_forms(html):
    out = []
    soup = BeautifulSoup(html,"html.parser")
    for f in soup.find_all("form"):
        out.append({"action":f.get("action",""),"method":f.get("method","GET").upper(),
                    "inputs":[i.get("name") for i in f.find_all("input") if i.get("name")]})
    return out[:20]

def tool_headers(headers):
    req = ["content-security-policy","x-frame-options","x-content-type-options",
           "strict-transport-security","referrer-policy","permissions-policy"]
    lk = [k.lower() for k in headers.keys()]
    miss = [h for h in req if h not in lk]
    return {"missing":miss,"present":[h for h in req if h not in miss]}

def tool_subdomains(domain):
    try:
        u = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(u, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8","ignore"))
        s = set()
        for e in data:
            for n in e.get("name_value","").split("\n"):
                n = n.strip().lower()
                if n and "*" not in n: s.add(n)
        return sorted(s)[:100]
    except Exception as e:
        return {"error":str(e)}

def tool_tech(html, headers):
    tech = []
    if headers.get("Server"): tech.append({"cat":"server","name":headers["Server"]})
    if headers.get("X-Powered-By"): tech.append({"cat":"backend","name":headers["X-Powered-By"]})
    low = html.lower()
    sigs = {"react":"React","next.js":"Next.js","vue":"Vue","angular":"Angular",
            "jquery":"jQuery","bootstrap":"Bootstrap","tailwind":"Tailwind",
            "wordpress":"WordPress","shopify":"Shopify","cloudflare":"Cloudflare",
            "gtag":"GTM","ga(":"Google Analytics","sentry":"Sentry","stripe":"Stripe",
            "recaptcha":"reCAPTCHA","firebase":"Firebase","supabase":"Supabase",
            "vercel":"Vercel","netlify":"Netlify","github.io":"GitHub Pages"}
    for s,n in sigs.items():
        if s in low: tech.append({"cat":"framework","name":n})
    return tech

# ============================================
# TOOLS: ACTIVE RECON (aman)
# ============================================

def tool_ports(host, timeout=1):
    common = [21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017]
    exp = []
    def chk(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
            r = s.connect_ex((host,p)); s.close(); return p if r==0 else None
        except: return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(chk, common):
            if r: exp.append(r)
    return exp

def tool_dns(domain):
    out = {}
    for t in ["A","MX","NS","TXT"]:
        try:
            r = subprocess.run(["nslookup","-type="+t,domain],capture_output=True,text=True,timeout=5)
            if r.returncode==0: out[t]=r.stdout.split("\n")[:10]
        except: pass
    return out

def tool_whois(domain):
    try:
        r = subprocess.run(["whois",domain],capture_output=True,text=True,timeout=10)
        info = {}
        for line in r.stdout.split("\n"):
            if ":" in line:
                k,_,v = line.partition(":")
                k = k.strip().lower()
                if k in ["registrar","creation date","registry expiry date","name server"]:
                    info[k]=v.strip()
        return info if info else {"error":"empty"}
    except Exception as e: return {"error":str(e)}

def tool_robots(base):
    out = {}
    for p in ["robots.txt","sitemap.xml"]:
        h,s,_ = fetch(base+"/"+p, timeout=5)
        if h: out[p]={"status":s,"size":len(h),"preview":h[:500]}
    return out

def tool_ssl(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host,443),timeout=5) as s:
            with ctx.wrap_socket(s,server_hostname=host) as ss:
                c = ss.getpeercert()
                return {"issuer":dict(x[0] for x in c.get("issuer",[])),
                        "subject":dict(x[0] for x in c.get("subject",[])),
                        "expires":c.get("notAfter"),"version":ss.version()}
    except Exception as e: return {"error":str(e)}

def tool_secrets(html):
    pats = {"AWS":r"AKIA[0-9A-Z]{16}","Google API":r"AIza[0-9A-Za-z\-_]{35}",
            "GitHub":r"gh[pousr]_[A-Za-z0-9]{36}","Stripe":r"sk_live_[0-9a-zA-Z]{24}",
            "JWT":r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
            "PrivateKey":r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"}
    out = []
    for n,p in pats.items():
        for m in re.findall(p,html)[:3]:
            out.append({"type":n,"value":m[:50]+"..."})
    return out

def tool_redirect(html, base):
    red = []
    soup = BeautifulSoup(html,"html.parser")
    for a in soup.find_all("a",href=True):
        h = a["href"]
        if any(k in h.lower() for k in ["redirect","url=","next=","return=","continue=","dest="]):
            red.append(h)
    return red[:20]

# ============================================
# TOOLS: CONFIG CHECK
# ============================================

def tool_http_methods(base):
    import urllib.request
    methods = ["GET","POST","PUT","DELETE","OPTIONS","TRACE"]
    allowed = []
    for m in methods:
        try:
            req = urllib.request.Request(base, method=m, headers={"User-Agent":"Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                allowed.append({"method":m,"status":r.status,"allow":r.headers.get("Allow","")})
        except urllib.error.HTTPError as e:
            allowed.append({"method":m,"status":e.code,"allow":e.headers.get("Allow","")})
        except: pass
    return allowed

def tool_cors(base):
    try:
        req = urllib.request.Request(base, headers={"Origin":"https://evil.com","User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")
            return {"acao":acao,"acac":acac,"wildcard":"*" in acao,"creds":acac.lower()=="true"}
    except: return {"error":"cors fetch failed"}

def tool_cookies(headers):
    raw = headers.get("Set-Cookie","")
    return {"raw":raw[:300] if raw else "(none)","has_secure":"Secure" in raw,"has_httponly":"HttpOnly" in raw,"has_samesite":"SameSite" in raw}

def tool_exposed_files(base):
    files = ["/.env","/.git/config","/.DS_Store","/backup.zip","/backup.sql","/config.php.bak","/phpinfo.php","/server-status","/wp-config.php.bak","/actuator/env","/swagger-ui.html","/graphql"]
    found = []
    for f in files:
        h,s,_ = fetch(base+f, timeout=3)
        if h and s==200 and len(h)>0:
            found.append({"path":f,"status":s,"preview":h[:150]})
    return found

def tool_error_page(base):
    h,s,_ = fetch(base+"/this-page-does-not-exist-"+str(int(__import__("time").time())), timeout=5)
    if h:
        low = h.lower()
        stack = any(k in low for k in ["stack trace","exception","at java.","at kotlin.","traceback (most recent"])
        return {"status":s,"stack_trace":stack,"preview":h[:300]}
    return {"error":"no response"}

# ============================================
# ORCHESTRATOR — 20 TOOLS
# ============================================

def run_all_20(target, host, domain):
    out = {}
    html,status,headers = fetch(target)
    if html is None:
        return {"error":"fetch failed: "+headers.get("error","")}

    out["endpoints"] = tool_endpoints(html,target)
    out["parameters"] = tool_params(out["endpoints"])
    out["forms"] = tool_forms(html)
    out["security_headers"] = tool_headers(headers)
    out["technology"] = tool_tech(html,headers)
    out["subdomains"] = tool_subdomains(domain)
    out["ports"] = tool_ports(host)
    out["dns"] = tool_dns(domain)
    out["whois"] = tool_whois(domain)
    out["robots_sitemap"] = tool_robots(target)
    out["ssl"] = tool_ssl(host)
    out["secrets"] = tool_secrets(html)
    out["redirects"] = tool_redirect(html,target)
    out["http_methods"] = tool_http_methods(target)
    out["cors"] = tool_cors(target)
    out["cookies"] = tool_cookies(headers)
    out["exposed_files"] = tool_exposed_files(target)
    out["error_page"] = tool_error_page(target)
    out["wayback"] = tool_wayback(domain)
    out["js_endpoints"] = tool_js_endpoints(target, html)
    out["dir_fuzz"] = tool_dir_fuzz(target)
    out["openapi"] = tool_openapi(target)
    out["passive_vulns"] = tool_passive_vulns(html, headers, target)
    out["cf_bypass"] = tool_cf_bypass(domain)
    out["subdomain_takeover"] = tool_subdomain_takeover(out["subdomains"] if isinstance(out["subdomains"], list) else [])
    out["email_harvest"] = tool_email_harvest(html, target)
    out["comment_harvest"] = tool_comment_harvest(html)
    out["waf_detect"] = tool_waf_detect(headers, html)
    out["assets_parsed"] = TA.parse_all_assets(html, target)

    return out

# ============================================
# TOOL 21: WAYBACKURLS (historical endpoints)
# ============================================
def tool_wayback(domain):
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=200"
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8","ignore"))
        urls = [row[0] for row in data[1:] if len(row) > 0]
        return sorted(set(urls))[:150]
    except Exception as e:
        return {"error": str(e)}

# ============================================
# TOOL 22: JS ENDPOINT EXTRACTOR (from .js files)
# ============================================
def tool_js_endpoints(base, html):
    endpoints = set()
    # Cari file .js di HTML
    js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html)
    for js in js_urls[:5]:  # Max 5 file biar gak lama
        full = urllib.parse.urljoin(base, js)
        content, status, _ = fetch(full, timeout=10)
        if content:
            # Regex endpoint dari JS
            for m in re.findall(r'["\'](/api/[^"\']+)["\']', content):
                endpoints.add(base.rsplit("/",1)[0] + m)
            for m in re.findall(r'(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["\']([^"\']+)["\']', content):
                if m.startswith("http"): endpoints.add(m)
                elif m.startswith("/"): endpoints.add(base.rsplit("/",1)[0] + m)
            # Cari path di string literal
            for m in re.findall(r'["\'](/v[0-9]/[a-zA-Z0-9_\-/]+)["\']', content):
                endpoints.add(base.rsplit("/",1)[0] + m)
    return sorted(endpoints)[:100]

# ============================================
# TOOL 23: DIRECTORY FUZZING (mini wordlist)
# ============================================
def tool_dir_fuzz(base):
    paths = ["/admin","/login","/api","/api/v1","/api/v2","/.env","/.git/config","/.git/HEAD",
             "/backup.zip","/backup.sql","/config.json","/swagger.json","/openapi.json",
             "/graphql","/actuator","/actuator/env","/phpinfo.php","/server-status",
             "/wp-admin","/wp-login.php","/robots.txt","/sitemap.xml","/.well-known/security.txt",
             "/api/auth","/api/user","/api/admin","/api/tools","/api/stats","/health","/status"]
    found = []
    for p in paths:
        h, s, _ = fetch(base + p, timeout=3)
        if h and s in [200, 301, 302, 401, 403] and len(h) > 0:
            found.append({"path": p, "status": s, "size": len(h)})
    return found[:30]

# ============================================
# TOOL 24: OPENAPI/SWAGGER DISCOVERY
# ============================================
def tool_openapi(base):
    spec_paths = ["/swagger.json","/openapi.json","/api/swagger.json","/api/openapi.json",
                  "/v2/api-docs","/v3/api-docs","/docs","/swagger-ui.html"]
    for p in spec_paths:
        h, s, _ = fetch(base + p, timeout=5)
        if h and s == 200 and ("openapi" in h.lower() or "swagger" in h.lower()):
            try:
                spec = json.loads(h)
                return {"path": p, "title": spec.get("info",{}).get("title",""),
                        "version": spec.get("info",{}).get("version",""),
                        "paths": list(spec.get("paths",{}).keys())[:50]}
            except:
                return {"path": p, "raw_preview": h[:500]}
    return {"error": "no openapi/swagger found"}

# ============================================
# TOOL 25: PASSIVE VULN HINTS (header/body check)
# ============================================
def tool_passive_vulns(html, headers, base):
    vulns = []
    low = html.lower()
    # XSS hint: form input tanpa sanitasi pattern
    if "<form" in low and ("<input" in low) and "csrf" not in low:
        vulns.append({"type":"xss","severity":"High","evidence":"Form tanpa CSRF token, input user mungkin gak di-sanitize"})
    # SQL error leak
    sql_errors = ["sql syntax","mysql_","postgresql","ora-","sqlite_","odbc"]
    for e in sql_errors:
        if e in low:
            vulns.append({"type":"sqli","severity":"Critical","evidence":f"Error SQL '{e}' bocor di HTML"})
            break
    # Stack trace leak
    if "stack trace" in low or "traceback (most recent" in low or "at java." in low:
        vulns.append({"type":"info_disclosure","severity":"Medium","evidence":"Stack trace bocor di response"})
    # Exposed env in HTML
    if "db_password" in low or "api_key" in low or "secret_key" in low:
        vulns.append({"type":"js_secret","severity":"Critical","evidence":"Kata 'db_password'/'api_key'/'secret_key' muncul di HTML"})
    # X-Powered-By version
    pby = headers.get("X-Powered-By","")
    if pby and any(c.isdigit() for c in pby):
        vulns.append({"type":"backend_version","severity":"Low","evidence":f"X-Powered-By bocorin versi: {pby}"})
    # Server version
    srv = headers.get("Server","")
    if srv and any(c.isdigit() for c in srv):
        vulns.append({"type":"backend_version","severity":"Low","evidence":f"Server header bocorin versi: {srv}"})
    return vulns

# ============================================
# TOOL 26: CLOUDFLARE BYPASS CHECK
# ============================================
def tool_cf_bypass(domain):
    out = {"is_cloudflare": False, "origin_candidates": []}
    try:
        # Cek DNS record A
        r = subprocess.run(["nslookup","-type=A",domain],capture_output=True,text=True,timeout=5)
        ips = re.findall(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', r.stdout)
        # Cloudflare IP ranges (simplified)
        cf_ranges = ["104.","172.67.","172.64.","162.158.","188.114.","190.93.","197.234.","198.41."]
        cf_ips = [ip for ip in ips if any(ip.startswith(r) for r in cf_ranges)]
        out["is_cloudflare"] = len(cf_ips) > 0
        # Cari origin dari MX
        r2 = subprocess.run(["nslookup","-type=MX",domain],capture_output=True,text=True,timeout=5)
        mx = re.findall(r'mail exchanger\s*=\s*\S+\s+(\S+)', r2.stdout)
        out["mx_records"] = mx[:5]
    except Exception as e:
        out["error"] = str(e)
    return out

# ============================================
# TOOL 27: SUBDOMAIN TAKEOVER CHECK
# ============================================
def tool_subdomain_takeover(subdomains):
    if not isinstance(subdomains, list): return {"error":"subdomains invalid"}
    fingerprints = {
        "herokuapp.com": "Heroku (No such app)",
        "github.io": "GitHub Pages (There isn't a GitHub Pages site here)",
        "s3.amazonaws.com": "AWS S3 (NoSuchBucket)",
        "cloudfront.net": "CloudFront (Bad request)",
        "vercel.app": "Vercel (404: NOT_FOUND)",
        "netlify.app": "Netlify (Not Found)",
        "azurewebsites.net": "Azure (Error 404)",
        "fastly.net": "Fastly (Fastly error: unknown domain)",
    }
    vulnerable = []
    for sub in subdomains[:30]:
        for fp_svc, fp_label in fingerprints.items():
            if fp_svc in sub:
                try:
                    h, s, _ = fetch("http://" + sub, timeout=3)
                    if h and any(k in h.lower() for k in ["no such app","there isn't","nosuchbucket","not found","bad request","404"]):
                        vulnerable.append({"subdomain": sub, "service": fp_label, "severity": "High"})
                except: pass
    return {"checked": len(subdomains[:30]), "vulnerable": vulnerable}

# ============================================
# TOOL 28: EMAIL HARVESTING
# ============================================
def tool_email_harvest(html, base):
    emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html))
    # Cari di mailto
    for m in re.findall(r'mailto:([^"\'>\s]+)', html):
        emails.add(m)
    return {"count": len(emails), "list": sorted(emails)[:20]}

# ============================================
# TOOL 29: COMMENT HARVESTING
# ============================================
def tool_comment_harvest(html):
    comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    interesting = []
    for c in comments[:20]:
        c = c.strip()
        if len(c) > 5 and not c.startswith(("[","if","<")):
            interesting.append(c[:200])
    return {"count": len(interesting), "list": interesting[:15]}

# ============================================
# TOOL 30: WAF DETECTION
# ============================================
def tool_waf_detect(headers, html):
    h_low = {k.lower():v for k,v in headers.items()}
    srv = h_low.get("server","").lower()
    wafs = []
    if "cloudflare" in srv or "cf-ray" in h_low: wafs.append("Cloudflare")
    if "akamai" in srv or "akamai" in str(headers).lower(): wafs.append("Akamai")
    if "cloudfront" in str(headers).lower() or "x-amz-cf-id" in h_low: wafs.append("AWS CloudFront")
    if "sucuri" in str(headers).lower(): wafs.append("Sucuri")
    if "incapsula" in str(headers).lower() or "x-iinfo" in h_low: wafs.append("Imperva Incapsula")
    if "fastly" in str(headers).lower() or "x-served-by" in h_low: wafs.append("Fastly")
    if "x-sucuri-id" in h_low: wafs.append("Sucuri")
    return {"waf": wafs if wafs else ["(none detected)"], "confidence": "High" if wafs else "Low"}
