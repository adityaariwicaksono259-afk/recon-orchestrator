import re, json, socket, ssl, subprocess, urllib.parse, urllib.request
from bs4 import BeautifulSoup
import concurrent.futures

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

    return out
