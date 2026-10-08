import base64, hashlib, hmac, json, os, queue, secrets, socket, ssl, struct, threading, time, tkinter as tk
import certifi
from tkinter import ttk, messagebox
from urllib.parse import urlparse, quote
import urllib.parse

import httpx
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2 import utilities as h2_utilities
from h2 import stream as h2_stream
from h2.events import ResponseReceived, DataReceived, StreamEnded, StreamReset, RemoteSettingsChanged, ConnectionTerminated

FXA = "https://api.accounts.firefox.com/v1"
GUARDIAN = "https://vpn.mozilla.org"
CLIENT_ID = "5882386c6d801776"
SCOPE = "profile https://identity.mozilla.com/apps/vpn"
PROTOCOL = "identity.mozilla.com/picl/v1/"
REMOTE_SETTINGS_V2 = "https://firefox.settings.services.mozilla.com/v2/buckets/main/collections/vpn-serverlist/changeset?_expected=0"
REMOTE_SETTINGS_V1 = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"


def hkdf(ikm, info, length, salt=b"\0" * 32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, prev = b"", b""
    for i in range(1, (length + 31) // 32 + 1):
        prev = hmac.new(prk, prev + info.encode() + bytes([i]), hashlib.sha256).digest()
        out += prev
    return out[:length]


def pbkdf2(password, salt, iterations=1000, length=32):
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=length)


def auth_pw(email, password):
    quick = pbkdf2(password.encode(), (PROTOCOL + "quickStretch:" + email).encode())
    return hkdf(quick, PROTOCOL + "authPW", 32).hex()


def hawk_header(method, url, session_hex, body):
    token = bytes.fromhex(session_hex)
    expanded = hkdf(token, PROTOCOL + "sessionToken", 64)
    token_id, key = expanded[:32].hex(), expanded[32:]
    ts = str(int(time.time()))
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(6)).decode().rstrip("=")
    u = urlparse(url)
    path = u.path + (("?" + u.query) if u.query else "")
    payload_hash = ""
    if body:
        d = hashlib.sha256(b"hawk.1.payload\napplication/json\n" + body + b"\n").digest()
        payload_hash = base64.b64encode(d).decode()
    normalized = f"hawk.1.header\n{ts}\n{nonce}\n{method.upper()}\n{path}\n{u.hostname}\n{u.port or 443}\n{payload_hash}\n\n".encode()
    mac = base64.b64encode(hmac.new(key, normalized, hashlib.sha256).digest()).decode()
    s = f'Hawk id="{token_id}", ts="{ts}", nonce="{nonce}", mac="{mac}"'
    return s + (f', hash="{payload_hash}"' if payload_hash else "")


class TokenStore:
    def __init__(self):
        self.path = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "FoxyVPN", "auth.bin")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
    def _protect(self, data):
        if os.name != "nt": return data
        import ctypes
        class BLOB(ctypes.Structure):
            _fields_=[("cbData",ctypes.c_uint32),("pbData",ctypes.POINTER(ctypes.c_ubyte))]
        raw=ctypes.create_string_buffer(data); out=BLOB(); inp=BLOB(len(data), ctypes.cast(raw,ctypes.POINTER(ctypes.c_ubyte)))
        if ctypes.windll.crypt32.CryptProtectData(ctypes.byref(inp),None,None,None,None,0,ctypes.byref(out)):
            b=ctypes.string_at(out.pbData,out.cbData); ctypes.windll.kernel32.LocalFree(out.pbData); return b
        return data
    def _unprotect(self,data):
        if os.name != "nt": return data
        import ctypes
        class BLOB(ctypes.Structure):
            _fields_=[("cbData",ctypes.c_uint32),("pbData",ctypes.POINTER(ctypes.c_ubyte))]
        raw=ctypes.create_string_buffer(data); out=BLOB(); inp=BLOB(len(data), ctypes.cast(raw,ctypes.POINTER(ctypes.c_ubyte)))
        if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(inp),None,None,None,None,0,ctypes.byref(out)):
            b=ctypes.string_at(out.pbData,out.cbData); ctypes.windll.kernel32.LocalFree(out.pbData); return b
        return data
    def save(self, obj):
        open(self.path,"wb").write(self._protect(json.dumps(obj).encode()))
    def load(self):
        try: return json.loads(self._unprotect(open(self.path,"rb").read()))
        except Exception: return None
    def clear(self):
        try: os.remove(self.path)
        except OSError: pass


class FastlyChallengeSolver:
    def __init__(self, log): self.log=log
    def solve(self):
        import re
        for base in ("https://api.accounts.firefox.com", "https://accounts.firefox.com"):
            try:
                c=httpx.Client(http2=True, timeout=60, follow_redirects=True, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"})
                page=c.get(base+"/").text
                if "/_fs-ch-" not in page or "Client Challenge" not in page: continue
                m=re.search(r'/_fs-ch-[A-Za-z0-9]+', page)
                if not m: continue
                prefix=base+m.group(0)
                script=c.get(prefix+"/script.js?reload=true").text
                matches=list(re.finditer(r'init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"',script))
                if not matches: continue
                mm=matches[-1]; challenges=json.loads(mm.group(1)); token=mm.group(2)
                for _ in range(3):
                    answers=[]
                    for ch in challenges:
                        typ=ch.get('ty'); data=ch.get('data') or {}
                        if typ=='pow':
                            target=bytes.fromhex(data.get('hash','')); basev=data.get('base','')
                            ans=None
                            alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
                            for a in alphabet:
                                for b in alphabet:
                                    x=a+b
                                    if hashlib.sha256((basev+x).encode()).digest()==target: ans=x; break
                                if ans: break
                            if ans is None: raise RuntimeError('Fastly proof-of-work solution not found')
                            answers.append({'ty':'pow','base':basev,'answer':ans,'hmac':data.get('hmac',''),'expires':data.get('expires','')})
                        elif typ=='clientmetrics':
                            answers.append({'ty':'clientmetrics','webdriver':False,'bot_detection_result':{'bot_detected':False,'bot_kind':None},'browser_metrics':{'client_data':'{}','error_trace':None},'detector_results':{},'v':2})
                        elif typ=='pat':
                            rr=c.post(prefix+'/pat?token='+quote(token,safe=''),headers={'Accept':'text/plain','Content-Type':'application/json','Origin':base})
                            auth=rr.json().get('auth','') if rr.status_code<400 else ''
                            answers.append({'ty':'pat','auth':auth})
                        else: raise RuntimeError("Unsupported Fastly challenge type: "+str(typ))
                    rr=c.post(prefix+'/fst-post-back',json={'token':token,'data':answers},headers={'Accept':'application/json','Origin':base})
                    body=rr.json()
                    if body.get('status')=='success':
                        self.log('Firefox Accounts security challenge solved.')
                        return c.cookies
                    challenges=body.get('ch') or []; token=body.get('tok','')
                    if not challenges or not token: break
            except Exception as e:
                self.log('Fastly challenge attempt failed: '+str(e))
        raise RuntimeError('Firefox Accounts returned HTTP 406 and the security challenge could not be completed')

class MozillaAuth:
    def __init__(self, log):
        self.store, self.log, self.pending=TokenStore(),log,None
        self._login_email=None
        self._login_password=None
        self.client=httpx.Client(http2=True,timeout=30,headers={"User-Agent":"MozillaVPN/2.35.0 (Windows; iap:true)","Accept":"application/json"})
    def saved_credentials(self):
        d=self.store.load() or {}
        email=d.get("email")
        password=d.get("password")
        if email and password:
            return email, password
        return None, None

    def _save_credentials(self, email, password):
        d=self.store.load() or {}
        d["email"] = email
        d["password"] = password
        self.store.save(d)

    def _post(self,path,body,session=None):
        url=FXA+path; raw=json.dumps(body,separators=(',',':')).encode(); headers={'Content-Type':'application/json','Content-Length':str(len(raw))}
        if session: headers['Authorization']=hawk_header('POST',url,session,raw)
        r=self.client.post(url,content=raw,headers=headers)
        if r.status_code==406:
            cookies=FastlyChallengeSolver(self.log).solve()
            for k,v in cookies.items(): self.client.cookies.set(k,v,domain='.firefox.com')
            r=self.client.post(url,content=raw,headers=headers)
        if r.status_code>=400:
            try: msg=r.json().get('message',r.text[:300])
            except Exception: msg=r.text[:300]
            raise RuntimeError(f'Firefox Accounts HTTP {r.status_code}: {msg}')
        return r.json() if r.text else {}
    def login(self,email,password):
        self._login_email=email
        self._login_password=password
        body={'email':email,'authPW':auth_pw(email,password),'verificationMethod':'email-2fa'}
        try: d=self._post('/account/login',body)
        except RuntimeError as e:
            if 'HTTP 400' in str(e) or 'HTTP 406' in str(e):
                body.pop('verificationMethod',None); d=self._post('/account/login',body)
            else: raise
        self.pending=d.get('sessionToken')
        if not self.pending: raise RuntimeError('Firefox Account did not return a session token')
        if d.get('verified',False): self._complete()
        else: return '2FA'
        return 'OK'
    def verify(self,code):
        if not self.pending: raise RuntimeError('No pending Firefox Account session')
        self._post('/session/verify_code',{'code':code},self.pending); self._complete(); return 'OK'
    def _complete(self):
        d=self._post('/oauth/token',{'client_id':CLIENT_ID,'grant_type':'fxa-credentials','scope':SCOPE,'access_type':'offline'},self.pending)
        old=self.store.load() or {}
        payload={'access':d['access_token'],'refresh':d.get('refresh_token'),'exp':int(time.time())+int(d.get('expires_in',86400))}
        if self._login_email and self._login_password:
            payload['email']=self._login_email
            payload['password']=self._login_password
        else:
            for k in ('email','password'):
                if old.get(k): payload[k]=old[k]
        self.store.save(payload); self.pending=None
        self._login_email=None
        self._login_password=None
    def access_token(self):
        d=self.store.load()
        if not d:return None
        if d.get('exp',0)>time.time()+60:return d.get('access')
        if not d.get('refresh'):return None
        r=self.client.post(FXA+'/oauth/token',json={'client_id':CLIENT_ID,'grant_type':'refresh_token','refresh_token':d['refresh'],'scope':SCOPE})
        if r.status_code>=400:return None
        x=r.json(); old=d; d={'access':x['access_token'],'refresh':x.get('refresh_token',old['refresh']),'exp':int(time.time())+int(x.get('expires_in',86400))};
        for k in ('email','password'):
            if old.get(k): d[k]=old[k]
        self.store.save(d); return d['access']
    def invalidate_access(self):
        d=self.store.load()
        if d:
            d['exp']=0
            self.store.save(d)


class MozillaAPI:
    def __init__(self, auth, log):
        self.auth,self.log=auth,log
        self.client=httpx.Client(http2=True,timeout=30,headers={"User-Agent":"MozillaVPN/2.35.0 (sys:windows; iap:true)","Accept":"application/json"})
        self._proxy_lock=threading.Lock()
        self._proxy_token=None
        self._proxy_token_time=0.0
    def _get(self,url):
        r=self.client.get(url); r.raise_for_status(); return r
    def _guardian_get(self, path, tok):
        return self.client.get(GUARDIAN+path, headers={
            "Authorization":"Bearer "+tok,
            "User-Agent":"MozillaVPN/2.35.0 (sys:windows; iap:true)",
            "Accept":"application/json",
        })

    def _request_proxy_pass(self, tok):
        r=self._guardian_get("/api/v1/fpn/token",tok)
        if r.status_code==406:
            try:
                cookies=FastlyChallengeSolver(self.log).solve()
                for k,v in cookies.items(): self.client.cookies.set(k,v,domain='.mozilla.org')
                r=self._guardian_get("/api/v1/fpn/token",tok)
            except Exception as e:
                self.log("Guardian security challenge failed: "+str(e))
        return r

    def proxy_pass(self, force_refresh=False):
        # Proxy Pass has a shorter lifetime than the Firefox Account access
        # token. Cache it briefly, but always support an explicit refresh after
        # Fastly reports expired_token on a CONNECT attempt.
        with self._proxy_lock:
            if (not force_refresh and self._proxy_token and
                    time.time() - self._proxy_token_time < 300):
                return self._proxy_token

            tok=self.auth.access_token()
            if not tok: raise RuntimeError("Not signed in")
            r=self._request_proxy_pass(tok)

            # A stale OAuth access token can also produce 401 here. Force the
            # OAuth layer to refresh it, then request a new Proxy Pass.
            if r.status_code == 401:
                self.auth.invalidate_access()
                tok=self.auth.access_token()
                if not tok: raise RuntimeError("Firefox Account access token expired and could not be refreshed")
                self.log("Firefox Account access token refreshed; requesting a new Proxy Pass.")
                r=self._request_proxy_pass(tok)

            if r.status_code in (401,403):
                # The Android client treats a rejected proxy pass as an inactive
                # Guardian entitlement: activate once, then retry with the
                # current OAuth access token.
                a=self.client.post(GUARDIAN+"/api/v1/fpn/activate",headers={
                    "Authorization":"Bearer "+tok,
                    "User-Agent":"MozillaVPN/2.35.0 (sys:windows; iap:true)",
                    "Accept":"application/json",
                    "Content-Type":"application/json",
                },content=b"")
                if a.status_code==406:
                    cookies=FastlyChallengeSolver(self.log).solve()
                    for k,v in cookies.items(): self.client.cookies.set(k,v,domain='.mozilla.org')
                    a=self.client.post(GUARDIAN+"/api/v1/fpn/activate",headers={
                        "Authorization":"Bearer "+tok,
                        "User-Agent":"MozillaVPN/2.35.0 (sys:windows; iap:true)",
                        "Accept":"application/json","Content-Type":"application/json"
                    },content=b"")
                if a.status_code not in (200,204):
                    detail=a.text[:300]
                    raise RuntimeError(f"Mozilla Guardian activation failed: HTTP {a.status_code}: {detail}")
                self.log("Mozilla Guardian entitlement activated; requesting a fresh Proxy Pass.")
                r=self._request_proxy_pass(tok)
            if r.status_code==429: raise RuntimeError("Mozilla VPN proxy quota exceeded")
            if r.status_code in (401,403):
                try: detail=r.json()
                except Exception: detail=r.text[:300]
                raise RuntimeError(f"Mozilla Proxy Pass request rejected: HTTP {r.status_code}: {detail}")
            r.raise_for_status()
            token=r.json().get("token")
            if not token: raise RuntimeError("Mozilla Proxy Pass response did not contain a token")
            self._proxy_token=token
            self._proxy_token_time=time.time()
            return token
    def servers(self):
        headers={"Accept-Encoding":"gzip","User-Agent":"FoxyVPN/1.0.4 Windows","Accept":"application/json"}
        payload=None
        errors=[]
        # v2 is the current Remote Settings API. Its changeset endpoint requires
        # _expected=; 0 is valid when we have no local timestamp/cache yet.
        for url in (REMOTE_SETTINGS_V2, REMOTE_SETTINGS_V1):
            try:
                r=self.client.get(url,headers=headers)
                if r.status_code >= 400:
                    errors.append(f"{url}: HTTP {r.status_code}")
                    continue
                payload=r.json()
                self.log(f"Remote Settings loaded: HTTP {r.status_code} from {'v2' if '/v2/' in url else 'v1'}")
                break
            except Exception as e:
                errors.append(f"{url}: {e}")
        if payload is None:
            raise RuntimeError("Unable to load Mozilla VPN server list; " + " | ".join(errors))

        if not isinstance(payload,dict):
            raise RuntimeError("Mozilla VPN server list returned an unexpected JSON shape")

        # v2: {changes:[records...], metadata:{...}, timestamp:...}
        # v1: {data:[records...], ...}
        records=payload.get("changes")
        if records is None:
            records=payload.get("data",[])
        if isinstance(records,dict):
            records=[records]

        def unwrap(item):
            if not isinstance(item,dict):
                return []
            if item.get("deleted") is True:
                return []
            for key in ("record","new","value","data"):
                val=item.get(key)
                if isinstance(val,dict):
                    return [val]
            return [item]

        candidates=[]
        for item in records or []:
            candidates.extend(unwrap(item))

        out=[]
        def add_country(c):
            if not isinstance(c,dict): return
            # Some RS wrappers put the actual country under `country`.
            if isinstance(c.get("country"),dict):
                c=c["country"]
            name=str(c.get("name") or c.get("country_name") or "").strip()
            code=str(c.get("code") or c.get("country_code") or "").strip()
            if not code or name.lower()=="catchall anycast": return
            cities=c.get("cities") or []
            for city in cities:
                if not isinstance(city,dict): continue
                city_name=str(city.get("name") or city.get("city") or "").strip()
                for srv in city.get("servers") or []:
                    if not isinstance(srv,dict) or srv.get("quarantined"): continue
                    location=f"{name} / {city_name}"
                    added=False
                    protocols=srv.get("protocols") or []
                    # Current vpn-serverlist records may expose hostname/port directly
                    # and omit the protocols array. Firefox's own server-list tests
                    # use exactly that shape, so direct server endpoints are valid.
                    for proto in protocols:
                        if not isinstance(proto,dict): continue
                        if proto.get("name") not in ("connect","wireguard","masque"): continue
                        host=proto.get("host") or srv.get("hostname")
                        port=proto.get("port") or srv.get("port") or 443
                        if host:
                            try: port=int(port)
                            except Exception: port=443
                            out.append((location,str(host),port))
                            added=True
                            break
                    if not added:
                        host=srv.get("hostname") or srv.get("host")
                        port=srv.get("port") or 443
                        if host:
                            try: port=int(port)
                            except Exception: port=443
                            out.append((location,str(host),port))

        # Usually each candidate is a country record. Keep a recursive fallback
        # so future harmless RS envelope changes do not turn the list into zero.
        def walk(obj):
            if isinstance(obj,dict):
                if obj.get("cities") is not None:
                    add_country(obj)
                else:
                    for v in obj.values():
                        if isinstance(v,(dict,list)): walk(v)
            elif isinstance(obj,list):
                for v in obj: walk(v)

        walk(candidates)
        result=list(dict.fromkeys(out))
        if not result:
            keys=", ".join(sorted(payload.keys()))
            raise RuntimeError(f"Mozilla returned 0 usable VPN servers (response keys: {keys}; records: {len(records or [])})")
        self.log(f"Parsed {len(result)} usable Mozilla VPN server endpoints")
        return result


class H2Tunnel:
    """HTTP/2 CONNECT tunnel. Local TCP bytes are carried in H2 DATA frames."""
    def __init__(self, host, port, bearer, log, bearer_provider=None):
        self.host,self.port,self.bearer,self.log=host,port,bearer,log
        self.bearer_provider=bearer_provider
        self.sock=None; self.h2=None; self.stream=1; self._send_lock=threading.Lock()

    def _send_pending(self):
        data=self.h2.data_to_send()
        if data:
            with self._send_lock:
                self.sock.sendall(data)

    def _install_connect_validation(self):
        # Current hyper-h2 enforces :path + :scheme on every request, while
        # the Android Netty client in the original FoxyVPN project emits the
        # RFC authority-form CONNECT without either pseudo-header.  Relax only
        # that specific validation rule.
        if getattr(h2_utilities, "_foxyvpn_connect_patch", False):
            return
        original = h2_utilities._check_pseudo_header_field_acceptability
        def patched(pseudo_headers, method, flags):
            if (not flags.is_response_header and not flags.is_trailer and
                method == b"CONNECT" and b":method" in pseudo_headers and
                b":authority" in pseudo_headers and
                b":path" not in pseudo_headers and b":scheme" not in pseudo_headers):
                invalid = pseudo_headers & h2_utilities._RESPONSE_ONLY_HEADERS
                if invalid:
                    from h2.exceptions import ProtocolError
                    raise ProtocolError(f"Encountered response-only headers {invalid}")
                return
            return original(pseudo_headers, method, flags)
        h2_utilities._check_pseudo_header_field_acceptability = patched
        h2_utilities._foxyvpn_connect_patch = True

    def _wait_settings(self):
        while True:
            data=self.sock.recv(65535)
            if not data: raise RuntimeError("Mozilla HTTP/2 edge closed during preface")
            events=self.h2.receive_data(data)
            self._send_pending()
            for e in events:
                if isinstance(e, RemoteSettingsChanged):
                    return
                if isinstance(e, ConnectionTerminated):
                    raise RuntimeError(f"Mozilla HTTP/2 connection terminated during preface: {e.error_code}")

    def open(self,target):
        self._install_connect_validation()
        raw=socket.create_connection((self.host,self.port),timeout=20)
        ctx=ssl.create_default_context(cafile=certifi.where())
        # Advertise HTTP/2 during TLS ALPN negotiation. Without this, Python's SSL layer sends no h2 protocol offer and Mozilla correctly returns ALPN=None.
        ctx.set_alpn_protocols(["h2"])
        self.sock=ctx.wrap_socket(raw,server_hostname=self.host)
        self.sock.settimeout(20)
        alpn=self.sock.selected_alpn_protocol()
        if alpn != 'h2':
            raise RuntimeError(f"Mozilla edge did not negotiate HTTP/2 (ALPN={alpn!r})")
        self.h2=H2Connection(H2Configuration(client_side=True,header_encoding="utf-8"))
        self.h2.initiate_connection(); self._send_pending()
        self._wait_settings()

        authority=f"{target[0]}:{target[1]}"
        # Match the Android implementation exactly: CONNECT + authority +
        # proxy-authorization.  Do not add :path/:scheme unless a future
        # Mozilla edge explicitly requires them.
        headers=[
            (":method","CONNECT"),
            (":authority",authority),
            ("proxy-authorization","Bearer "+self.bearer),
        ]
        self.log(f"Mozilla H2 CONNECT {authority} via {self.host}:{self.port} (Android-compatible headers)")
        self.h2.send_headers(self.stream,headers,end_stream=False)
        self._send_pending()
        while True:
            data=self.sock.recv(65535)
            if not data: raise RuntimeError("Mozilla HTTP/2 edge closed during CONNECT")
            events=self.h2.receive_data(data)
            self._send_pending()
            for e in events:
                if isinstance(e,ResponseReceived):
                    status=dict(e.headers).get(":status")
                    if status != "200":
                        details=dict(e.headers)
                        if (str(status) == "401" and self.bearer_provider and
                                str(details.get("x-fastly-proxy-auth-failed", "")).lower() == "expired_token"):
                            self.log("Mozilla Proxy Pass expired; refreshing token and retrying CONNECT once.")
                            self.bearer=self.bearer_provider()
                            self.close()
                            # Re-open the same target with a fresh Proxy Pass.
                            return self.open(target)
                        raise RuntimeError(f"Mozilla proxy rejected CONNECT: HTTP {status} headers={details}")
                    self.sock.settimeout(None)
                    self.log(f"Mozilla H2 CONNECT established: {authority}")
                    return
                if isinstance(e,StreamReset):
                    raise RuntimeError(f"Mozilla proxy reset CONNECT stream: {e.error_code} ({getattr(e.error_code,'name', '')})")
                if isinstance(e,ConnectionTerminated):
                    raise RuntimeError(f"Mozilla HTTP/2 connection terminated during CONNECT: {e.error_code}")

    def pump_local_to_h2(self, local):
        try:
            while True:
                data=local.recv(65535)
                if not data: break
                off=0
                while off < len(data):
                    window=self.h2.local_flow_control_window(self.stream)
                    if window <= 0:
                        self._wait_for_window()
                        continue
                    chunk=data[off:off+min(window,16384)]
                    self.h2.send_data(self.stream,chunk,end_stream=False)
                    off += len(chunk)
                    self._send_pending()
        except Exception:
            pass
        try:
            self.h2.end_stream(self.stream); self._send_pending()
        except Exception: pass

    def _wait_for_window(self):
        data=self.sock.recv(65535)
        if not data: raise RuntimeError("Mozilla HTTP/2 edge closed while waiting for flow control")
        events=self.h2.receive_data(data)
        self._send_pending()
        for e in events:
            if isinstance(e,StreamReset):
                raise RuntimeError(f"Mozilla proxy reset stream: {e.error_code} ({getattr(e.error_code,'name', '')})")
            if isinstance(e,ConnectionTerminated):
                raise RuntimeError(f"Mozilla HTTP/2 connection terminated: {e.error_code}")

    def pump_h2_to_local(self, local):
        try:
            while True:
                data=self.sock.recv(65535)
                if not data: break
                events=self.h2.receive_data(data)
                self._send_pending()
                for e in events:
                    if isinstance(e,DataReceived) and e.stream_id == self.stream:
                        local.sendall(e.data)
                        self.h2.acknowledge_received_data(len(e.data),self.stream)
                        self._send_pending()
                    elif isinstance(e,StreamEnded) and e.stream_id == self.stream:
                        return
                    elif isinstance(e,StreamReset) and e.stream_id == self.stream:
                        return
                    elif isinstance(e,ConnectionTerminated):
                        return
        except Exception:
            pass

    def close(self):
        try:
            if self.h2:
                self.h2.close_connection(); self._send_pending()
        except Exception: pass
        try: self.sock.close()
        except Exception: pass


class SocksServer:
    def __init__(self, app, host="127.0.0.1", port=1080):
        self.app,self.host,self.port=app,host,port
        self.stop=threading.Event()
        self.sock=None
        self.thread=None
        self.tunnels=set()
        self.tunnels_lock=threading.Lock()

    def start(self):
        self.stop.clear()
        self.sock=socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.bind((self.host,self.port))
        self.sock.listen(64)
        self.thread=threading.Thread(target=self.run,daemon=True)
        self.thread.start()

    def add_tunnel(self, tunnel):
        with self.tunnels_lock:
            if self.stop.is_set():
                try: tunnel.close()
                except Exception: pass
                return False
            self.tunnels.add(tunnel)
            return True

    def remove_tunnel(self, tunnel):
        with self.tunnels_lock:
            self.tunnels.discard(tunnel)

    def close_active_tunnels(self):
        with self.tunnels_lock:
            active=list(self.tunnels)
            self.tunnels.clear()
        if active:
            self.app.log(f"Closing {len(active)} active Mozilla tunnel(s) for server switch")
        for tunnel in active:
            try: tunnel.close()
            except Exception: pass
    def run(self):
        self.app.log(f"SOCKS5 listening on {self.host}:{self.port}")
        while not self.stop.is_set():
            try: c,_=self.sock.accept(); threading.Thread(target=self.client,args=(c,),daemon=True).start()
            except OSError: break
    def client(self,c):
        tunnel=None
        edge=self.app.edge
        bearer=self.app.proxy_pass
        try:
            if not edge or not bearer:
                raise RuntimeError("Proxy is not ready; select a server and start SOCKS5 again")
            c.settimeout(20)
            # Detect protocol from the first byte. 0x05 is SOCKS5; an ASCII
            # letter indicates an HTTP proxy request (CONNECT/GET/etc.).
            first=c.recv(1)
            if not first:
                raise RuntimeError("Client closed connection")
            if first == b"\x05":
                def recv_exact(n):
                    buf=b""
                    while len(buf)<n:
                        part=c.recv(n-len(buf))
                        if not part: raise RuntimeError("SOCKS5 client closed connection")
                        buf += part
                    return buf
                n=recv_exact(1)[0]
                methods=recv_exact(n)
                c.sendall(b"\x05\x00")
                h=recv_exact(4); atyp=h[3]
                if atyp==1:
                    host=socket.inet_ntoa(recv_exact(4))
                elif atyp==3:
                    ln=recv_exact(1)[0]
                    if ln == 0: raise RuntimeError("SOCKS5 domain name is empty")
                    host=recv_exact(ln).decode("idna")
                elif atyp==4:
                    host=socket.inet_ntop(socket.AF_INET6,recv_exact(16))
                else:
                    raise RuntimeError(f"Unsupported SOCKS5 address type: 0x{atyp:02x}")
                port=struct.unpack("!H",recv_exact(2))[0]
                tunnel=H2Tunnel(edge[1],edge[2],bearer,self.app.log, self.app.refresh_proxy_pass)
                if not self.add_tunnel(tunnel): return
                tunnel.open((host,port))
                c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                self.app.log(f"SOCKS5 connected {host}:{port}")
                self.relay_h2(c,tunnel)
            else:
                # Also accept HTTP proxy CONNECT on the same port. This avoids
                # the confusing "Unsupported SOCKS version: 80/80..." error
                # when a browser is configured as an HTTP proxy.
                data=first
                while b"\r\n\r\n" not in data and len(data)<8192:
                    part=c.recv(4096)
                    if not part: break
                    data += part
                line=data.split(b"\r\n",1)[0].decode("latin-1","replace")
                parts=line.split()
                if len(parts) < 2:
                    raise RuntimeError(f"Invalid HTTP proxy request: {line[:120]}")
                method, target = parts[0].upper(), parts[1]
                if method == "CONNECT":
                    if ":" not in target: raise RuntimeError("HTTP CONNECT target must be host:port")
                    host,port_s=target.rsplit(":",1); port=int(port_s)
                    tunnel=H2Tunnel(edge[1],edge[2],bearer,self.app.log, self.app.refresh_proxy_pass)
                    if not self.add_tunnel(tunnel): return
                    tunnel.open((host,port))
                    c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    self.app.log(f"HTTP CONNECT connected {host}:{port}")
                    self.relay_h2(c,tunnel)
                elif target.lower().startswith(("http://","https://")):
                    # Forward ordinary HTTP proxy requests (absolute-form), e.g.
                    # POST http://149.154.175.100:80/api HTTP/1.1.  The Mozilla
                    # tunnel is opened to the origin and the request-target is
                    # rewritten to origin-form before forwarding.
                    u=urllib.parse.urlsplit(target)
                    if not u.hostname: raise RuntimeError("HTTP proxy URL has no host")
                    port=u.port or (443 if u.scheme.lower()=="https" else 80)
                    if u.scheme.lower()=="https":
                        # An HTTPS absolute-form request should normally arrive
                        # as CONNECT; reject rather than sending TLS bytes to an
                        # HTTP origin.
                        raise RuntimeError("HTTPS proxy requests must use CONNECT")
                    tunnel=H2Tunnel(edge[1],edge[2],bearer,self.app.log, self.app.refresh_proxy_pass)
                    if not self.add_tunnel(tunnel): return
                    tunnel.open((u.hostname,port))
                    head,sep,body=data.partition(b"\r\n\r\n")
                    lines=head.split(b"\r\n")
                    if not lines: raise RuntimeError("Empty HTTP proxy request")
                    path=(u.path or "/") + (("?" + u.query) if u.query else "")
                    lines[0]=parts[0].encode("latin-1") + b" " + path.encode("utf-8") + b" " + (parts[2].encode("latin-1") if len(parts)>2 else b"HTTP/1.1")
                    # Strip proxy-only headers and normalize Host for the origin.
                    clean=[lines[0]]
                    saw_host=False
                    for rawline in lines[1:]:
                        if not rawline or b":" not in rawline: continue
                        name=rawline.split(b":",1)[0].strip().lower()
                        if name in {b"proxy-connection", b"proxy-authorization", b"connection", b"keep-alive", b"te", b"trailer", b"upgrade"}:
                            continue
                        if name == b"host":
                            clean.append(b"Host: "+u.hostname.encode("idna")+(b":"+str(port).encode() if (u.port is not None) else b""))
                            saw_host=True
                        else:
                            clean.append(rawline)
                    if not saw_host:
                        clean.append(b"Host: "+u.hostname.encode("idna")+(b":"+str(port).encode() if (u.port is not None) else b""))
                    forwarded=b"\r\n".join(clean)+b"\r\n\r\n"+body
                    # Send the already-read request bytes through H2, then keep
                    # the socket open for any remaining request body.
                    tunnel.h2.send_data(tunnel.stream, forwarded, end_stream=False)
                    tunnel._send_pending()
                    self.app.log(f"HTTP proxied {method} {u.hostname}:{port}{path}")
                    self.relay_h2_after_prefix(c,tunnel)
                else:
                    raise RuntimeError(f"Unsupported HTTP proxy target: {target[:80]}")
        except Exception as e:
            self.app.log("Proxy error: "+str(e))
            try:
                if first == b"\x05": c.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                else: c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except Exception: pass
        finally:
            if tunnel:
                try: tunnel.close()
                except Exception: pass
                self.remove_tunnel(tunnel)
            try:c.close()
            except:pass
    def relay_h2_after_prefix(self, local, tunnel):
        # Continue forwarding request-body bytes and receive response DATA.
        done=threading.Event()
        def up():
            try: tunnel.pump_local_to_h2(local)
            finally: done.set()
        def down():
            try: tunnel.pump_h2_to_local(local)
            finally: done.set()
        threading.Thread(target=up,daemon=True).start()
        threading.Thread(target=down,daemon=True).start()
        done.wait()

    def relay_h2(self, local, tunnel):
        done=threading.Event()
        def up():
            try: tunnel.pump_local_to_h2(local)
            finally: done.set()
        def down():
            try: tunnel.pump_h2_to_local(local)
            finally: done.set()
        threading.Thread(target=up,daemon=True).start()
        threading.Thread(target=down,daemon=True).start()
        done.wait()

    def relay(self,a,b):
        a.settimeout(None); b.settimeout(None); done=threading.Event()
        def cp(x,y):
            try:
                while not done.is_set():
                    d=x.recv(65535)
                    if not d: break
                    y.sendall(d)
            except Exception: pass
            done.set()
        t1=threading.Thread(target=cp,args=(a,b),daemon=True); t2=threading.Thread(target=cp,args=(b,a),daemon=True); t1.start(); t2.start(); done.wait()
    def close(self): self.stop.set();
    def shutdown(self):
        self.stop.set()
        self.close_active_tunnels()
        try:
            self.sock.close()
        except Exception: pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.5)
        self.thread=None


class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title("FoxyVPN — Mozilla Proxy"); self.geometry("760x600"); self.auth=MozillaAuth(self.log); self.api=MozillaAPI(self.auth,self.log); self.edge=None; self.proxy_pass=None; self.socks=None; self.q=queue.Queue(); self.dark=True; self.server_data=[]; self.build(); self._load_saved_credentials(); self.after(100,self.drain)
    def log(self,msg): self.q.put(time.strftime("%H:%M:%S ")+msg)
    def drain(self):
        while not self.q.empty(): self.logs.insert("end",self.q.get()); self.logs.see("end")
        self.after(100,self.drain)
    def _load_saved_credentials(self):
        email, password = self.auth.saved_credentials()
        if email and password:
            self.email.insert(0, email)
            self.password.insert(0, password)
            self.log("Saved Firefox Account credentials loaded.")

    def build(self):
        self.columnconfigure(0,weight=1); self.rowconfigure(3,weight=1); top=ttk.Frame(self,padding=15); top.grid(sticky="ew"); top.columnconfigure(1,weight=1)
        ttk.Label(top,text="FoxyVPN",font=("Segoe UI",22,"bold")).grid(row=0,column=0,sticky="w"); ttk.Label(top,text="Mozilla Account → HTTP/2 Proxy → Local SOCKS5").grid(row=1,column=0,columnspan=2,sticky="w")
        auth=ttk.LabelFrame(self,text="Firefox Account",padding=12); auth.grid(padx=15,pady=8,sticky="ew"); auth.columnconfigure(1,weight=1)
        ttk.Label(auth,text="Email").grid(row=0,column=0); self.email=ttk.Entry(auth); self.email.grid(row=0,column=1,sticky="ew",padx=6); ttk.Label(auth,text="Password").grid(row=1,column=0); self.password=ttk.Entry(auth,show="•"); self.password.grid(row=1,column=1,sticky="ew",padx=6); ttk.Button(auth,text="Sign in",command=self.login).grid(row=0,column=2,rowspan=2,padx=6)
        self.code=ttk.Entry(auth); ttk.Label(auth,text="2FA code").grid(row=2,column=0); self.code.grid(row=2,column=1,sticky="ew",padx=6); ttk.Button(auth,text="Verify",command=self.verify).grid(row=2,column=2)
        box=ttk.LabelFrame(self,text="Server",padding=12); box.grid(padx=15,pady=8,sticky="ew"); box.columnconfigure(0,weight=1); self.servers=ttk.Combobox(box,state="readonly"); self.servers.grid(row=0,column=0,sticky="ew"); self.servers.bind("<<ComboboxSelected>>", self.server_selected); ttk.Button(box,text="Refresh",command=self.refresh_servers).grid(row=0,column=1,padx=6); ttk.Button(box,text="Apply Server",command=self.apply_server).grid(row=0,column=2,padx=6); ttk.Button(box,text="Start SOCKS5",command=self.start).grid(row=0,column=3)
        logs=ttk.LabelFrame(self,text="Logs",padding=8); logs.grid(row=3,padx=15,pady=8,sticky="nsew"); logs.rowconfigure(0,weight=1); logs.columnconfigure(0,weight=1); self.logs=tk.Listbox(logs); self.logs.grid(sticky="nsew"); ttk.Button(self,text="Stop",command=self.stop).grid(pady=(0,12));
    def login(self):
        def work():
            try:
                r=self.auth.login(self.email.get().strip(),self.password.get()); self.log("Firefox Account sign-in started" + (" — enter 2FA code" if r=="2FA" else " — authenticated"))
            except Exception as e:self.log("Login failed: "+str(e))
        threading.Thread(target=work,daemon=True).start()
    def verify(self):
        threading.Thread(target=lambda:self._try(lambda:self.auth.verify(self.code.get().strip()),"2FA verified"),daemon=True).start()
    def refresh_servers(self):
        threading.Thread(target=self._servers,daemon=True).start()
    def _servers(self):
        try:
            s=self.api.servers(); self.server_data=s; self.after(0,lambda:self.servers.configure(values=[x[0] for x in s])); self.log(f"Loaded {len(s)} Mozilla VPN servers")
            saved=self.auth.store.load() or {}; selected=saved.get("server")
            if selected:
                for i,x in enumerate(s):
                    if x[0] == selected:
                        self.after(0,lambda i=i:self.servers.current(i)); break
        except Exception as e:self.log("Server list failed: "+str(e))
    def refresh_proxy_pass(self):
        self.proxy_pass=self.api.proxy_pass(force_refresh=True)
        self.log("Fresh Mozilla Proxy Pass acquired (token redacted).")
        return self.proxy_pass

    def _selected_edge(self):
        idx=self.servers.current()
        if idx < 0 or idx >= len(self.server_data):
            return None
        return self.server_data[idx]

    def server_selected(self, _event=None):
        edge=self._selected_edge()
        if not edge: return
        self.log(f"Server selected: {edge[0]}")
        # Persist the selection so it remains after restarting the app.
        d=self.auth.store.load() or {}
        d["server"]=edge[0]
        self.auth.store.save(d)
        if self.socks:
            self.apply_server()

    def apply_server(self):
        edge=self._selected_edge()
        if not edge:
            self.log("Select a server first")
            return
        was_running = self.socks is not None
        old_edge = self.edge
        if was_running:
            self.log(f"Switching server: {old_edge[0] if old_edge else 'unknown'} -> {edge[0]}")
            self.stop()
        self.edge=edge
        d=self.auth.store.load() or {}
        d["server"]=edge[0]
        self.auth.store.save(d)
        self.log(f"Applied server: {edge[0]} ({edge[1]}:{edge[2]})")
        if was_running:
            self.start()

    def start(self):
        edge=self._selected_edge()
        if not edge:
            self.log("Select/refresh a server first")
            return
        if self.socks:
            self.log("SOCKS5 is already running; use Apply Server to switch servers.")
            return
        def work(edge=edge):
            try:
                self.edge=edge
                d=self.auth.store.load() or {}
                d["server"]=edge[0]
                self.auth.store.save(d)
                self.proxy_pass=self.api.proxy_pass()
                self.log(f"Proxy Pass acquired for {edge[0]} (token redacted)")
                self.socks=SocksServer(self); self.socks.start(); self.log("Ready: SOCKS5 127.0.0.1:1080")
            except Exception as e:self.log("Start failed: "+str(e))
        threading.Thread(target=work,daemon=True).start()

    def stop(self):
        if self.socks:
            old=self.edge
            self.socks.shutdown()
            self.socks=None
            self.log("SOCKS5 stopped; all active Mozilla H2 tunnels closed")
        self.edge=None
    def _try(self,fn,msg):
        try: fn(); self.log(msg)
        except Exception as e:self.log(str(e))

if __name__=="__main__": App().mainloop()
