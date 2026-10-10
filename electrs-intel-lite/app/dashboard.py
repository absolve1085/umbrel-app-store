#!/usr/bin/env python3
import json, sqlite3, argparse, datetime, time, math, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from parse_pcap import script_to_address, read_varint, addr_to_script

APP_PASSWORD = os.environ.get('APP_PASSWORD', '')

TABLES = '''
create table if not exists geo(ip text primary key, label text, country text,
  country_code text, city text, isp text, lat real, lon real, proxy int, hosting int,
  asn text, checked_at real);
create table if not exists wallet_txs(scripthash text, txid text, height int, ts int,
  recv int, spent int, delta int, primary key(scripthash, txid));
create table if not exists utxos(scripthash text, txid text, vout int, value int,
  height int, primary key(scripthash, txid, vout));
create table if not exists wallet_clusters(scripthash text primary key, wallet_id int, account_id int);
create table if not exists tx_parties(txid text, address text, is_input int, value int,
  primary key(txid, address, is_input));
create table if not exists signals(id integer primary key, conn_id int, ts real, kind text, detail text);
create table if not exists edges(wallet_id int, counterparty text, n_txs int, total_value int,
  primary key(wallet_id, counterparty));
create table if not exists alerts(id integer primary key, ts real, kind text, detail text, seen int default 0);
create table if not exists watch(address text primary key, note text);
create table if not exists labels(address text primary key, label text);
create table if not exists watch_state(address text, last_ts real, primary key(address));
'''

def tx_outputs(rawhex):
    try:
        b = bytes.fromhex(rawhex)
        i = 4
        if b[i] == 0 and b[i + 1] != 0:
            i += 2
        n, i = read_varint(b, i)
        for _ in range(n):
            i += 36
            sl, i = read_varint(b, i)
            i += sl + 4
        m, i = read_varint(b, i)
        outs = []
        for _ in range(m):
            v = int.from_bytes(b[i:i + 8], 'little')
            i += 8
            sl, i = read_varint(b, i)
            outs.append((v, script_to_address(b[i:i + sl])))
            i += sl
        return outs
    except Exception:
        return []

def btc(v):
    return (v or 0) / 1e8

def fmt_ts(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if t else None

def qmarks(ips):
    return ','.join('?' * len(ips)) or "''"

def shs_for_ips(con, ips):
    out = []
    for (p,) in con.execute('''select distinct q.params from requests q join conns c on c.id=q.conn_id
        where c.ip in (%s) and q.method like '%%scripthash%%' ''' % qmarks(ips), ips):
        try:
            sh = json.loads(p)[0]
        except Exception:
            continue
        if isinstance(sh, str) and len(sh) == 64:
            out.append(sh)
    return out

class Graph:
    def __init__(self):
        self.p = {}
    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x
    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[ra] = rb

def geo_for(con, ips):
    out = []
    for ip in ips:
        r = con.execute('''select label,country,country_code,city,isp,lat,lon,proxy,hosting,asn
            from geo where ip=?''', (ip,)).fetchone()
        if not r:
            out.append({'ip': ip, 'label': 'geolocalizacion pendiente (geo.py)', 'flags': [], 'map': None,
                        'internal': False})
        elif r[0]:
            out.append({'ip': ip, 'label': r[0], 'flags': [], 'map': None, 'internal': True})
        else:
            flags = [f for f, v in zip(['PROXY', 'HOSTING/VPN'], (r[7], r[8])) if v]
            label = ' / '.join(str(x) for x in (r[1], r[3], r[4]) if x)
            m = ('https://www.openstreetmap.org/?mlat=%s&mlon=%s#map=11/%s/%s'
                 % (r[5], r[6], r[5], r[6])) if r[5] is not None else None
            out.append({'ip': ip, 'label': label or '?', 'flags': flags, 'map': m, 'asn': r[9],
                        'internal': False})
    return out

def sh_row(con, sh):
    r = con.execute('''select scripthash,address,balance_conf,balance_unconf,n_seen,first_seen,last_seen
        from scripthashes where scripthash=?''', (sh,)).fetchone()
    if not r:
        return None
    d = {'scripthash': r[0], 'address': r[1], 'balance_conf': btc(r[2]), 'balance_unconf': btc(r[3]),
         'n_seen': r[4], 'first_seen': fmt_ts(r[5]), 'resolved': r[2] is not None or r[3] is not None}
    try:
        t = con.execute('''select count(*),coalesce(sum(recv),0),coalesce(sum(spent),0)
            from wallet_txs where scripthash=?''', (sh,)).fetchone()
        u = con.execute('select count(*),coalesce(sum(value),0) from utxos where scripthash=?', (sh,)).fetchone()
        d.update(n_txs=t[0], flow_recv=btc(t[1]), flow_sent=btc(t[2]), n_utxos=u[0], utxo_sum=btc(u[1]))
    except Exception:
        pass
    return d

def wallets_structure(con, shs):
    wc = dict((r[0], (r[1], r[2])) for r in con.execute(
        'select scripthash,wallet_id,account_id from wallet_clusters'))
    groups = {}
    for sh in shs:
        wid, aid = wc.get(sh, (None, None))
        key = wid if wid is not None else 'u:' + sh
        groups.setdefault(key, {}).setdefault(aid if aid is not None else 0, []).append(sh)
    wlist = []
    for idx, wid in enumerate(sorted(groups, key=str)):
        accounts = []
        for aid in sorted(groups[wid]):
            rows = [x for x in (sh_row(con, s) for s in groups[wid][aid]) if x]
            if not rows:
                continue
            sub_c = sum(x['balance_conf'] for x in rows)
            sub_u = sum(x['balance_unconf'] for x in rows)
            accounts.append({'label': 'CUENTA-%d' % (aid + 1), 'shs': rows,
                             'subtotal': sub_c, 'subtotal_u': sub_u})
        if not accounts:
            continue
        accounts.sort(key=lambda a: -a['subtotal'])
        for i, a in enumerate(accounts):
            a['label'] = 'CUENTA-%d' % (i + 1)
        wlist.append({'label': 'WALLET-' + chr(ord('A') + idx) if idx < 26 else 'W%d' % idx,
                      'accounts': accounts,
                      'total': sum(a['subtotal'] for a in accounts),
                      'n_shs': sum(len(a['shs']) for a in accounts),
                      'n_accounts': len(accounts)})
    wlist.sort(key=lambda w: -w['total'])
    return wlist

def behavior(con, ips):
    tss = [r[0] for r in con.execute('''select q.ts from requests q join conns c on c.id=q.conn_id
        where c.ip in (%s)''' % qmarks(ips), ips)]
    hours = [0] * 24
    for t in tss:
        hours[datetime.datetime.fromtimestamp(t, datetime.timezone.utc).hour] += 1
    tz = None
    if tss:
        x = sum(n * math.cos(2 * math.pi * h / 24) for h, n in enumerate(hours))
        y = sum(n * math.sin(2 * math.pi * h / 24) for h, n in enumerate(hours))
        if x or y:
            mean_h = (math.degrees(math.atan2(y, x)) / 15) % 24
            off = ((round(mean_h - 14) + 12) % 24) - 12
            tz = 'UTC%+d aprox (horario de actividad)' % off
    span = (max(tss) - min(tss)) if tss else 0
    rate = len(tss) / span if span > 60 else 0
    return {'hours': hours, 'tz': tz, 'n_queries': len(tss), 'rate': round(rate, 2),
            'dormant_days': round((time.time() - max(tss)) / 86400, 1) if tss else None}

def compute_profiles(con):
    shs_all = {}
    for ip, p in con.execute('''select distinct c.ip, q.params from requests q
            join conns c on c.id=q.conn_id where q.method like '%scripthash%' '''):
        try:
            sh = json.loads(p)[0]
        except Exception:
            continue
        if isinstance(sh, str) and len(sh) == 64:
            shs_all.setdefault('sh:' + sh, []).append(ip)
    g = Graph()
    for sh, ips in shs_all.items():
        for ip in ips:
            g.union('ip:' + ip, sh)
    wc = {}
    for sh, wid, aid in con.execute('select scripthash,wallet_id,account_id from wallet_clusters'):
        wc[sh] = wid
    for sh, wid in wc.items():
        g.union('sh:' + sh, 'w:' + str(wid))
    for r in con.execute('select ip from conns'):
        g.find('ip:' + r[0])
    comps = {}
    for node in g.p:
        comps.setdefault(g.find(node), []).append(node)
    profiles = []
    for c in comps.values():
        ips = sorted({n[3:] for n in c if n.startswith('ip:')})
        if not ips:
            continue
        qm = qmarks(ips)
        conns = con.execute('select ip,port,user_agent,n_reqs,first_ts,last_ts from conns where ip in (%s)' % qm, ips).fetchall()
        agents = sorted({r[2] for r in conns if r[2]})
        shs = sorted({n[3:] for n in c if n.startswith('sh:')})
        first = min([r[4] for r in conns if r[4]], default=None)
        last = max([r[5] for r in conns if r[5]], default=None)
        wallets = wallets_structure(con, shs)
        total_conf = sum(w['total'] for w in wallets)
        total_unconf = sum(a['subtotal_u'] for w in wallets for a in w['accounts'])
        txs = []
        for txid, t, ip, raw in con.execute('select txid,ts,ip,rawhex from txs where ip in (%s)' % qm, ips):
            outs = tx_outputs(raw)
            txs.append({'txid': txid, 'ts': fmt_ts(t), 'ip': ip,
                        'amount': btc(sum(v for v, _ in outs)),
                        'outputs': [{'address': a or '(script no estandar)', 'value': btc(v)} for v, a in outs]})
        sigs = [{'ts': fmt_ts(r[0]), 'kind': r[1], 'detail': r[2]} for r in con.execute(
            '''select s.ts, s.kind, s.detail from signals s join conns c on c.id=s.conn_id
            where c.ip in (%s) order by s.ts desc limit 20''' % qm, ips)]
        wids = sorted({wc[s] for s in shs if s in wc})
        cp = {}
        if wids:
            wq = ','.join('?' * len(wids))
            for r in con.execute('''select e.counterparty, sum(e.n_txs), sum(e.total_value),
                coalesce(l.label,'') from edges e left join labels l on l.address=e.counterparty
                where e.wallet_id in (%s) and e.counterparty not like 'script:%%'
                and e.counterparty not in (select address from change_addrs)
                group by e.counterparty order by 3 desc limit 15''' % wq, wids):
                cp[r[0]] = {'address': r[0], 'n_txs': r[1], 'value': btc(r[2]), 'label': r[3]}
            cp = sorted(cp.values(), key=lambda x: -x['value'])[:15]
        beh = behavior(con, ips)
        tags = []
        if len(set(agents)) > 1:
            tags.append('NAT-MULTIPLEX')
        if len(wallets) > 1:
            tags.append('MULTI-WALLET')
        if any(w['n_accounts'] > 1 for w in wallets):
            tags.append('MULTI-CUENTA')
        if txs:
            tags.append('BROADCASTER')
        if total_conf >= 100_000_000:
            tags.append('HIGH-BALANCE')
        if len(shs) > 200:
            tags.append('CRAWLER')
        if beh['rate'] and beh['rate'] > 5:
            tags.append('BOT')
        if all(ip.startswith(('10.', '172.', '192.168.')) for ip in ips):
            tags.append('RED-PRIVADA')
        profiles.append({'ips': ips, 'agents': agents, 'first_seen': fmt_ts(first),
                         'last_seen': fmt_ts(last), 'n_queries': sum(r[3] or 0 for r in conns),
                         'wallets': wallets, 'txs': txs, 'signals': sigs, 'counterparties': cp,
                         'behavior': beh, 'tags': tags, 'geo': geo_for(con, ips),
                         'total_conf': total_conf, 'total_unconf': total_unconf,
                         'n_wallets': len(wallets), 'n_txs': len(txs), 'shs': shs,
                         'flow_recv': sum(x.get('flow_recv', 0) for w in wallets for a in w['accounts'] for x in a['shs']),
                         'flow_sent': sum(x.get('flow_sent', 0) for w in wallets for a in w['accounts'] for x in a['shs']),
                         'n_history': sum(x.get('n_txs', 0) for w in wallets for a in w['accounts'] for x in a['shs'])})
    profiles.sort(key=lambda x: -(x['total_conf'] + x['total_unconf']))
    for i, p in enumerate(profiles):
        p['id'] = i
        p['name'] = 'PERFIL-%02d' % i
    return profiles

def overview(con):
    profiles = compute_profiles(con)
    return {'n_profiles': len(profiles),
            'total_btc': sum(p['total_conf'] + p['total_unconf'] for p in profiles),
            'n_wallets': sum(p['n_wallets'] for p in profiles),
            'n_txs': con.execute('select count(*) from txs').fetchone()[0],
            'n_queries': con.execute('select count(*) from requests').fetchone()[0],
            'n_alerts': con.execute('select count(*) from alerts where seen=0').fetchone()[0],
            'generated': fmt_ts(time.time())}

def stats(con):
    ua = [{'ua': r[0], 'n': r[1], 'reqs': r[2] or 0} for r in con.execute(
        'select coalesce(user_agent,"?"), count(*), sum(n_reqs) from conns group by 1 order by 2 desc')]
    days = [{'day': r[0], 'n': r[1]} for r in con.execute(
        "select date(first_ts,'unixepoch'), count(*) from conns group by 1 order by 1")]
    crawlers = [{'ip': r[0], 'n': r[1]} for r in con.execute(
        '''select c.ip, count(distinct q.params) n from requests q join conns c on c.id=q.conn_id
        where q.method like '%scripthash%' group by c.ip order by n desc limit 10''')]
    return {'ua': ua, 'days': days, 'crawlers': crawlers,
            'n_shs': con.execute('select count(*) from scripthashes').fetchone()[0],
            'n_wallets': con.execute('select count(distinct wallet_id) from wallet_clusters').fetchone()[0],
            'n_alerts': con.execute('select count(*) from alerts').fetchone()[0]}

def build_feed(con, shs, wallets=None):
    shq = ','.join('?' * len(shs)) or "''"
    owned = {r[0] for r in con.execute(
        'select address from scripthashes where scripthash in (%s) and address is not null' % shq, shs)}
    labels = dict(con.execute('select address, label from labels'))
    changeset = {r[0] for r in con.execute('select address from change_addrs')}
    bcast = {r[0]: r[1] for r in con.execute('select txid, ip from txs')}

    def ext(lst):
        out = []
        for a in lst:
            if a.startswith('script:'):
                continue
            if a in changeset:
                out.append('(change interno)')
                continue
            out.append(a)
        return out

    feed = []
    for txid, height, ts, recv, spent in con.execute('''select wt.txid, max(wt.height), max(wt.ts),
        sum(wt.recv), sum(wt.spent) from wallet_txs wt
        where wt.scripthash in (%s) group by wt.txid''' % shq, shs):
        parties = con.execute('select address, is_input, value from tx_parties where txid=?',
                              (txid,)).fetchall()
        frm = sorted(set(ext({a for a, i, v in parties if i == 1 and a not in owned})))
        to = sorted(set(ext({a for a, i, v in parties if i == 0 and a not in owned})))
        accts = []
        for w in (wallets if wallets is not None else []):
            for a in w['accounts']:
                shl = tuple(x['scripthash'] for x in a['shs'])
                if shl and con.execute(
                        'select 1 from wallet_txs where txid=? and scripthash in (%s) limit 1'
                        % ','.join('?' * len(shl)), (txid,) + shl).fetchone():
                    accts.append(w['label'] + '/' + a['label'])
        feed.append({'txid': txid, 'height': height, 'ts': fmt_ts(ts) or ('altura ' + str(height)),
                     'recv': btc(recv), 'spent': btc(spent), 'delta': btc(recv - spent),
                     'dir': 'IN' if recv > spent else ('OUT' if spent > recv else 'NET'),
                     'frm': [{'a': a, 'l': labels.get(a, '')} for a in frm],
                     'to': [{'a': a, 'l': labels.get(a, '')} for a in to],
                     'ip': bcast.get(txid), 'accts': accts})
    feed.sort(key=lambda x: x['ts'] or '', reverse=True)
    return feed

def build_utxos(con, shs):
    shq = ','.join('?' * len(shs)) or "''"
    return [{'address': r[0] or r[1][:12] + '…', 'txid': r[2], 'vout': r[3],
             'value': btc(r[4]), 'height': r[5]}
            for r in con.execute('''select s.address, u.scripthash, u.txid, u.vout,
                u.value, u.height from utxos u left join scripthashes s
                on s.scripthash=u.scripthash where u.scripthash in (%s)''' % shq, shs)]

class Handler(BaseHTTPRequestHandler):
    db = None
    def log_message(self, *a):
        pass
    def authed(self):
        if not APP_PASSWORD:
            return True
        h = self.headers.get('Authorization', '')
        return h == 'Bearer ' + APP_PASSWORD
    def denied(self):
        b = json.dumps({'error': 'auth'}).encode()
        self.send_response(401)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def j(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        if not self.authed() and self.path.split('?')[0] != '/':
            self.denied()
            return
        con = sqlite3.connect(self.db)
        con.executescript(TABLES)
        try:
            path = self.path.split('?')[0]
            if path == '/':
                b = PAGE.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            elif path == '/api/overview':
                self.j(overview(con))
            elif path == '/api/profiles':
                self.j(compute_profiles(con))
            elif path == '/api/stats':
                self.j(stats(con))
            elif path == '/api/alerts':
                if 'mark' in self.path:
                    con.execute('update alerts set seen=1')
                    con.commit()
                self.j([{'ts': fmt_ts(r[0]), 'kind': r[1], 'detail': r[2]} for r in con.execute(
                    'select ts, kind, detail from alerts order by ts desc limit 100')])
            elif path == '/api/watch':
                self.j([{'address': r[0], 'note': r[1]} for r in con.execute('select address, note from watch')])
            elif path.startswith('/api/profile/'):
                pid = int(path.rsplit('/', 1)[1])
                ps = compute_profiles(con)
                if 0 <= pid < len(ps):
                    p = ps[pid]
                    qm = qmarks(p['ips'])
                    rows = con.execute('''select q.ts, c.ip, q.method, q.params from requests q
                        join conns c on c.id=q.conn_id where c.ip in (%s) order by q.ts limit 400''' % qm,
                        p['ips']).fetchall()
                    p['queries'] = [{'ts': fmt_ts(r[0]), 'ip': r[1], 'method': r[2],
                                     'params': (r[3] or '')[:70]} for r in rows]
                    tss = [r[0] for r in rows]
                    if tss:
                        span = max(tss) - min(tss) or 1
                        step = span / 40 or 1
                        hist = [0] * 40
                        for t in tss:
                            hist[min(39, int((t - min(tss)) / step))] += 1
                        p['hist'] = hist
                    shq = ','.join('?' * len(p['shs'])) or "''"
                    p['feed'] = build_feed(con, p['shs'], p['wallets'])
                    p['history'] = [{'address': r[0] or '(?)', 'txid': r[1], 'height': r[2],
                                     'ts': fmt_ts(r[3]) or ('altura ' + str(r[2])),
                                     'recv': btc(r[4]), 'spent': btc(r[5]), 'delta': btc(r[6])}
                                    for r in con.execute('''select s.address, wt.txid, wt.height, wt.ts,
                                        wt.recv, wt.spent, wt.delta from wallet_txs wt
                                        left join scripthashes s on s.scripthash=wt.scripthash
                                        where wt.scripthash in (%s) order by wt.ts''' % shq, p['shs'])]
                    p['utxo_list'] = build_utxos(con, p['shs'])
                    self.j(p)
                else:
                    self.send_error(404)
            elif path.startswith('/api/wallet/'):
                _, _, _, apid, awidx = path.split('/')
                ps = compute_profiles(con)
                pid, widx = int(apid), int(awidx)
                if pid < len(ps) and widx < len(ps[pid]['wallets']):
                    p = ps[pid]
                    w = p['wallets'][widx]
                    for a in w['accounts']:
                        shl = [x['scripthash'] for x in a['shs']]
                        a['feed'] = build_feed(con, shl, [w])
                        a['utxos'] = build_utxos(con, shl)
                    self.j({'name': p['name'], 'ips': p['ips'], 'geo': p['geo'],
                            'tags': p['tags'], 'agents': p['agents'], 'wallet': w, 'pid': pid})
                else:
                    self.send_error(404)
            else:
                self.send_error(404)
        finally:
            con.close()
    def do_POST(self):
        if not self.authed():
            self.denied()
            return
        con = sqlite3.connect(self.db)
        con.executescript(TABLES)
        try:
            if self.path == '/api/watch':
                n = int(self.headers.get('Content-Length', 0))
                body = json.loads(self.rfile.read(n) or b'{}')
                addr = (body.get('address') or '').strip()
                try:
                    addr_to_script(addr)
                except Exception as e:
                    self.j({'ok': False, 'error': 'direccion invalida: %s' % e})
                    return
                if body.get('remove'):
                    con.execute('delete from watch where address=?', (addr,))
                else:
                    con.execute('insert or replace into watch values(?,?)', (addr, body.get('note') or ''))
                con.commit()
                self.j({'ok': True})
            else:
                self.send_error(404)
        finally:
            con.close()

PAGE = """<!doctype html><html><head><meta charset='utf-8'>
<title>electrs intel</title><style>
:root{--bg:#0b0e14;--panel:#121722;--line:#1e2633;--fg:#c9d4e3;--dim:#5c6b80;--acc:#4da3ff;--pos:#2ecc8f;--neg:#ff6b6b}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--fg);font:14px/1.45 'SF Mono',Menlo,Consolas,monospace;height:100vh;display:flex;flex-direction:column}
header{display:flex;gap:20px;align-items:center;padding:10px 20px;border-bottom:1px solid var(--line);background:var(--panel);flex-wrap:wrap}
header h1{font-size:15px;letter-spacing:2px;color:var(--acc);cursor:pointer}
header .stat{color:var(--dim);font-size:12px} header .stat b{color:var(--fg)}
header button{background:var(--bg);color:var(--acc);border:1px solid var(--line);border-radius:4px;padding:4px 10px;font:inherit;cursor:pointer}
header button:hover{border-color:var(--acc)}
header button.alert{color:var(--neg)}
.search{background:var(--bg);border:1px solid var(--line);color:var(--fg);padding:5px 10px;border-radius:4px;font:inherit;width:210px;margin-left:auto}
main{flex:1;display:flex;min-height:0}
#side{width:340px;border-right:1px solid var(--line);overflow-y:auto;background:var(--panel)}
.pcard{padding:12px 16px;border-bottom:1px solid var(--line);cursor:pointer}
.pcard:hover{background:#161d2b} .pcard.sel{background:#182236;border-left:3px solid var(--acc)}
.pcard .n{color:var(--acc);font-size:12px}
.pcard .ip{font-size:15px;margin:2px 0}
.pcard .sub{color:var(--dim);font-size:11px}
#detail{flex:1;overflow-y:auto;padding:22px 28px}
h2{font-size:13px;letter-spacing:2px;color:var(--dim);margin:26px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
h2:first-child{margin-top:0}
.badge{display:inline-block;padding:1px 8px;border:1px solid var(--line);border-radius:3px;font-size:11px;color:var(--dim);margin-right:6px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{color:var(--dim);text-align:left;font-weight:normal;padding:5px 10px;border-bottom:1px solid var(--line)}
td{padding:5px 10px;border-bottom:1px solid #141a26}
tr:hover td{background:#141b28}
tr.grp td{color:var(--acc);background:#121a29;border-bottom:1px solid var(--line)}
.kpis{display:flex;gap:16px;flex-wrap:wrap;margin:14px 0}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 18px;min-width:140px}
.kpi .v{font-size:19px;color:var(--acc)} .kpi .l{font-size:11px;color:var(--dim)}
#bars{display:flex;align-items:flex-end;gap:2px;height:60px;margin:8px 0}
#bars div{background:var(--acc);opacity:.55;flex:1;min-height:1px}
#hbars{display:flex;align-items:flex-end;gap:1px;height:50px;margin:8px 0 2px}
#hbars div{background:var(--acc);opacity:.5;flex:1;min-height:1px}
.qrow{display:grid;grid-template-columns:170px 130px 240px 1fr;gap:8px;padding:3px 8px;font-size:12px;border-bottom:1px solid #121824}
.qrow .m{color:var(--ok)} .qrow .ip{color:var(--dim)}
.iprow{margin:5px 0;font-size:12.5px}
.iprow b{color:var(--acc);margin-right:8px}
.iprow a{color:var(--acc);text-decoration:none;margin-left:8px}
.tx{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 14px;margin-bottom:10px}
.tx .txid{color:var(--acc);font-size:12px}
.wallet{display:flex;gap:14px;align-items:baseline}
.wallet .a{color:var(--fg)} .wallet .s{color:var(--dim);font-size:11px}
.balance{color:var(--pos)} .none{color:var(--dim)}
.out{color:var(--neg)}
#empty{color:var(--dim);padding:40px}
.sig{display:flex;gap:14px;padding:6px 10px;border-left:3px solid var(--acc);background:#131722;margin-bottom:6px;font-size:12.5px}
.sig .k{color:var(--dim);min-width:140px}
.wcard{background:var(--panel);border:1px solid var(--line);border-radius:6px;margin-bottom:12px;padding:10px 14px;cursor:pointer}
.wcard:hover{border-color:var(--acc)}
.whdr{color:var(--acc);margin-bottom:6px}
.acchdr{color:var(--fg);font-size:12px;letter-spacing:1px;margin:8px 0 4px}
.addr{display:flex;gap:16px;font-size:12.5px;padding:2px 0 2px 14px}
.addr .a{min-width:340px}
.addr .v{min-width:130px}
.addr .s{color:var(--dim)}
details{margin-top:24px;border:1px solid var(--line);border-radius:6px;padding:8px 14px;background:var(--panel)}
details summary{cursor:pointer;color:var(--dim)}
details h2{margin-top:18px}
</style></head><body>
<header><h1 onclick='view("stats")'>ELECTRS-INTEL</h1>
<div class='stat'>perfiles <b id='s1'>-</b></div><div class='stat'>wallets <b id='s2'>-</b></div>
<div class='stat'>BTC <b id='s3'>-</b></div><div class='stat'>txs <b id='s4'>-</b></div>
<div class='stat'>queries <b id='s5'>-</b></div>
<button class='alert' id='ab' onclick='view("alerts")'>ALERTAS 0</button>
<input class='search' id='q' placeholder='filtrar ip / address / agent' oninput='render()'>
<input class='search' id='wa' placeholder='vigilar direccion bc1.../12...' style='width:240px'>
<button onclick='addWatch()'>VIGILAR</button>
</header>
<main><div id='side'></div><div id='detail'><div id='empty'>cargando…</div></div></main>
<script>
let profiles=[],sel=null,mode='profile';
let TOKEN=localStorage.getItem('ei_token')||'';
const api=(u,o)=>fetch(u,Object.assign({},o||{},{headers:Object.assign({'Authorization':'Bearer '+TOKEN},(o&&o.headers)||{})}))
 .then(r=>{if(r.status===401){const t=prompt('Token de acceso:');if(t){TOKEN=t;localStorage.setItem('ei_token',t);return api(u,o)}throw new Error('auth')}return r});
const f8=v=>v==null?'-':v.toFixed(8), f2=v=>v==null?'-':v.toFixed(2);
const esc=s=>(s||'').replace(/</g,'&lt;');
async function load(){
 const [ov,ps]=await Promise.all([api('/api/overview').then(r=>r.json()),api('/api/profiles').then(r=>r.json())]);
 s1.textContent=ov.n_profiles;s2.textContent=ov.n_wallets;s3.textContent=f2(ov.total_btc);
 s4.textContent=ov.n_txs;s5.textContent=ov.n_queries;ab.textContent='ALERTAS '+ov.n_alerts;
 profiles=ps;render();
 if(mode==='profile'&&sel==null&&ps.length)select(ps[0].id);
}
function render(){
 const q=document.getElementById('q').value.toLowerCase();
 const all=profiles.filter(p=>!q||JSON.stringify(p).toLowerCase().includes(q));
 const list=all.filter(p=>p.n_wallets>0||p.n_txs>0);
 const rest=all.length-list.length;
 side.innerHTML=list.map(p=>`<div class='pcard ${sel===p.id&&mode==='profile'?'sel':''}' onclick='select(${p.id})'>
  <div class='n'>${p.name} · ${p.n_wallets} wallet(s) · ${p.shs.length} sh · ${p.n_txs} tx</div>
  <div class='ip'>${p.ips.join(', ')}</div>
  <div class='sub'>${f8(p.total_conf+p.total_unconf)} BTC · ${p.agents.join(' | ')||'?'}</div>
  <div class='sub'>${p.geo.map(g=>g.label.split(' / ')[0]).join(' · ')}</div></div>`).join('')
 +(rest?`<div class='pcard' style='opacity:.45'><div class='n'>SIN WALLET (${rest})</div>
   <div class='sub'>conexiones sin direcciones vigilar (scanners/probes) — ocultas</div></div>`:'')
 ||'<div id=empty>sin resultados</div>';
}
async function select(id){
 sel=id;mode='profile';render();
 const p=await api('/api/profile/'+id).then(r=>r.json());
 const hb=(p.behavior.hours||[]).map(v=>`<div title='${v}' style='height:${Math.round(100*v/Math.max(1,...(p.behavior.hours||[1])))}%'></div>`).join('');
 let wsec='';
 p.wallets.forEach((w,wi)=>{
  wsec+=`<div class='wcard' onclick='selectWallet(${p.id},${wi})'><div class='whdr'>${w.label} · ${w.n_accounts} cuenta(s) · ${f8(w.total)} BTC · ver detalle ></div>`;
  w.accounts.forEach(a=>{
   const shown=a.shs.slice(0,6), rest=a.shs.length-shown.length;
   wsec+=`<div class='acchdr'>${a.label} · ${f8(a.subtotal)} BTC · ${a.shs.length} direcciones</div>`;
   shown.forEach(x=>{wsec+=`<div class='addr'><span class='a'>${x.address||`<span class='none' title='${x.scripthash}'>${x.scripthash.slice(0,20)}… (sin fondos)</span>`}</span>
    <span class='v'>${x.resolved?f8(x.balance_conf):'—'}</span>
    <span class='s'>${x.n_txs||0} tx · ${x.n_utxos||0} utxo</span></div>`});
   if(rest>0) wsec+=`<div class='sub' style='padding:2px 0 2px 14px'>+ ${rest} direcciones mas — lista completa en el detalle de la wallet</div>`;
  });
  wsec+='</div>';
 });
 const gpub=p.geo.filter(g=>!g.internal), gint=p.geo.length-gpub.length;
 const feed=(p.feed||[]).map(m=>`<tr>
  <td>${m.ts}</td>
  <td class='${m.dir=='IN'?'balance':'out'}'>${m.dir=='IN'?'+':m.dir=='OUT'?'−':''}${f8(Math.abs(m.delta))}</td>
  <td>${m.dir=='IN'?`de ${esc(m.frm.map(x=>x.l||x.a.slice(0,14)).join(', ')||'?')}`:`a ${esc(m.to.map(x=>x.l||x.a.slice(0,14)).join(', ')||'?')}`}</td>
  <td style='color:var(--dim);font-size:11px'>${m.accts.join(' ')}</td>
  <td class='a' style='font-size:11px'>${m.txid.slice(0,12)}…</td>
  <td>${m.height}</td>
  <td>${m.ip?`<span class='badge'>difundida ${m.ip}</span>`:''}</td></tr>`).join('');
 detail.innerHTML=`
 <h2>${p.name} — ${f8(p.total_conf+p.total_unconf)} BTC · ${p.n_wallets} WALLET(S) · ${p.shs.length} direcciones</h2>
 <div>${p.tags.map(t=>`<span class='badge'>${t}</span>`).join('')}</div>
 <h2>UBICACION</h2>
 ${gpub.map(g=>`<div class='iprow'><b>${g.ip}</b> ${esc(g.label)} ${g.flags.map(f=>`<span class='badge'>${f}</span>`).join('')} ${g.map?`<a href='${g.map}' target='_blank'>(mapa)</a>`:''}</div>`).join('')||'<div class=none>sin IP publica geolocalizable</div>'}
 ${gint?`<div class='sub'>+ ${gint} IP(s) interna(s) Tor/LAN sin ubicacion</div>`:''}
 <div style='color:var(--dim);font-size:12px;margin:6px 0'>${p.agents.join(' · ')||'-'} · ${p.first_seen||'-'} → ${p.last_seen||'-'} · ${p.n_queries} queries${p.behavior.tz?' · '+p.behavior.tz:''}</div>
 <h2>WALLETS / CUENTAS / DIRECCIONES</h2>
 ${wsec}
 <h2>MOVIMIENTOS (${(p.feed||[]).length} txs · flujo +${f8(p.flow_recv)} / −${f8(p.flow_sent)})</h2>
 <table><tr><th>fecha</th><th>importe</th><th>contraparte</th><th>cuenta</th><th>txid</th><th>altura</th><th></th></tr>
 ${feed||'<tr><td colspan=7 class=none>sin movimientos</td></tr>'}</table>
 <h2>SEÑALES</h2>
 ${p.signals.map(s=>`<div class='sig'><span class='k'>${s.ts}</span><span class='k'>${s.kind}</span><span>${esc(s.detail)}</span></div>`).join('')||'<div class=none>ninguna</div>'}
 <h2>CONTRAPARTES</h2>
 <table><tr><th>direccion</th><th>etiqueta</th><th>txs</th><th>volumen</th></tr>
 ${(p.counterparties||[]).map(c=>`<tr><td class=a>${c.address}</td>
  <td>${c.label?`<span class='badge'>${esc(c.label)}</span>`:'<span class=none>-</span>'}</td>
  <td>${c.n_txs}</td><td>${f8(c.value)}</td></tr>`).join('')||'<tr><td colspan=4 class=none>sin datos</td></tr>'}</table>
 <details><summary>detalles tecnicos</summary>
 <div id='hbars'>${hb}</div><div style='color:var(--dim);font-size:11px;margin-bottom:10px'>actividad por hora UTC</div>
 <h2>UTXOS</h2>
 <table><tr><th>direccion</th><th>txid</th><th>vout</th><th>valor</th><th>altura</th></tr>
 ${(p.utxo_list||[]).map(u=>`<tr><td>${u.address.slice(0,14)}…</td><td class='a'>${u.txid.slice(0,16)}…</td>
  <td>${u.vout}</td><td>${f8(u.value)}</td><td>${u.height}</td></tr>`).join('')}</table>
 <h2>TXS DIFUNDIDAS POR ESTE PERFIL</h2>
 ${p.txs.map(t=>`<div class='tx'><div class='txid'>${t.txid}</div>
  <div style='color:var(--dim);font-size:12px'>${t.ts} · desde ${t.ip} · total ${f8(t.amount)} BTC</div>
  ${t.outputs.map(o=>`<div class='wallet'><span class='a'>${o.address}</span><span class='balance'>${f8(o.value)} BTC</span></div>`).join('')}</div>`).join('')||'<div class=none>ninguna</div>'}
 <h2>LOG DE QUERIES ELECTRUM</h2>
 ${(p.queries||[]).slice().reverse().map(r=>`<div class='qrow'><span>${r.ts}</span><span class='ip'>${r.ip}</span><span class='m'>${r.method}</span><span style='color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>${esc(r.params)}</span></div>`).join('')}
 </details>`;
}
async function selectWallet(pid,widx){
 mode='wallet';render();
 const d=await api('/api/wallet/'+pid+'/'+widx).then(r=>r.json());
 const w=d.wallet;
 const gpub=d.geo.filter(g=>!g.internal), gint=d.geo.length-gpub.length;
 let html=`<h2 style='cursor:pointer;color:var(--acc)' onclick='select(${pid})'>< volver a ${d.name}</h2>
 <h2>${d.name} / ${w.label} · ${f8(w.total)} BTC · ${w.n_accounts} CUENTA(S)</h2>
 <div>${d.tags.map(t=>`<span class='badge'>${t}</span>`).join('')}</div>
 ${gpub.map(g=>`<div class='iprow'><b>${g.ip}</b> ${esc(g.label)} ${g.map?`<a href='${g.map}' target='_blank'>(mapa)</a>`:''}</div>`).join('')}
 ${gint?`<div class='sub'>+ ${gint} IP(s) interna(s) Tor/LAN sin ubicacion</div>`:''}`;
 w.accounts.forEach(a=>{
  const resueltas=a.shs.filter(x=>x.address).length;
  html+=`<h2>${a.label} · ${f8(a.subtotal)} BTC · ${a.shs.length} direcciones consultadas
   (${resueltas} identificadas, ${a.shs.length-resueltas} sin fondos — solo hash)</h2>
  ${a.shs.map(x=>x.address
   ?`<div class='addr'><span class='a'>${x.address}</span><span class='v'>${x.resolved?f8(x.balance_conf):'—'}</span>
     <span class='s'>visto ${x.n_seen}x · ${x.n_txs||0} tx · ${x.n_utxos||0} utxo</span></div>`
   :`<div class='addr'><span class='a none' title='${x.scripthash}'>${x.scripthash.slice(0,34)}…</span><span class='v'>—</span>
     <span class='s'>sin fondos · visto ${x.n_seen}x</span></div>`).join('')}
  <table><tr><th>fecha</th><th>importe</th><th>contraparte</th><th>txid</th><th>altura</th></tr>
  ${a.feed.map(m=>`<tr><td>${m.ts}</td>
   <td class='${m.dir=='IN'?'balance':'out'}'>${m.dir=='IN'?'+':'−'}${f8(Math.abs(m.delta))}</td>
   <td>${m.dir=='IN'?esc(m.frm.map(x=>x.l||x.a.slice(0,14)).join(', ')||'?'):esc(m.to.map(x=>x.l||x.a.slice(0,14)).join(', ')||'?')}</td>
   <td class='a' style='font-size:11px'>${m.txid.slice(0,12)}…</td><td>${m.height}</td></tr>`).join('')||'<tr><td colspan=5 class=none>sin movimientos</td></tr>'}</table>
  <table><tr><th>utxo de ${a.label}</th><th>txid:vout</th><th>valor</th><th>altura</th></tr>
  ${a.utxos.map(u=>`<tr><td>${u.address.slice(0,20)}…</td><td class='a' style='font-size:11px'>${u.txid.slice(0,20)}…:${u.vout}</td>
   <td>${f8(u.value)}</td><td>${u.height}</td></tr>`).join('')||'<tr><td colspan=4 class=none>sin utxos</td></tr>'}</table>`;
 });
 detail.innerHTML=html;
}
async function view(m){
 mode=m;
 if(m==='alerts'){
  const al=await api('/api/alerts').then(r=>r.json());
  detail.innerHTML=`<h2>ALERTAS (${al.length})</h2>
  ${al.map(a=>`<div class='sig'><span class='k'>${a.ts}</span><span class='k'>${a.kind}</span><span>${esc(a.detail)}</span></div>`).join('')||'<div class=none>ninguna</div>'}
  <button onclick="markAlerts()">marcar leidas</button>`;
  render();
 } else if(m==='stats'){
  const s=await api('/api/stats').then(r=>r.json());
  const mx=Math.max(1,...s.days.map(d=>d.n));
  detail.innerHTML=`<h2>ESTADISTICAS DEL SERVIDOR</h2>
  <div class='kpis'>
   <div class='kpi'><div class='v'>${s.n_shs}</div><div class='l'>scripthashes vistos</div></div>
   <div class='kpi'><div class='v'>${s.n_wallets}</div><div class='l'>wallets clusterizadas</div></div>
   <div class='kpi'><div class='v'>${s.n_alerts}</div><div class='l'>alertas</div></div>
  </div>
  <h2>WALLETS POR SOFTWARE</h2>
  <table><tr><th>user-agent</th><th>conexiones</th><th>queries</th></tr>
  ${s.ua.map(u=>`<tr><td>${esc(u.ua)}</td><td>${u.n}</td><td>${u.reqs}</td></tr>`).join('')}</table>
  <h2>CONEXIONES POR DIA</h2>
  <div id='bars'>${s.days.map(d=>`<div title='${d.day}: ${d.n}' style='height:${Math.round(100*d.n/mx)}%'></div>`).join('')}</div>
  <h2>TOP ENUMERADORES (posibles crawlers)</h2>
  <table><tr><th>ip</th><th>scripthashes distintos</th></tr>
  ${s.crawlers.map(c=>`<tr><td>${c.ip}</td><td>${c.n}</td></tr>`).join('')}</table>`;
  render();
 }
}
async function markAlerts(){await api('/api/alerts?mark');view('alerts')}
async function addWatch(){
 const a=document.getElementById('wa').value.trim();
 if(!a)return;
 const r=await api('/api/watch',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({address:a})}).then(r=>r.json());
 if(r.ok){document.getElementById('wa').value='';view('alerts');}
 else alert(r.error);
}
load();setInterval(load,10000);
</script></body></html>"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default='snoop.db')
    ap.add_argument('--listen', default='127.0.0.1:8877')
    a = ap.parse_args()
    Handler.db = a.db
    host, port = a.listen.rsplit(':', 1)
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    print('electrs-intel en http://%s:%s  db=%s' % (host, port, a.db))
    srv.serve_forever()

if __name__ == '__main__':
    main()
