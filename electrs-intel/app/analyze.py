#!/usr/bin/env python3
import json, sqlite3, argparse, time, math
from parse_pcap import scripthash_of, script_to_address, addr_to_script
from harvest import tx_io
from resolve import Client

def jaccard(a, b):
    A, B = set(a), set(b)
    return len(A & B) / len(A | B) if A and B else 0.0

class UF:
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

def build_bursts(con, gap):
    rows = con.execute('''select c.id, c.ip, q.ts, q.params from requests q
        join conns c on c.id=q.conn_id where q.method like '%scripthash%'
        order by c.id, q.ts''').fetchall()
    bursts = []
    cur = None
    for cid, ip, ts, p in rows:
        try:
            sh = json.loads(p)[0]
        except Exception:
            continue
        if not (isinstance(sh, str) and len(sh) == 64):
            continue
        if cur and cur['conn'] == cid and ts - cur['last'] <= gap:
            cur['shs'].add(sh)
            cur['last'] = ts
        else:
            cur = {'conn': cid, 'ip': ip, 'first': ts, 'last': ts, 'shs': {sh}}
            bursts.append(cur)
    return bursts

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default='snoop.db')
    ap.add_argument('--server', default=None)
    ap.add_argument('--burst-gap', type=float, default=10.0)
    ap.add_argument('--jac', type=float, default=0.5)
    ap.add_argument('--fetch-limit', type=int, default=200)
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.executescript('''
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
    create table if not exists change_addrs(address text primary key);
    ''')
    for t in ('wallet_clusters', 'signals', 'edges', 'tx_parties', 'change_addrs'):
        con.execute('delete from ' + t)

    bursts = build_bursts(con, a.burst_gap)
    has_chain = True
    try:
        con.execute('select 1 from wallet_txs limit 1')
    except Exception:
        has_chain = False

    def virgin(sh):
        if not has_chain:
            return False
        r = con.execute('select coalesce(max(recv),0) from wallet_txs where scripthash=?', (sh,)).fetchone()
        u = con.execute('select coalesce(sum(value),0) from utxos where scripthash=?', (sh,)).fetchone()
        return (r[0] or 0) == 0 and (u[0] or 0) == 0

    now = time.time()
    for b in bursts:
        vs = [sh for sh in b['shs'] if virgin(sh)]
        polls = con.execute('''select count(*) from requests where conn_id=?
            and method like '%get_history%' ''', (b['conn'],)).fetchone()[0]
        if vs and polls >= 3:
            con.execute('insert into signals(conn_id,ts,kind,detail) values(?,?,?,?)',
                        (b['conn'], b['last'], 'esperando_cobro',
                         '%d direcciones virgenes vigiladas con %d polls (factura?)' % (len(vs), polls)))
    for cid, ts in con.execute('''select conn_id, min(ts) from requests
            where method='blockchain.estimatefee' group by conn_id'''):
        ip = con.execute('select ip from conns where id=?', (cid,)).fetchone()[0]
        con.execute('insert into signals(conn_id,ts,kind,detail) values(?,?,?,?)',
                    (cid, ts, 'preparando_gasto', 'estimatefee consultado desde ' + ip))
    for cid, ts, p in con.execute('''select conn_id, ts, params from requests
            where method='blockchain.transaction.get' '''):
        try:
            txid = json.loads(p)[0]
        except Exception:
            continue
        if has_chain:
            r = con.execute('select max(ts) from wallet_txs where txid=?', (txid,)).fetchone()
            if r and r[0] and now - r[0] > 90 * 86400:
                ip = con.execute('select ip from conns where id=?', (cid,)).fetchone()[0]
                con.execute('insert into signals(conn_id,ts,kind,detail) values(?,?,?,?)',
                            (cid, ts, 'auditoria', 'tx antigua consultada desde ' + ip))

    client = None
    if a.server:
        host, port = a.server.rsplit(':', 1)
        client = Client((host, int(port)))
    fetched = 0
    txin = {}
    txin_addr = {}
    for (txid, raw) in con.execute('select txid, rawhex from txs_raw').fetchall():
        ins, _ = tx_io(raw)
        shs = []
        addrs = []
        for ptxid, vout in ins:
            praw = con.execute('select rawhex from txs_raw where txid=?', (ptxid,)).fetchone()
            if not praw and client and fetched < a.fetch_limit:
                r = client.call('blockchain.transaction.get', [ptxid, False])
                if isinstance(r, str):
                    con.execute('insert or replace into txs_raw values(?,?)', (ptxid, r))
                    fetched += 1
                    praw = (r,)
            if praw:
                _, pouts = tx_io(praw[0])
                if vout < len(pouts):
                    v, sc = pouts[vout]
                    sh = scripthash_of(sc)
                    shs.append(sh)
                    addrs.append((sh, script_to_address(sc) or 'script:' + sc[:12], v))
        txin[txid] = shs
        txin_addr[txid] = addrs

    for (txid, raw) in con.execute('select txid, rawhex from txs_raw').fetchall():
        for sh, addr, v in txin_addr.get(txid, []):
            con.execute('insert or ignore into tx_parties values(?,?,1,?)', (txid, addr, v))
        _, outs = tx_io(raw)
        for v, sc in outs:
            con.execute('insert or ignore into tx_parties values(?,?,0,?)',
                        (txid, script_to_address(sc) or 'script:' + sc[:12], v))

    W = UF()
    A = UF()
    byconn = {}
    for i, b in enumerate(bursts):
        for sh in b['shs']:
            W.union('b%d' % i, 'sh:' + sh)
            A.union('b%d' % i, 'sh:' + sh)
        byconn.setdefault(b['conn'], []).append(i)
    for cid, idxs in byconn.items():
        for k in idxs[1:]:
            W.union('b%d' % idxs[0], 'b%d' % k)
    for i in range(len(bursts)):
        for j in range(i + 1, len(bursts)):
            if jaccard(bursts[i]['shs'], bursts[j]['shs']) >= a.jac:
                W.union('b%d' % i, 'b%d' % j)
                A.union('b%d' % i, 'b%d' % j)
    for txid, shs in txin.items():
        for k in range(1, len(shs)):
            W.union('sh:' + shs[0], 'sh:' + shs[k])

    wallet_of = {}
    account_root = {}
    for b in bursts:
        for sh in b['shs']:
            wallet_of[sh] = W.find('sh:' + sh)
            account_root[sh] = A.find('sh:' + sh)
    wroots = sorted(set(wallet_of.values()))
    wid = {r: n for n, r in enumerate(wroots)}
    acc_pairs = sorted(set((wallet_of[sh], account_root[sh]) for sh in wallet_of))
    aid = {r: n for n, r in enumerate(acc_pairs)}
    for sh, w in wallet_of.items():
        con.execute('insert or replace into wallet_clusters values(?,?,?)',
                    (sh, wid[w], aid[(w, account_root[sh])]))

    now2 = time.time()
    for txid, shs in txin.items():
        known = [s for s in shs if s in wallet_of]
        if not known:
            continue
        k = known[0]
        for s in shs:
            if s in wallet_of:
                continue
            con.execute('insert or replace into wallet_clusters values(?,?,?)',
                        (s, wid[wallet_of[k]], aid[(wallet_of[k], account_root[k])]))
            if not con.execute('select 1 from scripthashes where scripthash=?', (s,)).fetchone():
                con.execute('''insert into scripthashes(scripthash,first_seen,last_seen,n_seen)
                  values(?,?,?,0)''', (s, now2, now2))

    wallet_id_of = {sh: wid[w] for sh, w in wallet_of.items()}
    for txid, shs in txin.items():
        raw = con.execute('select rawhex from txs_raw where txid=?', (txid,)).fetchone()[0]
        _, outs = tx_io(raw)
        in_set = set(shs)
        wids = {wallet_id_of[s] for s in shs if s in wallet_id_of}
        for v, sc in outs:
            osh = scripthash_of(sc)
            if osh in in_set:
                continue
            addr = script_to_address(sc) or 'script:' + sc[:12]
            for w in wids:
                con.execute('''insert into edges values(?,?,1,?) on conflict(wallet_id, counterparty)
                  do update set n_txs=n_txs+1, total_value=total_value+?''', (w, addr, v, v))
        out_wids = {wallet_id_of[scripthash_of(sc)] for v, sc in outs if scripthash_of(sc) in wallet_id_of}
        for sh, addr, v in txin_addr.get(txid, []):
            for w in out_wids:
                if wallet_id_of.get(sh) == w:
                    continue
                con.execute('''insert into edges values(?,?,1,?) on conflict(wallet_id, counterparty)
                  do update set n_txs=n_txs+1''', (w, addr, v))

    spent_by_wallet = {}
    for txid, shs in txin.items():
        ws = {wallet_id_of[s] for s in shs if s in wallet_id_of}
        for sh, addr, v in txin_addr.get(txid, []):
            for w in ws:
                spent_by_wallet.setdefault(w, set()).add(addr)
    addr_sh = {r[0]: r[1] for r in con.execute(
        'select address, scripthash from scripthashes where address is not null')}
    for w, addrs in spent_by_wallet.items():
        for addr in addrs:
            sh = addr_sh.get(addr)
            if sh is not None and wallet_id_of.get(sh) == w:
                continue
            con.execute('delete from edges where wallet_id=? and counterparty=?', (w, addr))
            con.execute('insert or ignore into change_addrs values(?)', (addr,))

    new_alerts = 0
    for (addr,) in con.execute('select address from watch').fetchall():
        try:
            sh = scripthash_of(addr_to_script(addr))
        except Exception:
            continue
        r = con.execute('''select c.ip, q.ts from requests q join conns c on c.id=q.conn_id
            where q.params like ? order by q.ts desc limit 1''', ('%' + sh + '%',)).fetchone()
        st = con.execute('select last_ts from watch_state where address=?', (addr,)).fetchone()
        prev = st[0] if st and st[0] is not None else -1
        if r and r[1] > prev:
            con.execute('insert into alerts(ts,kind,detail) values(?,?,?)',
                        (r[1], 'watch_query', '%s consultado desde %s' % (addr, r[0])))
            con.execute('insert or replace into watch_state values(?,?)', (addr, r[1]))
            new_alerts += 1
        for txid, ts, ip, raw in con.execute('select txid,ts,ip,rawhex from txs').fetchall():
            _, outs = tx_io(raw)
            if any(script_to_address(sc) == addr for v, sc in outs):
                mark = 'watch_tx:' + addr + ':' + txid
                if not con.execute('select 1 from alerts where detail like ?',
                                   ('%' + mark + '%',)).fetchone():
                    con.execute('insert into alerts(ts,kind,detail) values(?,?,?)',
                                (ts, 'watch_tx', '%s recibe en %s difundida por %s %s'
                                 % (addr, txid[:16], ip, mark)))
                    new_alerts += 1
    con.commit()
    if client:
        client.s.close()
    print('bursts: %d | wallets: %d | alertas nuevas: %d' % (len(bursts), len(wid), new_alerts))

if __name__ == '__main__':
    main()
