#!/usr/bin/env python3
import json, sqlite3, argparse, time, urllib.request, ipaddress

def internal_label(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return 'ip no valida'
    if a.is_loopback:
        return 'localhost'
    if a.version == 4 and a in ipaddress.ip_network('172.16.0.0/12'):
        return 'red interna docker (posible contenedor Tor del servidor)'
    if a.is_private:
        return 'red privada LAN (NAT)'
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', default='snoop.db')
    ap.add_argument('--refresh', action='store_true')
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.execute('''create table if not exists geo(ip text primary key, label text, country text,
        country_code text, city text, isp text, lat real, lon real, proxy int, hosting int,
        asn text, checked_at real)''')
    ips = [r[0] for r in con.execute('select distinct ip from conns')]
    todo = []
    for ip in ips:
        lab = internal_label(ip)
        if lab:
            con.execute('insert or replace into geo(ip,label,checked_at) values(?,?,?)',
                        (ip, lab, time.time()))
        elif a.refresh or not con.execute('select 1 from geo where ip=?', (ip,)).fetchone():
            todo.append(ip)
    for i in range(0, len(todo), 100):
        batch = todo[i:i + 100]
        req = urllib.request.Request('http://ip-api.com/batch', data=json.dumps(batch).encode(),
                                     headers={'Content-Type': 'application/json'})
        try:
            res = json.loads(urllib.request.urlopen(req, timeout=20).read())
        except Exception as e:
            print('error geo:', e)
            break
        for ip, r in zip(batch, res):
            if r.get('status') != 'success':
                con.execute('insert or replace into geo(ip,label,checked_at) values(?,?,?)',
                            (ip, 'sin datos', time.time()))
                continue
            con.execute('''insert or replace into geo values(?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (ip, None, r.get('country'), r.get('countryCode'), r.get('city'),
                         r.get('isp'), r.get('lat'), r.get('lon'), int(bool(r.get('proxy'))),
                         int(bool(r.get('hosting'))), r.get('as'), time.time()))
    con.commit()
    for (ip,) in con.execute('select ip from geo'):
        row = con.execute('select label,country,city,isp from geo where ip=?', (ip,)).fetchone()
        print(ip, '->', row[0] or ' | '.join(str(x) for x in row[1:] if x))

if __name__ == '__main__':
    main()
