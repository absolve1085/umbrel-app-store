#!/usr/bin/env python3
import json, os, socket

EXCLUDE = ('electrs-intel', 'intel', 'monitor', 'sniffer', 'buildx')

def http_unix(path, sock='/var/run/docker.sock'):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock)
    s.send(('GET %s HTTP/1.0\r\n\r\n' % path).encode())
    buf = b''
    while True:
        d = s.recv(65536)
        if not d:
            break
        buf += d
    s.close()
    return json.loads(buf.split(b'\r\n\r\n', 1)[1])

def default_gateway():
    try:
        for line in open('/proc/net/route').read().splitlines()[1:]:
            f = line.split()
            if f[1] == '00000000':
                return '.'.join(str(int(f[2][i:i+2], 16)) for i in (6, 4, 2, 0))
    except Exception:
        pass
    return None

def reachable(host, port, timeout=2):
    try:
        s = socket.create_connection((host, int(port)), timeout)
        s.close()
        return True
    except Exception:
        return False

def main():
    port = os.environ.get('ELECTRUM_PORT', '50001')
    gw = default_gateway()
    try:
        containers = http_unix('/containers/json')
    except Exception:
        containers = []
    for c in containers:
        if c.get('State') != 'running':
            continue
        names = ' '.join(c.get('Names') or []).lower()
        if any(x in names for x in EXCLUDE):
            continue
        if any(k in names for k in ('electrs', 'electrumx', 'fulcrum', 'electrum')):
            # puerto publicado en el host -> usar el gateway (las redes docker
            # estan aisladas entre si, la IP interna del contenedor no es
            # alcanzable desde la red de esta app)
            pubs = [p.get('PublicPort') for p in (c.get('Ports') or []) if p.get('PublicPort')]
            pref = [p for p in pubs if str(p) == port] or [p for p in pubs if p == 50001] or pubs
            for pp in pref:
                if gw and reachable(gw, pp):
                    print('%s:%s' % (gw, pp))
                    return
            for net in ((c.get('NetworkSettings') or {}).get('Networks') or {}).values():
                ip = net.get('IPAddress')
                if ip and reachable(ip, port):
                    print('%s:%s' % (ip, port))
                    return
    if gw and reachable(gw, port):
        print('%s:%s' % (gw, port))
        return
    print('')

if __name__ == '__main__':
    main()
