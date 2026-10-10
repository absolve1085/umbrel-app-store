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

def main():
    port = os.environ.get('ELECTRUM_PORT', '50001')
    try:
        containers = http_unix('/containers/json')
    except Exception:
        print('')
        return
    for c in containers:
        if c.get('State') != 'running':
            continue
        names = ' '.join(c.get('Names') or []).lower()
        if any(x in names for x in EXCLUDE):
            continue
        if any(k in names for k in ('electrs', 'electrumx', 'fulcrum', 'electrum')):
            for net in ((c.get('NetworkSettings') or {}).get('Networks') or {}).values():
                ip = net.get('IPAddress')
                if ip:
                    print('%s:%s' % (ip, port))
                    return
    print('')

if __name__ == '__main__':
    main()
