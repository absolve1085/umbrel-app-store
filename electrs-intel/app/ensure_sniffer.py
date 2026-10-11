#!/usr/bin/env python3
import json, os, socket, io, tarfile, sys, time

SOCK = '/var/run/docker.sock'
NAME = 'electrs-intel-sniffer'
IMAGE = 'electrs-intel-sniffer:0.2.2'

def req(method, path, body=None, raw=False):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    data = b'' if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    h = '%s %s HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n' % (method, path)
    if body is not None:
        h += 'Content-Type: %s\r\nContent-Length: %d\r\n' % (
            'application/x-tar' if raw else 'application/json', len(data))
    s.sendall(h.encode() + b'\r\n' + data)
    buf = b''
    while True:
        d = s.recv(65536)
        if not d:
            break
        buf += d
    s.close()
    head, _, body_out = buf.partition(b'\r\n\r\n')
    status = int(head.split(b' ')[1])
    return status, body_out

def image_exists():
    return req('GET', '/images/%s/json' % IMAGE)[0] == 200

def build_image():
    df = b'FROM alpine:3.20\nRUN apk add --no-cache tcpdump\nENTRYPOINT ["tcpdump"]\n'
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode='w') as t:
        info = tarfile.TarInfo('Dockerfile')
        info.size = len(df)
        t.addfile(info, io.BytesIO(df))
    last = b''
    for attempt in range(3):
        try:
            st, out = req('POST', '/build?t=' + IMAGE, bio.getvalue(), raw=True)
        except Exception as e:
            # el build via sock a veces se corta a mitad de stream (pull lento)
            last = repr(e).encode()
            time.sleep(10)
            continue
        if st in (200, 201):
            return
        last = out[-300:]
        time.sleep(10)
    print('build fallo:', last)
    sys.exit(1)

def container_state():
    st, out = req('GET', '/containers/%s/json' % NAME)
    if st != 200:
        return None
    return json.loads(out)

def tcpdump_cmd(port, excl):
    cmd = ['-i', 'any', '-s0', '-U', '-W', '30', '-C', '100',
           '-w', '/data/capture.pcap', 'tcp', 'port', str(port)]
    for ip in excl:
        cmd += ['and', 'not', 'host', ip]
    return cmd

def main():
    data_dir = os.environ.get('APP_DATA_DIR', '/data')
    port = os.environ.get('ELECTRUM_PORT', '50001')
    excl = [ip.strip() for ip in os.environ.get('EXCLUDE_IPS', '').split(',') if ip.strip()]
    if not image_exists():
        print('compilando imagen', IMAGE)
        build_image()
    c = container_state()
    joined = ' '.join(c['Config']['Cmd']) if (c and c.get('Config', {}).get('Cmd')) else ''
    needed = ['port %s' % port] + ['host %s' % ip for ip in excl]
    cmd_ok = c and all(n in joined for n in needed)
    if c:
        running = c.get('State', {}).get('Running')
        if running and cmd_ok:
            print('sniffer ya corriendo en puerto', port)
            return
        req('DELETE', '/containers/%s?force=1' % NAME)
    body = {
        'Image': IMAGE,
        'Cmd': tcpdump_cmd(port, excl),
        'HostConfig': {
            'NetworkMode': 'host',
            'CapAdd': ['NET_RAW', 'NET_ADMIN'],
            'Binds': [data_dir.rstrip('/') + '/data:/data'],
            'RestartPolicy': {'Name': 'unless-stopped'},
        },
    }
    st, out = req('POST', '/containers/create?name=' + NAME, body)
    if st not in (200, 201):
        print('create fallo:', st, out[:300])
        sys.exit(1)
    st, _ = req('POST', '/containers/%s/start' % NAME)
    print('sniffer %s (puerto %s)' % ('iniciado' if st in (200, 204) else 'fallo al iniciar: %s' % st, port))

if __name__ == '__main__':
    main()
