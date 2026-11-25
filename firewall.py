"""
firewall.py — user-space програмний брандмауер (демо).

Запуск: python firewall.py --config config.json
"""
import argparse, json, os, threading, time, socket, selectors, ipaddress, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass, field
from typing import List

LOG_PATH = 'logs/events.jsonl'
_LOG_LOCK = threading.Lock()


def jlog(obj: dict):
    """Запис події у JSONL-журнал (thread-safe)."""
    obj.setdefault('ts_iso', datetime.datetime.fromtimestamp(obj['ts']).isoformat(timespec='seconds'))
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with _LOG_LOCK:
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')


# ---------------------------------------------------------------------------
# Структура правила
# ---------------------------------------------------------------------------

@dataclass(order=True)
class Rule:
    priority: int                                   # менше = вищий пріоритет
    id: int      = field(compare=False, default=0)
    action: str  = field(compare=False, default='deny')   # 'allow' | 'deny'
    src_ip_cidr: str = field(compare=False, default='0.0.0.0/0')
    dst_ip_cidr: str = field(compare=False, default='0.0.0.0/0')
    src_port: int    = field(compare=False, default=0)    # 0 = будь-який
    dst_port: int    = field(compare=False, default=0)
    proto: str       = field(compare=False, default='TCP')# 'TCP' | 'UDP'
    enabled: bool    = field(compare=False, default=True)
    comment: str     = field(compare=False, default='')

    def matches(self, src_ip, dst_ip, src_port, dst_port, proto):
        if not self.enabled:
            return False
        if self.proto.upper() != proto.upper():
            return False
        try:
            if ipaddress.ip_address(src_ip) not in ipaddress.ip_network(self.src_ip_cidr, strict=False):
                return False
            if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(self.dst_ip_cidr, strict=False):
                return False
        except Exception:
            return False
        if self.src_port and self.src_port != src_port:
            return False
        if self.dst_port and self.dst_port != dst_port:
            return False
        return True


def _nets_overlap(a: str, b: str) -> bool:
    """True, якщо два CIDR перетинаються."""
    try:
        return ipaddress.ip_network(a, strict=False).overlaps(
               ipaddress.ip_network(b, strict=False))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Набір правил із виявленням конфліктів
# ---------------------------------------------------------------------------

class RuleSet:
    def __init__(self, rules=None):
        self._lock = threading.Lock()
        self.rules: List[Rule] = sorted(rules or [])
        self.next_id = (max((r.id for r in self.rules), default=0) + 1)

    def to_dict(self):
        with self._lock:
            return [vars(r).copy() for r in self.rules]

    def get_by_id(self, rid: int):
        with self._lock:
            for r in self.rules:
                if r.id == rid:
                    return vars(r).copy()
        return None

    def add(self, r: Rule):
        """
        Додати правило з перевіркою конфліктів.

        Виявлення:
          duplicate_rule             — точний збіг + та сама дія → відхиляється.
          conflict_same_specificity  — точний збіг + інша дія → попередження.
          overlap_conflict           — перетин CIDR з іншою дією → попередження.
        """
        with self._lock:
            warnings = []
            for x in self.rules:
                # Трафік перетинається?
                same_traffic = (
                    x.proto.lower() == r.proto.lower()
                    and _nets_overlap(x.src_ip_cidr, r.src_ip_cidr)
                    and _nets_overlap(x.dst_ip_cidr, r.dst_ip_cidr)
                    and (x.src_port == 0 or r.src_port == 0 or x.src_port == r.src_port)
                    and (x.dst_port == 0 or r.dst_port == 0 or x.dst_port == r.dst_port)
                )
                if not same_traffic:
                    continue
                # Точний дублікат (включно з priority)?
                exact = (x.src_ip_cidr == r.src_ip_cidr and x.dst_ip_cidr == r.dst_ip_cidr
                         and x.src_port == r.src_port and x.dst_port == r.dst_port
                         and x.priority == r.priority)
                if exact and x.action == r.action:
                    return {'warning': 'duplicate_rule', 'existing_id': x.id}
                if exact and x.action != r.action:
                    warnings.append({'warning': 'conflict_same_specificity', 'existing_id': x.id,
                                     'detail': f'правило {x.id} має ту саму специфічність, але іншу дію'})
                elif x.action != r.action:
                    warnings.append({'warning': 'overlap_conflict', 'existing_id': x.id,
                                     'detail': (f'правило {x.id} ({x.proto} {x.src_ip_cidr}→'
                                                f'{x.dst_ip_cidr}:{x.dst_port}) перетинається, дія різна')})

            r.id = self.next_id
            self.next_id += 1
            self.rules.append(r)
            self.rules.sort()
            result: dict = {'id': r.id}
            if warnings:
                result['warnings'] = warnings
            return result

    def remove(self, rid: int):
        with self._lock:
            self.rules = [r for r in self.rules if r.id != rid]

    def update(self, rid: int, **kw):
        with self._lock:
            for r in self.rules:
                if r.id == rid:
                    for k, v in kw.items():
                        if hasattr(r, k):
                            setattr(r, k, v)
                    self.rules.sort()
                    return True
        return False

    def find_conflicts(self):
        """
        Аудит усієї таблиці правил (GET /conflicts).
          duplicate  — однакові поля трафіку та дія (надлишкове правило);
          conflict   — трафік перетинається, дії різні (вирішується пріоритетом);
          shadowed   — правило з вищим пріоритетом повністю покриває нижче,
                       тому нижче ніколи не спрацює.
        Вимкнені правила не аналізуються.
        """
        def covers(a: Rule, b: Rule) -> bool:   # a ⊇ b
            try:
                return (ipaddress.ip_network(b.src_ip_cidr, strict=False).subnet_of(
                            ipaddress.ip_network(a.src_ip_cidr, strict=False))
                        and ipaddress.ip_network(b.dst_ip_cidr, strict=False).subnet_of(
                            ipaddress.ip_network(a.dst_ip_cidr, strict=False))
                        and (a.src_port == 0 or a.src_port == b.src_port)
                        and (a.dst_port == 0 or a.dst_port == b.dst_port))
            except Exception:
                return False

        with self._lock:
            active = [r for r in self.rules if r.enabled]
        found = []
        for i, a in enumerate(active):          # active відсортовано: a має вищий пріоритет
            for b in active[i + 1:]:
                if a.proto.upper() != b.proto.upper():
                    continue
                same = (a.src_ip_cidr, a.dst_ip_cidr, a.src_port, a.dst_port) == \
                       (b.src_ip_cidr, b.dst_ip_cidr, b.src_port, b.dst_port)
                overlap = (_nets_overlap(a.src_ip_cidr, b.src_ip_cidr)
                           and _nets_overlap(a.dst_ip_cidr, b.dst_ip_cidr)
                           and (0 in (a.src_port, b.src_port) or a.src_port == b.src_port)
                           and (0 in (a.dst_port, b.dst_port) or a.dst_port == b.dst_port))
                if not overlap:
                    continue
                if same and a.action == b.action:
                    kind = 'duplicate'
                elif covers(a, b):
                    kind = 'shadowed'
                elif a.action != b.action:
                    kind = 'conflict'
                else:
                    continue
                found.append({
                    'type': kind, 'winner_id': a.id, 'loser_id': b.id,
                    'resolution': (f'діє правило {a.id} (priority={a.priority}, {a.action}); '
                                   f'правило {b.id} (priority={b.priority}, {b.action}) '
                                   + ('ніколи не спрацює' if kind in ('duplicate', 'shadowed')
                                      else 'спрацює лише поза зоною перетину')),
                })
        return found

    def reason(self, rid: int, action: str) -> str:
        """Людиночитна причина рішення для журналу."""
        if rid == 0:
            return 'implicit_allow: жодне правило не збіглося'
        with self._lock:
            r = next((x for x in self.rules if x.id == rid), None)
        if r is None:
            return f'rule {rid}'
        desc = r.comment or f'{r.proto} {r.src_ip_cidr}->{r.dst_ip_cidr}:{r.dst_port or "*"}'
        return f'rule {rid} ({action}, priority={r.priority}): {desc}'

    def decide(self, src_ip, dst_ip, src_port, dst_port, proto):
        """Перший збіг (вищий пріоритет). Якщо збігу немає — implicit allow."""
        with self._lock:
            for r in self.rules:
                if r.matches(src_ip, dst_ip, src_port, dst_port, proto):
                    return r.action, r.id
        return 'allow', 0


# ---------------------------------------------------------------------------
# TCP-проксі
# ---------------------------------------------------------------------------

def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host


def tcp_proxy(listen_host, listen_port, target_host, target_port, rm):
    """
    Приймає TCP-з'єднання, перевіряє rm.ruleset, проксює або відхиляє.
    rm передається за посиланням → reload() одразу вступає в силу.
    """
    sel = selectors.DefaultSelector()
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((listen_host, listen_port))
    ls.listen(128)
    ls.setblocking(False)
    sel.register(ls, selectors.EVENT_READ)

    def accept(sock):
        conn, addr = sock.accept()
        conn.setblocking(False)
        src_ip, src_port = addr
        dst_ip = _resolve(target_host)
        action, rid = rm.ruleset.decide(src_ip, dst_ip, src_port, target_port, 'TCP')
        jlog({'ts': time.time(), 'event': 'tcp.connect', 'proto': 'TCP',
              'src': list(addr), 'dst': [dst_ip, target_port],
              'action': action, 'rule_id': rid, 'reason': rm.ruleset.reason(rid, action)})
        if action != 'allow':
            conn.close()
            return
        try:
            upstream = socket.create_connection((target_host, target_port), timeout=5)
            upstream.setblocking(False)
        except Exception as e:
            jlog({'ts': time.time(), 'event': 'tcp.error',
                  'src': list(addr), 'dst': [target_host, target_port], 'err': str(e)})
            conn.close()
            return
        sel.register(conn,     selectors.EVENT_READ, data=upstream)
        sel.register(upstream, selectors.EVENT_READ, data=conn)

    def forward(src, dst):
        try:
            data = src.recv(4096)
            if not data:
                for s in (src, dst):
                    try: sel.unregister(s)
                    except Exception: pass
                    try: s.close()
                    except Exception: pass
                return
            dst.sendall(data)
        except Exception:
            for s in (src, dst):
                try: sel.unregister(s)
                except Exception: pass
                try: s.close()
                except Exception: pass

    while True:
        for key, _ in sel.select(timeout=1):
            if key.fileobj is ls:
                accept(ls)
            else:
                forward(key.fileobj, key.data)


# ---------------------------------------------------------------------------
# UDP-релей
# ---------------------------------------------------------------------------

def udp_proxy(listen_host, listen_port, target_host, target_port, rm):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_host, listen_port))
    while True:
        data, addr = sock.recvfrom(65535)
        src_ip, src_port = addr
        dst_ip = _resolve(target_host)
        action, rid = rm.ruleset.decide(src_ip, dst_ip, src_port, target_port, 'UDP')
        jlog({'ts': time.time(), 'event': 'udp.packet', 'proto': 'UDP',
              'bytes': len(data), 'src': list(addr), 'dst': [dst_ip, target_port],
              'action': action, 'rule_id': rid, 'reason': rm.ruleset.reason(rid, action)})
        if action != 'allow':
            continue
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(2)
            up.sendto(data, (dst_ip, target_port))
            try:
                resp, _ = up.recvfrom(65535)
                sock.sendto(resp, addr)
            except socket.timeout:
                pass
            up.close()
        except Exception as e:
            jlog({'ts': time.time(), 'event': 'udp.error', 'err': str(e)})


# ---------------------------------------------------------------------------
# Admin REST API (stdlib http.server)
# ---------------------------------------------------------------------------

_rm = None   # RuleManager; встановлюється в main()


def _search_logs(qs: dict) -> dict:
    path = LOG_PATH
    if not os.path.exists(path):
        return {'events': [], 'count': 0, 'total': 0}
    limit   = int((qs.get('limit')  or ['100'])[0])
    action_f = (qs.get('action') or [None])[0]
    src_f    = (qs.get('src')    or [None])[0]
    proto_f  = (qs.get('proto')  or [None])[0]
    event_f  = (qs.get('event')  or [None])[0]
    results  = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                e = json.loads(line)
            except Exception:
                continue
            if action_f and e.get('action') != action_f: continue
            if proto_f  and e.get('proto', '').upper() != proto_f.upper(): continue
            if event_f  and e.get('event') != event_f: continue
            if src_f:
                s = e.get('src', '')
                if isinstance(s, list): s = s[0]
                if src_f not in str(s): continue
            results.append(e)
    total = len(results)
    return {'events': results[-limit:], 'count': min(len(results), limit), 'total': total}


class _Admin(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass   # прибрати шум HTTP-логів у консолі

    def _json(self, code, payload):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload, ensure_ascii=False, default=str).encode())

    def _body(self):
        n = int(self.headers.get('Content-Length', '0'))
        return json.loads(self.rfile.read(n) or b'{}')

    def do_GET(self):
        p = urlparse(self.path)
        parts = [x for x in p.path.strip('/').split('/') if x]
        if parts == ['conflicts']:
            c = _rm.ruleset.find_conflicts()
            return self._json(200, {'count': len(c), 'conflicts': c})
        if not parts or parts[0] not in ('rules', 'logs'):
            return self._json(404, {'error': 'not_found'})
        if parts[0] == 'rules':
            if len(parts) == 1:
                return self._json(200, _rm.ruleset.to_dict())
            try:
                d = _rm.ruleset.get_by_id(int(parts[1]))
                return self._json(200 if d else 404, d or {'error': 'not_found'})
            except ValueError:
                return self._json(400, {'error': 'bad id'})
        if parts[0] == 'logs':
            return self._json(200, _search_logs(parse_qs(p.query)))

    def do_POST(self):
        parts = [x for x in urlparse(self.path).path.strip('/').split('/') if x]
        if not parts:
            return self._json(404, {'error': 'not_found'})
        if parts[0] == 'rules':
            body = self._body()
            try:
                r = Rule(
                    priority    = int(body.get('priority', 100)),
                    action      = body.get('action', 'deny'),
                    src_ip_cidr = body.get('src_ip_cidr', '0.0.0.0/0'),
                    dst_ip_cidr = body.get('dst_ip_cidr', '0.0.0.0/0'),
                    src_port    = int(body.get('src_port', 0)),
                    dst_port    = int(body.get('dst_port', 0)),
                    proto       = body.get('proto', 'TCP'),
                    enabled     = bool(body.get('enabled', True)),
                    comment     = body.get('comment', ''),
                )
            except Exception as e:
                return self._json(400, {'error': 'bad_rule', 'detail': str(e)})
            return self._json(200, _rm.ruleset.add(r))
        if parts[0] == 'reload':
            _rm.load()
            return self._json(200, {'ok': True, 'rules': len(_rm.ruleset.rules)})
        return self._json(404, {'error': 'not_found'})

    def do_PATCH(self):
        parts = [x for x in urlparse(self.path).path.strip('/').split('/') if x]
        if len(parts) == 2 and parts[0] == 'rules':
            try:
                rid = int(parts[1])
            except ValueError:
                return self._json(400, {'error': 'bad id'})
            ok = _rm.ruleset.update(rid, **self._body())
            return self._json(200 if ok else 404, {'ok': ok})
        return self._json(404, {'error': 'not_found'})

    def do_DELETE(self):
        parts = [x for x in urlparse(self.path).path.strip('/').split('/') if x]
        if len(parts) == 2 and parts[0] == 'rules':
            try:
                rid = int(parts[1])
            except ValueError:
                return self._json(400, {'error': 'bad id'})
            _rm.ruleset.remove(rid)
            return self._json(200, {'ok': True})
        return self._json(404, {'error': 'not_found'})


# ---------------------------------------------------------------------------
# Менеджер конфігурації
# ---------------------------------------------------------------------------

class RuleManager:
    def __init__(self, path: str):
        self.path = path
        self.ruleset = RuleSet([])
        self._services = []
        self._admin_host = '127.0.0.1'
        self._admin_port = 8081
        self.load()

    def load(self):
        """Гаряче перезавантаження config.json (правила API зберігаються)."""
        global LOG_PATH
        with open(self.path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        LOG_PATH = cfg.get('logging', {}).get('path', LOG_PATH)
        self._services    = cfg.get('services', [])
        self._admin_host  = cfg.get('admin', {}).get('host', '127.0.0.1')
        self._admin_port  = cfg.get('admin', {}).get('port', 8081)

        # Правила з файлу
        new_rules = []
        for d in cfg.get('rules', []):
            new_rules.append(Rule(
                priority    = d.get('priority', 100),
                id          = d.get('id', 0),
                action      = d.get('action', 'deny'),
                src_ip_cidr = d.get('src_ip_cidr', '0.0.0.0/0'),
                dst_ip_cidr = d.get('dst_ip_cidr', '0.0.0.0/0'),
                src_port    = d.get('src_port', 0),
                dst_port    = d.get('dst_port', 0),
                proto       = d.get('proto', 'TCP'),
                enabled     = d.get('enabled', True),
                comment     = d.get('comment', ''),
            ))
        new_rs  = RuleSet(new_rules)
        cfg_ids = {r.id for r in new_rs.rules}
        # Зберегти правила, додані через API (їх нема в конфізі), з тими самими id
        for r in self.ruleset.rules:
            if r.id not in cfg_ids:
                new_rs.rules.append(r)
        new_rs.rules.sort()
        new_rs.next_id = max([new_rs.next_id, self.ruleset.next_id] +
                             [r.id + 1 for r in new_rs.rules])
        self.ruleset = new_rs

    @property
    def services(self):    return self._services
    @property
    def admin_host(self):  return self._admin_host
    @property
    def admin_port(self):  return self._admin_port


# ---------------------------------------------------------------------------
# Точка входу
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='User-space firewall proxy demo (ЛР №7)')
    ap.add_argument('--config', default='config.json', help='шлях до config.json')
    args = ap.parse_args()

    global _rm
    _rm = RuleManager(args.config)

    admin_srv = HTTPServer((_rm.admin_host, _rm.admin_port), _Admin)
    threading.Thread(target=admin_srv.serve_forever, daemon=True, name='admin-api').start()
    print(f'[*] Admin API  http://{_rm.admin_host}:{_rm.admin_port}')
    print(f'    GET /rules | POST /rules | PATCH /rules/{{id}} | DELETE /rules/{{id}}')
    print(f'    POST /reload | GET /conflicts | GET /logs?action=deny&limit=20')

    threads = []
    for s in _rm.services:
        proto = s.get('proto', 'TCP').upper()
        fn = tcp_proxy if proto == 'TCP' else udp_proxy
        t = threading.Thread(
            target=fn,
            args=(s['listen_host'], s['listen_port'],
                  s['target_host'],  s['target_port'], _rm),
            daemon=True,
            name=f'{proto}:{s["listen_port"]}',
        )
        t.start()
        threads.append(t)
        print(f'[*] {proto} proxy  {s["listen_host"]}:{s["listen_port"]}'
              f'  →  {s["target_host"]}:{s["target_port"]}')

    print('[*] Натисніть Ctrl+C для зупинки.\n')
    try:
        [t.join() for t in threads]
    except KeyboardInterrupt:
        print('\n[*] Зупинка...')


if __name__ == '__main__':
    main()
