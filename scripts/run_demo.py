#!/usr/bin/env python3
"""
run_demo.py — автоматичні сценарії демонстрації брандмауера (лише stdlib).

Потрібно, щоб уже працювали:  scripts/echo_server.py  і  firewall.py --config config.json
Запуск: python scripts/run_demo.py
"""
import json, socket, sys, urllib.request, urllib.error

API = 'http://127.0.0.1:8081'
results = []


def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b'{}')


MAIN_PORT = 8086          # проксі → echo 9000 (8080 часто зайнятий nginx)


def tcp(port=MAIN_PORT, msg=b'hello'):
    """True — з'єднання пройшло (отримали echo), False — відхилено."""
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as s:
            s.sendall(msg)
            return s.recv(4096).startswith(b'ECHO:')
    except OSError:
        return False


def udp(msg=b'ping'):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    try:
        s.sendto(msg, ('127.0.0.1', 5353))
        return s.recvfrom(4096)[0].startswith(b'ECHO:')
    except OSError:
        return False
    finally:
        s.close()


def check(sid, title, ok, detail=''):
    results.append(bool(ok))
    print(f'[{"PASS" if ok else "FAIL"}] {sid:<4} {title}' + (f'  — {detail}' if detail else ''))


def rule(**kw):
    base = {'action': 'deny', 'src_ip_cidr': '0.0.0.0/0', 'dst_ip_cidr': '0.0.0.0/0',
            'src_port': 0, 'dst_port': 9000, 'proto': 'TCP', 'priority': 100, 'enabled': True}
    base.update(kw)
    return base


def main():
    try:
        current = api('GET', '/rules')
    except Exception as e:
        sys.exit(f'Admin API недоступний ({e}). Спершу запустіть firewall.py.')
    for r in current:                         # чистий старт
        api('DELETE', f'/rules/{r["id"]}')

    print('=' * 70)
    print('  ЛР7 — сценарії демонстрації програмного брандмауера')
    print('=' * 70)

    check('S01', 'Без правил TCP проходить (implicit allow)', tcp())

    r_deny = api('POST', '/rules', rule(comment='block echo 9000'))
    check('S02', "Додано deny TCP :9000 → з'єднання відхилено",
          'id' in r_deny and not tcp(), f'id={r_deny.get("id")}')

    r_allow = api('POST', '/rules', rule(action='allow', src_ip_cidr='127.0.0.1/32',
                                         priority=10, comment='allow localhost'))
    check('S03', 'allow priority=10 → проходить без перезапуску', tcp(),
          f'id={r_allow.get("id")}, warnings={[w["warning"] for w in r_allow.get("warnings", [])]}')

    dup = api('POST', '/rules', rule(comment='block echo 9000'))
    check('S04', 'Точний дублікат відхилено', dup.get('warning') == 'duplicate_rule',
          json.dumps(dup, ensure_ascii=False))

    c1 = api('POST', '/rules', rule(action='allow', comment='same spec, other action'))
    kinds = [w['warning'] for w in c1.get('warnings', [])]
    check('S05', 'Конфлікт тієї ж специфічності → попередження',
          'conflict_same_specificity' in kinds, f'id={c1.get("id")}, {kinds}')

    c2 = api('POST', '/rules', rule(action='deny', dst_ip_cidr='127.0.0.0/8', priority=50,
                                    comment='deny 127/8'))
    kinds2 = [w['warning'] for w in c2.get('warnings', [])]
    check('S06', 'Перекриття CIDR з різною дією → overlap_conflict',
          'overlap_conflict' in kinds2, f'id={c2.get("id")}, {kinds2}')

    conf = api('GET', '/conflicts')
    types = sorted({c['type'] for c in conf.get('conflicts', [])})
    check('S07', 'GET /conflicts — аудит таблиці правил', conf.get('count', 0) > 0,
          f'count={conf.get("count")}, types={types}')
    for c in conf.get('conflicts', []):
        print(f'        · {c["type"]:<9} {c["resolution"]}')

    api('PATCH', f'/rules/{r_allow["id"]}', {'enabled': False})
    check('S08', 'PATCH enabled=false для allow → знову deny', not tcp())

    for rid in (r_deny['id'], r_allow['id'], c1['id'], c2['id']):
        api('DELETE', f'/rules/{rid}')
    check('S09', 'DELETE правил → трафік знову проходить', tcp(),
          f'rules={len(api("GET", "/rules"))}')

    u = api('POST', '/rules', rule(proto='UDP', dst_port=9001, comment='block udp echo'))
    blocked = not udp()
    api('PATCH', f'/rules/{u["id"]}', {'action': 'allow'})
    passed = udp()
    check('S10', 'UDP: deny → немає відповіді; PATCH action=allow → відповідь',
          blocked and passed, f'blocked={blocked}, passed={passed}')
    api('DELETE', f'/rules/{u["id"]}')

    scan = api('POST', '/rules', rule(dst_port=0, priority=1, comment='deny all TCP'))
    res = [tcp(p) for p in (MAIN_PORT, 8082, 8083, 8084, 8085)]
    check('S11', 'deny all TCP + «сканування» 5 портів → усі відхилені', not any(res))
    for _ in range(12):
        tcp(MAIN_PORT)
    check('S12', 'Серія з 12 відхилених спроб (для аналізатора)', True)
    api('DELETE', f'/rules/{scan["id"]}')

    logs = api('GET', '/logs?action=deny&proto=TCP&limit=5')
    check('S13', 'GET /logs?action=deny — пошук у журналі', logs.get('total', 0) > 0,
          f'total={logs.get("total")}, показано={logs.get("count")}')
    if logs.get('events'):
        print('        · reason останнього:', logs['events'][-1].get('reason'))

    keep = api('POST', '/rules', rule(dst_port=9005, comment='survives reload'))
    rl = api('POST', '/reload')
    survived = any(r['id'] == keep['id'] for r in api('GET', '/rules'))
    check('S14', 'POST /reload — гаряче перечитування config.json, API-правила збережено',
          rl.get('ok') and survived and not tcp(8085))
    api('DELETE', f'/rules/{keep["id"]}')

    bad = api('POST', '/rules', {'priority': 'abc'})
    check('S15', 'Некоректне правило → 400 bad_rule', bad.get('error') == 'bad_rule')

    print('=' * 70)
    print(f'  Результат: {sum(results)}/{len(results)} PASS')
    print('=' * 70)
    sys.exit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
