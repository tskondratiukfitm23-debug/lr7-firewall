#!/usr/bin/env python3
"""
analyze_logs.py — інструмент аналізу журналу подій брандмауера.

Використання:
    python analyze_logs.py [logs/events.jsonl] [опції]

Опції:
    --action allow|deny       фільтр за дією
    --proto  TCP|UDP          фільтр за протоколом
    --src    IP               фільтр за IP-адресою джерела
    --dst    IP:PORT          фільтр за адресою призначення
    --event  tcp.connect|...  фільтр за типом події
    --from   YYYY-MM-DDTHH:MM початок діапазону часу
    --to     YYYY-MM-DDTHH:MM кінець діапазону часу
    --limit  N                показати останніх N рядків (за замовч. 1000)
    --json                    вивести у форматі JSON
    --anomalies               показати виявлені аномалії
    --events                  показати таблицю подій
"""
import argparse, json, sys, collections, datetime, os


# ---------------------------------------------------------------------------
# Завантаження і фільтрація подій
# ---------------------------------------------------------------------------

def _ts_parse(s: str) -> float:
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d'):
        try:
            return datetime.datetime.strptime(s, fmt).timestamp()
        except ValueError:
            pass
    raise ValueError(f'Невідомий формат часу: {s!r}')


def load_events(path: str, args) -> list:
    if not os.path.exists(path):
        sys.exit(f'Файл не знайдено: {path}')
    fr = _ts_parse(args.frm) if args.frm else None
    to = _ts_parse(args.to)  if args.to  else None
    events = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            ts = e.get('ts', 0)
            if fr and ts < fr: continue
            if to and ts > to: continue
            if args.action and e.get('action') != args.action: continue
            if args.proto  and e.get('proto', '').upper() != args.proto.upper(): continue
            if args.event  and e.get('event')  != args.event: continue
            if args.src:
                src = e.get('src', '')
                if isinstance(src, list): src = src[0]
                if args.src not in str(src): continue
            if args.dst:
                dst = e.get('dst', '')
                if isinstance(dst, list): dst = f'{dst[0]}:{dst[1]}'
                if args.dst not in str(dst): continue
            events.append(e)
    return events[-args.limit:]


# ---------------------------------------------------------------------------
# Допоміжні функції
# ---------------------------------------------------------------------------

def _fmt_ts(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S')


def _src_str(e: dict) -> str:
    s = e.get('src', '?')
    if isinstance(s, list):
        return str(s[0])
    return str(s)


def _dst_str(e: dict) -> str:
    d = e.get('dst', '?')
    if isinstance(d, list) and len(d) >= 2:
        return f'{d[0]}:{d[1]}'
    return str(d)


# ---------------------------------------------------------------------------
# Зведений звіт
# ---------------------------------------------------------------------------

def print_summary(events: list):
    total      = len(events)
    by_action  = collections.Counter(e.get('action', '—') for e in events)
    by_proto   = collections.Counter(e.get('proto',  '—') for e in events)
    by_event   = collections.Counter(e.get('event',  '—') for e in events)

    denies = [e for e in events if e.get('action') == 'deny']
    allows = [e for e in events if e.get('action') == 'allow']

    top_deny_src = collections.Counter(_src_str(e) for e in denies).most_common(5)
    top_deny_dst = collections.Counter(_dst_str(e) for e in denies).most_common(5)
    top_rule     = collections.Counter(e.get('rule_id') for e in events
                                       if e.get('rule_id')).most_common(5)

    sep = '=' * 62
    print(sep)
    print('  ЗВЕДЕНИЙ ЗВІТ ЖУРНАЛУ БРАНДМАУЕРА')
    print(sep)
    print(f'  Усього подій   : {total}')
    print(f'  Дозволено      : {by_action.get("allow", 0)}')
    print(f'  Відхилено      : {by_action.get("deny", 0)}')
    print(f'  По протоколах  : ' + ', '.join(f'{k}={v}' for k, v in by_proto.items()))
    print(f'  Типи подій     : ' + ', '.join(f'{k}={v}' for k, v in by_event.items()))

    if top_deny_src:
        print(f'\n  ТОП-5 джерел відхилених пакетів:')
        for ip, cnt in top_deny_src:
            print(f'    {ip:<22} {cnt} пакетів')

    if top_deny_dst:
        print(f'\n  ТОП-5 цілей відхилених пакетів:')
        for dst, cnt in top_deny_dst:
            print(f'    {dst:<28} {cnt} пакетів')

    if top_rule:
        print(f'\n  Найактивніші правила (rule_id):')
        for rid, cnt in top_rule:
            print(f'    id={rid:<4}  {cnt} спрацювань')

    print(sep)


# ---------------------------------------------------------------------------
# Таблиця подій
# ---------------------------------------------------------------------------

def print_events_table(events: list):
    hdr = f'  {"Час":<10} {"Подія":<18} {"Дія":<8} {"Прото":<6} {"Джерело":<22} {"Призначення":<24} {"Rule":<4}'
    print(f'\n{hdr}')
    print('  ' + '-' * 95)
    for e in events:
        print(f'  {_fmt_ts(e.get("ts", 0)):<10}'
              f' {e.get("event", "?"):<18}'
              f' {e.get("action", "—"):<8}'
              f' {e.get("proto", "?"):<6}'
              f' {_src_str(e):<22}'
              f' {_dst_str(e):<24}'
              f' {e.get("rule_id", "—")}')


# ---------------------------------------------------------------------------
# Виявлення аномалій
# ---------------------------------------------------------------------------

def detect_anomalies(events: list) -> list:
    anomalies = []

    # 1. Сканування портів: одне джерело відхилене на 5+ різних dst_port за 60 с
    deny_by_src: dict = collections.defaultdict(list)
    for e in events:
        if e.get('action') != 'deny':
            continue
        dst = e.get('dst', [])
        if not isinstance(dst, list) or len(dst) < 2:
            continue
        deny_by_src[_src_str(e)].append({'ts': e.get('ts', 0), 'port': dst[1]})

    for ip, entries in deny_by_src.items():
        entries.sort(key=lambda x: x['ts'])
        for i, start in enumerate(entries):
            window = [x for x in entries[i:] if x['ts'] - start['ts'] <= 60]
            ports  = {x['port'] for x in window}
            if len(ports) >= 5:
                anomalies.append({
                    'type': 'PORT_SCAN', 'severity': 'HIGH',
                    'src': ip,
                    'detail': f'{len(window)} спроб, {len(ports)} різних портів за 60 с',
                })
                break

    # 2. Масове відхилення: одна пара src+dst ≥ 10 разів
    deny_pairs: collections.Counter = collections.Counter()
    for e in events:
        if e.get('action') != 'deny':
            continue
        deny_pairs[(_src_str(e), _dst_str(e))] += 1

    for (src, dst), cnt in deny_pairs.items():
        if cnt >= 10:
            anomalies.append({
                'type': 'REPEATED_DENIAL', 'severity': 'MEDIUM',
                'src': src, 'dst': dst,
                'detail': f'відхилено {cnt} разів',
            })

    # 3. Помилки проксі
    errors = [e for e in events if 'error' in e.get('event', '')]
    if errors:
        anomalies.append({
            'type': 'PROXY_ERRORS', 'severity': 'LOW',
            'detail': f'{len(errors)} помилок проксі',
        })

    # 4. Нерівномірний трафік (сплеск): > 20 подій за 5 с
    times = sorted(e.get('ts', 0) for e in events)
    for i, t0 in enumerate(times):
        burst = sum(1 for t in times[i:] if t - t0 <= 5)
        if burst > 20:
            anomalies.append({
                'type': 'TRAFFIC_BURST', 'severity': 'MEDIUM',
                'detail': f'{burst} подій за 5 с починаючи з {_fmt_ts(t0)}',
            })
            break

    return anomalies


def print_anomalies(anomalies: list):
    print('\n  АНОМАЛІЇ:')
    if not anomalies:
        print('    Аномалій не виявлено.')
        return
    for a in anomalies:
        line = f'  [{a.get("severity","?"):6}] {a.get("type","?"):<22}'
        src = a.get('src', '')
        dst = a.get('dst', '')
        if src: line += f'  src={src}'
        if dst: line += f'  dst={dst}'
        line += f'  — {a.get("detail","")}'
        print(line)


# ---------------------------------------------------------------------------
# Пошук дублікатів / конфліктів у самому журналі
# ---------------------------------------------------------------------------

def detect_log_duplicates(events: list) -> list:
    """
    Знаходить повторювані шаблони трафіку (src+dst+proto+action),
    що можуть свідчити про дубльовані або надлишкові правила.
    """
    counter: collections.Counter = collections.Counter()
    for e in events:
        key = (_src_str(e), _dst_str(e),
               e.get('proto', '?'), e.get('action', '?'))
        counter[key] += 1
    return [(k, v) for k, v in counter.items() if v >= 5]


# ---------------------------------------------------------------------------
# Точка входу
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='Аналіз журналу брандмауера (ЛР №7)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('path',       nargs='?', default='logs/events.jsonl',
                    help='шлях до JSONL-журналу')
    ap.add_argument('--action',   help='фільтр: allow|deny')
    ap.add_argument('--proto',    help='фільтр: TCP|UDP')
    ap.add_argument('--src',      help='фільтр за IP-джерелом (підрядок)')
    ap.add_argument('--dst',      help='фільтр за призначенням (підрядок)')
    ap.add_argument('--event',    help='фільтр за типом події')
    ap.add_argument('--from',     dest='frm', metavar='DATETIME',
                    help='з часу (ISO, напр. 2025-01-01T12:00)')
    ap.add_argument('--to',       metavar='DATETIME',
                    help='до часу (ISO)')
    ap.add_argument('--limit',    type=int, default=1000,
                    help='максимум рядків (за замовч. 1000)')
    ap.add_argument('--json',     action='store_true',
                    help='вивести як JSON')
    ap.add_argument('--anomalies', action='store_true',
                    help='виявити аномалії (сканування портів, сплески тощо)')
    ap.add_argument('--events',   action='store_true',
                    help='показати таблицю подій')
    ap.add_argument('--dupes',    action='store_true',
                    help='знайти повторювані шаблони трафіку')
    args = ap.parse_args()

    events = load_events(args.path, args)

    if args.json:
        print(json.dumps(events, ensure_ascii=False, indent=2))
        return

    print_summary(events)

    if args.anomalies:
        anoms = detect_anomalies(events)
        print_anomalies(anoms)

    if args.dupes:
        dupes = detect_log_duplicates(events)
        print('\n  ПОВТОРЮВАНІ ШАБЛОНИ ТРАФІКУ (≥5 разів):')
        if not dupes:
            print('    Не знайдено.')
        for (src, dst, proto, action), cnt in sorted(dupes, key=lambda x: -x[1]):
            print(f'    {cnt:>4}×  {proto:<4} {action:<6}  {src} → {dst}')

    if args.events:
        print_events_table(events)


if __name__ == '__main__':
    main()
