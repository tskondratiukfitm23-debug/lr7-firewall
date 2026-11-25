# ЛР №7. Розробка програмного брандмауера

**Виконав:** Кондратюк Тимофій Сергійович, гр. 22340, ФІТМ, КСУ ім. Бориса Грінченка
**Дисципліна:** Прикладні аспекти програмування в системах інформаційної та кібербезпеки

Навчальний **user-space брандмауер** у вигляді L3/L4-проксі (TCP/UDP), що фільтрує трафік
за правилами (IP/CIDR, порт, протокол), веде JSONL-журнал подій, дозволяє **додавати, змінювати,
вимикати та видаляти правила без перезапуску** через REST API і виявляє **дубльовані, конфліктні
та затінені правила**. Потрібен лише Python ≥ 3.9 (тільки stdlib), права root не потрібні.

---

## 1. Структура проєкту

| Файл | Призначення |
|------|-------------|
| `firewall.py` | Сервіс: RuleEngine, TCP/UDP-проксі, Admin API, Logger |
| `config.json` | Конфігурація: Admin API, шлях журналу, сервіси-проксі, початкові правила |
| `analyze_logs.py` | Аналіз журналу: фільтри, зведення, таблиця, аномалії, повтори |
| `scripts/echo_server.py` | Локальні цільові TCP/UDP echo-сервіси (демо без інтернету) |
| `scripts/run_demo.py` | 15 автоматичних сценаріїв демонстрації (S01–S15) |
| `tests/test_firewall.py` | 24 модульні тести RuleEngine |

## 2. Швидкий старт

```bash
git clone https://github.com/tskondratiukfitm23-debug/lr7-firewall.git && cd lr7-firewall
python3 scripts/echo_server.py &                 # термінал 1: цільові сервіси
python3 firewall.py --config config.json         # термінал 2: брандмауер
python3 scripts/run_demo.py                      # термінал 3: 15 сценаріїв
python3 analyze_logs.py logs/events.jsonl --anomalies --dupes
python3 tests/test_firewall.py                   # або: python3 -m pytest -q
```

## 3. Архітектура

```
               ┌────────────────────────── firewall.py ──────────────────────────┐
 клієнт ──TCP──▶ TCP Proxy :8086,8082-8085 ─┐                                      │──▶ echo 9000,9002-9005
 клієнт ──UDP──▶ UDP Relay :5353 ───────────┼─▶ RuleEngine (RuleSet.decide) ──allow─│──▶ echo 9001
               │                            │        │ deny → close/drop          │
 адмін ──HTTP──▶ Admin API :8081 ──add/patch/delete/reload──▶ RuleSet (lock)       │
               │      │ GET /logs, /conflicts                │                     │
               │      ▼                                      ▼                     │
               │  RuleManager (config.json)          Logger → logs/events.jsonl ───┼──▶ analyze_logs.py
               └──────────────────────────────────────────────────────────────────┘
```

| Компонент | Реалізація | Роль |
|-----------|-----------|------|
| **Proxy** | `tcp_proxy()` (selectors), `udp_proxy()` | Приймає з'єднання/датаграму, питає RuleEngine, проксює або відкидає |
| **RuleEngine** | `Rule`, `RuleSet` | Зберігає відсортовану таблицю правил, `decide()`, `add()` з перевіркою конфліктів, `find_conflicts()` |
| **AdminAPI** | `_Admin` (`http.server`) | REST-керування правилами, пошук у журналі, аудит конфліктів |
| **Logger** | `jlog()` | Потокобезпечний запис JSONL (lock) |
| **RuleManager** | `RuleManager` | Читання `config.json`, гаряче перезавантаження (`/reload`) |

Проксі-потоки отримують **посилання на RuleManager**, а не копію правил, тому кожна зміна
через API або `/reload` діє з наступного з'єднання/датаграми — **без перезапуску**.
Доступ до таблиці захищено `threading.Lock`.

## 4. Структура правила

| Поле | Тип | За замовч. | Опис |
|------|-----|-----------|------|
| `id` | int | авто | Унікальний ідентифікатор (присвоює RuleSet) |
| `action` | `"allow"` \| `"deny"` | `deny` | Дія при збігу |
| `src_ip_cidr` | CIDR | `0.0.0.0/0` | Мережа джерела |
| `dst_ip_cidr` | CIDR | `0.0.0.0/0` | Мережа призначення (цільовий сервіс проксі) |
| `src_port` | 0–65535 | `0` | Порт джерела, `0` = будь-який |
| `dst_port` | 0–65535 | `0` | Порт призначення, `0` = будь-який |
| `proto` | `"TCP"` \| `"UDP"` | `TCP` | Протокол |
| `priority` | int | `100` | **Менше число = вищий пріоритет** |
| `enabled` | bool | `true` | Вимкнене правило ігнорується |
| `comment` | string | `""` | Опис; потрапляє в `reason` журналу |

JSON-схема:

```json
{
  "type": "object",
  "properties": {
    "action":      {"enum": ["allow", "deny"]},
    "src_ip_cidr": {"type": "string", "format": "cidr"},
    "dst_ip_cidr": {"type": "string", "format": "cidr"},
    "src_port":    {"type": "integer", "minimum": 0, "maximum": 65535},
    "dst_port":    {"type": "integer", "minimum": 0, "maximum": 65535},
    "proto":       {"enum": ["TCP", "UDP"]},
    "priority":    {"type": "integer"},
    "enabled":     {"type": "boolean"},
    "comment":     {"type": "string"}
  }
}
```

**Алгоритм рішення:** правила відсортовані за `priority` (за зростанням); перше увімкнене
правило, що збіглося за протоколом, CIDR і портами, визначає дію. Якщо збігу немає —
**implicit allow** (`rule_id = 0`). Для продакшну рекомендовано default-deny
(додати правило `deny` з найнижчим пріоритетом, напр. `priority: 65535`).

## 5. Admin API (`http://127.0.0.1:8081`)

| Метод | Шлях | Опис |
|-------|------|------|
| `GET` | `/rules` | Список правил (у порядку застосування) |
| `GET` | `/rules/{id}` | Одне правило |
| `POST` | `/rules` | Додати правило → `{"id": N}` + `warnings[]` або `{"warning":"duplicate_rule"}` |
| `PATCH` | `/rules/{id}` | Змінити поля (`enabled`, `action`, `priority`, …) |
| `DELETE` | `/rules/{id}` | Видалити правило |
| `POST` | `/reload` | Перечитати `config.json` (правила з API зберігаються) |
| `GET` | `/conflicts` | Аудит усієї таблиці: duplicate / conflict / shadowed |
| `GET` | `/logs?action=&proto=&src=&event=&limit=` | Пошук у журналі |

Приклади (`curl`):

```bash
curl -s -X POST localhost:8081/rules -H 'Content-Type: application/json' \
  -d '{"action":"deny","dst_port":9000,"proto":"TCP","priority":100,"comment":"block echo"}'
curl -s -X PATCH localhost:8081/rules/1 -d '{"enabled":false}'
curl -s -X DELETE localhost:8081/rules/1
curl -s localhost:8081/conflicts
curl -s 'localhost:8081/logs?action=deny&limit=5'
```

## 6. Журнал подій

Кожне рішення (allow і deny) записується одним JSON-рядком у `logs/events.jsonl`:

```json
{"ts": 1795626432.93, "ts_iso": "2026-11-25T17:07:12", "event": "tcp.connect", "proto": "TCP",
 "src": ["127.0.0.1", 37454], "dst": ["127.0.0.1", 9005], "action": "deny", "rule_id": 7,
 "reason": "rule 7 (deny, priority=100): survives reload"}
```

| Поле | Опис |
|------|------|
| `ts`, `ts_iso` | Час (epoch і ISO-8601) |
| `event` | `tcp.connect`, `udp.packet`, `tcp.error`, `udp.error` |
| `proto`, `src`, `dst` | Протокол, джерело `[ip, port]`, призначення `[ip, port]` |
| `action`, `rule_id` | Рішення і правило, що спрацювало (`0` = implicit allow) |
| `reason` | Причина: правило, дія, пріоритет, коментар |
| `bytes` | Розмір датаграми (UDP) |

Формат JSONL дозволяє дописувати без блокування всього файлу, обробляти потоково та
імпортувати в ELK/Splunk/SQLite.

### Аналізатор `analyze_logs.py`

```bash
python3 analyze_logs.py logs/events.jsonl                       # зведення
python3 analyze_logs.py --action deny --proto TCP --events      # таблиця відхилених TCP
python3 analyze_logs.py --src 127.0.0.1 --from 2026-11-25T17:00 --to 2026-11-25T18:00
python3 analyze_logs.py --anomalies --dupes                     # аномалії + повтори
python3 analyze_logs.py --action deny --json                    # експорт у JSON
```

| Аномалія | Критерій | Рівень |
|----------|----------|--------|
| `PORT_SCAN` | одне джерело відхилене на ≥ 5 різних портах за 60 с | HIGH |
| `REPEATED_DENIAL` | одна пара src→dst відхилена ≥ 10 разів | MEDIUM |
| `TRAFFIC_BURST` | > 20 подій за 5 с | MEDIUM |
| `PROXY_ERRORS` | є події `*.error` (недоступна ціль тощо) | LOW |

`--dupes` показує шаблони трафіку (src, dst, proto, action), що повторюються ≥ 5 разів,
— кандидати на окреме правило або ознака надлишкових правил.

## 7. Виявлення та вирішення конфліктів

Два правила **перетинаються**, якщо в них однаковий протокол, мережі джерела **і**
призначення перетинаються (`ipaddress.overlaps`), а порти рівні або хоча б один дорівнює `0`.

### 7.1. Перевірка при додаванні (`POST /rules`)

| Ситуація | Відповідь | Що відбувається |
|----------|-----------|-----------------|
| Ті самі поля трафіку, `priority` і `action` | `{"warning":"duplicate_rule","existing_id":N}` | Правило **не додається** |
| Ті самі поля і `priority`, але інша `action` | `warnings: [conflict_same_specificity]` | Додається з попередженням |
| Трафік перетинається, `action` різна | `warnings: [overlap_conflict]` | Додається з попередженням |

### 7.2. Аудит таблиці (`GET /conflicts`)

Для кожної пари увімкнених правил A (вищий пріоритет) і B (нижчий):

| Тип | Умова | Наслідок |
|-----|-------|----------|
| `duplicate` | однакові поля трафіку і дія | B надлишкове — можна видалити |
| `shadowed` | A повністю покриває B (`subnet_of`, порти) | B **ніколи не спрацює** |
| `conflict` | часткове перетинання, різні дії | B діє лише поза зоною перетину |

У полі `resolution` вказано, яке правило виграє і чому, наприклад:
`діє правило 2 (priority=10, allow); правило 1 (priority=100, deny) спрацює лише поза зоною перетину`.

### 7.3. Політика вирішення

1. **Детерміновано:** виграє правило з меншим `priority`; при рівному пріоритеті — те, що додане раніше
   (стабільне сортування).
2. Точні дублікати відкидаються автоматично.
3. Конфлікти не блокуються (адміністратор може навмисно робити виняток — «allow для одного хоста
   поверх deny для всіх»), але повертаються як попередження і видні в `/conflicts`.
4. Затінене правило адміністратор виправляє: змінює `priority` (`PATCH`), звужує CIDR/порт
   або видаляє/вимикає.

## 8. Демонстрація (`scripts/run_demo.py`)

| № | Сценарій | Очікування |
|---|----------|------------|
| S01 | Без правил | TCP проходить (implicit allow) |
| S02 | `deny` TCP :9000 | з'єднання відхилено, подія в журналі |
| S03 | `allow` 127.0.0.1/32 з `priority=10` | проходить **без перезапуску** |
| S04 | Точний дублікат | `duplicate_rule`, не додано |
| S05 | Та сама специфічність, інша дія | `conflict_same_specificity` |
| S06 | Перекриття `127.0.0.0/8` | `overlap_conflict` |
| S07 | `GET /conflicts` | список conflict/shadowed з поясненням |
| S08 | `PATCH enabled=false` для allow | знову deny |
| S09 | `DELETE` правил | трафік проходить |
| S10 | UDP: deny → `PATCH action=allow` | немає відповіді → є відповідь |
| S11 | `deny all TCP` + 5 портів | усі відхилені (імітація сканування) |
| S12 | 12 повторних спроб | матеріал для аналізатора |
| S13 | `GET /logs?action=deny` | пошук у журналі, є `reason` |
| S14 | `POST /reload` | config перечитано, правила з API збережено |
| S15 | Некоректне правило | `400 bad_rule` |

Результат локального прогону: **15/15 PASS**; модульні тести: **24 passed**;
аналізатор виявив `PORT_SCAN` (HIGH), `REPEATED_DENIAL` і `TRAFFIC_BURST` (MEDIUM).

## 9. Обмеження і шлях до продакшну

- Це **user-space проксі**, а не фільтр пакетів ядра: фільтруються лише з'єднання до
  налаштованих портів проксі; «джерело» — клієнт проксі, «призначення» — цільовий сервіс.
- Рішення приймається на рівні TCP-з'єднання / UDP-датаграми, без аналізу вмісту (немає DPI, stateful-відстеження UDP).
- Продуктивність обмежена GIL і потоками; `gethostbyname` при кожному з'єднанні.
- Admin API без автентифікації — слухає лише `127.0.0.1`; правила з API не зберігаються на диск.
- Implicit allow за замовчуванням (для навчання); у продакшні — default-deny.

**Кроки до prod-рівня:** nftables/iptables (Linux), Windows Filtering Platform, PF (BSD/macOS)
або eBPF/XDP і NFQUEUE з правами адміністратора; автентифікація API (mTLS/токени) і RBAC;
персистентне сховище правил з версіонуванням; TLS-termination перед проксі; асинхронний
ввід-вивід (asyncio/epoll); ротація журналу і відправлення в SIEM.
