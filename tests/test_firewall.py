"""
tests/test_firewall.py — модульні тести брандмауера (без запуску сервера).

Запуск: python tests/test_firewall.py      (або: python -m pytest -q)
"""
import os, sys, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from firewall import Rule, RuleSet, _nets_overlap


def _rule(**kw) -> Rule:
    base = dict(priority=100, action='deny', src_ip_cidr='0.0.0.0/0',
                dst_ip_cidr='0.0.0.0/0', src_port=0, dst_port=0,
                proto='TCP', enabled=True, comment='')
    base.update(kw)
    return Rule(**base)


# --- _nets_overlap ---------------------------------------------------------
def test_nets_overlap_subset():
    assert _nets_overlap('10.0.0.0/8', '10.1.0.0/16')

def test_nets_overlap_disjoint():
    assert not _nets_overlap('10.0.0.0/8', '192.168.0.0/16')

def test_nets_overlap_any():
    assert _nets_overlap('0.0.0.0/0', '1.2.3.4/32')


# --- Rule.matches ----------------------------------------------------------
def test_rule_matches_port_and_proto():
    r = _rule(dst_port=80)
    assert r.matches('1.2.3.4', '5.6.7.8', 12345, 80, 'TCP')
    assert not r.matches('1.2.3.4', '5.6.7.8', 12345, 443, 'TCP')
    assert not r.matches('1.2.3.4', '5.6.7.8', 12345, 80, 'UDP')

def test_rule_disabled_never_matches():
    assert not _rule(dst_port=80, enabled=False).matches('1.2.3.4', '5.6.7.8', 1, 80, 'TCP')

def test_rule_cidr_filter():
    r = _rule(dst_ip_cidr='10.0.0.0/8')
    assert r.matches('1.1.1.1', '10.5.5.5', 1000, 80, 'TCP')
    assert not r.matches('1.1.1.1', '192.168.1.1', 1000, 80, 'TCP')

def test_rule_src_port():
    r = _rule(src_port=12345)
    assert r.matches('1.1.1.1', '2.2.2.2', 12345, 80, 'TCP')
    assert not r.matches('1.1.1.1', '2.2.2.2', 9999, 80, 'TCP')


# --- RuleSet.decide --------------------------------------------------------
def test_decide_implicit_allow():
    assert RuleSet([]).decide('1.2.3.4', '5.6.7.8', 100, 80, 'TCP') == ('allow', 0)

def test_decide_deny():
    rs = RuleSet([]); rid = rs.add(_rule(dst_port=80))['id']
    assert rs.decide('1.2.3.4', '5.6.7.8', 100, 80, 'TCP') == ('deny', rid)

def test_decide_priority_allow_wins():
    rs = RuleSet([])
    rs.add(_rule(priority=100, action='deny', dst_port=80))
    rs.add(_rule(priority=10, action='allow', dst_port=80))
    assert rs.decide('1.2.3.4', '5.6.7.8', 100, 80, 'TCP')[0] == 'allow'

def test_decide_priority_deny_wins():
    rs = RuleSet([])
    rs.add(_rule(priority=5, action='deny', dst_port=443))
    rs.add(_rule(priority=50, action='allow', dst_port=443))
    assert rs.decide('1.2.3.4', '5.6.7.8', 100, 443, 'TCP')[0] == 'deny'


# --- RuleSet.add: конфлікти при додаванні ----------------------------------
def test_add_ok_without_warnings():
    res = RuleSet([]).add(_rule(dst_port=80))
    assert 'id' in res and 'warnings' not in res

def test_add_duplicate_rejected():
    rs = RuleSet([])
    rs.add(_rule(dst_port=80, priority=10))
    res = rs.add(_rule(dst_port=80, priority=10))
    assert res.get('warning') == 'duplicate_rule' and len(rs.rules) == 1

def test_add_conflict_same_specificity():
    rs = RuleSet([])
    rs.add(_rule(action='deny', dst_port=80, priority=10))
    res = rs.add(_rule(action='allow', dst_port=80, priority=10))
    assert 'id' in res
    assert any(w['warning'] == 'conflict_same_specificity' for w in res['warnings'])

def test_add_overlap_conflict():
    rs = RuleSet([])
    rs.add(_rule(action='deny', dst_ip_cidr='10.0.0.0/8', dst_port=80, priority=50))
    res = rs.add(_rule(action='allow', dst_ip_cidr='10.1.0.0/16', dst_port=80, priority=60))
    assert any(w['warning'] == 'overlap_conflict' for w in res['warnings'])

def test_add_no_conflict_other_proto():
    rs = RuleSet([])
    rs.add(_rule(action='deny', dst_port=53, proto='TCP'))
    assert 'warnings' not in rs.add(_rule(action='allow', dst_port=53, proto='UDP'))


# --- find_conflicts: аудит таблиці -----------------------------------------
def test_find_conflicts_shadowed():
    rs = RuleSet([])
    a = rs.add(_rule(action='deny', priority=1))['id']                       # усе TCP
    b = rs.add(_rule(action='allow', dst_ip_cidr='10.0.0.0/8', priority=50))['id']
    c = rs.find_conflicts()
    assert any(x['type'] == 'shadowed' and x['winner_id'] == a and x['loser_id'] == b for x in c)

def test_find_conflicts_partial_overlap():
    rs = RuleSet([])
    rs.add(_rule(action='allow', src_ip_cidr='127.0.0.1/32', dst_port=9000, priority=10))
    rs.add(_rule(action='deny', dst_port=9000, priority=100))
    assert [x['type'] for x in rs.find_conflicts()] == ['conflict']

def test_find_conflicts_ignores_disabled():
    rs = RuleSet([])
    rs.add(_rule(action='deny', priority=1, enabled=False))
    rs.add(_rule(action='allow', dst_port=80, priority=50))
    assert rs.find_conflicts() == []


# --- remove / update (гаряча зміна) ----------------------------------------
def test_remove_restores_allow():
    rs = RuleSet([]); rid = rs.add(_rule(dst_port=80))['id']
    rs.remove(rid)
    assert rs.decide('1.1.1.1', '2.2.2.2', 100, 80, 'TCP')[0] == 'allow'

def test_update_disable():
    rs = RuleSet([]); rid = rs.add(_rule(dst_port=80))['id']
    assert rs.update(rid, enabled=False)
    assert rs.decide('1.1.1.1', '2.2.2.2', 100, 80, 'TCP')[0] == 'allow'

def test_update_priority_resorts():
    rs = RuleSet([])
    d = rs.add(_rule(action='deny', dst_port=80, priority=10))['id']
    rs.add(_rule(action='allow', src_ip_cidr='1.1.1.1/32', dst_port=80, priority=50))
    rs.update(d, priority=90)
    assert rs.decide('1.1.1.1', '2.2.2.2', 100, 80, 'TCP')[0] == 'allow'

def test_update_unknown_id():
    assert RuleSet([]).update(999, enabled=False) is False

def test_reason_text():
    rs = RuleSet([]); rid = rs.add(_rule(dst_port=80, comment='block http'))['id']
    assert 'block http' in rs.reason(rid, 'deny')
    assert rs.reason(0, 'allow').startswith('implicit_allow')


if __name__ == '__main__':
    passed = failed = 0
    for name, fn in sorted((k, v) for k, v in globals().items() if k.startswith('test_')):
        try:
            fn(); print(f'  PASS  {name}'); passed += 1
        except Exception:
            print(f'  FAIL  {name}'); traceback.print_exc(); failed += 1
    print(f'\n{passed} passed, {failed} failed')
    sys.exit(1 if failed else 0)
