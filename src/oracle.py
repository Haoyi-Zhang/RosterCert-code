"""Separate set-based oracle and flow-certificate checker.

Does not import roster.py. Independence here concerns implementation structure,
not independent authorship, external peer review, or mechanized general proofs.
"""
from __future__ import annotations
from itertools import combinations
from typing import Any


def ancestors(events: list[dict[str, Any]]) -> dict[str, set[str]]:
    by_id = {e['id']: e for e in events}
    result: dict[str, set[str]] = {}
    for name in by_id:
        found: set[str] = set()
        stack = [name]
        while stack:
            x = stack.pop()
            if x not in found:
                found.add(x); stack.extend(by_id[x]['parents'])
        result[name] = found
    return result


def ideals(events: list[dict[str, Any]]) -> list[frozenset[str]]:
    """Enumerate every bit-subset, accepting by direct parent containment only."""
    if len(events) > 12:
        raise ValueError('oracle limit is 12 events')
    names = [e['id'] for e in events]
    out = []
    for bits in range(1 << len(events)):
        cut = frozenset(x for i, x in enumerate(names) if bits >> i & 1)
        if all(set(e['parents']) <= cut for e in events if e['id'] in cut):
            out.append(cut)
    return out


def state(events: list[dict[str, Any]], cut: frozenset[str],
          reach: dict[str, set[str]] | None = None) -> dict[str, str]:
    reach = ancestors(events) if reach is None else reach
    owners = {e['owner'] for e in events}
    out = {}
    for owner in owners:
        writes = [e for e in events if e['owner'] == owner and e['id'] in cut]
        maximal = [e for e in writes if not any(e['id'] != f['id'] and
                   e['id'] in reach[f['id']] for f in writes)]
        if len(maximal) == 1 and maximal[0]['active']:
            out[owner] = maximal[0]['id']
    return out


def family(case: dict[str, Any]) -> tuple[list[frozenset[str]], list[frozenset[str]]]:
    all_cuts = ideals(case['events'])
    lo, hi = set(case['lower']), set(case['upper'])
    inside = [c for c in all_cuts if lo <= c <= hi]
    reach = ancestors(case['events'])
    good = []
    for cut in inside:
        s = state(case['events'], cut, reach)
        if all(s.get(i) == e for i, e in case['profile'].items()):
            good.append(cut)
    return inside, good


def optimum(events: list[dict[str, Any]], lower: list[str], upper: list[str]) -> tuple[int, frozenset[str]]:
    reach = ancestors(events)
    by_id = {e['id']: e for e in events}
    best = -1; witness = frozenset()
    for cut in ideals(events):
        if set(lower) <= cut <= set(upper):
            score = sum(by_id[e]['weight'] for e in state(events, cut, reach).values())
            if score > best:
                best, witness = score, cut
    return best, witness


def width(events: list[dict[str, Any]]) -> int:
    reach = ancestors(events)
    names = list(reach)
    for size in range(len(names), -1, -1):
        for xs in combinations(names, size):
            if all(a not in reach[b] and b not in reach[a] for a, b in combinations(xs, 2)):
                return size
    return 0


def replay_flow(events: list[dict[str, Any]], lower: list[str], upper: list[str], cert: dict[str, Any]) -> bool:
    """Rebuild capacities independently; check feasibility and equal primal/dual value."""
    try:
        keys = {'cut','objective','flow_value','arcs','source','sink','order','big'}
        if not isinstance(cert, dict) or set(cert) != keys: return False
        if any(type(cert[k]) is not int for k in ('objective','flow_value','source','sink','big')): return False
        for k in ('cut','order'):
            if not isinstance(cert[k], list) or any(not isinstance(x,str) for x in cert[k]): return False
        if not isinstance(cert['arcs'], list): return False
        if any(not isinstance(a,list) or len(a)!=4 for a in cert['arcs']): return False
        if not isinstance(lower,list) or not isinstance(upper,list): return False
        if any(not isinstance(x,str) for x in lower+upper): return False
        if len(lower)!=len(set(lower)) or len(upper)!=len(set(upper)): return False
        universe={e['id'] for e in events}
        if not set(lower)<=set(upper)<=universe: return False
        for bound in (set(lower),set(upper)):
            if any(not set(e['parents'])<=bound for e in events if e['id'] in bound): return False
        order = cert['order']; n = len(events)
        if len(order) != n or set(order) != {e['id'] for e in events}: return False
        by_id = {e['id']: e for e in events}; index = {e: i for i, e in enumerate(order)}
        if any(index[p] >= index[e['id']] for e in events for p in e['parents']): return False
        reach = ancestors(events)
        for a, b in combinations(events, 2):
            if a['owner'] == b['owner'] and a['id'] not in reach[b['id']] and b['id'] not in reach[a['id']]:
                return False
        previous = {}; delta = []
        for name in order:
            e = by_id[name]; weight = e['weight'] if e['active'] else 0
            delta.append(weight - previous.get(e['owner'], 0)); previous[e['owner']] = weight
        big = 1 + sum(map(abs, delta)); s, t = n, n + 1
        if (cert['source'], cert['sink'], cert['big']) != (s, t, big): return False
        expected: dict[tuple[int, int], int] = {}
        def add(a: int, b: int, w: int) -> None:
            expected[a,b] = expected.get((a,b), 0) + w
        for i, name in enumerate(order):
            if delta[i] > 0: add(s, i, delta[i])
            if delta[i] < 0: add(i, t, -delta[i])
            if name in lower: add(s, i, big)
            if name not in upper: add(i, t, big)
            for p in by_id[name]['parents']: add(i, index[p], big)
        provided = {}; balance = [0] * (n + 2)
        for a,b,c,f in cert['arcs']:
            if any(type(x) is not int for x in (a,b,c,f)): return False
            if (a,b) in provided or (a,b) not in expected or c != expected[a,b] or not 0 <= f <= c: return False
            provided[a,b] = c; balance[a] -= f; balance[b] += f
        if provided != expected: return False
        flow = cert['flow_value']
        if type(flow) is not int or flow < 0: return False
        if balance[s] != -flow or balance[t] != flow or any(balance[i] for i in range(n)): return False
        cut = frozenset(cert['cut'])
        if len(cut) != len(cert['cut']) or not set(lower) <= cut <= set(upper): return False
        if any(not set(e['parents']) <= cut for e in events if e['id'] in cut): return False
        side = {s} | {index[x] for x in cut}
        crossing = sum(c for (a,b), c in expected.items() if a in side and b not in side)
        if crossing != flow: return False
        objective = sum(by_id[x]['weight'] for x in state(events, cut, reach).values())
        return objective == cert['objective'] == sum(max(x,0) for x in delta) - flow
    except (KeyError, TypeError, ValueError, IndexError):
        return False
