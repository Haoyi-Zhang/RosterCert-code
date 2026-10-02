"""Deterministic benign finite models; no keys, signatures, services, or attacks on systems."""
from __future__ import annotations
from itertools import combinations
import random
from typing import Any

SEED = 20260911

def event(name: str, owner: str, parents=(), active=True, weight=1, key=None) -> dict[str, Any]:
    return {'id': name, 'owner': owner, 'parents': list(parents), 'active': active,
            'key': (key if key is not None else 'public-' + name) if active else '', 'weight': weight}


def downward(events, selected):
    by_id = {x['id']: x for x in events}; out = set(selected); stack = list(out)
    while stack:
        for p in by_id[stack.pop()]['parents']:
            if p not in out:
                out.add(p); stack.append(p)
    return sorted(out)


def local_state(events, selected):
    # Used ONLY to select half the sampled queries, never to adjudicate an outcome.
    reach = {x['id']: set(downward(events, [x['id']])) for x in events}
    out = {}
    for owner in sorted({x['owner'] for x in events}):
        writes = [x for x in events if x['owner'] == owner and x['id'] in selected]
        maxima = [x for x in writes if not any(x['id'] != y['id'] and x['id'] in reach[y['id']] for y in writes)]
        if len(maxima) == 1 and maxima[0]['active']:
            out[owner] = maxima[0]['id']
    return out


def generate() -> list[dict[str, Any]]:
    rng = random.Random(SEED); cases = []
    for j in range(1200):
        n = 4 + j % 3; ev = []
        for i in range(n):
            parents = [f'e{k}' for k in range(i) if rng.random() < 0.28]
            ev.append(event(f'e{i}', f'identity-{rng.randrange(3)}', parents,
                            rng.random() >= 0.20, rng.randrange(8)))
        hi = downward(ev, [e['id'] for e in ev if rng.random() < 0.70])
        lo = downward(ev, [name for name in hi if rng.random() < 0.24])
        if j % 2 == 0:
            middle = downward(ev, lo + [name for name in hi if rng.random() < 0.5])
            profile = {i: e for i, e in local_state(ev, middle).items() if rng.random() < 0.8}
        else:
            profile = {}
            for e in ev:
                if rng.random() < 0.48:
                    profile[e['owner']] = e['id']
        cases.append({'kind': 'sampled-window', 'events': ev, 'lower': lo, 'upper': hi,
                      'profile': profile})
    for kind in ('stale-floor', 'fork', 'inactive-key', 'causal-mix'):
        for j in range(200):
            w = 1 + j % 7
            if kind == 'stale-floor':
                ev = [event('e0', 'A', weight=w), event('e1', 'A', ['e0'], weight=w+1)]
                lo = ['e0', 'e1']; profile = {'A': 'e0'}
            elif kind == 'fork':
                ev = [event('e0', 'A', active=False, weight=0), event('e1', 'A', ['e0'], weight=w),
                      event('e2', 'A', ['e0'], weight=w)]
                lo = ['e0','e1','e2']; profile = {'A': 'e1'}
            elif kind == 'inactive-key':
                ev = [event('e0', 'A', weight=w), event('e1', 'A', ['e0'], active=False, weight=0)]
                lo = []; profile = {'A': 'e1'}
            else:
                ev = [event('e0', 'A', weight=w), event('e1', 'A', ['e0'], weight=w),
                      event('e2', 'B', ['e1'], weight=w)]
                lo = []; profile = {'A': 'e0', 'B': 'e2'}
            # Irrelevant concurrent writes vary the view without changing the defect.
            for k in range(j % 3):
                ev.append(event(f'x{k}', f'other-{k}', weight=j % 5))
            cases.append({'kind': kind, 'events': ev, 'lower': lo,
                          'upper': sorted(e['id'] for e in ev), 'profile': profile})
    for j in range(150):
        n = 4 + j % 5; ev = []; last = {}
        for i in range(n):
            owner = f'identity-{rng.randrange(3)}'
            ps = {f'e{k}' for k in range(i) if rng.random() < 0.18}
            if owner in last: ps.add(last[owner])
            ev.append(event(f'e{i}', owner, sorted(ps), rng.random() >= 0.24, rng.randrange(8)))
            last[owner] = f'e{i}'
        hi = downward(ev, [e['id'] for e in ev if rng.random() < 0.75])
        lo = downward(ev, [x for x in hi if rng.random() < 0.2])
        cases.append({'kind': 'chain-optimization', 'events': ev, 'lower': lo, 'upper': hi, 'profile': {}})
    graphs = []
    for n in range(4):
        edges = list(combinations(range(n), 2))
        for bits in range(1 << len(edges)):
            graphs.append((n, [list(e) for i, e in enumerate(edges) if bits >> i & 1]))
    graphs += [(4, [list(e) for e in combinations(range(4),2)]),
               (4, [[0,1],[1,2],[2,3]]), (4, [[0,1],[1,2],[2,3],[0,3]])]
    for n, edges in graphs:
        ev = []
        for i in range(n):
            ev.extend([event(f'g{i}', f'i{i}', active=False, weight=0),
                       event(f'd{i}', f'i{i}', [f'g{i}'], active=False, weight=0),
                       event(f'x{i}', f'i{i}', [f'g{i}'] + [f'd{a}' for a,b in edges if b == i])])
        cases.append({'kind': 'fork-hardness', 'events': ev, 'lower': [],
                      'upper': sorted(e['id'] for e in ev), 'profile': {}, 'graph_n': n, 'graph_edges': edges})
    for i, case in enumerate(cases):
        case['id'] = f'case-{i+1:06d}'
    return cases
