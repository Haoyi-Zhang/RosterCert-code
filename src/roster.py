"""Finite causal-roster algorithms. No cryptographic authentication is implemented.

Events are authenticated INPUT ASSUMPTIONS, not trusted because this parser reads them.
A cut is a downward-closed set. Incomparable maximal writes quarantine an identity.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

from wire_profile import MAX_IDENTIFIER, ascii_identifier, scalar_text


@dataclass(frozen=True)
class Event:
    name: str
    owner: str
    active: bool
    key: str
    parents: tuple[str, ...]
    weight: int


class Roster:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        if not isinstance(records, list) or len(records) > 64:
            raise ValueError('events must be a list of at most 64 entries')
        events: dict[str, Event] = {}
        fields = {'id', 'owner', 'active', 'key', 'parents', 'weight'}
        for row in records:
            if not isinstance(row, dict) or set(row) != fields:
                raise ValueError('event fields do not match the schema')
            ascii_identifier(row['id'], 'event id', limit=MAX_IDENTIFIER)
            ascii_identifier(row['owner'], 'event owner', limit=MAX_IDENTIFIER)
            scalar_text(row['key'], 'event key', allow_empty=True, limit=MAX_IDENTIFIER)
            if row['id'] in events:
                raise ValueError('duplicate event identifier')
            if type(row['active']) is not bool or type(row['weight']) is not int:
                raise ValueError('active must be bool and weight must be int')
            if not 0 <= row['weight'] <= 100:
                raise ValueError('weight outside supported bounds')
            if (row['active'] and not row['key']) or (not row['active'] and row['key']):
                raise ValueError('active keys must be nonempty; inactive keys must be empty')
            parents = row['parents']
            if not isinstance(parents, list):
                raise ValueError('invalid parent list')
            for index, parent in enumerate(parents):
                ascii_identifier(parent, f'parent[{index}]', limit=MAX_IDENTIFIER)
            if len(parents) != len(set(parents)):
                raise ValueError('duplicate parent')
            events[row['id']] = Event(row['id'], row['owner'], row['active'], row['key'],
                                      tuple(parents), row['weight'])
        if any(p not in events for e in events.values() for p in e.parents):
            raise ValueError('missing parent')
        order: list[Event] = []
        pending = set(events)
        done: set[str] = set()
        while pending:
            ready = sorted(x for x in pending if set(events[x].parents) <= done)
            if not ready:
                raise ValueError('cycle')
            for name in ready:
                order.append(events[name]); done.add(name); pending.remove(name)
        self.events = tuple(order)
        self.index = {e.name: i for i, e in enumerate(order)}
        self.n = len(order)
        self.all = (1 << self.n) - 1
        self.anc: list[int] = []
        self.writes: dict[str, int] = {}
        for i, event in enumerate(order):
            a = 1 << i
            for p in event.parents:
                a |= self.anc[self.index[p]]
            self.anc.append(a)
            self.writes[event.owner] = self.writes.get(event.owner, 0) | (1 << i)
        # Immutable strict descendants of each admitted event. Current-state
        # lookup intersects these with same-owner present writes, not all events.
        self._strict_desc = tuple(
            sum(1 << j for j in range(self.n) if j != i and self.anc[j] & (1 << i))
            for i in range(self.n)
        )

    def mask(self, names: Iterable[str]) -> int:
        if isinstance(names, (str, bytes)):
            raise ValueError('cut must be a collection, not a string')
        result = 0
        for name in names:
            if name not in self.index:
                raise ValueError('unknown event')
            result |= 1 << self.index[name]
        return result

    def names(self, mask: int) -> list[str]:
        return sorted(e.name for i, e in enumerate(self.events) if mask & (1 << i))

    def closure(self, mask: int) -> int:
        result = 0
        for i in range(self.n):
            if mask & (1 << i):
                result |= self.anc[i]
        return result

    def ideal(self, mask: int) -> bool:
        return type(mask) is int and mask >= 0 and not (mask & ~self.all) and self.closure(mask) == mask

    def bounds(self, lower: int, upper: int) -> None:
        if not self.ideal(lower) or not self.ideal(upper) or lower & ~upper:
            raise ValueError('invalid ideal interval')

    def current(self, cut: int) -> dict[str, str]:
        if not self.ideal(cut):
            raise ValueError('not a cut')
        out: dict[str, str] = {}
        for owner, writes in self.writes.items():
            present = cut & writes
            maximal = [i for i in range(self.n) if present & (1 << i) and
                       not (present & self._strict_desc[i])]
            if len(maximal) == 1 and self.events[maximal[0]].active:
                out[owner] = self.events[maximal[0]].name
        return out

    def authorized(self, cut: int, profile: dict[str, str]) -> bool:
        state = self.current(cut)
        return all(state.get(owner) == name for owner, name in profile.items())

    def window(self, lower: int, upper: int, profile: dict[str, str]) -> tuple[int, int] | None:
        """Return EXACT ideal interval of cuts realizing a fixed active profile."""
        self.bounds(lower, upper)
        forced = lower
        banned = 0
        for owner, name in profile.items():
            if name not in self.index:
                return None
            i = self.index[name]
            event = self.events[i]
            if event.owner != owner or not event.active or not (upper & (1 << i)):
                return None
            forced |= self.anc[i]
            banned |= upper & self.writes[owner] & ~self.anc[i]
        maximum = upper
        for i in range(self.n):
            if self.anc[i] & banned:
                maximum &= ~(1 << i)
        return None if forced & ~maximum else (forced, maximum)

    def universal(self, lower: int, upper: int, profile: dict[str, str]) -> bool:
        return self.window(lower, upper, profile) == (lower, upper)

    def fork_free(self) -> bool:
        for writes in self.writes.values():
            indices = [i for i in range(self.n) if writes & (1 << i)]
            for pos, i in enumerate(indices):
                for j in indices[pos + 1:]:
                    if not (self.anc[i] & (1 << j) or self.anc[j] & (1 << i)):
                        return False
        return True

    def optimize_chain(self, lower: int, upper: int) -> dict[str, Any]:
        """Classical maximum-closure reduction, with a primal/dual flow certificate."""
        self.bounds(lower, upper)
        if not self.fork_free():
            raise ValueError('maximum-closure reduction requires per-identity chains')
        previous: dict[str, int] = {}
        delta: list[int] = []
        for e in self.events:
            value = e.weight if e.active else 0
            delta.append(value - previous.get(e.owner, 0))
            previous[e.owner] = value
        big = 1 + sum(abs(x) for x in delta)
        n = self.n + 2; source = self.n; sink = self.n + 1
        cap = [[0] * n for _ in range(n)]
        for i, e in enumerate(self.events):
            if delta[i] > 0: cap[source][i] += delta[i]
            if delta[i] < 0: cap[i][sink] -= delta[i]
            if lower & (1 << i): cap[source][i] += big
            if not upper & (1 << i): cap[i][sink] += big
            for p in e.parents:
                cap[i][self.index[p]] += big
        residual = [row[:] for row in cap]
        value = 0
        while True:
            parent = [-1] * n; parent[source] = source
            queue = deque([source])
            while queue and parent[sink] == -1:
                u = queue.popleft()
                for v in range(n):
                    if residual[u][v] > 0 and parent[v] == -1:
                        parent[v] = u; queue.append(v)
            if parent[sink] == -1: break
            aug = sum(sum(row) for row in cap) + 1
            v = sink
            while v != source:
                u = parent[v]; aug = min(aug, residual[u][v]); v = u
            v = sink
            while v != source:
                u = parent[v]
                residual[u][v] -= aug; residual[v][u] += aug; v = u
            value += aug
        reach = {source}; queue = deque([source])
        while queue:
            u = queue.popleft()
            for v in range(n):
                if residual[u][v] > 0 and v not in reach:
                    reach.add(v); queue.append(v)
        cut = sum(1 << i for i in range(self.n) if i in reach)
        objective = sum(max(x, 0) for x in delta) - value
        arcs = [[u, v, cap[u][v], cap[u][v] - residual[u][v]]
                for u in range(n) for v in range(n) if cap[u][v] > 0]
        return {'cut': self.names(cut), 'objective': objective, 'flow_value': value,
                'arcs': arcs, 'source': source, 'sink': sink,
                'order': [e.name for e in self.events], 'big': big}
