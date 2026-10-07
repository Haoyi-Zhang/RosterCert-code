"""Named source-integrity fixtures only; never enumerate the invalid campaign."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
from roster import Roster
from session import (normalize_context, history_payload, session_statement,
                     delegation_payload, base_payload)
from generate_reference_example import build
from reference_profile import certificate_bytes, verify_reference_certificate


def event(name, owner, parents=(), active=True, key='same-owner-key'):
    return {'id': name, 'owner': owner, 'parents': list(parents),
            'active': active, 'key': key if active else '', 'weight': 1}


def literal_state(events, names):
    """Independent graph paths, no roster masks or historic implementation copy."""
    selected = set(names)
    by_name = {row['id']: row for row in events}
    for name in selected:
        if name not in by_name or not set(by_name[name]['parents']) <= selected:
            raise ValueError('not a cut')
    children = {name: [] for name in by_name}
    for row in events:
        for parent in row['parents']:
            children[parent].append(row['id'])
    live = {}
    for row in events:
        name, owner = row['id'], row['owner']
        if name not in selected:
            continue
        queue, seen, displaced = list(children[name]), set(), False
        while queue:
            other = queue.pop()
            if other in seen:
                continue
            seen.add(other)
            if other in selected and by_name[other]['owner'] == owner:
                displaced = True
            queue.extend(children[other])
        if not displaced:
            live.setdefault(owner, []).append(row)
    return {owner: rows[0]['id'] for owner, rows in live.items()
            if len(rows) == 1 and rows[0]['active']}


def fixtures():
    chain = [event('a', 'A'), event('b', 'B', ['a']),
             event('a2', 'A', ['b']), event('off', 'A', ['a2'], False)]
    fork = [event('g', 'A', active=False), event('x', 'A', ['g']),
            event('y', 'A', ['g']), event('z', 'A', ['x', 'y'])]
    chain64 = [event(f'e{i:02}', 'A', [] if not i else [f'e{i-1:02}'])
               for i in range(64)]
    return [([], [[]]),
            (chain, [[], ['a'], ['a', 'b'], ['a', 'b', 'a2'], ['a', 'b', 'a2', 'off']]),
            (fork, [[], ['g'], ['g', 'x'], ['g', 'y'], ['g', 'x', 'y'], ['g', 'x', 'y', 'z']]),
            (chain64, [[], ['e00'], [r['id'] for r in chain64]])]


def snapshot():
    rows = []
    for events, cuts in fixtures():
        model = Roster(list(reversed(events)))
        for names in cuts:
            mask = model.mask(names)
            current = model.current(mask)
            if current != literal_state(events, names):
                raise AssertionError('literal current-state mismatch')
            profiles = [{}, current] + [{r['owner']: r['id']} for r in events]
            rows.append({'events': events, 'cut': names, 'current': current,
                         'queries': [[p, model.authorized(mask, p),
                                      model.window(0, mask, p), model.universal(0, mask, p)]
                                     for p in profiles]})
    contexts = []
    events = fixtures()[1][0]
    for mode, lower, cut in [('HIST', [], ['a']), ('FRESH', [], ['a', 'b']),
                             ('ROBUST', ['a'], None)]:
        context = {'domain': 'owned-domain', 'mode': mode, 'application': 'owned-app',
                   'session': 'owned-session', 'message': 'approve', 'namespace': 'owned',
                   'events': events, 'lower': lower, 'upper': ['a', 'b'],
                   'cut': cut, 'profile': [['A', 'a']]}
        table = [['A', 'a', 'owned-ephemeral']]
        contexts.append({'normalized': normalize_context(context),
                         'history': history_payload(context).hex(),
                         'statement': session_statement(context, table).hex(),
                         'delegation': delegation_payload(context, table, 'A').hex(),
                         'base': base_payload(context, table).hex()})
    cert, anchor = build()
    return {'rosters': rows, 'contexts': contexts, 'certificate': cert,
            'anchor': anchor, 'bytes': certificate_bytes(cert, anchor).hex()}


class CurrentVersionsTests(unittest.TestCase):
    def test_named_fixtures_full_context_and_public_certificate(self):
        result = snapshot()
        self.assertEqual(len(result['rosters']), 15)
        self.assertEqual(bytes.fromhex(result['bytes']),
                         (ROOT / 'examples/reference-certificate.json').read_bytes())
        self.assertEqual(result['anchor']+'\n',
                         (ROOT / 'examples/reference-history-public-key.txt').read_text())
        self.assertTrue(verify_reference_certificate(result['certificate'], result['anchor']))
        for field in ('message', 'session', 'mode'):
            bad = copy.deepcopy(result['certificate'])
            bad['context'][field] += '!'
            self.assertFalse(verify_reference_certificate(bad, result['anchor']))

    def test_invalid_cut_and_admission_boundaries(self):
        model = Roster(fixtures()[1][0])
        for mask in (-1, True, 1 << 4, model.mask(['b'])):
            with self.assertRaisesRegex(ValueError, 'not a cut'):
                model.current(mask)
        bad = fixtures()[3][0]+[event('extra', 'B')]
        with self.assertRaisesRegex(ValueError, 'at most 64'):
            Roster(bad)
        self.assertIsInstance(model._strict_desc, tuple)
        for i, mask in enumerate(model._strict_desc):
            self.assertFalse(mask & (1 << i))
        # A cross-owner descendant alone must not retire A's version.
        self.assertEqual(model.current(model.mask(['a', 'b'])), {'A': 'a', 'B': 'b'})
        fork = Roster(fixtures()[2][0])
        self.assertEqual(fork.current(fork.mask(['g', 'x', 'y'])), {})
        self.assertEqual(fork.current(fork.all), {'A': 'z'})


if __name__ == '__main__':
    unittest.main()
