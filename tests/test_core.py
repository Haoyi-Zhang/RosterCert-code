from __future__ import annotations
import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from roster import Roster
from oracle import replay_flow
from cases import event
from session import (base_payload, delegation_payload, history_payload, normalize_context,
                     session_statement, verify_symbolic_session)

class CoreTests(unittest.TestCase):
    def test_empty(self):
        r=Roster([])
        self.assertEqual(r.window(0,0,{}),(0,0))
        self.assertTrue(r.universal(0,0,{}))
        c=r.optimize_chain(0,0)
        self.assertTrue(replay_flow([],[],[],c))
    def test_invalid_schema(self):
        samples=[]
        e=event('a','A')
        for field,value in [('id',''),('owner',''),('active',1),('weight',True),('weight',-1),('weight',101),('key',''),('parents','a')]:
            x=copy.deepcopy(e);x[field]=value;samples.append([x])
        x=copy.deepcopy(e);x['other']=0;samples.append([x])
        x=copy.deepcopy(e);del x['id'];samples.append([x])
        samples += [[e,e], [event('a','A',['missing'])], [event('a','A',['a'])],
                    [event('a','A',['b']),event('b','B',['a'])],
                    [event('a','A'),event('b','B',['a','a'])]]
        for sample in samples:
            with self.subTest(sample=sample), self.assertRaises(ValueError): Roster(sample)
    def test_invalid_cuts(self):
        r=Roster([event('a','A'),event('b','A',['a'])])
        for cut in (-1,True,4,2): self.assertFalse(r.ideal(cut))
        with self.assertRaises(ValueError):r.bounds(3,1)
        with self.assertRaises(ValueError):r.current(2)
        with self.assertRaises(ValueError):r.mask('a')
        with self.assertRaises(ValueError):r.mask(['missing'])
    def test_cross_identity_causality(self):
        r=Roster([event('a','A'),event('r','A',['a']),event('b','B',['r'])])
        self.assertIsNotNone(r.window(0,r.all,{'A':'a'}))
        self.assertIsNotNone(r.window(0,r.all,{'B':'b'}))
        self.assertIsNone(r.window(0,r.all,{'A':'a','B':'b'}))
    def test_fork_and_resolution(self):
        ev=[event('g','A',active=False),event('x','A',['g']),event('y','A',['g']),event('z','A',['x','y'])]
        r=Roster(ev)
        self.assertEqual(r.current(r.mask(['g','x','y'])),{})
        self.assertEqual(r.current(r.all),{'A':'z'})
        self.assertFalse(r.fork_free())
        with self.assertRaises(ValueError):r.optimize_chain(0,r.all)
    def test_profile_validation(self):
        r=Roster([event('a','A'),event('b','B',active=False)])
        for p in ({'B':'a'},{'A':'missing'},{'B':'b'}):self.assertIsNone(r.window(0,r.all,p))
    def test_reused_public_key_is_not_version_identity(self):
        r=Roster([event('a','A',key='same'),event('b','A',['a'],key='same')])
        self.assertIsNone(r.window(r.all,r.all,{'A':'a'}))
        self.assertIsNotNone(r.window(r.all,r.all,{'A':'b'}))
    def test_certificate_tampering(self):
        ev=[event('a','A',weight=7),event('b','A',['a'],weight=1),event('c','B',['b'],weight=8)]
        r=Roster(ev);c=r.optimize_chain(0,r.all)
        self.assertTrue(replay_flow(ev,[],r.names(r.all),c))
        for field in ('objective','flow_value','big','source','sink'):
            bad=copy.deepcopy(c);bad[field]+=1
            self.assertFalse(replay_flow(ev,[],r.names(r.all),bad))
        bad=copy.deepcopy(c);bad['arcs'][0][2]+=1
        self.assertFalse(replay_flow(ev,[],r.names(r.all),bad))
    def test_certificate_schema_is_strict(self):
        ev=[event('a','A')];r=Roster(ev);c=r.optimize_chain(0,r.all)
        for field,value in [('cut','a'),('objective',True),('source',True),('order','a'),('arcs',{})]:
            bad=copy.deepcopy(c);bad[field]=value
            self.assertFalse(replay_flow(ev,[],['a'],bad))
        bad=copy.deepcopy(c);bad['extra']=0
        self.assertFalse(replay_flow(ev,[],['a'],bad))
        self.assertFalse(replay_flow(ev,['a','a'],['a'],c))
    def test_nonideal_certificate_bound_is_rejected(self):
        ev=[event('a','A'),event('b','B',['a'])];r=Roster(ev);c=r.optimize_chain(0,r.all)
        self.assertFalse(replay_flow(ev,[],['b'],c))
    def session_context(self):
        return {
            'domain':'AMS-CAUSAL-ROSTER', 'mode':'HIST',
            'application':'benign-example', 'session':'session-1',
            'message':'approve', 'namespace':'example-roster',
            'events':[event('a','A'),event('b','B')],
            'lower':[], 'upper':['a','b'], 'cut':['a','b'],
            'profile':[['A','a'],['B','b']],
        }
    def test_session_separation_exact_binding(self):
        c=self.session_context()
        table=[['A','a','ephemeral-A'],['B','b','ephemeral-B']]
        delegations={i:delegation_payload(c,table,i) for i in ('A','B')}
        common=base_payload(c,table)
        base={i:common for i in ('A','B')}
        self.assertTrue(verify_symbolic_session(c,table,delegations,base))
        for field in ('domain','application','session','message','namespace'):
            bad=copy.deepcopy(c);bad[field]+='!'
            self.assertFalse(verify_symbolic_session(bad,table,delegations,base))
        bad=copy.deepcopy(c);bad['events'][0]['key']='changed'
        self.assertFalse(verify_symbolic_session(bad,table,delegations,base))
        self.assertFalse(verify_symbolic_session(c,[['A','a','new'],['B','b','ephemeral-B']],delegations,base))
    def test_session_table_and_mode_validation(self):
        c=self.session_context()
        table=[['A','a','ephemeral-A'],['B','b','ephemeral-B']]
        self.assertEqual(session_statement(c,list(reversed(table))),session_statement(c,table))
        with self.assertRaises(ValueError):session_statement(c,[['A','a','same'],['B','b','same']])
        with self.assertRaises(ValueError):session_statement(c,[['A','a','ephemeral-A']])
        bad=copy.deepcopy(c);bad['mode']='ROBUST';bad['cut']=None
        with self.assertRaises(ValueError):normalize_context(bad)
        fresh=copy.deepcopy(c);fresh['mode']='FRESH'
        self.assertEqual(normalize_context(fresh)['cut'],['a','b'])
    def test_session_table_binds_version_event(self):
        c=self.session_context();table=[['A','a','ephemeral-A'],['B','b','ephemeral-B']]
        bad=copy.deepcopy(table);bad[0][1]='b'
        with self.assertRaises(ValueError):session_statement(c,bad)

    def test_history_payload_excludes_application_message_but_binds_view(self):
        c=self.session_context();base=history_payload(c)
        changed=copy.deepcopy(c);changed['message']+='!'
        self.assertEqual(history_payload(changed),base)
        changed=copy.deepcopy(c);changed['namespace']+='!'
        self.assertNotEqual(history_payload(changed),base)
        changed=copy.deepcopy(c);changed['events'][0]['weight']+=1
        self.assertNotEqual(history_payload(changed),base)

    def test_context_length_and_event_uniqueness(self):
        c=self.session_context();c['message']='x'*4097
        with self.assertRaises(ValueError):normalize_context(c)
        c=self.session_context();c['profile']=[['A','a'],['B','a']]
        with self.assertRaises(ValueError):normalize_context(c)

    def test_session_missing_authorization_rejected(self):
        c=self.session_context();table=[['A','a','ephemeral-A'],['B','b','ephemeral-B']]
        ds={i:delegation_payload(c,table,i) for i in ('A','B')}
        common=base_payload(c,table);base={i:common for i in ('A','B')}
        del ds['B']
        self.assertFalse(verify_symbolic_session(c,table,ds,base))
        ds={i:delegation_payload(c,table,i) for i in ('A','B')}
        base['A']+=b'!'
        self.assertFalse(verify_symbolic_session(c,table,ds,base))

if __name__=='__main__':unittest.main()
