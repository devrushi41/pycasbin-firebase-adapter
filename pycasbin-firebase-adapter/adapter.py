import casbin
from casbin import persist
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore


class CasbinRule(object):
    '''
    CasbinRule model
    '''

    def __init__(self, ptype, v0, v1, v2, v3, v4, v5):
        self.ptype = ptype
        self.v0 = v0
        self.v1 = v1
        self.v2 = v2
        self.v3 = v3
        self.v4 = v4
        self.v5 = v5

    @staticmethod
    def from_dict(source):
        return CasbinRule(source['ptype'], source['v0'], source['v1'], source['v2'], source['v3'], source['v4'], source['v5'])

    def to_dict(self):
        return {
            'ptype': self.ptype,
            'v0': self.v0,
            'v1': self.v1,
            'v2': self.v2,
            'v3': self.v3,
            'v4': self.v4,
            'v5': self.v5
        }

    def __str__(self):
        return '{}, {}, {}, {}, {}, {}, {}'.format(self.ptype, self.v0, self.v1, self.v2, self.v3, self.v4, self.v5)

    def __repr__(self):
        return '{} {} {} {} {} {} {}'.format(self.ptype, self.v0, self.v1, self.v2, self.v3, self.v4, self.v5)


class Adapter(persist.Adapter):
    """the interface for Casbin adapters."""

    def __init__(self, firebaseCredPath=None, projectId=None):
        '''
        Initialize the adapter
        '''
        if(firebaseCredPath and projectId):
            cred = credentials.Certificate(firebaseCredPath)
            firebase_admin.initialize_app(cred)
        else:
            cred = credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred, {
                'projectId': projectId,
            })
        self._collection = 'casbin'
        self._document = 'rules'

        self.db = firestore.client()
        self.rulesRef = self.db.collection(
            self._collection).document(self._document)

    def load_policy(self, model):
        '''
        implementing add Interface for casbin \n
        load all policy rules from firebase firestore \n
        '''

        # get the rules from the collection document
        rules = self.rulesRef.get().to_dict()['rules']
        for rule in rules:
            casbinRule = CasbinRule.from_dict(rule)
            persist.load_policy_line(str(casbinRule), model)

    def _save_policy_line(self, ptype, rule):
        self.rulesRef.update({"rules": firestore.ArrayUnion([rule])})

    def save_policy(self, model):
        '''
        implementing add Interface for casbin \n
        save the policy in firestore \n
        '''
        for sec in ["p", "g"]:
            if sec not in model.model.keys():
                continue
            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    self._save_policy_line(ptype, rule)

    def add_policy(self, sec, ptype, rule):
        """add policy rules to firebase"""
        self._save_policy_line(ptype, rule)

    def remove_policy(self, sec, ptype, rule):
        """delete policy rules from firebase"""
        self.rulesRef.update({"rules": firestore.ArrayRemove([rule])})

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """
        delete policy rules for matching filters from firebase
        """
        pass
