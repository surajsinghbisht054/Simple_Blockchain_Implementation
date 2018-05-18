#!/usr/bin/python
#
#
# import modules
import json
import os
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import time


# Simple Request Transection
class RequestTransection:
    def __init__(self):
        '''
        
        '''
        self.category = ''
        self.sender   = ''
        self.receiver = ''
        self.amount   = ''
        self.time     = str(time.time())
        self.fee      = ''
        self.sign     = ''
        self.pubkey   = ''
        self.prvkey   = ''
        self.rsa_key  = ''
        
    def getitems(self):
        return {
            "category" : self.category,
            "sender"   : self.sender,
            "receiver" : self.receiver,
            "amount"   : self.amount,
            "fee"      : self.fee,
            "sign"     : self.sign,
            "time"     : self.time,
            
        }
    
    def __repr__(self):
        return "< Transection {} | {} >".format(self.category, self.time)

    def new_user(self):
        random  = RSA.Random.new().read
        self.rsa_key = RSA.generate(512, random) 
        self.prvkey  =  self.rsa_key.exportKey() # private key object
        self.pubkey  =  self.rsa_key.publickey().exportKey() # public key object
        self.create_transection("n", '', )
        return
    
    def create_transection(self, category, sender, receiver, amount, fee):
        category = category.lower()
        if category not in ['new', 'send', 'receive']:
            raise "please use valid categories like new, send or receive"
        
        self.category = category
        self.sender   = sender
        self.receiver = receiver
        self.amount   = amount
        self.fee      = fee
        return

    def previous_block_hash(self, blockitemdict):
        return sha256("{index}{previoushash}{timestamp}{hash}{datahash}{nonce}{targetbit}".format(**blockitemdict)).hexdigest()


# In[62]:


class RequestBlock:
    def __init__(self, index, previoushash, targetbit=3, transbuffer = []):
        self.index       = index
        self.previoushash = previoushash
        self.timestamp   = str(time.time())
        self.targetbit   = targetbit
        self.hash        = ''
        self.datahash    = ''
        self.dataload    = []
        self.nonce       = ''
        self.transbuffer = transbuffer
        self.calculate_block()
        
    def previous_block_hash(self, blockitemdict):
        return sha256("{index}{previoushash}{timestamp}{hash}{datahash}{nonce}{targetbit}".format(**blockitemdict)).hexdigest()

    def merkle_hash(self):
        hl1 = []
        hl2 = []
        
        for data in self.dataload:
            #print data.getitem()
            hl1.append(sha256("{category}{sender}{receiver}{amount}{fee}{sign}{time}".format(**data.getitems())).hexdigest())
        
        if not hl1:
            return sha256('').hexdigest()
        
        while True:
            v1 = ''
            v2 = ''
            hl2 = []
    
            if int(len(hl1) % 2)==0 and len(hl1)>1:
                # Even Number's List
        
                for h in hl1:
                    if not v1:
                        v1 = h
                        continue
                    v2 = h
            
                    hl2.append(sha256(v1+v2).hexdigest())
                    v1 = ''
                    v2 = ''
    
            elif int(len(hl1) % 2)==1 and len(hl1)>1:
                hl2 = hl1
                hl2.append('')
    
    
            elif len(hl1)==1:
                return hl1[0]
            
            else:
                return False

            hl1 = hl2        

        return False
        
    
    def calculate_block(self): 
        # load transections from Node Buffer
        self.load_data_from_network_buffer()
        tmp = self.merkle_hash()
        if not tmp:
            print "[Note] No Data load Found"
        self.datahash = tmp
        return
        
    def load_data_from_network_buffer(self):
        for trans_req in self.transbuffer:
            if trans_req not in self.dataload:
                self.dataload.append(trans_req)
        return
        
    def getitems(self):
        return {
            "index"       : self.index,
            "previoushash": self.previoushash,
            "timestamp"   : self.timestamp,
            "targetbit"   : self.targetbit,
            "hash"        : self.hash,
            "datahash"    : self.datahash,
            "dataload"    : [i.getitems() for i in self.dataload],
            "nonce"       : self.nonce,
        }



class MineBlock:
    def __init__(self):
        self.pow = False
        self.block = ''
        self.difficulty = 0
        
    
    def load(self, block):
        self.block = block
        self.difficulty = int(self.block.targetbit)
        self.proof_of_work_number_generator()
        self.pow = True
        return
    
    def getblock(self):
        return self.block
    
    def getitems(self):
        return self.block.getitems()
    
    def previous_block_hash(self, blockitemdict):
        return sha256("{index}{previoushash}{timestamp}{hash}{datahash}{nonce}{targetbit}".format(**blockitemdict)).hexdigest()
    
    
    def proof_of_work_number_generator(self):
        self.block.nonce = 0
        while sha256("{}{}{}{}{}".format(self.block.previoushash,self.block.datahash,self.block.timestamp,self.block.targetbit,self.block.nonce)).hexdigest()[:self.difficulty]!='0'*self.difficulty:
            self.block.nonce+= 1
        self.block.hash = sha256("{}{}{}{}{}".format(self.block.previoushash,self.block.datahash,self.block.timestamp,self.block.targetbit,self.block.nonce)).hexdigest()
        return self.block.nonce
    


class SimpleBlockChain:
    
    def __init__(self, dbname='ChainStore.json'):
        self.dbname = dbname
        
        # Check BlockChain Json Storage File
        if os.path.exists(self.dbname):
            self.chain  = json.load(open(self.dbname, 'r'))
        else:
            self.chain = {
                "blockchain": [],
                'lastupdate': time.time(),
            }
        
        
        # Check BlockChain Status    
        if not self.check_chain_len():
            
            # Add Genesis Block
            self.add_genesis_block()
        
        
    # add genesis block request
    def add_genesis_block(self):
        print "Add Genesis Block Request"
        tmpobj = RequestBlock(1,0)
        mineblock = MineBlock()
        mineblock.load(tmpobj)
        self.new_block_request(mineblock.getblock())
        return
    
    # New Blocking Join Request
    def new_block_request(self, block):
        
        # Verify Block
        if self.validate_new_block(block):
            self.chain['blockchain'].append(block.getitems())
            pass
        return
    
    
    # Validate New Block Before Joining It to main Chain
    def validate_new_block(self, block):
        return True
        
        
    # Check block chain length
    def check_chain_len(self):
        return len(self.chain['blockchain'])
    
    def pre_block(self):
        return self.chain['blockchain'][-1]
        #return
        
    # save updates
    def close(self):
        f = open(self.dbname, 'w')
        self.chain['lastupdate']= time.time()
        json.dump(self.chain, f, sort_keys=True, indent=4, separators=(',', ': '))
        f.close()
        return
    
    
    
if __name__=='__main__':
    sbc = SimpleBlockChain() 
    trans = RequestTransection()
    trans.create_transection("send", "123456", "654231", '0', '500')
    print trans.previous_block_hash(sbc.pre_block())

    reqblock = RequestBlock(index=sbc.check_chain_len()+1, previoushash=trans.previous_block_hash(sbc.pre_block()), transbuffer=[trans])

    m = MineBlock()
    m.load(reqblock)
    sbc.new_block_request(block=m.getblock())

    print sbc.chain
    sbc.close()
