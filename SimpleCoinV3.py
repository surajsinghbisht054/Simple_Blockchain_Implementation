#!/usr/bin/python

__author__='''
        Suraj Singh bisht
        surajsinghbisht054@gmail.com
        www.bitforestinfo.com
        github.com/surajsinghbisht054


'''

# coding: utf-8

# In[9]:


import json
import os
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from hashlib import md5
from hashlib import sha256
from Crypto.Hash import SHA256
import binascii
import base64
import time


# In[10]:


#
# User Authentication Handling Class
#
class User:
    def __init__(self, private=None, public=None):
        '''
        A Simple Class To Handle User Authentication Activities
        
        '''
        
        if public:
            self.publickey = public
        else:
            self.publickey = ''
        
        if private:
            self.privatekey = RSA.importKey(private)
        else:
            (self.privatekey, self.address) = self.generate_key_pair()
        
    def generate_key_pair(self):
        '''
        Generate New Pair Of Keys For New Users 
        
        '''
        private = None
        public  = None

        # Random Number Generated
        random = RSA.Random.new().read
        PUB_LEN = 1024


        # RSA Object
        RSAKey = RSA.generate(PUB_LEN, random)

        # Private Key
        private = RSAKey.exportKey()

        # Public Key
        self.publickey =  RSAKey.publickey().exportKey()
        
        public = sha256(self.publickey).hexdigest()
        public = sha256(public).hexdigest()
        public = md5(public).hexdigest()
        
        return (private, public)
    
    def signature(self, data):
        '''
        Sign Data Using User Inserted/Generated Private Key
        '''
        
        r = RSA.importKey(self.privatekey)
        siger = PKCS1_v1_5.new(r)
        h = SHA256.new(data)
        return  binascii.hexlify(siger.sign(h))

#u = User()
#print u.publickey
#print u.privatekey
#print u.address
#print u.signature(u.address)


# In[11]:


# Global Functions

def previous_block_hash(blockitemdict):
    '''
    Global Function To Calculate previous block hashes
    '''
    return sha256("{index}{previoushash}{timestamp}{hash}{datahash}{nonce}{targetbit}".format(**blockitemdict)).hexdigest()

def transection_hash(data):
    '''
    Global Function To Calculate Transection hashes
    '''
    return sha256("{category}{txni}{coin}{fee}{signature}{time}".format(**data.getitems())).hexdigest() 

def merkle_hash(dataload):
    '''
     A Simple Class That Automatically Calculate Hashes Of All Transection feilds using
     Merkle Type Algorithm.
     
    '''
    
    # Two Empty Containers
    hl1 = [] 
    hl2 = [] 
    
    for data in dataload:
        hl1.append(transection_hash(data))
        
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


# In[12]:


#
# trasenction feild structure
# (
#    category,  --> mine, send, receive
#    sender     --> Sender Wallet Address
#    receiver   --> Receiver Wallet Address
#    txni,      --> input transection
#    txno,      --> output transection
#    ccoin      --> net balance 
#    coin,      --> coin
#    fee,       --> transection fee
#    time,      --> time
#    signature, --> hash = sha256(category + sender + receiver + txni + txno + coin + fee + time)
#                   hash = private_key_signature(hash)
# 
#    
#    verification --> SENDER_PUBLIC_KEY
# )
#
# Trasenction Unique Identities
# 
# structure 
#   (
#
#         Name  :  SHA256( sender + receiver )   ---> Result Hash Will Be Same 
#                                                    if Sender and Reciever are same (Not Unique)
#         txnid :  SHA256( Name + Signature)       --> Always Unique
#    
#         txn : trasenction feild
#
#   )
#
#
#
#







# Simple Request Transection ()
class RequestTransection:
    def __init__(self, user):
        '''
         A Simple Class To Handle And Generate Valid Transection Requests 
         Using User Object Authentication Object.
         
        '''
        self.category   = ''
        self.user       = user
        self.sender     = None
        self.receiver   = None
        self.txni       = []
        self.ccoin      = ''
        self.coin       = ''
        self.time       = ''
        self.fee        = ''
        self.signature  = ''
        self.transection = {}
        self.verification = ''
        
    def getitems(self):
        '''
        Get All Feild Items
        '''
        return {
            "category" : self.category,  
            "txni"   : self.txni,
            "ccoin"  : self.ccoin,
            "coin"   : self.coin,
            "fee"      : self.fee,
            "signature"     : self.signature,
            "time"     : self.time,
            
        }
    
    def __repr__(self):
        return "< transReq {} | {} >".format(self.category, self.time)

    
    def create_transection(self, category='mine', txni=[], coin='', 
                           fee='', receiver = '', sender = ''):
        '''
        Generate Valid Transection Request With Automatic Hash And Signature handling
        '''
        if not sender:
            sender = self.user.address
            
        if category=="mine":
            sender =''
            receiver = self.user.address
            
        if not receiver:
            raise "please insert valid receiver address."
        
        # Lower case --- > category
        category = category.lower()
        
        # Check category
        if category not in ['mine', 'send']:
            raise "please use valid categories like mine or send "
            
            
        # initialise values
        self.category  = category
        self.sender    = sender
        self.receiver  = receiver
        self.txni      = ''.join(i for i in txni)
        self.coin      = coin
        self.fee       = fee
        self.time      = str(time.time())
        #
        #    signature, --> hash = sha256(category + sender + receiver + txni + coin + fee + time)
        #                   private_key_signature(hash)
        #
        h = self.category + self.sender + self.receiver + self.txni + self.coin + self.fee + self.time
        h = sha256(h).hexdigest()
        
        
        if self.category!="mine":
            self.verification = self.user.publickey
        
        self.signature = self.user.signature(h)
        
        self.transection = {
            "name" : sha256(self.sender + self.receiver).hexdigest(),
            "txn"  : sha256( sha256(self.sender + self.receiver).hexdigest() + self.signature).hexdigest(),
            "load" : self.getitems(),
            
        }
        return


# In[13]:


#
#
# RequestBlock Object handler
#
# Structure
# ( 
#     index         ---> current block index in chain
#     previoushash  ---> previous block hash
#     timestamp     ---> timestamp
#     targetbit     ---> difficulty bit in hash calculation
#     hash          ---> self block hash (proof of work)
#     datahash      ---> datahash (merkle hash of transection feilds)
#     dataload      ---> all transection data
#     nonce         ---> nonce (proof of work)
#  )
#
#
#
#
#
class RequestBlock:
    def __init__(self, index, previoushash, targetbit=4, transbuffer = []):
        '''
         A Simple Class To Handle All Transection Request And Generate A Valid Block.
        '''
        
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

        
    
    def calculate_block(self): 
        '''
        Calculate Block Hash
        '''
        # load transections from Node Buffer
        self.load_data_from_network_buffer()
        tmp = merkle_hash(self.dataload)
        if not tmp:
            print "[Note] No Data load Found"
        self.datahash = tmp
        return
    
        
    def load_data_from_network_buffer(self):
        '''
        Load Trasection Requests
        '''
        for trans_req in self.transbuffer:
            if trans_req not in self.dataload:
                self.dataload.append(trans_req)
        return
        
    def getitems(self):
        '''
        return items
        '''
        return {
            "index"       : self.index,
            "previoushash": self.previoushash,
            "timestamp"   : self.timestamp,
            "targetbit"   : self.targetbit,
            "hash"        : self.hash,
            "datahash"    : self.datahash,
            "dataload"    : [i.transection for i in self.dataload],
            "nonce"       : self.nonce,
        }


# In[14]:


#
# Class Design To Perform Proof Of Work Hash Calculations
#
class MineBlock:
    '''
    A Simple Class That will Automatically handle Block Mining And Other Important Stuff.
    
    '''
    def __init__(self):
        self.pow = False
        self.block = ''
        self.difficulty = 0
        
    def block_validator(self, block):
        # Check Index
        # Check PRevious hash
        # check timestamp
        # check merkle hash
        if merkle_hash(block.dataload):
            return True
        return False
    
    def load(self, block):
        '''
        Load Block
        '''
        if self.block_validator(block):
            self.block = block
            self.difficulty = int(self.block.targetbit)
            self.proof_of_work_number_generator()
            self.pow = True
            return True
        
        return False
    
    def getblock(self):
        return self.block
    
    def getitems(self):
        return self.block.getitems()
    
    def proof_of_work_number_generator(self):
        self.block.nonce = 0
        while sha256("{}{}{}{}{}".format(self.block.previoushash,self.block.datahash,self.block.timestamp,self.block.targetbit,self.block.nonce)).hexdigest()[:self.difficulty]!='0'*self.difficulty:
            self.block.nonce+= 1
        self.block.hash = sha256("{}{}{}{}{}".format(self.block.previoushash,self.block.datahash,self.block.timestamp,self.block.targetbit,self.block.nonce)).hexdigest()
        return self.block.nonce
    


# In[15]:


#
# Class To handle Block chain database and act as a central sever to handle all block request
#
class SimpleBlockChain:
    '''
    A Simple Class To Handle Block Chain Database.
    '''
    def __init__(self, dbname='ChainStore.json', targetbit = 4):
        self.targetbit = targetbit
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
        '''
        Add Genesis Block
        '''
        print "Add Genesis Block Request"
        tmpobj = RequestBlock(1,0)
        mineblock = MineBlock()
        mineblock.load(tmpobj)
        self.new_block_request(mineblock.getblock())
        return
    
    # New Blocking Join Request
    def new_block_request(self, block):
        '''
        New Block Request
        '''
        # Verify Block
        if self.validate_new_block(block):
            self.chain['blockchain'].append(block.getitems())
            
            print "[+] Request Block Verified."
        else:
            print "[Error] Request Block Is Not Valid."
        return
    
    
    # Validate New Block Before Joining It to main Chain
    def validate_new_block(self, block):
        '''
        Validate And Verify Various Hash Calculations
        '''
        # check target bit
        # check block index
        # check previous block hash
        # check Proof of work
        # check timestamp
        # check datahash
        
        diff = self.targetbit == int(block.targetbit)
        
        if self.check_chain_len()==0:
            previoushash = True
        
        else:
            previoushash = block.previoushash == previous_block_hash(self.pre_block())#sha256("{index}{previoushash}{timestamp}{hash}{datahash}{nonce}{targetbit}".format(**self.pre_block())).hexdigest()
        
        proof_of_work_hash = sha256("{previoushash}{datahash}{timestamp}{targetbit}{nonce}".format(**block.getitems())).hexdigest()[:block.targetbit]=='0'*block.targetbit
        
        timestamp = float(block.timestamp) < time.time()
        
        index = block.index == self.check_chain_len()+1
        
        datahash = merkle_hash(block.dataload)
        
        if previoushash and proof_of_work_hash and timestamp and index and datahash and diff:
            return True
        print previoushash 
        print proof_of_work_hash 
        print timestamp 
        print index 
        print datahash 
        print diff
        return False
        
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
    
    
    
    


# In[18]:


# -----------------------------------------------------------
# ================= Global Object ===========================
# -----------------------------------------------------------
# Create Blockchain handler object
sbc = SimpleBlockChain() 

# ------------------------------------------------------------
# ==================== Miner =================================
# ------------------------------------------------------------


# Create User Authentication Object
u = User()

# Create First Transection And Get Miners Reward
req = RequestTransection(u)

#create_transection
req.create_transection(category='mine', coin='25', fee='0', receiver = u.address)

reward_trasection = req.transection



# assemble all transection and create a block object
reqblock = RequestBlock(
    index = sbc.check_chain_len()+1, 
    previoushash = previous_block_hash(sbc.pre_block()), 
    transbuffer=[req]
)

# Miner Object
mineblock = MineBlock()

# Load Block and find proof of work
mineblock.load(reqblock)


# print proof of work
mineblock.getitems()



# insert block object to blockchain handler
sbc.new_block_request(mineblock.getblock())

# Now, Our First Transection Is Complete..

# Now, Let's Try Second Transection Request By Any Node


# ------------------------------------------------------------
# ==================== Nodes =================================
# ------------------------------------------------------------

node = User()  # Example Node

# Create Transection Request object
n_address = node.address # Shared its receiving address with miners.. because at this time,
# miner is the only one account that contain 25 coins


# Miner Requested A Transection
req = RequestTransection(u)
req.create_transection(category='send', sender=u.address, receiver=n_address, coin='20',txni=reward_trasection['txn'])
transer_money_reference_ = req.transection


# Wait... To Add This Block... Miner Again Need To Use its Computational Power... So,,

# Create First Transection And Get Miners Reward
req1 = RequestTransection(u)  # 

#create_transection
req1.create_transection(category='mine', coin='25', fee='0', receiver = u.address)

reward_2_trasection = req1.transection


# assemble all transection and create a block object
reqblock = RequestBlock(
    index = sbc.check_chain_len()+1, 
    previoushash = previous_block_hash(sbc.pre_block()), 
    transbuffer=[req, req1]
)

# Miner Object
mineblock = MineBlock()

# Load Block and find proof of work
mineblock.load(reqblock)


# print proof of work
mineblock.getitems()



# insert block object to blockchain handler
sbc.new_block_request(mineblock.getblock())

sbc.close()

