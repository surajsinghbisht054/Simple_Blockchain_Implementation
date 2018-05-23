#!/usr/bin/python

__author__='''
        Suraj Singh bisht
        surajsinghbisht054@gmail.com
        www.bitforestinfo.com
        github.com/surajsinghbisht054


'''


# coding: utf-8

# In[100]:


import json
import os
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from hashlib import md5
from hashlib import sha256
from Crypto.Hash import SHA256
import binascii
import base64
import time


# In[101]:


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
        siger = PKCS1_PSS.new(r)
        h = SHA256.new(data)
        sign = base64.b64encode(siger.sign(h))
        return sign

#u = User()
#print u.publickey
#print u.privatekey
#print u.address
#print u.signature(u.address)


# In[102]:


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


# (
#    category,  --> mine, send, receive
#    sender     --> Sender Wallet Address
#    receiver   --> Receiver Wallet Address
#    txni,      --> input transection
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
def verify_transection(bco, transobj):
    # Load Values From Transection Object
    category     = transobj.category
    sender       = transobj.sender 
    receiver     = transobj.receiver
    txni         = transobj.txni
    ccoin        = transobj.ccoin
    coin         = transobj.coin
    fee          = transobj.fee
    timestamp    = transobj.time
    signature    = transobj.signature
    verification = transobj.verification
    
    # Check sender address length
    if len(receiver)!=32:
        print "[+] Condition No. 1 Failed By ", receiver
        return False
    
    # Check Current Transection Time With Previous block time
    if not (float(timestamp) < float(time.time())):
        print "[+] Condition No. 2 Failed By ", receiver
        print "[-] Timestamp {}, Current Time {}".format(timestamp, time.time())
        return False
    
    
    # Miners Transection Conditions
    if (category=='mine') and (sender!=''):
        print "[+] Condition No. 3 Failed By ", receiver
        return False
    
    if (category=='mine') and txni:
        print "[+] Condition No. 4 Failed By ", receiver
        return False
    
    if (category=='mine') and ccoin:
        print "[+] Condition No. 5 Failed By ", receiver
        return False
    
    if (category=='mine') and (int(coin) != 25 ):
        print "[+] Condition No. 6 Failed By ", receiver
        return False
    
    if (category=='mine') and fee:
        print "[+] Condition No. 7 Failed By ", receiver
        return False
    
    if (category=='mine') and not signature:
        print "[+] Condition No. 8 Failed By ", receiver
        return False
    
    if (category=='mine') and verification:
        print "[+] Condition No. 9 Failed By ", receiver
        return False
    
    # Miners Conditions Close
    if category=="mine":
        return True
    
    # Senders Conditions Verification
    if (category=='send') and (len(sender)!=32):
        print "[+] Condition No. 10 Failed By ", sender
        return False
    
    if (category=='send') and not txni:
        print "[+] Condition No. 11 Failed By ", sender
        return False
    
    if (category=='send') and not coin:
        print "[+] Condition No. 12 Failed By ", sender
        return False
    
    if (category=='send') and not fee:
        print "[+] Condition No. 13 Failed By ", sender
        return False
    
    if (category=='send') and not signature:
        print "[+] Condition No. 14 Failed By ", sender
        return False
    
    if (category=='send') and not verification:
        print "[+] Condition No. 15 Failed By ", sender
        return False
    
    
    # Verify verification and sender address
    public = sha256(verification).hexdigest()
    public = sha256(public).hexdigest()
    public = md5(public).hexdigest()
    
    
    
    if not (public==sender):
        print "[x] Invalid Sender Address : {} | {}".format(sender, public)
        return False
    
    # Verify Signature
    h = category + sender + receiver + txni + coin + fee + timestamp
    h = sha256(h).hexdigest()
    h = SHA256.new(h)
    
    r = RSA.importKey(verification)
    sign_verify = PKCS1_PSS.new(r)
    dsignature = base64.b64decode(signature)
    
    if not sign_verify.verify(h, dsignature):
        print "[x] Signature Invalid. Transection Index {} | Sender {} ".format(txni, sender)
        return False
    
    print "[+] Transection Signature Verified."
    
    #
    # So, Previous Conditions Verified That Request Is Generated From Real User
    #
    # Now, Let's Do Some mathematical Calculations for Amount.
    #
    
    input_transections = []
    balance = 0.0
    
    n = len(txni)/64
    for i in range(n):
        input_transections.append(txni[i*64: (i+1)*64])
    
    
    for pretxnid in input_transections:
        if bco.double_spend_check(sender, pretxnid):
            print "[x] Double Spend Detected. Transection Index {}, InputTransection {}".format(txni, pretxnid)
            return False
    # Find Transections Into Blockchain
        data = bco.search_transection_dict(pretxnid)

        if not data:
            print "[x] Invalid Transection Input."
            return False
        #{
        #    'category'
        #    'sender'
        #    'receiver'
        #    'fee': '', 
        #    'ccoin': '', 
        #    'txni': '', 
        #    'time': '1526936989.86', 
        #    'signature': '40eee107b43f2254ef8ea5c9d15f63bba6e872bb2421b3da09173fb88cdd1c8c6578bfe7780cc1d5223c289c95dbbb9bfcc303cd9379e4f47ea7ca095b1e1e4125ed6fbb3c072901dc7c45e34faeeccec1b07bbe972ed94f354a1153ed9ecca402098e64eaf07621d8b35deaa8bcd003edc8f3d8770a93627f8e073d4b1c6ff6', 
        #    'coin': '25'
        #}
        # Verify Input Transection Signatures
        load = data['load']
        
        if load['receiver']==sender:
            #
            # Taking Balance Inputs From Receiving Transections
            #
        
            # Verify Signature
            tmp = load['category'] + load['sender'] + load['receiver'] + load['txni'] + load['coin'] + load['fee'] + load['time']
            tmp = sha256(tmp).hexdigest()
            tmp = SHA256.new(tmp)
            dsignature = base64.b64decode(load['signature'])
        
            if sign_verify.verify(tmp, dsignature):
                print "[+] Input Transection {} \n\t\tVerified By {}".format(pretxnid, sender)
            else:
                print "[-] Input Transection {} \n\t\tVerification Failed By {}".format(pretxnid, sender)
                return False
        
            balance+= float(load['coin'])
        
        elif load['sender']==sender:
            #
            # Taking Inputs From Transection Balance Changes
            #
            balance+= float(load['ccoin'])
        
        else:
            print "[-] Something Wrong With Conditions."
            print load
            pass                                        
    
    
    if balance==0.0:
        print "[x] Insuffecient Balance"
        return False
    
    
    if balance < float(float(coin)+float(fee)+float(ccoin)):
        print "[x] Low Balance"
        return False
        
    return balance



# In[103]:


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
        time.sleep(1)
        return {
            "category" : self.category, 
            'sender': self.sender,
            'receiver' :self.receiver,
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
                           fee='', receiver = '', sender = '', ccoin=''):
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
        self.ccoin     = ccoin
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


# In[104]:


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
    def __init__(self, bco, targetbit=4, transbuffer = []):
        '''
         A Simple Class To Handle All Transection Request And Generate A Valid Block.
        '''
        self.bco         = bco   # SimpleBlockChain Class Object
        self.index       = self.bco.check_chain_len()+1
        
        if self.bco.pre_block():
            self.previoushash = previous_block_hash(self.bco.pre_block())
        else:
            self.previoushash = ''
            
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
        senders = []
        for trans_req in self.transbuffer:
            if trans_req not in self.dataload:
                if verify_transection(self.bco, trans_req):
                    if trans_req.sender not in senders:
                        self.dataload.append(trans_req)
                        senders.append(trans_req.sender)
                    else:
                        print "[x] Double Transection Request Found. ", trans_req
                else:
                    print "[x] Transection Verification Fail.", trans_req
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


# In[105]:


#
# Class Design To Perform Proof Of Work Hash Calculations
#
class MineBlock:
    '''
    A Simple Class That will Automatically handle Block Mining And Other Important Stuff.
    
    '''
    def __init__(self, block_chain_obj):
        self.bco = block_chain_obj
        self.pow = False
        self.block = ''
        self.difficulty = 0
        
    def block_validator(self, block):
        # Check Index
        # Check PRevious hash
        # check timestamp
        # check merkle hash
        
               
        if self.bco.check_chain_len()==0:
            previoushash = True
        
        else:
            previoushash = block.previoushash == previous_block_hash(self.bco.pre_block())#sha256("{index}{previoushash}{timestamp}{hash}{datahash}{nonce}{targetbit}".format(**self.pre_block())).hexdigest()
        
        timestamp = float(block.timestamp) < time.time()
        
        index = block.index == self.bco.check_chain_len()+1
        
        datahash = merkle_hash(block.dataload)
        
        if previoushash and timestamp and index and datahash:
            return True
        
        print "[+] Block Condition Failur During MineBLock Verification."
        print "[-] Previous hash verify  : ", previoushash 
        #print "[-] Proof Of Work verify  : ",  proof_of_work_hash 
        print "[-] Timestamp verify      : ",  timestamp 
        print "[-] Block Index verify    : ",  index 
        print "[-] Block Datahash verify : ",  datahash 
        return False
    
    def load(self, block):
        '''
        Load Block
        '''
        
        time.sleep(2)  # To pass timestamp condition
        
        
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
    


# In[106]:


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
            
    def getchain(self):
        return self.chain
    
    def search_transection_dict(self, txnid):
        for b in self.chain['blockchain'][::-1]:
            for l in b['dataload']:
                if l['txn']==txnid:
                    return l
        return False
    
    def get_all_transections(self, address):
        rectxn = []
        sentxn = []
        for b in self.chain['blockchain'][::-1]:
            for l in b['dataload']:
                txn =  l['txn']
                n = l['load']
                if n['sender']==address:
                    sentxn.append(l)
                if n['receiver']==address:
                    rectxn.append(l)
        
        return (rectxn, sentxn)
        
        
    # add genesis block request
    def add_genesis_block(self):
        '''
        Add Genesis Block
        '''
        print "[+] Add Genesis Block Request."
        tmpobj = RequestBlock(self)
        mineblock = MineBlock(self)
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
            
            print "[+] Request Block Verified. Index : ", block.index
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
        
        
        
        print "[+] Block Condition Failur During SimpleBLockChain Verification Member Function."
        print "[-] Previous hash verify  : ",  previoushash 
        print "[-] Proof Of Work verify  : ",  proof_of_work_hash 
        print "[-] Timestamp verify      : ",  timestamp 
        print "[-] Block Index verify    : ",  index 
        print "[-] Block Datahash verify : ",  datahash 
        print "[-] Block Targetbit verify: ",  diff
        return False
        
    # Check block chain length
    def check_chain_len(self):
        return len(self.chain['blockchain'])
    
    def pre_block(self):
        if self.chain['blockchain']:
            return self.chain['blockchain'][-1]
        #return
        
    # save updates
    def close(self):
        f = open(self.dbname, 'w')
        self.chain['lastupdate']= time.time()
        json.dump(self.chain, f, sort_keys=True, indent=4, separators=(',', ': '))
        f.close()
        return
    
    
    def get_address_trans(self, address):
        received = []
        sent = []
        changes = []
    
        retxn, setxn = self.get_all_transections(address)
    
        # Receiving Transection List
        for r in retxn:
            received.append((float(r['load']['coin']), r['txn']))
    
        # Spent Transection list
        for s in setxn:
            sent.append((float(s['load']['coin'])+float(s['load']['fee']), s['txn']))
        
            if s['load']['ccoin']:
                changes.append((float(s['load']['ccoin']), s['txn']))
        
        return (received, sent, changes)

    def get_address_balance(self, address):
        rec, sen, cha = self.get_address_trans(address)
    
        r = 0.0
        s = 0.0
        for amount, txnid in rec:
            r+= amount
        for amount, txnid in sen:
            s+= amount
    
        return r-s
    
    def double_spend_check(self, address, txn):
        rcv, snt = self.get_all_transections(address)
        input_transections = []
        
        for t in snt:
            k=t['load']['txni']
            n = len(k)/64
            for i in range(n):
                tmp = k[i*64: (i+1)*64]
                if tmp:
                    input_transections.append(tmp)
                
        if txn in input_transections:
            print "[X] Double Spend Found : ", txn
            
            return True
        print "[x] Double Spend Clear : ", input_transections, txn
        return False
 


    
    
    
    


# In[107]:


class PleaseMine:
    def __init__(self, sbc, auth, transreq = []):
        self.sbc = sbc
        self.auth = auth
        self.drop_fraud_minning_requests(transreq)
        self.add_award_transection()
        
    def drop_fraud_minning_requests(self, transreq):
        self.transreq = []
        
        for trans in transreq:
            if trans.category=="mine":
                pass
            elif trans.category=='send':
                self.transreq.append(trans)
            else:
                print "[x] Unknown Input Transections : ", transreq
        return
        
    def add_award_transection(self):
        req = RequestTransection(self.auth)
        #create_transection
        req.create_transection(category='mine', 
                               coin='25', 
                               receiver = self.auth.address)
        self.reward_txn = req.transection
        self.transreq.append(req)
        
        # assemble all transection and create a block object
        reqblock = RequestBlock(
            self.sbc,
            transbuffer=self.transreq
            )
    
        # Miner Object
        mineblock = MineBlock(self.sbc)


        # Load Block and find proof of work
        mineblock.load(reqblock)


        # print proof of work
        #print mineblock.getitems()

        # insert block object to blockchain handler
        self.sbc.new_block_request(mineblock.getblock())
        
        return
    
    


# In[108]:


import os
import pickle


# In[109]:



class Wallet:
    def __init__(self, db = 'walletdb.json'):
        self.dbname = db
        self.username = None
        self.password = None
        
        self.retreive_wallet()
        
        
    def create_new_user(self, username, password):
        # Create User Authentication Object
        u = User()
        
        self.db[username+password] = {
            'auth': pickle.dumps(u),
            'rtxn': [],
            'stxn': [],
            'bal' : [],
        }
        
        return
    
    def check_account(self, username, password):
        if username+password in self.db.keys():
            return True
        return False
    
    def load_account(self, username, password):
        if self.check_account(username, password):
            self.auth = pickle.loads(self.db[username+password]['auth'])
            self.rtxn = self.db[username+password]['rtxn']
            self.stxn = self.db[username+password]['stxn']
            self.bal = self.db[username+password]['bal']
        return
        
    def retreive_wallet(self):
        if os.path.exists(self.dbname):
            self.db = json.load(open(self.dbname, 'r'))
        else:
            self.db = {}
            
        return
    
    def refresh(self):
        self.close()
        self.retreive_wallet()
        return
    
    def close(self):
        tmp = open(self.dbname, 'w')
        json.dump(self.db, tmp, sort_keys=True, indent=4, separators=(',', ': '))
        tmp.close()
        return
        


# In[110]:



if __name__=='__main__':
    # -----------------------------------------------------------
    # ================= Global Object ===========================
    # -----------------------------------------------------------
    # Create Blockchain handler object
    sbc = SimpleBlockChain() 


    w = Wallet()
    w.create_new_user('suraj', 'singh')
    w.refresh()
    w.load_account('suraj', 'singh')
    # ------------------------------------------------------------
    # ==================== Miner =================================
    # ------------------------------------------------------------


    # Create User Authentication Object
    u = w.auth #= User()
    print "[*] Miner Address : ", u.address


    # [Mining First Block]
    miner = PleaseMine(sbc, u)
    print "[*] Miner Reward : ", miner.reward_txn['txn']


    # ------------------------------------------------------------
    # ==================== Nodes =================================
    # ------------------------------------------------------------

    node = User()  # Example Node
    print "[*] Node Address : ", node.address
    # Create Transection Request object
    n_address = node.address # Shared its receiving address with miners.. because at this time,
    # miner is the only one account that contain 25 coins


    # Miner Requested A Transection
    req = RequestTransection(u)
    req.create_transection(category='send', 
                           sender=u.address, 
                           receiver=n_address, 
                           fee='0.1' ,
                           coin='20',
                           ccoin = str(25.0-(20.0+0.1)),
                           txni= miner.reward_txn['txn']
                          )
    req1 = RequestTransection(u)

    req1.create_transection(category='send', 
                           sender=u.address, 
                           receiver=n_address, 
                           fee='0.1' ,
                           coin='20',
                           ccoin = str(25.0-(20.0+0.1)),
                           txni= miner.reward_txn['txn'][::-1]
                          )
    transer_money_reference_ = req.transection

    print "[+] Changes Left : ", req.ccoin

    # Wait... To Add This Block... Miner Again Need To Use its Computational Power... So,,


    u1 = User()
    #PleaseMine(sbc, u1, transreq=[req])
    #PleaseMine(sbc, u1, transreq=[req1])
    #PleaseMine(sbc, u1, transreq=[req, req1])


    sbc.close()


# In[111]:



print sbc.get_address_balance(u.address)

#retxn, setxn = sbc.get_all_transections(node.address)

