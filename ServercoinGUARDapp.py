import hashlib
from logging import exception
import requests
IP = input("Enter the IP or Domain of the server you're connecting to: ")
Port = int(input("What is the port?"))
DomainType = int(input("Is it a domain or an IP? type 1. for domain and 2. for IP"))

servercoinwallet = input("What is the servercoinwallet for this?")
httptype = input("type the http type it is.")
typeofcoins = int(input("1. for not FIAT and 2. for FIAT"))
if typeofcoins == 1:
 coinsperimpression = input("How many impressions per coin? ?")
else:
 coinsperimpressionFIAT = int(input("What is the FIAT price of the impressions per coin? "))
def sendNEWPRICE():
 LISTOFPRICES = []
 if not coinsperimpressionFIAT == "NONE":
  
  for item in TABLEOFWEBSITESTOCHECK:
     response = requests.get(item)
     
     if response.status_code==200:
         jsonthing = response.json()
         jsonthing = float(jsonthing["Success"])
         LISTOFPRICES.append(jsonthing)
 AVERAGEPRICEOFLISTPRICES = 0
 for item in LISTOFPRICES:
     AVERAGEPRICEOFLISTPRICES+=item
 AVERAGEPRICEOFLISTPRICES = AVERAGEPRICEOFLISTPRICES/len(LISTOFPRICES)
 NEWPPG = coinsperimpressionFIAT*AVERAGEPRICEOFLISTPRICES
 coinsperimpression = NEWPPG
 coinsperimpression = math.floor(NEWPPG)
if typeofcoins == 1:
    with open("impressionspercoin.txt","w") as file:
        file.write(str(coinsperimpression)) 
else:
     with open("impressionspercoinfiat.txt","w") as file:
        file.write(str(coinsperimpressionFIAT)) 
serverlist = []
thingvalue = True
import json
import os
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from ecdsa import SigningKey,VerifyingKey
from ecdsa.curves import SECP256k1
import time
import pickle
import mnemonic
from mnemonic import Mnemonic
TABLEOFWEBSITESTOCHECK = []
loadthisloop = True

while loadthisloop == True:
  loadinputty = int(input("1. for stopping this and 2. for continuing this"))
  if loadinputty == 2:
    newserver = input("What is the Address of the website you are getting your data from? Make sure to add https ")
    TABLEOFWEBSITESTOCHECK.append(newserver)
  else:
    loadthisloop = False


def getranked_highest_item(d, keynum, value_key):
    if len(d) < keynum:
        raise ValueError(f"Dictionary must have at least {keynum} items.")
    
    # Sort the dictionary by the specified value key in descending order and get the keys
    sorted_keys = sorted(d, key=lambda k: d[k][value_key], reverse=True)
    print("SORTEDKEYS: "+str(sorted_keys))
    # The ranked highest item will be at index keynum-1 (0-based index)
    ranked_highest_key = sorted_keys[keynum-1]
    
    return ranked_highest_key, d[ranked_highest_key]

def getranked_least_highest_item(d, keynum,value_key):
    if len(d) < keynum:
        raise ValueError(f"Dictionary must have at least {keynum} items.")
    
    # Sort the dictionary by values in ascending order and get the keys
    sorted_keys = sorted(d, key=lambda k: d[k][value_key])
    
    # The keynum-th least highest item will be at index keynum-1 (0-based index)
    ranked_key = sorted_keys[keynum - 1]
    
    return ranked_key, d[ranked_key]
# Example dictionary

import hashlib
import math
import socket
import requests
import base64
import copy
import random
import requests
from flask import app
from flask import request
from flask import Flask,jsonify,send_file,make_response
app = Flask(__name__)
hashlib.sha256("E".encode('utf-8')).hexdigest()
stuffindata = ''
class Cookie:
    def __init__(self, name, value, path="/", domain=None, secure=False, http_only=True, max_age=None):
        self.name = name
        self.value = value
        self.path = path
        self.domain = domain
        self.secure = secure
        self.http_only = http_only
        self.max_age = max_age

    def __str__(self):
        cookie_str = f"{self.name}={self.value}; Path={self.path}"
        if self.domain:
            cookie_str += f"; Domain={self.domain}"
        if self.secure:
            cookie_str += "; Secure"
        if self.http_only:
            cookie_str += "; HttpOnly"
        if self.max_age:
            cookie_str += f"; Max-Age={self.max_age}"
        return cookie_str

# Example usage
cookie = Cookie(name="sessionid", value="123456789", path="/", domain="example.com", secure=True, http_only=True, max_age=3600)
print(cookie)
with open('TextFile1.txt','r') as file:
    stuffindata = file.read()
while thingvalue == True:
        thinginput = int(input("Select 1 for adding a server to the serverlist and 2 for stopping this"))
        if thinginput == 1:
            server = input("What is the server ip?")
            port = input("What is the server port?")
            serverpower = server+':'+port
            serverlist.append(serverpower)
        else:
            thingvalue = False
if DomainType == 2:
 url =httptype+ IP + ":" + str(Port) + "/recieveservers"
else:
 url = httptype+str(IP)+"/recieveservers"
print("URL: "+str(url))
    
    
def addservertothat(server):
        if not server  in serverlist:
            serverlist.append(server)
for item in serverlist:
        try:
         response = requests.get(item)
         for item in response:
            addservertothat(item)
        except:
            lol=True

url2 = "http://"+IP+":"+str(Port)+"/recieveservers"
servers = []
try:
     servers33 = requests.get(url)
     servers33=servers33.json()
     servers33 = servers33["Success"]
     servers = servers33
except Exception as e:
        lol=True
for item in serverlist:
        urlthing = "http://"+serverlist[item]+"/recieveservers"
        try:
         serverthingpowerthing = requests.get(urlthing)
        
        except:
            lol=True
        superserverthing = serverthingpowerthing.json()

        for itemm in dict(superserverthing["Success"]):
            addservertothat(item)
serverlistlist = {}
serverhashlist = {}
serverlistdoubleup={}
def addtoserverhashlist(serverhash,serverthatsentit,item):
        if serverhash in serverhashlist:
            serverhashlist[serverhash]["Amount"]+=1
            serverhashlist[serverhash]["ServersThatGotIt"].append(serverthatsentit)
            serverlistdoubleup[serverhash]=item
        else:
            serverhashlist[serverhash] = {"Amount":1,"ServersThatGotIt":[]}
            serverhashlist[serverhash]["ServersThatGotIt"].append(serverthatsentit)
            serverlistdoubleup[serverhash]=item

it = 0
for item in servers:
       
       try:
        responsething = requests.get("http://"+servers[item]+"/recieveservers")
        responsething2 = requests.get("http://"+servers[item]+"/recieveservers2")
        
        responsething=responsething.json()
        responsething2 = responsething2.json()
        responsething2 = responsething2["Success"]

        serverlistlist[it] = {"Data":responsething["Success"],"Server":servers[item],"NEWDATA":responsething2}
      
        it+=1

       except Exception as E:
           lol=True
table_string=""
for item in serverlistlist:
      for itemm in serverlistlist[item]["Data"]:
        table_string = table_string+str(serverlistlist[item]["Data"][itemm])
      hashthing = hashlib.sha256(table_string.encode('utf8')).hexdigest()
      addtoserverhashlist(hashthing,serverlistlist[item]["Server"],item)
TOTALPOWERVALUE = True
FIRSTWAVE = True
HashList = {}
def addhashthingtohashlist(hasht,server):
      try:
        if not hasht in HashList:
            HashList[hasht] = {"Amount":1,"Serverswithhash":[]}
            HashList[hasht]["Serverswithhash"].append(server)
        else:
            HashList[hasht]["Amount"]+=1
            HashList[hasht]["Serverswithhash"].append(server)
      except Exception as e:
                  lol=True
def delete_fifth_character(input_string,startnum):
   newstring = ''
   numswenthrough = 0
   for item in input_string:
       numswenthrough+=1
       if not startnum == numswenthrough:
           newstring+=item
   return newstring
def convertthething(verifyingkey):
        verifyingkeyloader = str(verifyingkey)
        stufflist = ''
        for i in range(len(verifyingkeyloader)-59):
                   stufflist = stufflist+verifyingkeyloader[i+30]
        
        thingpower = ''
        Devicet = stufflist
       
        Num1 = 0
        Num2 = 0
        wentthroughnum = -1
        Devicex = ""
        devicey = ""
               
        neothing = {}
        for item in stuffindata:
               if not item == '/':
                  neothing[1] = str(item)
               
               
        for item in Devicet:
                wentthroughnum+=1
                if item == neothing[1] and Num1==0:
                 Num1 = wentthroughnum
                 
                if wentthroughnum == Num1+1 and item == 'n' and Num1>0:
                 Num2 = wentthroughnum
        
        Devicet = Devicet.replace(neothing[1],'')
        Devicet = delete_fifth_character(Devicet,Num2)
        thingpower33 = '''-----BEGIN PUBLIC KEY-----
REPLACE
-----END PUBLIC KEY-----'''
        wentthroughnum2 = -1
        for item in Devicet:
           if wentthroughnum2<Num1-1:
                 wentthroughnum2+=1
    
                 Devicex = Devicex+item
    
           else:
                 break
               
              
        wentthroughnum3 = -1
        for item in Devicet:
         wentthroughnum3+=1
         if wentthroughnum3>=Num1:
               devicey+=item
               thingpower = Devicex+'\n'+devicey
               
               
               thingpower33 = thingpower33.replace('REPLACE',thingpower)
        thingpower33 = '-----BEGIN PUBLIC KEY-----\n'+str(thingpower)+'\n-----END PUBLIC KEY-----'
        return thingpower33
max_hash_key = max(serverhashlist, key=lambda x: serverhashlist[x]['Amount'])

trueserverlist = serverlistlist[serverlistdoubleup[max_hash_key]]
class ServerCoinGuard:
    def __init__(self):
        self.reviewableservers = {}
        self.accounts = {}
        self.cookieidtoaccount = {}
        self.totalimpressions = 0
        self.ads = {}
    def addaccount(self,wallet,username,walletkey,signature):
          DICTIONARY = {}
          verifyingkeydatalist = {}
          verifyingkeyhashdatalist  ={}
          keydatanumber = 1
          data = {"wallet":wallet}

          for item in servers:
                                if keydatanumber>5:
                                    break
                               
                                urltosendto = trueserverlist["Data"][str(item)]
                                verifyingkeys22 = requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getverifyingkeyofwallet",json=data)

                                verifyingkeys22 = verifyingkeys22.json()
                                verifyingkeys22 = verifyingkeys22["Success"]
                                hashthis = ""
                                print("verifyingkeys22: "+str(verifyingkeys22))
                                hashthis = hashthis+str(verifyingkeys22["walletname"])
                                hashthis = hashthis+str(verifyingkeys22["Verifyingkey"])
                                hashthis = str(hashlib.sha256(hashthis.encode('utf-8')).hexdigest())
                                if not hashthis in verifyingkeyhashdatalist:
                                    verifyingkeyhashdatalist[hashthis] = {"Count":1}
                                else:
                                    verifyingkeyhashdatalist[hashthis]["Count"]+=1
                                verifyingkeydatalist[hashthis] = verifyingkeys22
                                keydatanumber+=1
          highest_item = max(verifyingkeydatalist, key=lambda x: verifyingkeyhashdatalist[x]['Count'])
          Datathing = verifyingkeydatalist[str(highest_item)]
          EASYTOUSEDATATHING = {}
          WALLETVALUES = {}

                       
          Walletindata = Datathing["walletname"]
          Verifyingkey = Datathing["Verifyingkey"]
          EASYTOUSEDATATHING[Walletindata] = {"Verifyingkey":load_pem_public_key(convertthething(Verifyingkey).encode('utf-8'),default_backend()),"Verifyingkeysummoningthing":Verifyingkey}
          WALLETVALUES[Walletindata] = {"Coins":0,"txextras":{}}
          DOITNOW = False
          print("DATAINEASYTHING: "+str(EASYTOUSEDATATHING))
          try:
                EASYTOUSEDATATHING[wallet]["Verifyingkey"].verify(
                   signature,
                   walletkey.encode('utf-8'),
                   ec.ECDSA(hashes.SHA256())
                )
                DOITNOW = True
          except Exception as e:
                print("Error: "+str(e))
                DOITNOW = False
          if DOITNOW == True:
              Salt = random.randint(1,9999999)
              cookieid = random.randint(1,99999999999999999999999999999999999999999999999999999)
              self.accounts[username] = {"Reviews":[],"Ratedreviews":[],"Comments":{},"CommentReviews":[],"ReviewNum":0,"cookieid":cookieid,"Password":hashlib.sha256((walletkey+str(Salt)).encode('utf-8')).hexdigest(),"Salt":str(Salt)}
              print(self.accounts[username]) 
              self.cookieidtoaccount[cookieid] = {"Username":username}
              print("COOKIEKEY: "+str(self.cookieidtoaccount[cookieid]))
              print("COOKIEID: "+str(cookieid))
          else:
              print("THERE'S THE ISSUE!")
          return "WE DID IT oK!"
    def loginaccount(self,wallet,username,walletkey,signature):
          DICTIONARY = {}
          verifyingkeydatalist = {}
          verifyingkeyhashdatalist  ={}
          keydatanumber = 1
          data = {"wallet":wallet}
          for item in servers:
                                if keydatanumber>5:
                                    break
                               
                                urltosendto = trueserverlist["Data"][str(item)]
                                verifyingkeys22 = requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getverifyingkeyofwallet",json=data)

                                verifyingkeys22 = verifyingkeys22.json()
                                verifyingkeys22 = verifyingkeys22["Success"]
                                hashthis = ""
                                print("verifyingkeys22: "+str(verifyingkeys22))
                                hashthis = hashthis+str(verifyingkeys22["walletname"])
                                hashthis = hashthis+str(verifyingkeys22["Verifyingkey"])
                                hashthis = str(hashlib.sha256(hashthis.encode('utf-8')).hexdigest())
                                if not hashthis in verifyingkeyhashdatalist:
                                    verifyingkeyhashdatalist[hashthis] = {"Count":1}
                                else:
                                    verifyingkeyhashdatalist[hashthis]["Count"]+=1
                                verifyingkeydatalist[hashthis] = verifyingkeys22
                                keydatanumber+=1
          highest_item = max(verifyingkeydatalist, key=lambda x: verifyingkeyhashdatalist[x]['Count'])
          Datathing = verifyingkeydatalist[str(highest_item)]
          EASYTOUSEDATATHING = {}
          WALLETVALUES = {}
                       
          Walletindata = Datathing["walletname"]
          Verifyingkey = Datathing["Verifyingkey"]
          EASYTOUSEDATATHING[Walletindata] = {"Verifyingkey":load_pem_public_key(convertthething(Verifyingkey).encode('utf-8'),default_backend()),"Verifyingkeysummoningthing":Verifyingkey}
          WALLETVALUES[Walletindata] = {"Coins":0,"txextras":{}}
          DOITNOW = False
          print("DATAINEASYTHING: "+str(EASYTOUSEDATATHING))
          try:
                EASYTOUSEDATATHING[wallet]["Verifyingkey"].verify(
                   signature,
                   walletkey.encode('utf-8'),
                   ec.ECDSA(hashes.SHA256())
                )
                DOITNOW = True
          except Exception as e:
                print("Error: "+str(e))
                DOITNOW = False
          if DOITNOW == True:
              return "YES"
          else:
              return "NO"
    def loginaccount2(self,username,password):
        print("Account: "+str(self.accounts[username]))
        Encodedpassword = hashlib.sha256((password+str(self.accounts[username]["Salt"])).encode('utf-8')).hexdigest()
        if Encodedpassword == self.accounts[username]["Password"]:
            return "YES"
        else:
            print("Encodedpassword: "+str(Encodedpassword))
            return "NO"
    def changepassword(self,wallet,username,walletkey,signature,newpassword):
          DICTIONARY = {}
          verifyingkeydatalist = {}
          verifyingkeyhashdatalist  ={}
          keydatanumber = 1
          data = {"wallet":wallet}
          for item in servers:
                                if keydatanumber>5:
                                    break
                               
                                urltosendto = trueserverlist["Data"][str(item)]
                                verifyingkeys22 = requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getverifyingkeyofwallet",json=data)
                                try:
                                 verifyingkeys22 = verifyingkeys22.json()
                                except:
                                 return "NO"
                                verifyingkeys22 = verifyingkeys22["Success"]
                                hashthis = ""
                                print("verifyingkeys22: "+str(verifyingkeys22))
                                hashthis = hashthis+str(verifyingkeys22["walletname"])
                                hashthis = hashthis+str(verifyingkeys22["Verifyingkey"])
                                hashthis = str(hashlib.sha256(hashthis.encode('utf-8')).hexdigest())
                                if not hashthis in verifyingkeyhashdatalist:
                                    verifyingkeyhashdatalist[hashthis] = {"Count":1}
                                else:
                                    verifyingkeyhashdatalist[hashthis]["Count"]+=1
                                verifyingkeydatalist[hashthis] = verifyingkeys22
                                keydatanumber+=1
          highest_item = max(verifyingkeydatalist, key=lambda x: verifyingkeyhashdatalist[x]['Count'])
          Datathing = verifyingkeydatalist[str(highest_item)]
          EASYTOUSEDATATHING = {}
          WALLETVALUES = {}
                       
          Walletindata = Datathing["walletname"]
          Verifyingkey = Datathing["Verifyingkey"]
          EASYTOUSEDATATHING[Walletindata] = {"Verifyingkey":load_pem_public_key(convertthething(Verifyingkey).encode('utf-8'),default_backend()),"Verifyingkeysummoningthing":Verifyingkey}
          WALLETVALUES[Walletindata] = {"Coins":0,"txextras":{}}
          DOITNOW = False
          print("DATAINEASYTHING: "+str(EASYTOUSEDATATHING))
          try:
                EASYTOUSEDATATHING[wallet]["Verifyingkey"].verify(
                   signature,
                   walletkey.encode('utf-8'),
                   ec.ECDSA(hashes.SHA256())
                )
                DOITNOW = True
          except Exception as e:
                print("Error: "+str(e))
                DOITNOW = False
          if DOITNOW == True:
              salt = random.randint(1,9999999)
              truepassword = str(newpassword)+str(salt)
              Encodedpassword = hashlib.sha256(truepassword.encode('utf-8')).hexdigest()
              self.accounts[username]["Salt"] = str(salt)
              self.accounts[username]["Password"] = Encodedpassword
              return "YES"
          else:
              return "NO"
    def changepassword2(self,username,password,newpassword):
        print("Account: "+str(self.accounts[username]))
        Encodedpassword = hashlib.sha256((password+str(self.accounts[username]["Salt"])).encode('utf-8')).hexdigest()
        if Encodedpassword == self.accounts[username]["Password"]:
            salt = random.randint(1,9999999)
            truepassword = str(newpassword)+str(salt)
            Encodedpassword2 = hashlib.sha256(truepassword.encode('utf-8')).hexdigest()
          
            self.accounts[username]["Salt"] = str(salt)
            self.accounts[username]["Password"] = Encodedpassword2
            realrealpassword = hashlib.sha256((password+str(self.accounts[username]["Salt"])).encode('utf-8')).hexdigest()
            if not realrealpassword == self.accounts[username]["Password"]:
             print("What????")
            return "YES"
        else:
            print("Encodedpassword: "+str(Encodedpassword))
            return "NO"
    def deleteaccount(self,wallet,username,walletkey,signature):
          DICTIONARY = {}
          verifyingkeydatalist = {}
          verifyingkeyhashdatalist  ={}
          keydatanumber = 1
          data = {"wallet":wallet}
          for item in servers:
                                if keydatanumber>5:
                                    break
                               
                                urltosendto = trueserverlist["Data"][str(item)]
                                verifyingkeys22 = requests.post(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"]+urltosendto+"/getverifyingkeyofwallet",json=data)

                                verifyingkeys22 = verifyingkeys22.json()
                                verifyingkeys22 = verifyingkeys22["Success"]
                                hashthis = ""
                                print("verifyingkeys22: "+str(verifyingkeys22))
                                hashthis = hashthis+str(verifyingkeys22["walletname"])
                                hashthis = hashthis+str(verifyingkeys22["Verifyingkey"])
                                hashthis = str(hashlib.sha256(hashthis.encode('utf-8')).hexdigest())
                                if not hashthis in verifyingkeyhashdatalist:
                                    verifyingkeyhashdatalist[hashthis] = {"Count":1}
                                else:
                                    verifyingkeyhashdatalist[hashthis]["Count"]+=1
                                verifyingkeydatalist[hashthis] = verifyingkeys22
                                keydatanumber+=1
          highest_item = max(verifyingkeydatalist, key=lambda x: verifyingkeyhashdatalist[x]['Count'])
          Datathing = verifyingkeydatalist[str(highest_item)]
          EASYTOUSEDATATHING = {}
          WALLETVALUES = {}
                       
          Walletindata = Datathing["walletname"]
          Verifyingkey = Datathing["Verifyingkey"]
          EASYTOUSEDATATHING[Walletindata] = {"Verifyingkey":load_pem_public_key(convertthething(Verifyingkey).encode('utf-8'),default_backend()),"Verifyingkeysummoningthing":Verifyingkey}
          WALLETVALUES[Walletindata] = {"Coins":0,"txextras":{}}
          DOITNOW = False
          print("DATAINEASYTHING: "+str(EASYTOUSEDATATHING))
          try:
                EASYTOUSEDATATHING[wallet]["Verifyingkey"].verify(
                   signature,
                   walletkey.encode('utf-8'),
                   ec.ECDSA(hashes.SHA256())
                )
                DOITNOW = True
          except Exception as e:
                print("Error: "+str(e))
                DOITNOW = False
          if DOITNOW == True:
              del self.accounts[username]
              return "YES"
          else:
              return "NO"
    def deleteaccount2(self,username,password):
        print("Account: "+str(self.accounts[username]))
        Encodedpassword = hashlib.sha256((password+str(self.accounts[username]["Salt"])).encode('utf-8')).hexdigest()
        if Encodedpassword == self.accounts[username]["Password"]:
            del self.accounts[username]
            return "YES"
        else:
            print("Encodedpassword: "+str(Encodedpassword))
            return "NO"
    def addfederatedserver(self,server):
        self.federatedservers.append(server)
        print("WE DID IT!")
    def addratedserver(self,server):
     if not server in self.reviewableservers:
        self.reviewableservers[server] = {"Reviews":{},"ReviewCount":0}
    def reviewaserver(self,review,server,account,stars,):
     if server in self.reviewableservers:
         newreviews = dict(self.reviewableservers[server]["Reviews"])

         self.reviewableservers[server] = {"Reviews":self.reviewableservers[server]["Reviews"],"ReviewCount":self.reviewableservers[server]["ReviewCount"]+1}
         newreviews[self.reviewableservers[server]["ReviewCount"]] = {"Review":review,"Dislikes":0,"Likes":0,"Comments":{},"Stars":stars,"Poster":account,"CommentCount":0,"CreationDate":time.time(),"ReviewCount":int(self.reviewableservers[server]["ReviewCount"])}
         self.reviewableservers[server] = {"Reviews":newreviews,"ReviewCount":self.reviewableservers[server]["ReviewCount"]}
         print("Reviews: "+str(newreviews[self.reviewableservers[server]["ReviewCount"]]))
         return self.reviewableservers[server]["ReviewCount"]
    def addcommenttoreview(self,review,server,account,comment):
     if not review in self.accounts[account]["Reviews"]:
      if server in self.reviewableservers:
          if review in self.reviewableservers[server]["Reviews"]:
              self.reviewableservers[server]["Reviews"][review]["CommentCount"]+=1
             
              self.reviewableservers[server]["Reviews"][review]["Comments"][self.reviewableservers[server]["Reviews"][review]["CommentCount"]] ={"Comment":comment,"Poster":account,"Dislikes":0,"Likes":0,"CreationDate":time.time(),"CommentCount": int(self.reviewableservers[server]["Reviews"][review]["CommentCount"])}
              print("CommentData: "+str(self.reviewableservers[server]["Reviews"][review]["Comments"][self.reviewableservers[server]["Reviews"][review]["CommentCount"]]))
              self.accounts[account]["Reviews"].append(review)
              return self.reviewableservers[server]["Reviews"][review]["CommentCount"]
    def likereview(self,review,server,account):
     if not review in self.accounts[account]["Ratedreviews"]:

       if server in self.reviewableservers:
           if review in self.reviewableservers[server]["Reviews"]:
               self.reviewableservers[server]["Reviews"][review]["Likes"]+=1
               self.accounts[account]["Ratedreviews"].append(review)

               print("Likes: "+str(self.reviewableservers[server]["Reviews"][review]["Likes"]))
    def dislikereview(self,review,server,account):
     if not review in self.accounts[account]["Ratedreviews"]:

       if server in self.reviewableservers:
           if review in self.reviewableservers[server]["Reviews"]:
               self.reviewableservers[server]["Reviews"][review]["Dislikes"]+=1
               self.accounts[account]["Ratedreviews"].append(review)

               print("Dislikes: "+str(self.reviewableservers[server]["Reviews"][review]["Dislikes"]))
    def likecommentreview(self,review,server,comment,account):
     if not comment in self.accounts[account]["CommentReviews"]:

       if server in self.reviewableservers:
           if review in self.reviewableservers[server]["Reviews"]:
               self.reviewableservers[server]["Reviews"][review]["Comments"][comment]["Likes"]+=1
               self.accounts[account]["CommentReviews"].append(comment)

               print("Likes: "+str(self.reviewableservers[server]["Reviews"][review]["Comments"][comment]["Likes"]))

    def dislikecommentreview(self,review,server,comment,account):
     if not comment in self.accounts[account]["CommentReviews"]:

       if server in self.reviewableservers:
           if review in self.reviewableservers[server]["Reviews"]:
               self.reviewableservers[server]["Reviews"][review]["Comments"][comment]["Dislikes"]+=1
               self.accounts[account]["CommentReviews"].append(comment)

               print("Dislikes: "+str(self.reviewableservers[server]["Reviews"][review]["Comments"][comment]["Dislikes"]))
    def getreviews(self,typemaster,number,server):
      if typemaster == "MostLikes":
        Key,value = getranked_highest_item(self.reviewableservers[server]["Reviews"],number,"Likes")
        return self.reviewableservers[server]["Reviews"][Key]
      elif typemaster == "LeastLikes":
        Key,value = getranked_least_highest_item(self.reviewableservers[server]["Reviews"],number,"Likes")
        print("KEY: "+str(Key))
        return self.reviewableservers[server]["Reviews"][Key]
      elif typemaster == "MostDislikes":
        Key,value = getranked_highest_item(self.reviewableservers[server]["Reviews"],number,"Dislikes")
        return self.reviewableservers[server]["Reviews"][Key]
      elif typemaster == "LeastDislikes":
        Key,value = getranked_least_highest_item(self.reviewableservers[server]["Reviews"],number,"Dislikes")
        return self.reviewableservers[server]["Reviews"][Key]
      elif typemaster == "NewestFirst":
        Key,value = getranked_highest_item(self.reviewableservers[server]["Reviews"],number,"CreationDate")
        return self.reviewableservers[server]["Reviews"][Key]
      elif typemaster == "OldestFirst":
        Key,value = getranked_least_highest_item(self.reviewableservers[server]["Reviews"],number,"CreationDate")
        return self.reviewableservers[server]["Reviews"][Key]
      elif typemaster == "HighestStars":
        print("NUMBER: "+str(number))
        Key,value = getranked_highest_item(self.reviewableservers[server]["Reviews"],number,"Stars")
        return self.reviewableservers[server]["Reviews"][Key]
      elif typemaster == "LowestStars":
        Key,value = getranked_least_highest_item(self.reviewableservers[server]["Reviews"],number,"Stars")

        return self.reviewableservers[server]["Reviews"][Key]
    def getcomments(self,typemaster,number,server,review):
      if typemaster == "MostLikes":
        Key,value = getranked_highest_item(self.reviewableservers[server]["Reviews"][review]["Comments"],number,"Likes")
        return self.reviewableservers[server]["Reviews"][review]["Comments"][Key]
      elif typemaster == "LeastLikes":
        Key,value = getranked_least_highest_item(self.reviewableservers[server]["Reviews"][review]["Comments"],number,"Likes")
        return self.reviewableservers[server]["Reviews"][review]["Comments"][Key]
      elif typemaster == "MostDislikes":
        Key,value = getranked_highest_item(self.reviewableservers[server]["Reviews"][review]["Comments"],number,"Dislikes")
        return self.reviewableservers[server]["Reviews"][review]["Comments"][Key]
      elif typemaster == "LeastDislikes":
        Key,value = getranked_least_highest_item(self.reviewableservers[server]["Reviews"][review]["Comments"],number,"Dislikes")
        return self.reviewableservers[server]["Reviews"][review]["Comments"][Key]
      elif typemaster == "NewestFirst":
        Key,value = getranked_highest_item(self.reviewableservers[server]["Reviews"][review]["Comments"],number,"CreationDate")
        return self.reviewableservers[server]["Reviews"][review]["Comments"][Key]
      elif typemaster == "OldestFirst":
        Key,value = getranked_least_highest_item(self.reviewableservers[server]["Reviews"][review]["Comments"],number,"CreationDate")
        return self.reviewableservers[server]["Reviews"][review]["Comments"][Key]
    def getstars(self,server):
        TotalStars = 0
        ReviewCount = 0
        for item in self.reviewableservers[server]["Reviews"]:
            ReviewCount+=1
            TotalStars+=int(self.reviewableservers[server]["Reviews"][item]["Stars"])
        TrueStars = TotalStars/ReviewCount
        return TrueStars
    def getcookieid(self,account):
        return self.accounts[account]["cookieid"]
    def getreversedcookieid(self,cookieid):
        print("COOKIEIDED:"+str(self.cookieidtoaccount))
        return self.cookieidtoaccount[int(cookieid)]["Username"]
    def logout(self,cookieid):
        username = self.cookieidtoaccount[int(cookieid)]["Username"]
        del self.cookieidtoaccount[int(cookieid)]
        cookieid = random.randint(1,99999999999999999999999999999999999999999999999999999)
        self.accounts[username] = {"Reviews":self.accounts[username]["Reviews"],"Ratedreviews":self.accounts[username]["Ratedreviews"],"Comments":self.accounts[username]["Comments"],"CommentReviews":self.accounts[username]["CommentReviews"],"ReviewNum":self.accounts[username]["ReviewNum"],"cookieid":cookieid,"Password":self.accounts[username]["Password"],"Salt":self.accounts[username]["Salt"]}
        self.cookieidtoaccount[int(cookieid)] = {"Username":username}
        print("COOKIEIDS: "+str(self.cookieidtoaccount))
        return "WE DID IT ZOEY!"
    def loadtheseup(self):
         with open("reviewableservers.txt","w") as file:
            json.dump(self.reviewableservers,file)
         with open("accounts.txt","w") as file:
            json.dump(self.accounts,file)
         with open("cookieidtoaccount.txt","w") as file:
            json.dump(self.cookieidtoaccount,file)
    def puttheseon(self):
        file_path = "reviewableservers.txt"

# Read the dictionary from the file
        try:
         with open(file_path, "r") as file:
          self.reviewableservers= json.load(file)
         print("Dictionary loaded successfully:")
        except FileNotFoundError:
         print(f"File not found: {file_path}")
        except json.JSONDecodeError:
         print(f"Error decoding JSON in file: {file_path}")
        file_path = "accounts.txt"

# Read the dictionary from the file
        try:
         with open(file_path, "r") as file:
          self.accounts = json.load(file)
         print("Dictionary loaded successfully:")
        except FileNotFoundError:
         print(f"File not found: {file_path}")
        except json.JSONDecodeError:
         print(f"Error decoding JSON in file: {file_path}")
        file_path = "cookieidtoaccount.txt"

# Read the dictionary from the file
        try:
         with open(file_path, "r") as file:
          self.cookieidtoaccount = json.load(file)
         print("Dictionary loaded successfully:")
        except FileNotFoundError:
         print(f"File not found: {file_path}")
        except json.JSONDecodeError:
         print(f"Error decoding JSON in file: {file_path}")
    def addad(self,coins,imagename,imagedata,link,imagetype,transactionid,transactionblock,wallet):
      keydatanumber = 1
      transactionidlist = {}
      try:
       with open("transactionidlist.txt","r") as file:
        transactionidlist = json.load(file)
      except:
       with open("transactionidlist.txt","w") as file:
         json.dump(transactionidlist,file)
      if transactionid in transactionidlist:
          return "STOP THIS NOW!"
      transactionhashlist = {}
      transactionlist = {}
      data = {"Blockamount":transactionblock}
      for item in servers:
       if keydatanumber>5:
           break
                               
       urltosendto = trueserverlist["Data"][str(item)]
       time.sleep(2000)
       oneoftheblocks = requests.post(str(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"])+str(urltosendto)+"/getoneoftheblocks",json=data)
       try:
        oneoftheblocks = oneoftheblocks.json()
        if len(oneoftheblocks["Success"]["BlockData"]) == 0:
         data = {"Blockamount":int(transactionblock)+1}
         oneoftheblocks = requests.post(str(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"])+str(urltosendto)+"/getoneoftheblocks",json=data)
         oneoftheblocks =oneoftheblocks.json()
          
         if len(oneoftheblocks["Success"]["BlockData"]) == 0:
          data = {"Blockamount":int(transactionblock)+2}
          oneoftheblocks = requests.post(str(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"])+str(urltosendto)+"/getoneoftheblocks",json=data)
          oneoftheblocks =oneoftheblocks.json()
          if len(oneoftheblocks["Success"]["BlockData"]) == 0:
           data = {"Blockamount":int(transactionblock)+3}
           oneoftheblocks = requests.post(str(trueserverlist["NEWDATA"][urltosendto]["PROTOCOL"])+str(urltosendto)+"/getoneoftheblocks",json=data)
           oneoftheblocks =oneoftheblocks.json()
       except Exception as e:
        print("There was an error: "+str(e))
       oneoftheblocks = oneoftheblocks["Success"]["BlockData"]
       print("Oneoftheblocks: "+str(oneoftheblocks))
       hashthis = ""
       hashthis = hashthis+str(oneoftheblocks[transactionid]["Sender"])+str(oneoftheblocks[transactionid]["Reciever"])+str(oneoftheblocks[transactionid]["amountofcoins"])+str(oneoftheblocks[transactionid]["transactionfee"])+str(oneoftheblocks[transactionid]["txextra"])
       hashthis = str(hashlib.sha256(hashthis.encode('utf-8')).hexdigest())
       if not hashthis in transactionhashlist:
                                    transactionhashlist[hashthis] = {"Count":1}
       else:
                                    transactionhashlist[hashthis]["Count"]+=1
       transactionlist[hashthis] = oneoftheblocks
      highest_item = max(transactionlist, key=lambda x: transactionhashlist[x]['Count'])
      blocktocheck = transactionlist[highest_item]
      if blocktocheck[transactionid]["Sender"] == wallet and blocktocheck[transactionid]["Reciever"] == servercoinwallet and blocktocheck[transactionid]['amountofcoins'] == coins:
        if not os.path.exists('static'):
           os.makedirs('static')
        superpath = os.path.join('static',str(wallet))

        if not os.path.exists(superpath):
           os.makedirs(superpath)
        superpath2 = os.path.join(superpath,(str(imagename)+"."+str(imagetype)))
        with open(superpath2,"wb") as file:
            file.write(base64.b64decode(imagedata))
        impressionsbeforethisrank = 0
        truecoins = coins/(10**8)
        impressions = float(truecoins)*float(coinsperimpression)
        if len(self.ads)>0:
         for item in self.ads:
             if self.ads[item]["Impressions"]>impressions:
                 impressionsbeforethisrank+=int(self.ads[item]["Impressions"])
             else:
                 break
        transactionidlist[transactionid] = "YES"
        with open("transactionidlist.txt","w") as file:
                     json.dump(transactionidlist,file)
        self.ads[random.randint(0,999999999999999999999999999999999)] = {"Impressions":impressions,"Image":str(wallet)+"/"+imagename+"."+str(imagetype),"Link":link,"MinNumber":impressionsbeforethisrank,"MaxNumber":impressionsbeforethisrank+impressions}
        self.totalimpressions+=impressions
    def getad(self):
        number = random.randint(0,self.totalimpressions)
        print("ADS: "+str(self.ads))
        for item in self.ads:
            if self.ads[item]["MinNumber"]<number and self.ads[item]["MaxNumber"]>number:
                self.ads[item]["Impressions"]-=1
                return self.ads[item]
            else:
                print("OH THAT'S WHY")
@app.route("/addserverpage",methods=['GET'])
def addserverpage(): 
     session_id = request.cookies.get("sessionid")
    
     if session_id:
        try:
         ServerCoinGuardthing.getreversedcookieid(session_id)
         return send_file("addserver2.html")
        except Exception as e:
            print("ERROR: "+str(e))
            return send_file("addserver.html")
     else:
        return send_file("Addaccounthtml.html")
@app.route("/changethatpassword",methods=['GET'])
def changepasswordpage():
    return send_file("changepassword.html")
@app.route("/deleteaccount",methods=['GET'])
def deleteaccountpage():
    return send_file("deleteaccount.html")
@app.route("/addad",methods=['POST'])
def addthead():
    data = request.json
    coins = data["coins"]
    link = data["link"]
    imagename = data["imagename"]
    imagedata = data["imagedata"]
    imagetype = data["imagetype"]
    transactionid = data["transactionid"]
    blocknum = data["blocknum"]
    wallet = data["wallet"]
    ServerCoinGuardthing.addad(coins,imagename,imagedata,link,imagetype,transactionid,blocknum,wallet)
    return jsonify({"Success":"We Did It"}),200
@app.route("/addtheserver",methods=['POST'])
def addtheserver():
    data = request.json
    print("DATAISHERE: "+str(data))
    ServerCoinGuardthing.addratedserver(data["serverName"])
    return jsonify({"Success":"WE DID IT!"}),200
@app.route("/signup",methods=['GET'])
def createaccountpage():
     session_id = request.cookies.get("sessionid")
    
     if session_id:
        try:
         ServerCoinGuardthing.getreversedcookieid(session_id)
         return f"You don't have to do this.'"
        except Exception as e:
            print("ERROR: "+str(e))
            return send_file("Addaccounthtml.html")
     else:
        return send_file("Addaccounthtml.html")
@app.route("/login",methods=['GET'])
def logaccountpage():
    session_id = request.cookies.get("sessionid")
    
    if session_id:
        try:
         ServerCoinGuardthing.getreversedcookieid(session_id)
         return f"You don't have to do this.'"
        except:
            return send_file("Loginaccount.html")
    else:
        return send_file("Loginaccount.html")
@app.route("/addaccount",methods=['POST'])
def addaccountpost():
    data = request.json
    print("DATA: "+str(data))
    signature = data["signature"]
    username = data["username"]
    password = data["password"]
    wallet = data["wallet"]
    signature = base64.b64decode(signature)
    print("SIGNATURE: "+str(signature))
    ServerCoinGuardthing.addaccount(wallet,username,password,signature)
    cookie_value = ServerCoinGuardthing.getcookieid(username)  # Assuming this function returns a string
    encoded_cookie_value = str(cookie_value).encode('utf-8')  # Encode the string as bytes
    response = make_response(jsonify(message="Cookie is set"))
    response.set_cookie("sessionid", encoded_cookie_value, max_age=3600000, secure=True, httponly=True, path="/")
    return response
@app.route("/logintoaccount",methods=['POST'])
def logintothataccount():
    data = request.json
    print("DATA: "+str(data))
    signature = data["signature"]
    username = data["username"]
    password = data["password"]
    wallet = data["wallet"]
    try:
     signature = base64.b64decode(signature)
    except:
     print("It's not here")
    print("SIGNATURE: "+str(signature))
    Result = ServerCoinGuardthing.loginaccount(wallet,username,password,signature)
    if Result == "YES":
     cookie_value = ServerCoinGuardthing.getcookieid(username)  # Assuming this function returns a string
     encoded_cookie_value = str(cookie_value).encode('utf-8')  # Encode the string as bytes
     response = make_response(jsonify(message="Cookie is set"))
     response.set_cookie("sessionid", encoded_cookie_value, max_age=3600000, secure=True, httponly=True, path="/")
     return response
    else:
        NewResult = ServerCoinGuardthing.loginaccount2(username,password)
        if NewResult == "YES":
             cookie_value = ServerCoinGuardthing.getcookieid(username)  # Assuming this function returns a string
             encoded_cookie_value = str(cookie_value).encode('utf-8')  # Encode the string as bytes
             response = make_response(jsonify(message="Cookie is set"))
             response.set_cookie("sessionid", encoded_cookie_value, max_age=3600000, secure=True, httponly=True, path="/")
             return response
        else:
            return jsonify({"Error":"You need the actual password or the actual wallet and signature."}),403
@app.route("/changepasswordofaccount",methods=['POST'])
def changethataccountspassword():
    data = request.json
    print("DATA: "+str(data))
    signature = data["signature"]
    username = data["username"]
    password = data["password"]
    newpassword = data["newpassword"]
    wallet = data["wallet"]
    try:
     signature = base64.b64decode(signature)
    except:
     print("It's not here")
    print("SIGNATURE: "+str(signature))
    Result = ServerCoinGuardthing.changepassword(wallet,username,password,signature,newpassword)
    if Result == "YES":
     cookie_value = ServerCoinGuardthing.getcookieid(username)  # Assuming this function returns a string
     encoded_cookie_value = str(cookie_value).encode('utf-8')  # Encode the string as bytes
     response = make_response(jsonify(message="Cookie is set"))
     response.set_cookie("sessionid", encoded_cookie_value, max_age=3600000, secure=True, httponly=True, path="/")
     return response
    else:
        NewResult = ServerCoinGuardthing.changepassword2(username,password,newpassword)
        if NewResult == "YES":
             cookie_value = ServerCoinGuardthing.getcookieid(username)  # Assuming this function returns a string
             encoded_cookie_value = str(cookie_value).encode('utf-8')  # Encode the string as bytes
             response = make_response(jsonify(message="Cookie is set"))
             response.set_cookie("sessionid", encoded_cookie_value, max_age=3600000, secure=True, httponly=True, path="/")
             return response
        else:
            return jsonify({"Error":"You need the actual password or the actual wallet and signature."}),403
@app.route("/deleteaccount",methods=['POST'])
def deletethataccount():
    data = request.json
    print("DATA: "+str(data))
    signature = data["signature"]
    username = data["username"]
    password = data["password"]
    wallet = data["wallet"]
    try:
     signature = base64.b64decode(signature)
    except:
     print("It's not here")
    print("SIGNATURE: "+str(signature))
    Result = ServerCoinGuardthing.deleteaccount(wallet,username,password,signature)
    if Result == "YES":
     cookie_value = ServerCoinGuardthing.getcookieid(username)  # Assuming this function returns a string
     encoded_cookie_value = str(cookie_value).encode('utf-8')  # Encode the string as bytes
     response = make_response(jsonify(message="Cookie is set"))
     response.set_cookie("sessionid", encoded_cookie_value, max_age=3600000, secure=True, httponly=True, path="/")
     return response
    else:
        NewResult = ServerCoinGuardthing.deleteaccount2(username,password)
        if NewResult == "YES":
             cookie_value = ServerCoinGuardthing.getcookieid(username)  # Assuming this function returns a string
             encoded_cookie_value = str(cookie_value).encode('utf-8')  # Encode the string as bytes
             response = make_response(jsonify(message="Cookie is set"))
             response.set_cookie("sessionid", encoded_cookie_value, max_age=3600000, secure=True, httponly=True, path="/")
             return response
        else:
            return jsonify({"Error":"You need the actual password or the actual wallet and signature."}),403
@app.route("/logout",methods=['POST'])
def logout():
     session_id = request.cookies.get("sessionid")
    
     if session_id:
         try:
          ServerCoinGuardthing.logout(session_id)
          return jsonify("Successfully logged out"),200
         except Exception as e:
          print("ERROR: "+str(e))
          return jsonify("WE FAILED!"),400
      
@app.route("/getstars",methods=['POST'])
def getstars():
    data = request.json
    server = data["Server"]
    stars = ServerCoinGuardthing.getstars(server)
    print("STARS: "+str(stars))
    return jsonify(stars),200
@app.route("/getreviews",methods=['POST'])
def getreviews():
    data = request.json
    server = data["Server"]
    sorttype = data["SortType"]
    number = data["Number"]
    Review = ServerCoinGuardthing.getreviews(sorttype,number,server)
    print("REVIEW: "+str(Review))
    return jsonify(dict(Review)),200
@app.route("/likereview",methods=['POST'])
def likereview():
    session_id = request.cookies.get("sessionid")
    
    if session_id:
     data = request.json
     server = data["Server"]
     review = data["Review"]
     account = ServerCoinGuardthing.getreversedcookieid(session_id)
     ServerCoinGuardthing.likereview(review,server,account)
     return jsonify("Successfully liked"),200
@app.route("/dislikereview",methods=['POST'])
def dislikereview():
    session_id = request.cookies.get("sessionid")
    
    if session_id:
     data = request.json
     server = data["Server"]
     review = data["Review"]
     account = ServerCoinGuardthing.getreversedcookieid(session_id)
     ServerCoinGuardthing.dislikereview(review,server,account)
     return jsonify("Successfully disliked"),200
@app.route("/makereview",methods=['POST'])
def makereview():
    session_id = request.cookies.get("sessionid")
    
    if session_id:
     data = request.json
     server = data["Server"]
     review = data["Review"]
     stars = data["Stars"]
     account = ServerCoinGuardthing.getreversedcookieid(session_id)
     ServerCoinGuardthing.reviewaserver(review,server,account,stars)
     return jsonify("Successfully added review"),200
@app.route("/getcomments",methods=['POST'])
def getcomments():
    data = request.json
    server = data["Server"]
    review = data["Review"]
    number = data["Number"]
    typemaster = data["SortOption"]
    comment = ServerCoinGuardthing.getcomments(typemaster,number,server,review)
    return jsonify(comment),200
@app.route("/likecomment",methods=['POST'])
def likecomment():
    session_id = request.cookies.get("sessionid")
    
    if session_id:
     data = request.json
     server = data["Server"]
     review = data["Review"]
     comment = data["CommentID"]
     account = ServerCoinGuardthing.getreversedcookieid(session_id)
     ServerCoinGuardthing.likecommentreview(review,server,comment,account)
     return jsonify("Successfully liked comment"),200

    
@app.route("/dislikecomment",methods=['POST'])
def dislikecomment():
    session_id = request.cookies.get("sessionid")
    
    if session_id:
     data = request.json
     server = data["Server"]
     review = data["Review"]
     comment = data["CommentID"]
     account = ServerCoinGuardthing.getreversedcookieid(session_id)
     ServerCoinGuardthing.dislikecommentreview(review,server,comment,account)
     return jsonify("Successfully disliked comment"),200
@app.route("/makecomment",methods=['POST'])
def makecomment():
    session_id = request.cookies.get("sessionid")
   
    if session_id:
     data = request.json
     server = data["Server"]
     review = data["Review"]
     comment = data["Comment"]
     account = ServerCoinGuardthing.getreversedcookieid(session_id)
     
     ServerCoinGuardthing.addcommenttoreview(review,server,account,comment)
     return jsonify("Successfully made comment"),200
    
@app.route("/rateservers",methods=['GET'])
def rateservers():
     session_id = request.cookies.get("sessionid")
    
     if session_id:
        try:
         ServerCoinGuardthing.getreversedcookieid(session_id)
         Specialdata = ""
         with open("Rateservers2.html","r") as file:
             Specialdata = file.read()
         ad1 = ServerCoinGuardthing.getad()
         ad2 = ServerCoinGuardthing.getad()
         print("Ad1: "+str(ad1))
         print("Ad2: "+str(ad2))
         try:
          Specialdata = Specialdata.replace("https://www.example.com/left-image",ad1["Link"])
          Specialdata = Specialdata.replace("https://www.example.com/right-image",ad2["Link"])
          Specialdata = Specialdata.replace("right-image2.png",ad1["Image"])
          Specialdata = Specialdata.replace("right-image.png",ad2["Image"])
         except:
          print("TRY HARDER!")
         RATENUM = random.randint(0,9999999999999999999999999999)
         ultrarate = "ULTRARATE"+str(RATENUM)+str(".html")
         with open(ultrarate,"w") as file:
             file.write(Specialdata)

         return send_file(str(ultrarate))
        except Exception as e:
            print("ERROR: "+str(e))
            Specialdata = ""
            with open("Rateservers2.html","r") as file:
             Specialdata = file.read()
            ad1 = ServerCoinGuardthing.getad()
            ad2 = ServerCoinGuardthing.getad()
            print("Ad1: "+str(ad1))
            print("Ad2: "+str(ad2))
            try:
             Specialdata = Specialdata.replace("https://www.example.com/left-image",ad1["Link"])
             Specialdata = Specialdata.replace("https://www.example.com/right-image",ad2["Link"])
             Specialdata = Specialdata.replace("right-image2.png",ad1["Image"])
             Specialdata = Specialdata.replace("right-image.png",ad2["Image"])
            except:
             print("TRY HARDER")
            RATENUM = random.randint(0,9999999999999999999999999999)
            ultrarate = "ULTRARATE"+str(RATENUM)+str(".html")
            with open(ultrarate,"w") as file:
             file.write(Specialdata)

            return send_file(str(ultrarate))
     else:
            Specialdata = ""
            with open("Rateservers2.html","r") as file:
             Specialdata = file.read()
            ad1 = ServerCoinGuardthing.getad()
            ad2 = ServerCoinGuardthing.getad()
            print("Ad1: "+str(ad1))
            print("Ad2: "+str(ad2))
            try:
             Specialdata = Specialdata.replace("https://www.example.com/left-image",ad1["Link"])
             Specialdata = Specialdata.replace("https://www.example.com/right-image",ad2["Link"])
             Specialdata = Specialdata.replace("right-image2.png",ad1["Image"])
             Specialdata = Specialdata.replace("right-image.png",ad2["Image"])
            except:
             print("Try Harder")
            RATENUM = random.randint(0,9999999999999999999999999999)
            ultrarate = "ULTRARATE"+str(RATENUM)+str(".html")
            with open(ultrarate,"w") as file:
             file.write(Specialdata)

            return send_file(str(ultrarate))


ServerCoinGuardthing = ServerCoinGuard()
ServerCoinGuardthing.puttheseon()
def loop1():
    time.sleep(45)
    ServerCoinGuardthing.loadtheseup()
def loop2():
    time.sleep(25)
    sendNEWPRICE()

thread1 = threading.Thread(target=loop1)
thread1.start()
thread2 = threading.Thread(target=loop2)
thread2.start()
if __name__ == '__main__':
    app.run(port=8000,host="0.0.0.0")
