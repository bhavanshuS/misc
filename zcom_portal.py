#!/usr/bin/python3
import scapy
import ipaddress
import socket
import random
import binascii
from struct import *
from scapy.all import *
from scapy.packet import Packet
from scapy.fields import *


def computeResponse(id_hex,password, challenge):
    #id_hex = binascii.unhexlify('0%x' %id_hex)
    id_hex = binascii.unhexlify(id_hex)
    challenge = binascii.unhexlify(challenge)
    result = id_hex+password+challenge
    response = hashlib.md5(result).hexdigest()
    print(response)

req_id=random.randint(0,5000)
serial_no=random.randint(1000,5000)
username="test"
password="test"
mac_addr="00:01:02:e2:25:80"
user_ip="10.1.1.112"
#username=sys.argv[1]
#password=sys.argv[2]
#mac_addr=sys.argv[3]
#user_ip=sys.argv[4]

wlc_ip="211.74.174.30"
req_id=0
udp_src_port=random.randint(49152,65536)
#class attribute(Packet):
#    name="attributes"

            
attr_fields_mac=[
            ByteField("Attr_type2",225),
            ByteField("Length2",8),
            MACField("sauce",mac_addr)
            ]
            
class attribute_pass(Packet):
    name="attributes"
    attr_fields_pass=[
            ByteField("Attr_type1",2),
            ByteField("Length1",len("bhavanshusir")+2),
            StrFixedLenField("value1","bhavanshusir",12)
            ]
class PORTAL_REQ_CHALLENGE(Packet):
    name= "req_chalange"
    fields_desc=[ 
            XByteField("Version",1),
            #IntField("portal code",0),
            XByteField("Type",1),
            XByteField("Pap/Chap",0),
            ByteField("Reserve",0),
            ShortField("Serial Number",serial_no),
            ShortField("Request ID",req_id),
            IntField("User IP",int(ipaddress.IPv4Address(user_ip))),
            XShortField("User Port",0),
            XByteField("Error Code",0),
            XByteField("Attribute Number",1)]+attr_fields_mac


            
            
########################################### INITIAL REQ CHALLENGE PORTAL ###################################

portal_req_challenge=PORTAL_REQ_CHALLENGE()
#portal_packet=PORTAL()
ip=IP(dst=wlc_ip)
udp=UDP(sport=udp_src_port, dport=2000)
portal_req_challenge_PACKET=ip/udp/portal_req_challenge
receive=sr1(portal_req_challenge_PACKET)
data = receive[Raw].load
req_id_hex=data[6:8].hex()
req_id_rcvd=int(req_id_hex,16)


############################################# CHAP PASSWORD ###################################
challenge=data[18:34].hex()     ##challenge extracted form packet ########
chap_id=binascii.unhexlify(data[6:7].hex())  ############ Chap id is first 8 bytes of req id ###########
challenge=binascii.unhexlify(challenge)
#print(challenge)
#print(chap_id)
print("=========")

print(data[6:7].hex())
print(chap_id)
print(password)
print(challenge.hex())
print("=========")

result = chap_id+password.encode('ascii')+challenge
print(len(result))
password= hashlib.md5(result).hexdigest()
#password= hashlib.md5(result).digest()
password=password.encode()

print(len(binascii.unhexlify(password)))
password=binascii.unhexlify(password)
#print(password.hex())

###############################################################################################

#print(req_id_hex)
#print(int(req_id_hex,16))
#print(len(data))
#print(do_disect_payload(receive))
#print(unpack('bbbbHHlhbbbbb16s3s',data))
######################################### END REQ CHALLENGE ########################################
#############################################################################################
attr_fields_user=[
            ByteField("Attr_type",1),
            ByteField("Length",len(username)+2),
            StrFixedLenField("value",username,len(username)),
            ]
attr_fields_pass=[
            ByteField("Attr_type1",4),
            ByteField("Length1",len(password)+2),
            #StrFixedLenField("value1",password,len(password))
            StrField("pass",password)
            ]


class PORTAL_REQ_AUTH(Packet):
    name= "portal_packet"
    fields_desc=[ 
            XByteField("Version",1),
            #IntField("portal code",0),
            XByteField("Type",3),
            XByteField("Pap/Chap",0),
            ByteField("Reserve",0),
            ShortField("Serial Number",serial_no),
            ShortField("Request ID",req_id_rcvd),
            IntField("User IP",int(ipaddress.IPv4Address(user_ip))),
            XShortField("User Port",0),
            XByteField("Error Code",0),
            XByteField("Attribute Number",3)]+attr_fields_user+attr_fields_pass+attr_fields_mac
    
portal_req_auth=PORTAL_REQ_AUTH()
ip=IP(dst=wlc_ip)
udp=UDP(sport=udp_src_port, dport=2000)
portal_req_auth_PACKET=ip/udp/portal_req_auth
receive=send(portal_req_auth_PACKET)
######################################### END AUTH REQ CHALLENGE ########################################
