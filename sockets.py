from socket import *
from struct import *
import sys
import select
import time
import binascii

UDP_CODE = getprotobyname('udp')
assert UDP_CODE == IPPROTO_UDP, "UDP Protocol type mismatch!"

HOST = gethostbyname(gethostname())

def construct_ip_header(hostname):
  '''
                8 bits        8 bits                   16 bits               = 32 bits
            |--------------------------------------------------------------|
            | ver | ihl |     ip_tos     |           ip_tot_len            |
            |--------------------------------------------------------------|
            |             ip_id          |           ip_frag_off           |
            |--------------------------------------------------------------|
            |   ip_ttl  |    ip_proto    |          ip_checksum            |
            |--------------------------------------------------------------|
            |                           ip_source                          |
            |--------------------------------------------------------------|
            |                           ip_dest                            |
            |--------------------------------------------------------------|
    '''
  
  source_ip = HOST
  dest_ip = gethostbyname(hostname)

  ip_ver = 4 #IPv4 baby -> 4 bits
  ip_ihl = 5 #5 words, 20 bytes (no options) -> 4 bits
  ip_tos = 0 #pretty sure this isn't really used much -> 8 bits
  ip_tot_len = 0	# kernel will fill this in (<3)
  ip_id = 1337	#packet id -> 16 bits
  ip_frag_off = 0 #fragmentation offset -> 16 bits
  ip_ttl = 5 # reduced by one on each hop -> 8 bits
  ip_proto = UDP_CODE #wooo! -> 8 bits
  ip_checksum = 0	# kernel will fill this in (<3)
  ip_source = inet_aton(source_ip)	#convert x.x.x.x to 32-bit packed binary format -> 32 bits
  ip_dest = inet_aton(dest_ip) #convert x.x.x.x to 32-bit packed binary format -> 32 bits

  ip_ihlver = (ip_ver << 4) + ip_ihl #combine to get 8 bits
  
  '''
   ! for network order (big endian)
   B for unsigned char -> 8 bits
   H for unsigned short -> 16 bits
   4s for 4 byte (32 bit) string
  '''
  ip_header = pack('!BBHHHBBH4s4s', ip_ihlver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_checksum, ip_source, ip_dest)
  
  return ip_header

def construct_udp_header():
  #everything is 16 bits
  udp_source = 20591 #20591	# source port
  udp_dest = 33433	# destination port
  udp_len = 8 #length will just be header length (min 8 bytes) as we will be sending an empty payload
  udp_checksum = 0
  
  #! for network order (big endian)
  udp_header = pack('!HHHH', udp_source, udp_dest, udp_len, udp_checksum)
  return udp_header

def construct_udp_packet():
  udp_header = construct_udp_header()
  payload = '' #we don't actually care to send data
  return udp_header + payload

def create_packet(hostname):
  ip_header = construct_ip_header(hostname)  
  payload = construct_udp_packet()
  return ip_header + payload

def await_response(my_socket, time_sent, timeout):
  time_left = timeout
  
  while True:
    rec_packet, addr = my_socket.recvfrom(5120)
    unpacked_ip = unpack('!BBHHHBBH4s4s', rec_packet[0:20])
    prot = unpacked_ip[6]
    if prot == 17:
      print "UDP (" + str((unpacked_ip[3])) + ")"
    elif prot == 6:
      print "TCP (" + str((unpacked_ip[3])) + ")"
    elif prot == 1:
      print "ICMP (WOOOOOOOOOO!) (" + str((unpacked_ip[3])) + ")"
    else:
      print str(prot) + "(" + str((unpacked_ip[3])) + ")"

if __name__ == '__main__':
  send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
  send_socket.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
  #send_socket.bind((HOST, 20591))
  
  recv_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
  recv_socket.bind((HOST, 20591))
  recv_socket.ioctl(SIO_RCVALL, RCVALL_ON)  
  
  hostname = 'www.google.com'
  hostip = gethostbyname(hostname)
  
  packet = create_packet(hostname)
  print send_socket.sendto(packet, (hostip , 33433))
  
  print await_response(recv_socket, time.time(), 100)
  
  
  
  
  
  
  