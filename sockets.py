from socket import *
from struct import *
import sys
import select
import time
import binascii
import os
import fcntl
import ctypes

class ifreq(ctypes.Structure):
  _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]

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

  source_ip = "129.22.59.79"
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
    rec_packet = my_socket.recv(5120)
    print "we passed read"
    unpacked_ip = unpack('!BBHHHBBH4s4s', rec_packet[0:19]) #0:20
    prot = unpacked_ip[6]
    assert prot == 1
    icmp_header = unpack('!BBH', rec_packet[20:23] #21:24
    icmp_type = icmp_header[0]
    icmp_code = icmp_header[1]

    if (icmp_type == 11 and icmp_code == 0):
      orig_ip_header = unpack('!BBHHHBBH4s4s', rec_packet[28:47]) #29-48
      orig_udp_header = unpack('!HHHH', rec_packet[48:55]) #49:56
      print 'yoyoyo'

if __name__ == '__main__':
  send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
  send_socket.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

  recv_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)

  '''
  recv_socket.bind((HOST, 20591))
  if os.name == 'nt':
    recv_socket.ioctl(SIO_RCVALL, RCVALL_ON)
  elif os.name == 'posix':
    IFF_PROMISC = 0x100
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914

    ifr = ifreq()
    ifr.ifr_ifrn = "eth0"
    fcntl.ioctl(recv_socket.fileno(), SIOCGIFFLAGS, ifr)
    ifr.ifr_flags |= IFF_PROMISC
    fcntl.ioctl(recv_socket.fileno(), SIOCSIFFLAGS, ifr)
  else:
    print "Your OS is not known"
    sys.exit()
  '''

  hostname = 'www.google.com'
  hostip = gethostbyname(hostname)

  packet = create_packet(hostname)
  print send_socket.sendto(packet, (hostip , 33433))

  print await_response(recv_socket, time.time(), 100)




