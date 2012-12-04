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

def calculate_ip_checksum(ip_packet):
  length = len(ip_packet)
  sum = 0
  count = 0

  unpacked = unpack('!BBHHHBBH4s4s', ip_packet)
  #print unpacked

  for word in unpacked:
    try:
      word = int(word)
    except ValueError:
      ip = inet_ntoa(word)
      hexn = ''.join(["%02X" % long(i) for i in ip.split('.')]) # http://code.activestate.com/recipes/65219-ip-address-conversion-functions/
      word = int(hexn, 16)

    sum = sum + word

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
	#complement and mask to 4 byte short
  sum = ~sum & 0xffff

  return sum

def calculate_udp_checksum():
  pass

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

  source_ip = "192.5.110.4"
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
'''
def await_response(my_socket, time_sent, timeout):
  time_left = timeout

  while True:
    ready = select.select([my_socket], [], [], time_left)
    if ready[0] == []:
        print "timeout"
    time_now = time.time()
    rec_packet, addr = my_socket.recvfrom(5120)

    unpacked_ip = unpack('!BBHHHBBH4s4s', rec_packet[0:20])
    print unpacked_ip
    prot = unpacked_ip[6]
    print prot
    #print unpacked_ip[3] # ip packet id
    if prot == 1:
      print addr
      icmp_header = rec_packet[20:28]
      print binascii.hexlify(icmp_header)
      #icmp_payload = rec_packet[29:]
     # print sys.getsizeof(icmp_payload)
      unpacked_header = unpack('bbHHh', icmp_header)
      #unpacked_payload = unpack('s', icmp_payload)
      print unpacked_header
      #print unpacked_payload

      type, code, checksum, p_id, sequence = unpacked_header

      print p_id

      if p_id == 1337 or p_id == 20591 or p_id == 33433:
        return time_now - time_sent
      time_left -= time_now - time_sent
      print time_left
      if time_left <= 0:
        return "timeout"
'''

def await_response(my_socket, time_sent, timeout):
  time_left = timeout

  while True:
    rec_packet = my_socket.recv(5120)
    print "we passed read"
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














