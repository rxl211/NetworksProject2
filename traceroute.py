from socket import *
from struct import *
from random import randint
import sys
import time

UDP_CODE = getprotobyname('udp')
assert UDP_CODE == IPPROTO_UDP, "UDP Protocol type mismatch!"

s=socket(AF_INET,SOCK_DGRAM);s.connect(('8.8.8.8',80))
HOST = s.getsockname()[0]
s.close()

def construct_ip_header(hostip, ttl, ipid):
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

  ip_ver = 4 #IPv4 baby -> 4 bits
  ip_ihl = 5 #5 words, 20 bytes (no options) -> 4 bits
  ip_tos = 0 #pretty sure this isn't really used much -> 8 bits
  ip_tot_len = 0	# kernel will fill this in (<3)
  ip_id = ipid	#packet id -> 16 bits
  ip_frag_off = 0 #fragmentation offset -> 16 bits
  ip_ttl = ttl # reduced by one on each hop -> 8 bits
  ip_proto = UDP_CODE #wooo! -> 8 bits
  ip_checksum = 0	# kernel will fill this in (<3)
  ip_source = inet_aton(source_ip)	#convert x.x.x.x to 32-bit packed binary
  ip_dest = inet_aton(hostip) #convert x.x.x.x to 32-bit packed binary

  ip_ihlver = (ip_ver << 4) + ip_ihl #combine to get 8 bits

  '''
   ! for network order (big endian)orig_udp_header
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

def create_packet(hostip, ttl, ipid):
  ip_header = construct_ip_header(hostip, ttl, ipid)
  payload = construct_udp_packet()
  return ip_header + payload

def validate_ip(orig_ip_header, hostip, ipid, ttl):
  orig_len = orig_ip_header[2]
  orig_id = orig_ip_header[3]
  orig_proto = orig_ip_header[6]
  orig_dest = inet_ntoa(orig_ip_header[9])

  return (orig_len == 28 and orig_id == ipid and orig_proto == UDP_CODE
          and orig_dest == hostip)

def validate_udp(orig_udp_header):
  orig_source = orig_udp_header[0]
  orig_dest = orig_udp_header[1]
  orig_len = orig_udp_header[2]

  return (orig_source == 20591 and orig_dest == 33433 and orig_len == 8)

def unpack_and_validate(rec_packet, hostip, ipid, ttl):
  unpacked_ip = unpack('!BBHHHBBH4s4s', rec_packet[0:20]) #0:20
  prot = unpacked_ip[6]
  addr = inet_ntoa(unpacked_ip[8])
  assert prot == 1, "Expecting ICMP packet but got something else"

  icmp_header = unpack('!BBH', rec_packet[20:24]) #21:24
  icmp_type = icmp_header[0]
  icmp_code = icmp_header[1]

  if (icmp_type == 11 and icmp_code == 0):
    orig_ip_header = unpack('!BBHHHBBH4s4s', rec_packet[28:48]) #29-48
    valid_icmp = True

  if(valid_icmp and validate_ip(orig_ip_header, hostip, ipid, ttl)):
      orig_udp_header = unpack('!HHHH', rec_packet[48:56]) #49:56
      valid_ip = True

  if(valid_icmp and valid_ip and validate_udp(orig_udp_header)):
        #this is our packet!
        return addr

  return False

def await_response(my_socket, hostip, ipid, ttl, time_sent, timeout):
  time_left = timeout
  time_start = time.time()
  while True:
    valid_icmp = False
    valid_ip = False
    time_before = time.time()

    try:
      rec_packet = my_socket.recv(5120)
    except:
      time_left = time_left - timeout
      if time_left <= 0:
        raise Exception

    timediff = time.time() - time_before

    addr = unpack_and_validate(rec_packet, hostip, ipid, ttl)
    if (addr):
      return time.time() - time_sent, addr

    time_left = time_left - timediff
    if time_left <= 0:
      raise Exception

def getNewTTL(ttl):
  return ttl+1

def traceroute(send_socket, recv_socket, hostip, timeout):
  ttl = 0
  tries_left = 3
  addr = ""
  while True:
    ttl = getNewTTL(ttl)
    print str(ttl) + ": ",
    while tries_left > 0:
      ipid = randint(1,6535)
      #print "["+str(ipid)+"] ",
      packet = create_packet(hostip, ttl, ipid)
      send_socket.sendto(packet, (hostip, 33433))
      try:
        response_time, addr = await_response(recv_socket, hostip, ipid, ttl,
                                              time.time(), timeout)
        response_time = round(response_time * 1000, 2)
        print str(response_time) + "ms",
        if(tries_left == 1):
          print " <=> " + str(addr),
          print " (" + str(gethostbyaddr(addr)[0]) + ")",
      except:
        print "*",
      tries_left = tries_left - 1
    print ""

    tries_left = 3

    if addr == hostip or ttl == 30:
      break


if __name__ == '__main__':

  if len(sys.argv) != 2:
    print "Please supply one and only one hostname"

  send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
  send_socket.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

  timeout = 3.0

  setdefaulttimeout(timeout)
  recv_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)

  hostname = sys.argv[1]

  try:
    hostip = gethostbyname(hostname)
  except:
    print "Could not resolve hostname"
    sys.exit()

  print "Tracing route to " + hostname + " ["+str(hostip)+"] with ",
  print "timeout set to " + str(timeout) + " seconds per probe"

  traceroute(send_socket, recv_socket, hostip, timeout)

  print "Trace complete"




