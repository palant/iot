#!/usr/bin/env python3
#
# Copyright (c) 2020, Paul A. Marrapese <paul@redprocyon.com>
# All rights reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
# SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.

import ipaddress, os, logging, math, socket, re, struct, threading, time
from typing import Generator

from netifaces import interfaces, ifaddresses, AF_INET

LOG_LEVEL = logging.DEBUG if 'DEBUG' in os.environ and os.environ['DEBUG'] else logging.INFO
logging.basicConfig(format='%(message)s', level=LOG_LEVEL)

P2P_LAN_BROADCAST_IP = '255.255.255.255'
P2P_LAN_PORT = 32108
P2P_MAGIC_NUM = 0xF1
P2P_HEADER_SIZE = 4
MSG_LAN_SEARCH = 0x30
MSG_LAN_SEARCH_EXT = 0x32
MSG_PUNCH_PKT = 0x41
YUNNI_CHECK_CODE_PATTERN = re.compile('[A-F]{5}')
VSTARCAM_PREFIXES = ['VSTD', 'VSTF', 'QHSV', 'EEEE', 'ROSS', 'ISRP', 'GCMN', 'ELSA']

def fetchLocalIPv4Addresses() -> Generator[str, None, None]:
  for iface in interfaces():
    addrs = ifaddresses(iface)
    if AF_INET in addrs: addrs = addrs[AF_INET]
    else: continue

    for addr in addrs:
      ip = ipaddress.IPv4Address(addr['addr'])
      if not ip.is_unspecified and not ip.is_loopback and not ip.is_link_local:
        yield str(ip)

class Encryption:
  KEY_TABLE = bytes.fromhex(
    '7c9ce84a13dedcb22f2123e4307b3d8c'
    'bc0b270c3cf79ae7087196009785efc1'
    '1fc4dba1c2ebd901faba3b05b8158783'
    '2872d18b5ad6da9358feaacc6e1bf0a3'
    '88ab43c00db545384f502266207f075b'
    '14981d9ba72ab9a8cbf1fc4947063eb1'
    '0e043a945eee541134dd4df9ecc7c9e3'
    '781a6f706ba4bda95dd5f8e5bb26af42'
    '37d8e1020aae5f1cc573094e6924906d'
    '12b319ad748a2940f52dbea559e0f479'
    'd24bce8982488425c6912ba2fb8fe9a6'
    'b09e3f65f603312eac0f952c5ced39b7'
    '336c567eb4a0fd7a815351868d9f77ff'
    '6a80dfe2bf10d775645776f355cdd0c8'
    '18e6364162cf99f2324c67606192cad3'
    'ea637d16b68ed46835c3529d46441e17'
  )

  @staticmethod
  def encrypt(key: bytes, plaintext: bytes) -> bytes:
    ciphertext = []
    previous_byte = 0
    for byte in plaintext:
      index = ((key[previous_byte & 3]) + previous_byte) & 0xff
      ciphertext.append(byte ^ Encryption.KEY_TABLE[index])
      previous_byte = ciphertext[-1]
    return bytes(ciphertext)

  @staticmethod
  def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    plaintext = []
    previous_byte = 0
    for byte in ciphertext:
      index = ((key[previous_byte & 3]) + previous_byte) & 0xff
      plaintext.append(byte ^ Encryption.KEY_TABLE[index])
      previous_byte = byte
    return bytes(plaintext)

  @staticmethod
  def enumerate_keys(k1: int) -> Generator[bytes, None, None]:
    # See https://palant.info/2026/01/05/analysis-of-pppp-encryption/ for explanation why only
    # these keys are possible.
    if k1 < 0 or k1 > 255:
      raise ValueError('Key byte has to be in the range 0..255')

    # Second key byte is always the two's complement of the first
    k2 = -k1 & 0xff

    # Third byte is dependent on the total sum of original key bytes, only three values are
    # actually relevant here.
    for total_sum in range(k1, 0x300 + k1, 0x100):
      # We assume that the original key length was at most 16 bytes
      max_length = 16
      for k3 in range(math.ceil((total_sum - max_length * 2) / 3), total_sum // 3 + 1):
        # Forth byte always has high bit set to zero, lowest bit is identical to k1
        for k4 in range(k1 & 1, 0x80, 2):
          yield bytes((k1, k2, k3 & 0xff, k4))

class Device:
  def __init__(self, prefix, serial, checkCode):
    self.prefix = prefix
    self.serial = serial
    self.checkCode = checkCode
    self.isYunniDevice = prefix in VSTARCAM_PREFIXES or YUNNI_CHECK_CODE_PATTERN.match(checkCode)
    self.uid = '%s-%s-%s' % (self.prefix, str(self.serial).zfill(6), self.checkCode)

class P2PClient:
  def __init__(self):
    self.devices = {}
    self.sockets = []
    for ip in fetchLocalIPv4Addresses():
      try:
        self.sockets.append(self.setup_socket(ip))
      except Exception as e:
        logging.error(f'LAN search failed on adapter {ip}: {e}')

  @staticmethod
  def enumerate_ciphertexts(plaintext: bytes) -> Generator[bytes, None, None]:
    for k1 in range(256):
      seen = set()
      for key in Encryption.enumerate_keys(k1):
        ciphertext = Encryption.encrypt(key, plaintext)
        if ciphertext not in seen:
          seen.add(ciphertext)
          yield ciphertext

  @staticmethod
  def setup_socket(source_ip: str) -> socket.socket:
    logging.debug(f'Setting up socket for source IP: {source_ip}')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(.5)
    s.bind((source_ip, 0))
    return s

  def receive(self, s: socket.socket) -> None:
    # parse responses until the application shuts down
    while True:
      try:
        (buff, rinfo) = s.recvfrom(1024)
        logging.debug('Data from %s: %s' % (rinfo, buff))

        try:
          for device in self.parsePunchPkt(buff):
            if device.uid in self.devices:
              continue

            device.ip = rinfo[0]
            self.devices[device.uid] = device

            if device.isYunniDevice:
              # the 'EEEE' prefix is used by both Yunni and CS2, but the check code makes it impossible to distinguish
              if device.prefix == 'EEEE': judgement = 'CS2 Network P2P or iLnkP2P'
              else: judgement = 'iLnkP2P'
            else: judgement = 'CS2 Network P2P'

            logging.info('===================================================\n'
                        '[*] Found %s device %s at %s\n'
                        '===================================================\n'
                          % (judgement, device.uid, device.ip)
                        )
        except Exception as e:
          logging.error('Failed to parse P2P message (%s): %s' % (e, buff))
          continue
      except socket.timeout as e:
        continue


  def tryLANSearch(self):
    logging.debug('Starting LAN search')

    for s in self.sockets:
      threading.Thread(target=self.receive, args=(s,), daemon=True).start()

    lanSearch = self.createP2PMessage(MSG_LAN_SEARCH)
    lanSearchExt = self.createP2PMessage(MSG_LAN_SEARCH_EXT)
    for s in self.sockets:
      s.sendto(lanSearch, (P2P_LAN_BROADCAST_IP, P2P_LAN_PORT))
      s.sendto(lanSearchExt, (P2P_LAN_BROADCAST_IP, P2P_LAN_PORT))

    interval = 1 / 6000   # limit rate to 6000 packets per second
    for request in self.enumerate_ciphertexts(lanSearch):
      start = time.perf_counter()
      for s in self.sockets:
        s.sendto(request, (P2P_LAN_BROADCAST_IP, P2P_LAN_PORT))
      elapsed = time.perf_counter() - start
      if elapsed < interval:
        time.sleep(interval - elapsed)

    # wait for outstanding responses
    time.sleep(1)

  @staticmethod
  def is_valid_punch_pkt(buff: bytes) -> Device | None:
    magic, msgType, size = struct.unpack('!BBH', buff[:4])
    if magic != P2P_MAGIC_NUM or msgType != MSG_PUNCH_PKT or size < 20 or size != len(buff) - 4:
      return None

    prefix, serial, checkCode = struct.unpack('!8sL8s', buff[4:24])
    prefix = prefix.rstrip(b'\0')
    checkCode = checkCode.rstrip(b'\0')
    if not re.match(rb'^[A-Z]+$', prefix) or serial >= 1000000 or not re.match(rb'^[A-Z]{5}$', checkCode):
      return None

    return Device(prefix.decode(), serial, checkCode.decode())

  @staticmethod
  def parsePunchPkt(buff: bytes) -> Generator[Device, None, None]:
    if len(buff) < 4:
      raise Exception('Invalid P2P message')

    found = False
    device = P2PClient.is_valid_punch_pkt(buff)
    if device is not None:
      found = True
      yield device
    else:
      k1 = Encryption.KEY_TABLE.index(buff[0] ^ P2P_MAGIC_NUM)
      for key in Encryption.enumerate_keys(k1):
        device = P2PClient.is_valid_punch_pkt(Encryption.decrypt(key, buff))
        if device is not None:
          found = True
          yield device

    if not found:
      raise Exception('Unexpected P2P message')

  def createP2PMessage(self, type, payload = bytes(0)):
    payloadSize = len(payload)
    buff = bytearray(P2P_HEADER_SIZE + payloadSize)
    buff[0] = P2P_MAGIC_NUM
    buff[1] = type
    buff[2:4] = payloadSize.to_bytes(2, 'big')
    buff[4:] = payload
    return buff

def main():
  logging.info('[*] P2P LAN Search v1.1\n'
               '[*] Copyright (c) 2020, Paul A. Marrapese <paul@redprocyon.com>\n'
               '[*] Searching for P2P devices...\n'
               '[*] This will take approximately 30 to 60 seconds.\n')
  client = P2PClient()
  client.tryLANSearch()

  if len(client.devices) == 0:
    logging.info('[*] No devices found.')
  logging.info('[*] Done.')

if __name__ == "__main__":
  main()
