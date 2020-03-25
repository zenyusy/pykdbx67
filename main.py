import logging
import argparse
from struct import unpack
from hashlib import sha256
from zlib import decompress
from getpass import getpass
from base64 import b64decode
import xml.etree.ElementTree as ET
from subprocess import run, DEVNULL
from Cryptodome.Cipher import AES, Salsa20

web = 'firefox'
clip = ['xclip', '-sel', 'c']

class clr:
    PURPLE = '\033[95m'
    OCEAN = '\033[96m'
    ENDC = '\033[0m'
    #BOLD = '\033[1m'
    #UNDERLINE = '\033[4m'
    #RED = '\033[91m'
    #GREEN = '\033[92m'
    #YELLOW = '\033[93m'
    #BLUE = '\033[94m'

head_map = (None, 'comment', 'cipher', 'gzip', 'main_seed', 'roll_seed',
    'rounds', 'IV', 'inner_key', 'head_chk', 'inner_cipher')
goodsig = b'\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5'
cipher_AES = b'\x31\xC1\xF2\xE6\xBF\x71\x43\x50\xBE\x58\x05\x21\x6A\xFC\x5A\xFF'
inner_Salsa20 = b'\x02\x00\x00\x00'
sal20_nounce = b'\xE8\x30\x09\x4B\x97\x20\x5D\x2A'
attribs = ('Notes', 'Title', 'URL', 'UserName')

def composite_key(password: bytes, keyfile:str) -> bytes:
    p = sha256(password).digest() if password else b''
    k = b''
    if keyfile:
        with open(keyfile, 'rb') as f:
            k = sha256(f.read()).digest()
    return sha256(p + k).digest()

def final_key(rollkey: bytes, rounds: int, rollseed: bytes, mainseed: bytes) -> bytes:
    logging.info(f'rounds: {rounds}')
    aes = AES.new(rollseed, AES.MODE_ECB)
    for i in range(rounds):
        rollkey = aes.encrypt(rollkey)
    rollkey = sha256(rollkey).digest()
    return sha256(mainseed + rollkey).digest()

def head2dict(f) -> dict:
    '''Parse kdbx header part '''
    sig, ver = unpack('<8sI', f.read(12))
    assert sig == goodsig, 'kdbx not supported'
    logging.info(f'ver {hex(ver)}')

    head = {}
    while True:
        index, size = unpack('<BH', f.read(3))
        data = f.read(size)
        if index == 0:
            break
        head[index] = data

    assert head[2] == cipher_AES, 'cipher not AES'
    assert head[10] == inner_Salsa20, 'stream cipher not Salsa20'
    logging.info('\n'.join(f'{head_map[i]} {head[i]}' for i in head))
    return head

def decbody(hd:dict, f, secpsw, secfile) -> bytes:
    '''Parse kdbx body '''
    aes = AES.new(
        final_key(
            composite_key(secpsw, secfile),
            unpack('<Q', hd[6])[0],
            hd[5],
            hd[4]),
        AES.MODE_CBC,
        hd[7])
    assert aes.decrypt(f.read(len(hd[9]))) == hd[9], 'decryption error'
    return aes.decrypt(f.read())

def body2xml(body: bytes, is_compressed) -> ET.Element:
    '''Parse AES-decrypted body to xml,
    where inner psw still Salsa20-encrypted.
    '''
    offset = 0 # in Bytes
    ret = b''
    blk_sz = 40

    # read data block by block
    while True:
        _, chk, size = unpack('<4s32sI', body[offset:offset+blk_sz])

        # last block flags
        if chk == b'\x00'*32 and size == 0:
            break
        offset += blk_sz

        data = body[offset:offset+size]
        assert sha256(data).digest() == chk, 'body corrupted'
        offset += size
        ret += data
    return ET.fromstring((decompress(ret, 31) if is_compressed else ret).decode())[1]

def xml2lst(xml: ET.Element, key) -> list:
    '''Restruct the root xml of kdbx to key-val pairs,
    and prepare plaintext password for clipboard.
    Return a list, each of whose element is a tuple:
    ({key: val,
      key: val,
      ...},
      plainpsw)
    '''
    ss = Salsa20.new(sha256(key).digest(), sal20_nounce)
    ret = []
    for entry in (xml.findall('./Group/Entry') + xml.findall('./Group/Group/Entry')):
        kv = {} # as ret[*][0]
        pln = None # plaintext-psw as ret[*][1]

        # get the "most recent" k-v pairs of this entry,
        # i.e., note, psw, title, URL, username, etc.
        for pair in entry.findall('./String'):
            if pair[0].text == 'Password':
                # psw found: only the 1st is currently in use;
                # other old ones need to involve in salsa20.
                for psw in entry.findall(".//Value[@Protected='True']"):
                    # psw may be empty
                    t = psw.text and ss.decrypt(b64decode(psw.text))
                    pln = pln or t
            else:
                kv[pair[0].text] = pair[1].text
        ret.append((kv, pln,))
    return ret

def must_input(prompt: str) -> str:
    i = None
    while not i:
        i = input(f'{prompt}{"" if i is None else " <must input>"}: ')
    return i

def yn(q:str, y=True) -> bool:
    '''Ask a yes-no 'q?' with a default answer, so that
    a lazy user can just hit ENTER to indicate the default.
    Anyway, return True if user input is 'y', False if 'n'.
    '''
    q = clr.OCEAN + q + '? ' + clr.ENDC
    return (input(q+'[y]/n ')!='n') if y else (input(q+'y/[n] ')=='y')

def clrkv(dct:dict, dlm: str):
    print(dlm.join((clr.PURPLE+k+clr.ENDC+': '+v) for k,v in dct.items() if v))

def sl(l: list):
    cho = ''
    while cho != 'e':
        cho = must_input('s(earch)? l(ist)? e(xit)?')[0]
        if cho == 's':
            kw = must_input('keyword').lower()
            nomatch = True
            for d, p in l:
                if any((d[a] and kw in d[a].lower()) for a in attribs):
                    clrkv(d, '\n')
                    if yn('thats it', False):
                        nomatch = False
                        if d[attribs[2]] and yn('open URL'):
                            run([web, d[attribs[2]]])
                        if p and yn('psw to clipb', False):
                            run(clip, input=p)
                        if d[attribs[3]] and yn('username to clipb', False):
                            run(clip, input=d[attribs[3]].encode())
                        if yn('clear clipb'):
                            run(clip, stdin=DEVNULL)
                        break
            if nomatch:
                logging.warning('no match')
        elif cho == 'l':
            exhausted = True
            for ct, entry in enumerate(l):
                clrkv(entry[0], '; ')
                if 9 == ct%10:
                    if not yn('more'):
                        exhausted = False
                        break
            if exhausted:
                logging.warning('all entries exhausted')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('db', help='the kdbx database')
    parser.add_argument('-k', '--keyfile', help='the key file')
    parser.add_argument('-o', '--header', action='store_true', help='only show header and quit')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(level=(logging.INFO if args.header or args.verbose else logging.WARNING),
        format='[%(levelname)s] %(message)s')
    with open(args.db, 'rb') as f:
        hd = head2dict(f)
        if not args.header:
            sl(xml2lst(
                    body2xml(
                        decbody(hd, f, getpass().encode(), args.keyfile),
                        unpack('<I', hd[3])),
                    hd[8]))

