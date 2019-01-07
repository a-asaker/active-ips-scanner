#!/usr/bin/env python3
#Coded By : A_Asaker 

import socket
from sys import argv


socket.setdefaulttimeout(5)
ips=[]
up=[]
filtered=[]

def Usage():
	print(''' [-] Active IPs Scanner Usage :
        ./Scanner.py [IP] [IP] [IP-range] ...
	    
    - Example :
	    ./Scanner.py 192.168.1.1-10 192.168.1.150 172.217.18.238
		''')

def chk_ip(i_ip,f_ip):
	if f_ip>i_ip:
		return(i_ip,f_ip)
	else:
		swap=i_ip
		i_ip=f_ip
		f_ip=swap
		return(i_ip,f_ip)

def ip_range(i_ip,f_ip,mask):
	if i_ip == f_ip:
		ips.append(mask+str(i_ip))
	else :
		i_ip,f_ip=chk_ip(i_ip,f_ip)
		for ip in range(i_ip,f_ip+1):
			ips.append(mask+str(ip))

def cnfg_ip(arg):
	try:
		mask = arg[:arg.rfind(".")+1]
		if arg.find("-") !=  -1:
			i_ip = int(arg[arg.rfind(".")+1:arg.rfind("-")])
			f_ip = int(arg[arg.rfind("-")+1:])
		else:
			i_ip = int(arg[arg.rfind(".")+1:])
			f_ip = int(arg[arg.rfind(".")+1:])
		ip_range(i_ip,f_ip,mask)
	except Exception as e:
		print(e)
		Usage()
		exit(0)

for arg in argv[1:]:
	cnfg_ip(arg)

def scan():
	msk_dict={"":""}
	priv_ip=[(s.connect(('1.1.1.1', 1)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
	priv_mask = priv_ip[:priv_ip.rfind(".")+1]
	msk_dict={priv_mask:1}
	print()
	for ip in ips:
		sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		mask = ip[:ip.rfind(".")+1]
		if mask in list(msk_dict):
			pass
		else:
			msk_dict[mask]=0
		try :
			sock.connect((ip,80))
			print(" IP :",ip,"Is Up.")
			up.append(ip)
			sock.close()
			msk_dict.update({mask:1})
		except ConnectionRefusedError:
			print(" IP :",ip,"Is Up.")
			up.append(ip)
			msk_dict.update({mask:1})
		except (socket.gaierror) as e:
			print(" [!] {} Is Not A Vaild Ip Address.".format(ip))
			break
		except socket.timeout:
			if msk_dict[mask]==1:
				print(" IP :",ip,"Is Filtered.")
				filtered.append(ip)
			else:
				print(" IP :",ip,"May be Down Or Unreachable.")
		except:
			print(" IP :",ip,"Is Down.")

def res_print():
	if len(filtered):
		print("\n [*]Filtered IPs (Firewall Blocks The Connection Or May Be Down.) : ")
		for ip in filtered:
			print(" - ",ip)	
	if len(up):
		print("\n [*]Active IPs : ")
		for ip in up:
			print(" - ",ip)
	print()

scan()
res_print()
