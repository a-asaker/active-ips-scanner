#!/usr/bin/env python3
# Coded By : A_Asaker

import socket
from sys import argv


def Usage():
	print(''' [-] Active IPs Scanner Usage :
    ./Scanner.py [IP] [IP] [IP-range] ... [Options]

    - Options : 
		-v Or -V : Verbose Mode
	    
    - Example :
	    ./Scanner.py 192.168.1.1-10 192.168.1.150 172.217.18.238
	    ./Scanner.py 192.168.1.1-10 192.168.1.150 172.217.18.238 -V
		''')
	exit(1)

socket.setdefaulttimeout(3)
ips=[]
up=[]
filtered=[]

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

v=0

for arg in argv[1:]:
	if arg=="-v" or arg=="-V":
		v=1
	else:
		cnfg_ip(arg)

if len(argv)==1:
	Usage()
elif len(argv)==2 and v==1:
	Usage()

def scan(ip,port):
	if port==80:next_port=53
	else:next_port=443
	sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	mask = ip[:ip.rfind(".")+1]
	if mask in list(msk_dict):
		pass
	else:
		msk_dict[mask]=0
	try :
		sock.connect((ip,port))
		if v==1:
			print(" IP :",ip,"Is Up.")
		up.append(ip)
		sock.close()
		msk_dict.update({mask:1})
		return "UP"
	except ConnectionRefusedError:
		if v==1:
			print(" IP :",ip,"Is Up.")
		up.append(ip)
		msk_dict.update({mask:1})
		return "UP"
	except (socket.gaierror) as e:
		print(" [!] {} Is Not A Vaild Ip Address.".format(ip))
		return
	except socket.timeout:
		if msk_dict[mask]==1:
			if v==1:
				print(" IP :",ip,"Is Filtered.")
			filtered.append(ip)
			return "FILTERED"
		else:
			if port==443:
				return "DOWN"
			else:
				stat=scan(ip,next_port)
				if port==53:
					return "DOWN"
				if stat != "UP":
					if v==1:
						print(" IP :",ip,"May be Filtered, Down Or Unreachable.")
	except Exception as e:
		if port==443:
			return "DOWN"
		else:
			stat=scan(ip,next_port)
			if port==53:
				return "DOWN"
			if stat != "UP":
				if v==1:
					print(" IP :",ip,"Is Down.")

print("\n [<|>] Scanning [{} Device/s] ... ".format(len(ips)),end="")
msk_dict={"":""}
priv_ip=[(s.connect(('1.1.1.1', 1)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
priv_mask = priv_ip[:priv_ip.rfind(".")+1]
msk_dict={priv_mask:1}
if v==1:
	print()
for ip in ips:
	scan(ip,80)

def res_print():
	if len(filtered):
		print("\n [*]Filtered IPs : ")
		for ip in filtered:
			print(" - ",ip)	
	if len(up):
		print("\n [*]Active IPs : ")
		for ip in up:
			print(" - ",ip)
	print(" Total Active Devices : [{}] Device/s".format(len(up)))
	print()
res_print()
