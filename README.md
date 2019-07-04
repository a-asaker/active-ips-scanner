# Active IPs/Hosts Scanner:

This Project Scans Some Given IPs To Find Out Whether These IPs Are Active/Alive Or Not. It Is Good For These Computers Which Doesn't Allowed To Have `Nmap` Or Other Scanners. It's Written In Python3 With Stdlibs, So It Should Work With All Computers Which Have Python And No Need For Installing Any Libraries. It's Slower Than Nmap And Not At The Same Accuracy Level Of Nmap Of Course, But It Works. If You Figured Out Any Issue You Can Submit It And I'll See What I Can Help With.

Coded By : a-asaker.    

# Usage: 

    ./ip_scanner.py [IP] [IP-Range] ...

-Example:

    ./ip_scanner.py 192.168.1.1-10 192.168.1.150 172.217.18.238

* Note : 

    You Should Add This Project To The Allowed/Trusted List Of The Firewall Or Disable Your Firewall Before Using This Project, Otherwise It Won't Work Properly.
