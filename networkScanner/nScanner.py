import scapy.all as scapy
import nmap
scanner = nmap.PortScanner()

print("Welcome to my network scanner")

print("<-------------------------------------->")

resp = input("""\n Please enter type of scan you want to perform
        1. SYN ACK Scan
        2. UDP Scan
        3. Comprehensive Scan 
        4. Netdiscover\n""")

print("You have selected option: ", resp)

if resp == '1':
    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP address is: ",ip_addr)
    type(ip_addr)

    print("Nmap Version: ",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ",scanner[ip_addr])
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    #dict {[123,45,455]}
elif resp == '2':
    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP address is: ",ip_addr)
    type(ip_addr)

    print("Nmap Version: ",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v sU')
    print(scanner.scaninfo())
    print("IP Status: ",scanner[ip_addr])
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ",scanner[ip_addr]['udp'].keys())

elif resp=='3':
    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP address is: ",ip_addr)
    type(ip_addr)

    print("Nmap Version: ",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ",scanner[ip_addr])
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    

elif resp == '4':
    def scan(ip):
        request = scapy.ARP(pdst=ip)
        #request.show()
        #scapy.ls(scapy.ARP())

        broadcast = scapy.Ether()
        broadcast.dst = "00:00:00:00:00:00" #broadcast
        broadcast.show()

        request_broadcast = broadcast/request
        request_broadcast.show()

        res1 = scapy.srp(request_broadcast, timeout=1)[0]
        for el in res1:
            print(el[1].psrc)
            print(el[1].hwsrc)
    scan("192.168.1.1/24")




else:
    print("Invalid input, Please choose 1, 2, 3, and 4")