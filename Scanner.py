#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("Welcome To Sharks Scanner")
print("This Is A Simple Port Scanner Tool Coded By Sharks Team")

ip_addr = input(" Inter The IP You Want To Scan:  ")
print("IP You Entered Is:  " , ip_addr)
type(ip_addr)

resp = input("""\nPlease Enter The Type Of Scan You Want To Run
                1)SYN ACK
                2)UDP 
                3)Comprehensive \n""")
print("You Have Selected : ", resp)

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['UDP'].keys())
elif resp == '3':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp >= '4':
    print("Please Enter a Valid Option")