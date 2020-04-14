#!/usr/bin/python3

import os
os.system("pip3 install python-nmap")

import nmap
scanner = nmap.PortScanner()

print("Hi, This is a Simple NMAP automation tool")

print(f"The current NMAP version is: {scanner.nmap_version()}")
c=input("This Script requires ADMINISTRATIVE Privliges!\nDo you want you continue?[y/n]: ")
if c != 'y':
    exit(0)
if os.geteuid() != 0:
    print("You do not have Administrative Privlidges. Please try again!")
    exit(0)

print("<---------------------------------------------->")
while True:
    ip_add = input("Enter the ip address you want to scan: ")
    print(f"The IP Address specified is: {ip_add}")
    prt=input("Enter the Port Range :")
    #type(ip_add)

    choice = input("""\nEnter the type of Scan you want to perform
                    1)SYN ACK Scan
                    2)UDP Scan
                    3)Comprehensive Scan
                    4)IP protocol Scan 
                    5)Agressive Scan\n>>>""")
    print(f"The Selected Option is: {choice}")
    if choice == "1":
        scanraw = scanner.scan(ip_add, prt, '-v -sS')
        print(f"The Scan Statistics are: {scanner.scanstats()}")
        print(f"The Scan Info is: {scanner.scaninfo()}")
        print(f"IP Address Status: {scanner[ip_add].state()}")
        print(f"The Hostname is:  {scanner[ip_add].hostnames()}")
        print(f"All the Network Protocols are: {scanner[ip_add].all_protocols()}")
        print(f"The Open Ports for TCP are: {scanner[ip_add]['tcp'].keys()}")
    
    elif choice == "2":
        scanraw = scanner.scan(ip_add, prt, '-v -sU')
        print(f"The Scan Statistics are: {scanner.scanstats()}")
        print(f"The Scan Info is: {scanner.scaninfo()}")
        print(f"IP Address Status: {scanner[ip_add].state()}")
        print(f"The Hostname is:  {scanner[ip_add].hostnames()}")
        print(f"All the Network Protocols are: {scanner[ip_add].all_protocols()}")
        print(f"The Open Ports for UDP are: {scanner[ip_add]['udp'].keys()}")

    elif choice == "3":
        scanraw = scanner.scan(ip_add, prt, '-v -sS -sU -sV -sC -A -O')
        print(f"The Scan Statistics are: {scanner.scanstats()}")
        print(f"The Scan Info is: {scanner.scaninfo()}")
        print(f"IP Address Status: {scanner[ip_add].state()}")
        print(f"The Hostname is:  {scanner[ip_add].hostnames()}")
        print(f"The Uptime for the network is: {scanner[ip_add].uptime()}")
        print(f"All the Network Protocols are: {scanner[ip_add].all_protocols()}")
        print(f"The Open Ports for TCP are: {scanner[ip_add]['tcp'].keys()}")
        print(f"The Open Ports for UDP are: {scanner[ip_add]['udp'].keys()}")
        print(f"The OS Specifications are: {scanner[ip_add]['osmatch']}")


    elif choice == "4":
        scanraw = scanner.scan(ip_add, None, '-v -sO')
        print(f"The Scan Info is: {scanner.scaninfo()}")
        print(f"The Scan Statistics are: {scanner.scanstats()}")
        print(f"IP Address Status: {scanner[ip_add].state()}")
        print(f"The Hostname is:  {scanner[ip_add].hostnames()}")
        print(f"All the Network Protocols are: {scanner[ip_add].all_protocols()}")
        print(f"The Open Ports for IP are: {scanner[ip_add]['ip'].keys()}")

    elif choice == "5":
        scanraw = scanner.scan(ip_add, prt, '-vv -A')
        print(f"The Scan Statistics are: {scanner.scanstats()}")
        print(f"The Scan Info is: {scanner.scaninfo()}")
        print(f"IP Address Status: {scanner[ip_add].state()}")
        print(f"The Hostname is:  {scanner[ip_add].hostnames()}")
        print(f"The Uptime for the network is: {scanner[ip_add].uptime()}")
        print(f"All the Network Protocols are: {scanner[ip_add].all_protocols()}")
        print(f"The Open Ports for TCP are: {scanner[ip_add]['tcp'].keys()}")
        print(f"The OS Specifications are: {scanner[ip_add]['osmatch']}")

    else:
        print("Please Make a valid choice :)")
        exit(0) 

    details = input("Do you want a RAW output of your choice?[y/n]: ")
    if details == "y":
        print("++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print(f"\n\n{scanraw}\n\n")
        print("++++++++++++++++++++++++++++++++++++++++++++++++++++++")

    cont=input("Do you want to Exit?[y/n]: ")
    if cont == "y":
        exit(0)
    else:
        continue
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp >= '4':
    print("Please enter a valid option")








