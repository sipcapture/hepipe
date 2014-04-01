#!/bin/sh

#Linux
cc -o hepipe hepipe.c -lpcap 
#-lsocket

#Solaris. Please be sure that your compiler is gcc or understand the packet attribute for structure
#cc -o hepipe hepipe.c -lpcap -lsocket