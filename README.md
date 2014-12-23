HEPipe
=======

## Description:
HEPipe *(pronounced HEP-pipe)* is an application for logging arbitrary data *(ie: logs, cdrs, debug lines)* to a *HEP/EEP* capture server such as [HOMER](https://github.com/sipcapture/homer) or [PCAPTURE](http://pcapture.com)

##Compilation:
###Linux
    cc -o hepipe hepipe.c -lpcap 

###Solaris
    cc -o hepipe hepipe.c -lpcap -lsocket
    NOTE: Please make sure that your compiler is gcc or understands the packet attribute for structure


##Format:

```
timesec;timeusec;correlationid;source_ip;source_port;destination_ip;destinaton_port;payload in json
```

##Usage Example:

```
echo '1396362930;1003;fd8f48ea-b9aa-11e3-92f7-1803731b65be;127.0.0.1;5060;10.0.0.1;5060;{"pl": 10, "jt": 10}' | ./hepipe  -s hepserver -p 9061
```
