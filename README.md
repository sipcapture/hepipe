![Build_Status](https://travis-ci.org/sipcapture/hepipe.svg?branch=master)

HEPipe
=======

## Description:

HEPipe *(pronounced HEP-pipe)* is an application for logging arbitrary data *(ie: logs, cdrs, debug lines)* to a *HEP/EEP* capture server such as [HOMER](https://github.com/sipcapture/homer) or [HEPIC](http://hepic.tel)

## Security

The optional capture password (`-P`) is embedded in HEPv3 as an authentication key chunk and sent to the collector over UDP in the same datagram as the rest of the packet. That matches the HEP/EEP on-the-wire format; it is not TLS-encrypted by this agent. Run hepipe on trusted networks or use VPN/IPsec/wire encryption between the host and the capture server if the auth key or payloads are sensitive.

## Compilation:

### Linux

    cc -o hepipe hepipe.c -lpcap 

### Solaris

    cc -o hepipe hepipe.c -lpcap -lsocket
    NOTE: Please make sure that your compiler is gcc or understands the packet attribute for structure

## Format:

```csv
timesec;timeusec;correlationid;source_ip;source_port;destination_ip;destinaton_port;payload in json
```

## Usage Example:

* `-t 100` - loging Protocol Type

```sh
echo '1396362930;1003;fd8f48ea-b9aa-11e3-92f7-1803731b65be;127.0.0.1;5060;10.0.0.1;5060;{"pl": 10, "jt": 10}' | ./hepipe  -s hepserver -p 9061 -t 100
```
