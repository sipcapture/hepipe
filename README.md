hepstream
=========

hep pipe application for logging

#Usage

timesec;timeusec;correlationid;source_ip;source_port;destination_ip;destinaton_port;payload in json

echo '1396362930;1003;fd8f48ea-b9aa-11e3-92f7-1803731b65be;127.0.0.1;5060;10.0.0.1;5060;{"pl": 10, "jt": 10}' | ./hepipe  -s hepserver -p 9061
