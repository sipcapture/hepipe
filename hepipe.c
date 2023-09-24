/*
 * $Id$
 *
 *  hepipe - Homer Stream agent. 
 *  Duplicate LOGS messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com> 
 *  (C) 2014 (http://www.sipcapture.org)
 *  Author: Lorenzo Mangani <lorenzo.mangani@gmail.com> 
 *  (C) 2015 (http://www.sipcapture.org)
 *
 * Homer Stream agent is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version
 *
 * Homer capture agent is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
*/


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifndef __USE_BSD
#define __USE_BSD  
#endif /* __USE_BSD */

#ifndef __FAVOR_BSD
#define __FAVOR_BSD 
#endif /* __FAVOR_BSD */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */
#define __FAVOR_BSD 
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>                                                  
#include <net/if.h>
#include <getopt.h>
#include <unistd.h>         
#include <signal.h>
#include <time.h>

/* Solaris */
#include <net/if.h>
#include <net/if_arp.h>

#include "core_hep.h"
#include "minIni/minIni.h"
#include "hepipe.h"

/* sender socket */
int sock;
int captid = 0;
int hepversion = 3;
char *capt_password = NULL;
char *correlation_id = NULL;
uint8_t link_offset = 14;
uint8_t chunk_vendor_id = 0;
uint8_t val1_chunk = 0;
uint8_t val2_chunk = 0;
/* logging TYPE */
int proto_type = 100;
int adv = 0;


void usage(int8_t e) {
#ifdef USE_CONFFILE
    printf("usage: hepipe <-vhc> <-s host> <-p port>\n"
           "            <-t type> <-i id> <-H 1|2|3> --config=<file>\n"
           "      -h  is help/usage\n"
           "      -v  is version information\n"
           "      -a  is advanced packet\n"
           "      -t  is protocol type packet\n"           
           "      -K  is vendor chunk id\n"           
           "      -V  is custom chunks id\n"           
           "      -s  is the capture server\n"
           "      -p  is use specified port of capture server. i.e. 9060\n"
           "  	  -P  is the capture password\n"
           "      -c  is checkout\n"
           "      -i  is capture identifity. Must be a 16-bit number. I.e: 101\n"
           "      -H  is HEP protocol version [1|2|3]. By default we use HEP version 3\n"
           "--config  is config file to use to specify some options. Default location is [%s]\n"
           "", DEFAULT_CONFIG);
	exit(e);
#else
    printf("usage: hepipe <-vhc> <-d dev> <-s host> <-p port>\n"
           "            <-t type> <-f filter file> <-i id> <-H 1|2|3>\n"
           "   -h  is help/usage\n"
           "   -v  is version information\n"
           "   -a  is advanced packet\n"
           "   -t  is protocol type packet\n"           
           "   -K  is vendor chunk id\n"           
           "   -V  is custom chunks id\n"           
           "   -s  is the capture server\n"
           "   -P  is the capture password\n"
           "   -p  is use specified port of capture server. i.e. 9060\n"
           "   -c  is checkout\n"
           "   -i  is capture identifity. Must be a 16-bit number. I.e: 101\n"
           "   -H  is HEP protocol version [1|2|3]. By default we use HEP version 3\n"
           "");
	exit(e);

#endif
}


void handler(int value)
{
	if(sock) close(sock);
        exit(0);
}


int main(int argc,char **argv)
{
        int mode, c, checkout=0, heps=0;
        struct addrinfo *ai, hints[1] = {{ 0 }};
        char *capt_host = NULL, *capt_port = NULL, *chunk_vals = NULL;
	uint16_t snaplen = 65535, promisc = 1, to = 100;	
	char *dav = NULL;

#ifdef USE_CONFFILE

        #define sizearray(a)  (sizeof(a) / sizeof((a)[0]))

        char *conffile = NULL;

        static struct option long_options[] = {
                {"config", optional_argument, 0, 'C'},
                {0, 0, 0, 0}
        };
	        
        while((c=getopt_long(argc, argv, "avhcp:s:c:f:i:H:C:K:V:P:", long_options, NULL))!=-1) {
#else
        while((c=getopt(argc, argv, "avhcp:s:c:f:t:i:H:C:K:V:P:"))!=EOF) {
#endif
                switch(c) {
#ifdef USE_CONFFILE
                        case 'C':
                                        conffile = optarg ? optarg : DEFAULT_CONFIG;
                                        break;
#endif
                        case 's':
                                        capt_host = optarg;
                                        break;
                        case 'p':
                                        capt_port = optarg;
                                        break;
                        case 'P':
                                        capt_password = optarg;
                                        break;                                        
                        case 'h':
                                        usage(0);
                                        break;
                        case 'c':
                                        checkout=1;
                                        break;                                                                                
                        case 'a':
                                        adv=1;
                                        break;                                                                                                                        
                                        
                        case 'v':
                                        printf("version: %s\n", VERSION);
#ifdef USE_HEP2
                                        printf("HEP2 is enabled\n");
#endif                                        
					exit(0);
                                        break;
                        case 'i':
                                        captid = atoi(optarg);
                                        break;             
                        case 't':
                                        proto_type = atoi(optarg);
                                        break;                                                     
                        case 'H':
                                        hepversion = atoi(optarg);
					heps=1;
                                        break;                                                    
                        case 'K':
                                        chunk_vendor_id = atoi(optarg);
                                        break;                                                                                             
                        case 'V':
                                        chunk_vals = optarg;
                                        break;                                                                                                                                     
	                default:
                                        abort();
                }
        }

#ifdef USE_CONFFILE

        long n;
        char ini[100];
        char captport_ini[100];
        char captportr_ini[100];
        char captid_ini[10];
        char hep_ini[2];

	if(heps == 0) {
		n = ini_gets("main", "hep", "dummy", hep_ini, sizearray(hep_ini), conffile);
		if(strcmp(hep_ini, "dummy") != 0) {
			 hepversion=atoi(hep_ini);
		}

		if(hepversion == 0)
			hepversion = 1;
	}

        if(captid == 0) {
                n = ini_gets("main", "identifier", "dummy", captid_ini, sizearray(captid_ini), conffile);
                if(strcmp(captid_ini, "dummy") != 0) {
                         captid=atoi(captid_ini);
                }
        }

        if(capt_host == NULL) {
                n = ini_gets("main", "capture_server", "dummy", ini, sizearray(ini), conffile);
                if(strcmp(ini, "dummy") != 0) {
                         capt_host=ini;
                }
        }

        if(capt_port == NULL) {
                n = ini_gets("main", "capture_server_port", "dummy", captport_ini, sizearray(captport_ini), conffile);
                if(strcmp(captport_ini, "dummy") != 0) {
                         capt_port=captport_ini;
                }
        }

#endif

	if(capt_host == NULL || capt_port == NULL) {
	        fprintf(stderr,"capture server and capture port must be defined!\n");
		usage(-1);
	}


        if(hepversion < 1 && hepversion > 3) {
            fprintf(stderr,"unsupported HEP version. Must be 1,2 or 3, but you have defined as [%i]!\n", hepversion);
            return 1;
        }

	hints->ai_flags = AI_NUMERICSERV;
        hints->ai_family = AF_UNSPEC;
        hints->ai_socktype = SOCK_DGRAM;
        hints->ai_protocol = IPPROTO_UDP;

        if (getaddrinfo(capt_host, capt_port, hints, &ai)) {
            fprintf(stderr,"capture: getaddrinfo() error");
            return 2;
        }

        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {                        
                 fprintf(stderr,"Sender socket creation failed: %s\n", strerror(errno));
                 return 3;
        }

        /* not blocking */
        mode = fcntl(sock, F_GETFL, 0);
        mode |= O_NDELAY | O_NONBLOCK;
        fcntl(sock, F_SETFL, mode);

        if (connect(sock, ai->ai_addr, (socklen_t)(ai->ai_addrlen)) == -1) {
            if (errno != EINPROGRESS) {
                    fprintf(stderr,"Sender socket creation failed: %s\n", strerror(errno));                    
                    return 4;
            }
        }
                 
        if(checkout) {
                fprintf(stdout,"Version     : [%s]\n", VERSION);
                fprintf(stdout,"Capture host: [%s]\n", capt_host);
                fprintf(stdout,"Capture port: [%s]\n", capt_port);
                fprintf(stdout,"Capture ID  : [%i]\n", captid);
                fprintf(stdout,"Capture pro : [%i]\n", proto_type);
                fprintf(stdout,"HEP version : [%i]\n", hepversion);
#ifdef USE_CONFFILE
                fprintf(stdout,"Config file : [%s]\n", conffile);
#endif
                return 0;
        }        
        
        
        if(chunk_vals)
        {        
            /* useconds */
            dav = strtok(chunk_vals, ":");
            if(dav) {
                val1_chunk = atoi(dav);
                chunk_vals+=(strlen(dav)+1);
                val2_chunk = atoi(chunk_vals);     
            }           
            else {
               val1_chunk = atoi(chunk_vals);
            }        
        }        

	read_from_pipe();

        handler(1);
        /* we should never get here during normal operation */
        return 0;
}


int read_from_pipe() {

	char buffer[BUF_SIZE];
	char cid[256];
        size_t contentSize = 1; // includes NULL
	char *pch = NULL, *tmpval = NULL;
	unsigned int offset;
	unsigned int tsec=0, tusec=0;
	char src_ip[256], dst_ip[256];
	uint16_t sport = 1, dport=2, val1=0, val2=0;
       	struct timeval tv;
       	                               
	char *content = malloc(sizeof(char) * BUF_SIZE);
	if(content == NULL)
	{
	    perror("Failed to allocate content");
	    exit(1);
	}

	content[0] = '\0'; // make null-terminated
	cid[0] = '\0';
	
	correlation_id = NULL;
	
	while(fgets(buffer, BUF_SIZE, stdin))
	{
		char *old = content;
		contentSize += strlen(buffer);
		content = realloc(content, contentSize);
		if(content == NULL)
		{
			perror("Failed to reallocate content");
			free(old);
			exit(2);
		}
		strcat(content, buffer);
	}
			
	if(content && adv == 0) {
		
		/* seconds */
		pch = strtok(content, ";");
		if(pch) tsec = atoi(pch);
		else goto error;	
		
		/* useconds */
		pch = strtok(NULL, ";");
		if(pch) tusec = atoi(pch);
		else goto error;	
		
                /* correlation id */
		pch = strtok(NULL, ";");
		if(pch) snprintf(cid, 256, "%s", pch);
		else goto error;
		
		/* src ip */
		pch = strtok(NULL, ";");
		if(pch) snprintf(src_ip, 256, "%s", pch);
		else goto error;
		
		/* sport */
		pch = strtok(NULL, ";");
		if(pch) sport = atoi(pch);
		else goto error;	
		
		/* dst ip */
		pch = strtok(NULL, ";");
		if(pch) snprintf(dst_ip, 256, "%s", pch);
		else goto error;
		
		/* dport */
		pch = strtok(NULL, ";");
		if(pch) dport = atoi(pch);
		else goto error;	
		
		/* data */
		pch = strtok(NULL, ";");
		if(!pch) goto error;	
	}	
	else if(content && adv == 1) 
	{
	        /* gettimeofday(&tv,NULL);
	        tsec = tv.tv_sec;
	        tusec = tv.tv_usec
	        */
	        
	        /* seconds */
		pch = strtok(content, ";");
		if(pch) tsec = atoi(pch);
		else goto error;	
		
		/* useconds */
		pch = strtok(NULL, ";");
		if(pch) tusec = atoi(pch);
		else goto error;	
		
                /* correlation id */
		pch = strtok(NULL, ";");
		if(pch) snprintf(cid, 256, "%s", pch);
		else goto error;
		
		pch = strtok(NULL, ";");
		if(pch) val1= atoi(pch);
		else goto error;
		
		pch = strtok(NULL, ";");
		if(pch) val2=atoi(pch);
		else goto error;
		
		snprintf(src_ip, 256, "127.0.0.20");
	        snprintf(dst_ip, 256, "127.0.0.30");
	
	}

	if(ferror(stdin))
	{
		free(content);
		perror("Error reading from stdin.");
	}

		
	printf("\nTIME: %d.%d | ", tsec, tusec);
	printf("\nCID: %s | ", cid ? cid : "NULL");			
	printf("\nPort: source: %d, destination: %d", sport, dport);			
	printf("\nDATA: %d/%d | STATUS: ", val1, val2);
	
	/* check our correlation */	
	if(cid && strlen(cid) > 0) correlation_id = cid;

	if(dump_proto_packet(pch, strlen(pch), tsec, tusec, src_ip, dst_ip, sport, dport, val1, val2)) {
	     printf("SENT\n");	
	}
	
	return 1;

	
	
	error:
	   if(content) free(content);
           return 1;
}


int dump_proto_packet(unsigned char *data, uint32_t len, uint32_t tsec, uint32_t tusec,  const char *ip_src, const char *ip_dst, uint16_t sport, uint16_t dport, uint16_t val1, uint16_t val2) {

	char timebuffer[30];	
	rc_info_t *rcinfo = NULL;

	rcinfo = malloc(sizeof(rc_info_t));
	memset(rcinfo, 0, sizeof(rc_info_t));

        rcinfo->src_port   = sport;
        rcinfo->dst_port   = dport;
        rcinfo->src_ip     = (char *)ip_src;
        rcinfo->dst_ip     = (char *)ip_dst;
        rcinfo->ip_family  = AF_INET;
        rcinfo->ip_proto   = 17;
        rcinfo->time_sec   = tsec;
        rcinfo->time_usec  = tusec;
        rcinfo->proto_type = proto_type;
        rcinfo->val1 = val1;
        rcinfo->val2 = val2;

	/* Duplcate */
	if(!send_hep_basic(rcinfo, data, (unsigned int) len)) {
	         printf("FAILED\n");
        }
        
        if(rcinfo) free(rcinfo);

	return 1;
}



int send_hep_basic (rc_info_t *rcinfo, unsigned char *data, unsigned int len) {

        switch(hep_version) {
        
            case 3:
		return send_hepv3(rcinfo, data , len);
                break;
                
            case 2:            
            case 1:        
                return send_hepv2(rcinfo, data, len);                    
                break;
                
            default:
                fprintf(stderr, "Unsupported HEP version [%d]\n", hep_version);                
                break;
        }

        return 0;
}

int send_hepv3 (rc_info_t *rcinfo, unsigned char *data, unsigned int len) {

    struct hep_generic *hg=NULL;
    void* buffer;
    unsigned int buflen=0, iplen=0,tlen=0;
    hep_chunk_ip4_t src_ip4, dst_ip4;
#ifdef USE_IPV6
    hep_chunk_ip6_t src_ip6, dst_ip6;    
#endif            
    hep_chunk_t payload_chunk;
    hep_chunk_t authkey_chunk;
    hep_chunk_t correlation_chunk;
    hep_chunk_uint16_t chunk_val1, chunk_val2;
    static int errors = 0;

    hg = malloc(sizeof(struct hep_generic));
    memset(hg, 0, sizeof(struct hep_generic));

    /* header set */
    memcpy(hg->header.id, "\x48\x45\x50\x33", 4);

    /* IP proto */
    hg->ip_family.chunk.vendor_id = htons(0x0000);
    hg->ip_family.chunk.type_id   = htons(0x0001);
    hg->ip_family.data = rcinfo->ip_family;
    hg->ip_family.chunk.length = htons(sizeof(hg->ip_family));
    
    /* Proto ID */
    hg->ip_proto.chunk.vendor_id = htons(0x0000);
    hg->ip_proto.chunk.type_id   = htons(0x0002);
    hg->ip_proto.data = rcinfo->ip_proto;
    hg->ip_proto.chunk.length = htons(sizeof(hg->ip_proto));
    

    /* IPv4 */
    if(rcinfo->ip_family == AF_INET) {
        /* SRC IP */
        src_ip4.chunk.vendor_id = htons(0x0000);
        src_ip4.chunk.type_id   = htons(0x0003);
        inet_pton(AF_INET, rcinfo->src_ip, &src_ip4.data);
        src_ip4.chunk.length = htons(sizeof(src_ip4));            
        
        /* DST IP */
        dst_ip4.chunk.vendor_id = htons(0x0000);
        dst_ip4.chunk.type_id   = htons(0x0004);
        inet_pton(AF_INET, rcinfo->dst_ip, &dst_ip4.data);        
        dst_ip4.chunk.length = htons(sizeof(dst_ip4));
        
        iplen = sizeof(dst_ip4) + sizeof(src_ip4); 
    }
#ifdef USE_IPV6
      /* IPv6 */
    else if(rcinfo->ip_family == AF_INET6) {
        /* SRC IPv6 */
        src_ip6.chunk.vendor_id = htons(0x0000);
        src_ip6.chunk.type_id   = htons(0x0005);
        inet_pton(AF_INET6, rcinfo->src_ip, &src_ip6.data);
        src_ip6.chunk.length = htons(sizeof(src_ip6));
        
        /* DST IPv6 */
        dst_ip6.chunk.vendor_id = htons(0x0000);
        dst_ip6.chunk.type_id   = htons(0x0006);
        inet_pton(AF_INET6, rcinfo->dst_ip, &dst_ip6.data);
        dst_ip6.chunk.length = htons(sizeof(dst_ip6));    
        
        iplen = sizeof(dst_ip6) + sizeof(src_ip6);
    }
#endif
        
    /* SRC PORT */
    hg->src_port.chunk.vendor_id = htons(0x0000);
    hg->src_port.chunk.type_id   = htons(0x0007);
    hg->src_port.data = rcinfo->src_port;
    hg->src_port.chunk.length = htons(sizeof(hg->src_port));
    
    /* DST PORT */
    hg->dst_port.chunk.vendor_id = htons(0x0000);
    hg->dst_port.chunk.type_id   = htons(0x0008);
    hg->dst_port.data = rcinfo->dst_port;
    hg->dst_port.chunk.length = htons(sizeof(hg->dst_port));
    
    
    /* TIMESTAMP SEC */
    hg->time_sec.chunk.vendor_id = htons(0x0000);
    hg->time_sec.chunk.type_id   = htons(0x0009);
    hg->time_sec.data = htonl(rcinfo->time_sec);
    hg->time_sec.chunk.length = htons(sizeof(hg->time_sec));
    

    /* TIMESTAMP USEC */
    hg->time_usec.chunk.vendor_id = htons(0x0000);
    hg->time_usec.chunk.type_id   = htons(0x000a);
    hg->time_usec.data = htonl(rcinfo->time_usec);
    hg->time_usec.chunk.length = htons(sizeof(hg->time_usec));
    
    /* Protocol TYPE */
    hg->proto_t.chunk.vendor_id = htons(0x0000);
    hg->proto_t.chunk.type_id   = htons(0x000b);
    hg->proto_t.data = rcinfo->proto_type;
    hg->proto_t.chunk.length = htons(sizeof(hg->proto_t));
    
    /* Capture ID */
    hg->capt_id.chunk.vendor_id = htons(0x0000);
    hg->capt_id.chunk.type_id   = htons(0x000c);
    hg->capt_id.data = htonl(captid);
    hg->capt_id.chunk.length = htons(sizeof(hg->capt_id));

    /* Payload */
    payload_chunk.vendor_id = htons(0x0000);
    payload_chunk.type_id   = htons(0x000f);
    payload_chunk.length    = htons(sizeof(payload_chunk) + len);
    
    tlen = sizeof(struct hep_generic) + len + iplen + sizeof(hep_chunk_t);

    /* auth key */
    if(capt_password != NULL) {

          tlen += sizeof(hep_chunk_t);
          /* Auth key */
          authkey_chunk.vendor_id = htons(0x0000);
          authkey_chunk.type_id   = htons(0x000e);
          authkey_chunk.length    = htons(sizeof(authkey_chunk) + strlen(capt_password));
          tlen += strlen(capt_password);
    }
    
    /* correlation id */
    if(correlation_id != NULL) {
          tlen += sizeof(hep_chunk_t);
          /* Auth key */
          correlation_chunk.vendor_id = htons(0x0000);
          correlation_chunk.type_id   = htons(0x0011);
          correlation_chunk.length    = htons(sizeof(correlation_chunk) + strlen(correlation_id));
          tlen += strlen(correlation_id);
    }
    
    /* val1 */
    if(chunk_vendor_id != 0 && val1_chunk != 0) {
          tlen += sizeof(hep_chunk_uint16_t);
          chunk_val1.chunk.vendor_id = htons(chunk_vendor_id);
          chunk_val1.chunk.type_id   = htons(val1_chunk);
          chunk_val1.data = htons(rcinfo->val1);
          chunk_val1.chunk.length = htons(sizeof(hep_chunk_uint16_t));
    }
    
    /* val2 */
    if(chunk_vendor_id != 0 && val2_chunk != 0) {
          tlen += sizeof(hep_chunk_uint16_t);
          chunk_val2.chunk.vendor_id = htons(chunk_vendor_id);
          chunk_val2.chunk.type_id   = htons(val2_chunk);
          chunk_val2.data = htons(rcinfo->val2);
          chunk_val2.chunk.length = htons(sizeof(hep_chunk_uint16_t));
    }
    
    /* total */
    hg->header.length = htons(tlen);

    buffer = (void*)malloc(tlen);
    if (buffer==0){
        fprintf(stderr,"ERROR: out of memory\n");
        free(hg);
        return 1;
    }
    
    memcpy((void*) buffer, hg, sizeof(struct hep_generic));
    buflen = sizeof(struct hep_generic);

    /* IPv4 */
    if(rcinfo->ip_family == AF_INET) {
        /* SRC IP */
        memcpy((void*) buffer+buflen, &src_ip4, sizeof(struct hep_chunk_ip4));
        buflen += sizeof(struct hep_chunk_ip4);
        
        memcpy((void*) buffer+buflen, &dst_ip4, sizeof(struct hep_chunk_ip4));
        buflen += sizeof(struct hep_chunk_ip4);
    }
#ifdef USE_IPV6
      /* IPv6 */
    else if(rcinfo->ip_family == AF_INET6) {
        /* SRC IPv6 */
        memcpy((void*) buffer+buflen, &src_ip4, sizeof(struct hep_chunk_ip6));
        buflen += sizeof(struct hep_chunk_ip6);
        
        memcpy((void*) buffer+buflen, &dst_ip6, sizeof(struct hep_chunk_ip6));
        buflen += sizeof(struct hep_chunk_ip6);
    }
#endif

    /* AUTH KEY CHUNK */
    if(capt_password != NULL) {

        memcpy((void*) buffer+buflen, &authkey_chunk,  sizeof(struct hep_chunk));
        buflen += sizeof(struct hep_chunk);

        /* Now copying payload self */
        memcpy((void*) buffer+buflen, capt_password, strlen(capt_password));
        buflen+=strlen(capt_password);
    }
    
     /* AUTH KEY CHUNK */
    if(correlation_id != NULL) {

        memcpy((void*) buffer+buflen, &correlation_chunk,  sizeof(struct hep_chunk));
        buflen += sizeof(struct hep_chunk);

        /* Now copying payload self */
        memcpy((void*) buffer+buflen, correlation_id, strlen(correlation_id));
        buflen+=strlen(correlation_id);
    }
    
    
    /* val1 */
    if(chunk_vendor_id != 0 && val1_chunk != 0) {
          
          memcpy((void*) buffer+buflen, &chunk_val1,  sizeof(chunk_val1));
          buflen += sizeof(hep_chunk_uint16_t);
    }
    
    /* val2 */
    if(chunk_vendor_id != 0 && val2_chunk != 0) {
          
          memcpy((void*) buffer+buflen, &chunk_val2,  sizeof(chunk_val2));
          buflen += sizeof(hep_chunk_uint16_t);
    }
    
    /* PAYLOAD CHUNK */
    memcpy((void*) buffer+buflen, &payload_chunk,  sizeof(struct hep_chunk));
    buflen +=  sizeof(struct hep_chunk);            

    /* Now copying payload self */
    memcpy((void*) buffer+buflen, data, len);    
    buflen+=len;    

    /* send this packet out of our socket */
    send(sock, buffer, buflen, 0); 
            
    /* FREE */        
    if(buffer) free(buffer);
    if(hg) free(hg);        
    
    return 1;
}


int send_hepv2 (rc_info_t *rcinfo, unsigned char *data, unsigned int len) {

    void* buffer;            
    struct hep_hdr hdr;
    struct hep_timehdr hep_time;
    struct hep_iphdr hep_ipheader;
    unsigned int totlen=0, buflen=0;
    static int errors=0;
#ifdef USE_IPV6
    struct hep_ip6hdr hep_ip6header;
#endif /* USE IPV6 */

    /* Version && proto */
    hdr.hp_v = hep_version;
    hdr.hp_f = rcinfo->ip_family;
    hdr.hp_p = rcinfo->ip_proto;
    hdr.hp_sport = htons(rcinfo->src_port); /* src port */
    hdr.hp_dport = htons(rcinfo->dst_port); /* dst port */

    /* IP version */    
    switch (hdr.hp_f) {        
                case AF_INET:
                    totlen  = sizeof(struct hep_iphdr);
                    break;
#ifdef USE_IPV6                    
                case AF_INET6:
                    totlen = sizeof(struct hep_ip6hdr);
                    break;
#endif /* USE IPV6 */
                    
    }
    
    hdr.hp_l = totlen + sizeof(struct hep_hdr);
    
    /* COMPLETE LEN */
    totlen += sizeof(struct hep_hdr);
    totlen += len;

    if(hep_version == 2) {
    	totlen += sizeof(struct hep_timehdr);
        hep_time.tv_sec = rcinfo->time_sec;
        hep_time.tv_usec = rcinfo->time_usec;
        hep_time.captid = captid;
    }

    /*buffer for ethernet frame*/
    buffer = (void*)malloc(totlen);
    if (buffer==0){
    	fprintf(stderr,"ERROR: out of memory\n");
        goto error;
    }

    /* copy hep_hdr */
    memcpy((void*) buffer, &hdr, sizeof(struct hep_hdr));
    buflen = sizeof(struct hep_hdr);

    switch (hdr.hp_f) {

    	case AF_INET:
        	/* Source && Destination ipaddresses*/
        	inet_pton(AF_INET, rcinfo->src_ip, &hep_ipheader.hp_src);
        	inet_pton(AF_INET, rcinfo->dst_ip, &hep_ipheader.hp_dst);

                /* copy hep ipheader */
                memcpy((void*)buffer + buflen, &hep_ipheader, sizeof(struct hep_iphdr));
                buflen += sizeof(struct hep_iphdr);

                break;
#ifdef USE_IPV6
	case AF_INET6:

                inet_pton(AF_INET6, rcinfo->src_ip, &hep_ip6header.hp6_src);
                inet_pton(AF_INET6, rcinfo->dst_ip, &hep_ip6header.hp6_dst);                        

                /* copy hep6 ipheader */
                memcpy((void*)buffer + buflen, &hep_ip6header, sizeof(struct hep_ip6hdr));
                buflen += sizeof(struct hep_ip6hdr);
                break;
#endif /* USE_IPV6 */
     }

     /* Version 2 has timestamp, captnode ID */
     if(hep_version == 2) {
     	/* TIMING  */
        memcpy((void*)buffer + buflen, &hep_time, sizeof(struct hep_timehdr));
        buflen += sizeof(struct hep_timehdr);
     }

     memcpy((void *)(buffer + buflen) , (void*)(data), len);
     buflen +=len;

     send(sock, buffer, buflen, 0); 
          
     /* FREE */
     if(buffer) free(buffer);

     return 1;

error:
     if(buffer) free(buffer);
     return 0;                     
}
