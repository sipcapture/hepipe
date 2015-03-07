#define VERSION "1.0.0 dev"
#define DEFAULT_CONFIG "/usr/local/etc/hepipe/hepipe.ini"

#define PROTO_SIP    0x01
#define ETH_P_IP 0x0800
#define BUF_SIZE 1024

/* functions */
int read_from_pipe();

int dump_proto_packet(unsigned char *data, uint32_t len, uint32_t tsec, uint32_t tusec,  const char *ip_src, const char *ip_dst, uint16_t sport, uint16_t dport, uint16_t val1, uint16_t val2);
int send_hep_basic (rc_info_t *rcinfo, unsigned char *data, unsigned int len);
int send_hepv3 (rc_info_t *rcinfo, unsigned char *data, unsigned int len);
int send_hepv2 (rc_info_t *rcinfo, unsigned char *data, unsigned int len);
