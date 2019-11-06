#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "netfilter.h"

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

// return = 0 : drop, return = 1 : accept
int check_pkt(uint8_t* pkt, int size){
	struct IP_HDR* pkt_iphdr;
	struct TCP_HDR* pkt_tcphdr;
	
	pkt_iphdr = pkt;
	int IP_len = ((pkt_iphdr->header) & 15) * 4;

	printf("IP len = %d \n", IP_len);

	if(pkt_iphdr->protocol != 6){
		printf("This is not a tcp packet\n");
		return 1;
	}

	pkt_tcphdr = pkt + IP_len;
	int TCP_len = ((pkt_tcphdr->flag) & 0xF0) / 4;

	printf("TCP len = %d \n",TCP_len);
	
	int HTTP_len = size - IP_len - TCP_len;	
	printf("HTTP len = %d\n",HTTP_len);	

	if(HTTP_len == 0){
		printf("No tcp data\n");
		return 1;
	}

	uint8_t* http_pkt = pkt + IP_len + TCP_len;

	int i = 0;
	for(i = 0; i < 6; ++i){
		if(memcmp(HTTP_METHOD[i], http_pkt, strlen(HTTP_METHOD[i])) != 0)
			break;
	}

	if(i == 6){
		printf("this is not http packet\n");
		return 1;
	}
	
	dump(pkt, size);
	
	int indexOfHost = 0;
	while(http_pkt[indexOfHost] != 0xd || http_pkt[indexOfHost + 1] != 0xa || memcmp(http_pkt + indexOfHost + 2, "Host", 4) != 0){
		indexOfHost++;
		if(indexOfHost == HTTP_len - 5){
			printf("NO host\n");
			return 1;
		}
	}
	if(memcmp(host_url, http_pkt + indexOfHost + 8, strlen(host_url)) == 0){
		printf("Block the this output\n");
		return 0;
	}
	return 1;
}

static cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data1)
{	
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(nfa);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(nfa);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(nfa);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(nfa);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(nfa);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(nfa);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(nfa, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	int flag_pkt = check_pkt(data, ret);
	int real_ret;
	printf("entering callback\n");

	if(flag_pkt == 0){
		real_ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else{
		real_ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	fputc('\n', stdout);
	
	return real_ret;
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

    if(argc != 2){
        printf("input wrong\n");
        return -1;
    }

    host_url = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
