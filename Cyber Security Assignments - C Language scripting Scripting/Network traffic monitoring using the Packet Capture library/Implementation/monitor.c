/*
	Packet sniffer using libpcap library
*/
#include<pcap.h>

#include<stdio.h>

#include<stdlib.h> // for exit()

#include<string.h> //for memset

#include<sys/socket.h>

#include <inttypes.h>

#include <netinet/udp.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/cdefs.h>

//Provides declarations for udp header
//Provides declarations for tcp header
//Provides declarations for ip header
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6
//this structures are used to calculate different packet flows of tcp and udp
struct network_flow_tcp {
   char * ip_src_nf; /*destination ip */
   char * ip_dst_nf; /*source host */
   u_short th_sport_nf; /* source port */
   u_short th_dport_nf; /*destination port*/
   u_int th_seq_nf; /*seq number */
   u_int th_ack_nf; /*ack number */
   /* destination port */

};
struct network_flow_udp {
   char * ip_src_nf; /*destination ip */
   char * ip_dst_nf; /*source host */
   u_short th_sport_nf; /* source port */
   u_short th_dport_nf; /* destination port */
   u_int th_seq_nf;
   u_int th_ack_nf;
   /* destination port */

};

struct network_flow_total {
   char * ip_src_nf; /*destination ip */
   char * ip_dst_nf; /*source host */
   u_short th_sport_nf; /* source port */
   u_short th_dport_nf; /* destination port */
   u_int th_seq_nf;
   u_int th_ack_nf;
   /* destination port */

};
/* Ethernet header */
struct sniff_ethernet {
   u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
   u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
   u_short ether_type;
   /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
   u_char ip_vhl; /* version << 4 | header length >> 2 */
   u_char ip_tos; /* type of service */
   u_short ip_len; /* total length */
   u_short ip_id; /* identification */
   u_short ip_off; /* fragment offset field */
   #define IP_RF 0x8000 /* reserved fragment flag */
   #define IP_DF 0x4000 /* dont fragment flag */
   #define IP_MF 0x2000 /* more fragments flag */
   #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
   u_char ip_ttl; /* time to live */
   u_char ip_p; /* protocol */
   u_short ip_sum; /* checksum */
   struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)(((ip) -> ip_vhl) & 0x0f)
#define IP_V(ip)(((ip) -> ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
   u_short th_sport; /* source port */
   u_short th_dport; /* destination port */
   tcp_seq th_seq; /* sequence number */
   tcp_seq th_ack; /* acknowledgement number */
   u_char th_offx2; /* data offset, rsvd */
   #define TH_OFF(th)(((th) -> th_offx2 & 0xf0) >> 4)
   u_char th_flags;
   #define TH_FIN 0x01
   #define TH_SYN 0x02
   #define TH_RST 0x04
   #define TH_PUSH 0x08
   #define TH_ACK 0x10
   #define TH_URG 0x20
   #define TH_ECE 0x40
   #define TH_CWR 0x80
   #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
   u_short th_win; /* window */
   u_short th_sum; /* checksum */
   u_short th_urp; /* urgent pointer */
};
/* TCP header */
typedef u_int tcp_seq;

/* UDP protocol header. */
struct sniff_udp {
   u_short uh_sport; /* source port */
   u_short uh_dport; /* destination port */
   u_short uh_ulen; /* udp length */
   u_short uh_sum; /* udp checksum */
};

void process_packet(u_char * ,
   const struct pcap_pkthdr * ,
      const u_char * );

void PrintData(const u_char * , int);

struct network_flow_tcp nf_tcp[1000000];
struct network_flow_udp nf_udp[1000000];
struct network_flow_total nf_total[1000000];

int tcp_bytes = 0;
int udp_bytes = 0;
int count_nf_tcp = 0;
int count_nf_udp = 0;
int count_nf_total = 0;
int tcpCount = 0;
int udpCount = 0;
int packet_num = 0;
int count_retransmissions = 0;
FILE * logfile;
struct sockaddr_in source, dest;

u_char * arr;
int tcp = 0, udp = 0, others = 0, igmp = 0, total = 0, i, j;

void function_exit() {
   printf("\nTotal number of network flows captured:%d", count_nf_tcp + count_nf_udp);
   printf("\nNumber of TCP network flows captured:%d", count_nf_tcp);
   printf("\nNumber of UDP network flows captured:%d", count_nf_udp);
   printf("\nTotal number of packets recieved:%d", packet_num);
   printf("\nNumber of TCP packets recieved:%d", tcpCount);
   printf("\nNumber of UDP packets recieved:%d", udpCount); 
   
   printf("\nTotal number of tcp bytes recieved :%d", tcp_bytes);
   printf("\nTotal number of udp bytes recieved:%d\n", udp_bytes);
   exit(0);
}

int main(int argc, char **argv) {
         
     
      
      if(argc==3){
        char * pcap_name;
        if(strcmp(argv[1],"-f")==0 && strlen(argv[2])!=0)
        {
                
               int size = strlen(argv[2]);
                pcap_name = (char *)malloc(size);
               strcpy(pcap_name,argv[2]);
              // printf("Pcap is %s",pcap_name);
                  pcap_t * handle;

                  char errbuf[100];
        
                  handle = pcap_open_offline(pcap_name, errbuf);
                  free(pcap_name);
                  pcap_loop(handle, 0, process_packet, NULL);

                  atexit(function_exit);
                  return 0;
                
        }
        else if(strcmp(argv[1],"-h")==0)
        {
                printf("\nHelp menu");
                printf("\n Enter -f flag followd by  pcap file name to monitor an input pcap file \n");
                
        }
        else{
                printf("\nEnter only -f or -h");
        }
 }
 else{
         printf("\nError");
         printf("\nEnter one of the flags below");
         printf("\n-f pcap file name");
         printf("\n-h help message\n");
 }
 
}

void process_packet(u_char * args,
   const struct pcap_pkthdr * header,
      const u_char * packet) {
   int found = 0;
   packet_num++;
   printf("\nPacket information:");
   printf("\n-----------------------------");

 
   const struct sniff_ip * ip; /* The IP header */
   const struct sniff_tcp * tcp; /* The TCP header */
   const struct sniff_udp * udp; /* The UDP header */
   
   /* Packet payload */

   int size_ip;
   int size_tcp;
   int size_udp;
   int size_payload;
 struct servent *appl_name;
  struct servent *appl_name1;
   /* Find start of IP header (1st LAYER is Ethernet)*/
   ip = (struct sniff_ip * )(packet + SIZE_ETHERNET);
   size_ip = IP_HL(ip) * 4;
   if (size_ip < 20) {
      printf("\nInvalid IP header length: %u bytes", size_ip);
      return;
   }

  
   int ip_header_length = (( * (packet + SIZE_ETHERNET)) & 0x0F);
   ip_header_length = ip_header_length * 4;
 
   u_char protocol = * ((packet + SIZE_ETHERNET) + 9);

   if ((protocol != IPPROTO_TCP) && (protocol != IPPROTO_UDP)) {
      printf("\nNot a TCP or UDP packet. Skipping...");
      return;
   }
   

   if ((protocol == IPPROTO_TCP)) 
   {
      tcpCount++;
       tcp = (struct sniff_tcp * )(packet + SIZE_ETHERNET + size_ip);

      for (int i = 0; i < count_nf_tcp; i++) 
      {
           
              
         if (strcmp(nf_tcp[i].ip_dst_nf, inet_ntoa(ip -> ip_dst)) == 0 &&
               strcmp(nf_tcp[i].ip_src_nf, inet_ntoa(ip -> ip_src)) == 0 &&
               nf_tcp[i].th_sport_nf ==tcp->th_sport &&
               nf_tcp[i].th_dport_nf == tcp -> th_dport) {
                       
     
            if (ntohs(tcp -> th_seq) > ntohs(nf_tcp[i].th_seq_nf)) {
               nf_tcp[i].th_seq_nf = tcp -> th_seq;

            } else {
               count_retransmissions++;
               printf("\nRetransmitted packet");  
            }
           found = 1;
         }

      }

    
      printf("\nSrc ip: %s", inet_ntoa(ip -> ip_src));
      printf("\nDst ip: %s", inet_ntoa(ip -> ip_dst));


      size_tcp = TH_OFF(tcp) * 4;
      if (size_tcp < 20) {
         printf("\n   * Invalid TCP header length: %u bytes", size_tcp);
         return;
      }

      printf("\nSrc port: %d", ntohs(tcp -> th_sport));
      printf("\nDst port: %d", ntohs(tcp -> th_dport));
      

      printf("\nProtocol: TCP");
      appl_name = getservbyport(tcp->th_sport,"tcp");
      appl_name1 = getservbyport(tcp->th_dport,"tcp");
    if(appl_name)
    {
      if(appl_name->s_name)
     printf("\nUpper layer protocols: %s \n",appl_name->s_name);
     
    }
  if(appl_name1)
  {
   if(appl_name1->s_name)
    printf("\nUpper layer protocols: %s \n",appl_name1->s_name);

  } 

   
      printf("\nTCP header length in bytes:%u ", size_tcp);

     
      size_payload = ntohs(ip -> ip_len) - (size_ip + size_tcp);
      printf("\nPayload length in bytes: %d\n", size_payload);
    
      tcp_bytes+=header->len;

      

      if (found == 0) {
         nf_tcp[count_nf_tcp].ip_src_nf = malloc(sizeof(inet_ntoa(ip -> ip_src)));
         nf_tcp[count_nf_tcp].ip_dst_nf = malloc(sizeof(inet_ntoa(ip -> ip_dst)));
         strcpy(nf_tcp[count_nf_tcp].ip_src_nf, inet_ntoa(ip -> ip_src));
         strcpy(nf_tcp[count_nf_tcp].ip_dst_nf, inet_ntoa(ip -> ip_dst));
         
         nf_tcp[count_nf_tcp].th_sport_nf = tcp -> th_sport;
         nf_tcp[count_nf_tcp].th_dport_nf = tcp -> th_dport;
         nf_tcp[count_nf_tcp].th_seq_nf = tcp -> th_seq;
         nf_tcp[count_nf_tcp].th_ack_nf = tcp -> th_ack;
        // found = 0;
         count_nf_tcp++;
      }

   }
   if ((protocol == IPPROTO_UDP)) 
   {
      udpCount++;

      printf("\nSrc ip: %s", inet_ntoa(ip -> ip_src));
      printf("\nDst ip: %s", inet_ntoa(ip -> ip_dst));

      udp = (struct sniff_udp * )(packet + SIZE_ETHERNET + size_ip);

      size_udp = ntohs(udp -> uh_ulen);

      int size_payload = ntohs(ip -> ip_len) - (size_ip + 8);
      int udp_header_length = size_udp - size_payload;

      printf("\nSrc port: %d", ntohs(udp -> uh_sport));
      printf("\nDst port: %d", ntohs(udp -> uh_dport));

    
    
      printf("\nProtocol: UDP");
      
      appl_name = getservbyport(udp->uh_sport,"udp");
      appl_name1 = getservbyport(udp->uh_dport,"udp");
     if(appl_name)
    {
     if(appl_name->s_name)
     {
        printf("\nUpper layer protocols: %s \n",appl_name->s_name);
     }

    }
  else if(appl_name1)
  {
if(appl_name1->s_name)
{
        printf("\nUpper layer protocols: %s \n",appl_name1->s_name);
        
}
    
  } 

      printf("\nUDP header length length in bytes:%d", udp_header_length);

      printf("\nUDP payload length in bytes:%d\n", size_payload);
      udp_bytes += header->len;

      for (int i = 0; i <= count_nf_udp; i++) {

         if (nf_udp[i].ip_dst_nf != NULL &&
            nf_udp[i].ip_src_nf != NULL &&
            nf_udp[i].th_sport_nf != 0 &&
            nf_udp[i].th_dport_nf != 0
         ) {

            if (

               (strcmp(nf_udp[i].ip_dst_nf, inet_ntoa(ip -> ip_dst)) == 0 &&
                  strcmp(nf_udp[i].ip_src_nf, inet_ntoa(ip -> ip_src)) == 0 &&
                  nf_udp[i].th_sport_nf == ntohs(udp -> uh_sport) &&
                  nf_udp[i].th_dport_nf == ntohs(udp -> uh_dport))

            ) {

               found = 1;

            }
         }

      }

      if (found == 0) {

         nf_udp[count_nf_udp].ip_src_nf = malloc(sizeof(inet_ntoa(ip -> ip_src)));
         nf_udp[count_nf_udp].ip_dst_nf = malloc(sizeof(inet_ntoa(ip -> ip_dst)));
         strcpy(nf_udp[count_nf_udp].ip_src_nf, inet_ntoa(ip -> ip_src));
         strcpy(nf_udp[count_nf_udp].ip_dst_nf, inet_ntoa(ip -> ip_dst));
         nf_udp[count_nf_udp].th_sport_nf = ntohs(udp -> uh_sport);
         nf_udp[count_nf_udp].th_dport_nf = ntohs(udp -> uh_dport);

         found = 0;
         count_nf_udp++;

      }

   }

}
        
        
        
