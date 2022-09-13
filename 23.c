#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define SNAP_LEN 1518

#define SIZE_ETHERNET 14

#define ETHER_ADDR_LEN	6


void MailKeywordSearch(const u_char*, const struct pcap_pkthdr* );


/* Ethernet header */
struct Ethernet_Header
{
        u_char  ether_dhost[ETHER_ADDR_LEN];  /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];  /* source host address */
        u_short ether_type;                   /* IP? ARP? RARP? etc */
};

/* IP header */
struct IPv4
{
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_checksum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


void my_callback(u_char *useless, const struct pcap_pkthdr* packetHeader, const u_char* packet)
{ 
  

  
  static int packet_count=1;
  
  printf("\n \nI Received Packet Number %d\n", packet_count++);
 
  const struct Ethernet_Header *ethernet;
  ethernet = (struct Ethernet_Header*)(packet);
  

  printf("Ethernet Type of This Packet is %x", ethernet->ether_type);
  if(ethernet->ether_type==8)
  { 
     printf("\nThis is an IPv4 Packet: \n");
     MailKeywordSearch(packet, packetHeader);
  }
  if(ethernet->ether_type==0x0806)
  {
     printf("\nThis is an ARP Packet");
  }
  if(ethernet->ether_type==0x86DD)
   {
     printf("\nThis is an IPv6 Packet");
   }
}




void MailKeywordSearch(const u_char* packet, const struct pcap_pkthdr* packetHeader)
{ 
  

  const struct  IPv4 *ip;
  ip = (struct IPv4*)(packet + SIZE_ETHERNET);
  int size_ip = IP_HL(ip)*4;
  char payloadcheck[packetHeader->len];
  int checkindex=0;
  
  int i;
  
  
  
printf("\nPrinting payload\n");
for(i=0;i<packetHeader->len;i++) { 
        if(isprint(packet[i]))
        {              
            printf("%c ", packet[i]); 
            payloadcheck[checkindex] = packet[i];
            checkindex++;
            
        }
        else
        printf(" . ",packet[i]);                  
        if((i%16==0 && i!=0) || i==packetHeader->len-1) 
            printf("\n"); 
    }
    
char sender[20]= "Buchanan";
char recipient[20]="DI";
    
 if(strstr(payloadcheck,"HELO") || strstr(payloadcheck,"EHLO") || strstr(payloadcheck,"helo") || strstr(payloadcheck,"ehlo") || strstr(payloadcheck, sender) || strstr(payloadcheck, recipient)!= NULL)
 {   
     printf("Email Content Matching:\n");
     printf("Keyword Found:%s \n", payloadcheck);
     printf("\nSource IP Address of this Packet is: %s\n", inet_ntoa(ip->ip_src));
     printf("\nDestination IP Address of this Packet is: %s\n", inet_ntoa(ip->ip_dst));
 }
    
 else
 {
    printf("The given keyword was not found\n");
 }
    
  
  printf("\n");
  }
  





int main(int argc, char *argv[])
{
  pcap_t* handler;
  char errbuf[PCAP_ERRBUF_SIZE];
  
  printf("File Name Entered is: %s\n", argv[1] );
  handler=pcap_open_offline(argv[1], errbuf);
  if(handler==NULL)
  {
    printf("Error Opening PCAP File %s", argv[1]);
    exit(1);
  }
  
  pcap_loop(handler, -1, my_callback,NULL);
  return(0);
}
