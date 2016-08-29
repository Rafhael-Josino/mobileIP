//df/IP mobile - Register with Foreing Router code

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
//#include <fstream>
#include "icmp_discovery_mah.h"
#include "socket_reb.h"
#include "udp_register_mah.h"



//---------------------------------------------------------------------

int main (int argc, char **argv)
{
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

  if (sockfd < 0){
    perror("could not create socket");
    return 0;
  }

  int on = 1;

  if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on)) == -1){
    perror("setsockopt");
    return 0;
  }

  //source ip
  struct ifreq ifr;
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ-1);
  ioctl(sockfd, SIOCGIFADDR, &ifr);
  printf("source IP: %s\n", inet_ntoa(((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr));

  unsigned int packet_size = sizeof (struct iphdr) + sizeof (struct icmp_mah) + sizeof (struct adv_ext);
  char* packet = (char*) malloc(packet_size);

  struct iphdr* ip = (struct iphdr*) packet;
  struct icmp_mah* icmp_adv = (struct icmp_mah*) (packet + sizeof(struct iphdr));
  struct adv_ext* ext = (struct adv_ext*) (packet + sizeof(struct iphdr) + sizeof(struct icmp_mah));

  unsigned int addrlen = 0;
  int bytesrecv = recvfrom(sockfd, packet, packet_size, 0, NULL, &addrlen);

  if(bytesrecv < 1)
  {
    perror("recv failed");
    return 0;
  }
  else
  {
    ip = (struct iphdr*) packet;
    icmp_adv = (struct icmp_mah*) (packet + sizeof(struct iphdr));
    ext = (struct adv_ext*) (packet + sizeof(struct iphdr) + sizeof(struct icmp_mah));
  }

  //struct in_addr addr;
  //addr.s_addr = ip->saddr;
  printf("\n\nPacote recebido\n");
  printpacket((unsigned char*)packet, packet_size);

  char* str = (char*)malloc(4);
  printf("\n\nRouter Address: ");
  inet_ntop(AF_INET,&(ip->saddr),str,INET_ADDRSTRLEN);
  printf("%s\n\n",str);
  writetable(str);

  if (ext->advt_flags & 0x80)
    socket_udp(ip->saddr);

  free(packet);
  free(str);
  close(sockfd);
  return 0;
}
