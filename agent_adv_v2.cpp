#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include "socket_reb.h"
#include "icmp_discovery_mah.h"

int main (int argc, char **argv)
{
  if (argc < 2){
    printf("usage: %s <destination IP>\n", argv[0]); // Se não houver o parâmetro de IP finaliza programa
    return 0;
  }

  unsigned int daddr = inet_addr(argv[1]);
  // transforma o segundo parametro no formato de endereço de IP
  // para router advertir todos os hosts ligados a este router, estuda-se usar o daddr sendo 224.0.0.1 (rfc1112) 
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); //Cria file descriptor do socket

  if (sockfd < 0){ //Verifica criação do file descriptor
    perror("could not create socket");
    return 0;
  }

  int on = 1;//Variável auxiliar na definição de opções
  //Seleciona opção HDRINCL, que significa que o header IP estará incluso no pacote
  //For receiving, the IP header is always include in the packet
  if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on)) == -1){
    perror("setsockopt");
    return 0;
  }

  //source ip
  struct ifreq ifr;//interface usada para configurar network devices
  ifr.ifr_addr.sa_family = AF_INET;//Usaremos a estrutura if_addr dentro da estrutura ifreq

  strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ-1);
  //strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ-1);// Obtém o IP local
  /*ioctl():manipulates the underlying device parameters of specias files
  Its first argument must be a file descriptor, like sockfd in this case
  Second argument a device-pedendent request code
  Third an untyped pointer to memory*/ 
  ioctl(sockfd, SIOCGIFADDR, &ifr);
  //2 arg: get or set address of device using ifr_name. Only with AF_INET
  printf("source IP: %s\n", inet_ntoa(((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr));

  //iphdr >> ja existe
  unsigned int packet_size = sizeof (struct iphdr) + sizeof (struct icmp_mah) + sizeof (struct adv_ext);
	printf("Tamanho do:\n\tiphdr:\t%lu\n\ticmp:\t%lu\n\tagnt adv ext:\t%lu\n",sizeof(struct iphdr),sizeof(struct icmp_mah),sizeof(struct adv_ext));
  //Define tamanho do pacote
  char* packet = (char*) malloc(packet_size);//Aloca espaço para o pacote
					     //Posicao zero	

  //Cria ponteiros das estruturas utilizadas no pacote e ajusta suas localizações
  struct iphdr* ip = (struct iphdr*) packet;//posicao 0
  struct icmp_mah* icmp_adv = (struct icmp_mah*) (packet + sizeof(struct iphdr));//posicao 0 + ip
  struct adv_ext* ext = (struct adv_ext*) (packet + sizeof(struct iphdr) + sizeof(struct icmp_mah));
  memset(packet, 0, packet_size);//Zera os valores nessa memoria
 
  //unsigned int maxAdvInterval = 600;//Range = 4 - 1800 segundos
  unsigned int maxAdvInterval = 600;//Valor provisorio
 // unsigned int life
  unsigned int minAdvInterval = 0.75*maxAdvInterval;//Range = 3 - maxAdvInterval segundos
  unsigned int N = 1; //Numero de CoAs advertidos
  u_int16_t seq_number = 1;
  unsigned char mobility_extension_flags;
  enum mobility_extension_flags
  {
    R = 0x80,//Registration required
    B = 0x40,//Busy
    H = 0x20,//Home agent
    F = 0x10,//Foreing agent
    M = 0x08,//Minimal encapsulation
    G = 0x04,//Generic Routing Encapsulation (GRE)
    r = 0x02,//bit reservado-> nunca setado
    T = 0x01 //Tunneling reverse
  };
  /*F ou (exclusivo) H tem de estar setados
  Home agent -> nunca pode estar em BUSY
  Busy -> continua mandando advertisements 
  R so esta setado se F estiver setado*/
  
  //ip checksum???
  //onde por a funcao htons()? Apenas em campos com 8 bytes?

  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = htons(packet_size);
  ip->id = 0;
  ip->frag_off = 0;
  ip->ttl = 1; //TTL para todos os agent advertisements deve ser 1
  ip->protocol = IPPROTO_ICMP;
  ip->saddr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
  ip->daddr = daddr;

  icmp_adv->icmp_type = ICMP_ROUTERADVERT;
  icmp_adv->icmp_code = 0;
  icmp_adv->icmp_cksum = 0;
  icmp_adv->ih_rtradv.irt_num_addrs = 1;
  icmp_adv->ih_rtradv.irt_wpa = 2;
  icmp_adv->ih_rtradv.irt_lifetime = htons(2*maxAdvInterval);//Range = maxAdvInterval - 9000 segundos
  icmp_adv->id_radv.ira_addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
  icmp_adv->id_radv.ira_preference = 0;

  ext->advt_type = MOBILITY_EXTENSION;
  ext->advt_length = 6 + 4*N;
  ext->advt_seq_num = htons(seq_number);
  ext->advt_reg_lifetime = htons(65535);//Inf -> 65535 segundos (cerca de 18 horas)
  ext->advt_flags = R | F;
  ext->advt_reserved = 0;
  ext->advt_CoA.care_of_addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;  

  //Estrutura utilizada para endereçamento no envio do pacote (socket RAW) (Estudar essa parte)
  struct sockaddr_in servaddr;
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = daddr;
  memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

  //Calcula o checksum do ICMP
  //icmp->checksum = checksum((unsigned short*)icmp,sizeof(struct icmphdr) + payloadSize);
  //Fazemos um checksum apenas para o icmp_adv?
  icmp_adv->icmp_cksum = checksum((unsigned short*)icmp_adv, sizeof(struct icmp_mah) + sizeof(struct adv_ext));
  
  ip->check = checksum((unsigned short*) packet, packet_size);

  printf("\n\nPacote completo\n");
  printpacket((unsigned char*)packet, packet_size);
  printf("\n\n");
  getchar();   

  clock_t t = clock();//Inicia contagem do tempo para envio do pacote
 
  if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 1)//Envia pacote e verifica envio
  {
    perror("send failed");
    return 0;
  }
  printf("packet sent!\n");
  memset(packet, 0, packet_size);//Inicia pacote

  unsigned int addrlen = 0;
  int bytesrecv = recvfrom(sockfd, packet, packet_size, 0, NULL, &addrlen);//Recebe echo reply
  printf("Tempo: %.2f ms\n", (clock() - t) * 1000.0f / CLOCKS_PER_SEC);//Calcula tempo demorado

  if (bytesrecv < 1){
    perror("recv failed");
    return 0;
  }
  else{
    printf("bytesrecv = %d\n",bytesrecv);
    ip = (struct iphdr*) packet;
    //icmp = (struct icmphdr*) (packet + sizeof(struct iphdr));
    icmp_adv = (struct icmp_mah*) (packet + sizeof(struct iphdr));
    ext = (struct adv_ext*) (packet + sizeof(struct iphdr) + sizeof(struct icmp_mah));
    struct in_addr addr;
    addr.s_addr = ip->saddr;
    printf("received %d bytes reply from %s\n", packet_size, inet_ntoa(addr));
  }

  printf("\n\nPacote completo\n");
  printpacket((unsigned char*)packet, bytesrecv);
  printf("\n\n");

  free(packet);
  close(sockfd);
  return 0;
}
