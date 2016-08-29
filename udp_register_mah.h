#ifndef SOCKET_REGISTER_MAH_
#define SOCKET_REGISTER_MAH_
#define REGISTRATION_REQUEST 1
#define REGISTRATION_REPLY 3

struct reg_req
{
  u_int8_t reg_type;
  unsigned char reg_flags;
  u_int16_t reg_lifetime;
  u_int32_t reg_home_addr;
  u_int32_t reg_home_agnt;
  u_int32_t reg_CoA;
  u_int32_t reg_ident;
};

int socket_udp(u_int32_t daddr)
{
  int sockudp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

  if (sockudp < 0){
    perror("could not create socket");
  }

  struct ifreq ifr;
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ-1);
  ioctl(sockudp, SIOCGIFADDR, &ifr);
  printf("Register to foreing agent:\n");
  printf("source IP: %s\n", inet_ntoa(((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr));

  unsigned int packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct reg_req);
  char* packet = (char*) malloc(packet_size);
  struct iphdr* ip = (struct iphdr*) packet;
  struct udphdr* udp = (struct udphdr*) (packet + sizeof(struct iphdr));
  struct reg_req* reg = (struct reg_req*) (packet + sizeof(struct iphdr) + sizeof(struct udphdr));
  memset(packet,0,packet_size);

  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = htons(packet_size);
  ip->id = 0;
  ip->frag_off = 0;
  ip->ttl = 60;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
  ip->daddr = daddr;

  udp->uh_sport = 0;
  udp->uh_dport = 434;
  udp->uh_ulen = sizeof(struct udphdr) + sizeof(struct reg_req);
  udp->uh_sum = 0xFFFF; //Checksum disabilitado no momento 

  reg->reg_type = REGISTRATION_REQUEST;
  reg->reg_flags = 0; //Flags destativadas no momento
  reg->reg_lifetime = 0xFFFF; //Lifetime infinito no momento
  reg->reg_home_addr = 0; //Descobrir qual será o home addr e como usar
  reg->reg_home_agnt = 0; //Mesmo caso do de cima
  reg->reg_CoA = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
  reg->reg_ident = 42;

  struct sockaddr_in servaddr;
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = daddr;
  memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

  ip->check = checksum((unsigned short*) packet, packet_size);

  printf("\n\nPacote registration request completo\n");
  printpacket((unsigned char*)packet, packet_size);
  printf("\n\n");
  getchar();

  if (sendto(sockudp, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 1)//Envia pacote e verifica envio
  {
    perror("registration request send failed\n");
    return 0;
  }
  printf("packet sent!\n");

  free(packet);
  close(sockudp);
  return 0;
}
#endif 
