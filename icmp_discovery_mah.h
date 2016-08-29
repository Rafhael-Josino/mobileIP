#ifndef ICMP_DISCOVERY_MAH_
#define ICMP_DISCOVERY_MAH_
#define	ICMP_ROUTERADVERT	9	/* router advertisement */
#define	ICMP_ROUTERSOLICIT	10	/* router solicitation */
#define MOBILITY_EXTENSION	16	/* mobility agent advertisement
					   extension */
struct icmp_ra_addr_mah
{
  u_int32_t ira_addr;
  u_int32_t ira_preference;
};

struct icmp_mah
{
  u_int8_t  icmp_type;	/* type of message, see below */
  u_int8_t  icmp_code;	/* type sub code */
  u_int16_t icmp_cksum;	/* ones complement checksum of struct */
	
  struct ih_rtradv
  {
      u_int8_t irt_num_addrs;
      u_int8_t irt_wpa;
      u_int16_t irt_lifetime;
  }ih_rtradv;

  struct icmp_ra_addr_mah id_radv;
};

struct icmp_sol
{
  u_int8_t  icmp_type;	/* type of message, see below */
  u_int8_t  icmp_code;	/* type sub code */
  u_int16_t icmp_cksum;	/* ones complement checksum of struct */
  u_int32_t icmp_reserved;
};

//-----------------------------------------------------------------
  
struct agnt_adv_CoA
{  
  u_int32_t care_of_addr;
};

struct adv_ext
{
  u_int8_t  advt_type;
  u_int8_t  advt_length;
  u_int16_t advt_seq_num;
  u_int16_t advt_reg_lifetime;
  unsigned char advt_flags;
  u_int8_t advt_reserved;

  struct agnt_adv_CoA advt_CoA;
};

struct pref_num_length
{
  u_int8_t net_length;
};

struct pref_num
{
  u_int8_t pref_type;
  u_int8_t pref_length;
  
  struct pref_num_length pref_netLength;
};

struct padding
{
  u_int8_t byte_padding;
};
#endif
