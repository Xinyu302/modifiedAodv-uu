#ifndef _AODV_RRET_H
#define _AODV_RRET_H

#ifndef NS_NO_GLOBALS
#include "defs.h"
#include "routing_table.h"
#include "aodv_rrcq.h"

typedef struct {
    u_int8_t type;

    u_int8_t hcnt;

    u_int32_t lifetime;
    u_int32_t dest_addr;
    u_int32_t dest_seqno;
    u_int32_t orig_addr;
    u_int32_t orig_seqno;

    u_int32_t Cost;
    u_int32_t Channel;
    u_int32_t dest_count;
}RRET ;

typedef struct {
    u_int32_t dest_addr;
    u_int32_t dest_seqno;
} RRET_udest;

#define RRET_SIZE sizeof(RRET)

#define RRET_UDEST_SIZE sizeof(RRET_udest)

#define RRET_CALC_SIZE(rret) (RRET_SIZE + (rret->dest_count)*RRET_UDEST_SIZE) //这里和rreq 不同

#define RRET_UDEST_FIRST(rret) (RRET_udest *)((char*)(rret)+RRET_SIZE)

#define RRET_UDEST_NEXT(udest) ((RRET_udest *)((char *)udest + RRET_UDEST_SIZE))


#endif				/* NS_NO_GLOBALS */




#ifndef NS_NO_DECLARATIONS

RRET* rret_create(RRCQ * rrcq,
                  u_int8_t flags,
                  int hcnt,
                  int cost,
                  u_int32_t life,u_int32_t Channel
                  );

AODV_ext *rret_add_ext(RRET * rret, int type, unsigned int offset,
                       int len, char *data);

void rret_forward(RRET * rret,  int size,rt_table_t* rev_rt,rt_table_t* fwd_rt,int  ttl);
void rret_process(RRET * rret, int rretlen, struct in_addr ip_src,
                  struct in_addr ip_dst, int ip_ttl,
                  unsigned int ifindex);
void rret_send(RRET * rret, rt_table_t * rev_rt, rt_table_t * fwd_rt, int size);

#endif /* NS_NO_DECLARATIONS */

#endif //NS_2_35_AODV_RRET_H
