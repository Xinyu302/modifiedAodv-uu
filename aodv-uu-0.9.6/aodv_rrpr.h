#ifndef _AODV_RRPR_H
#define _AODV_RRPR_H

#ifndef NS_NO_GLOBALS
#include "defs.h"
#include "routing_table.h"
/* RREQ Flags: */
#define RRPR_JOIN          0x1
#define RRPR_REPAIR        0x2
#define RRPR_GRATUITOUS    0x4
#define RRPR_DEST_ONLY     0x8

typedef struct {
    u_int8_t type;
#if defined(__LITTLE_ENDIAN)
    u_int8_t res1:4;
    u_int8_t d:1;
    u_int8_t g:1;
    u_int8_t r:1;
    u_int8_t j:1;
#elif defined(__BIG_ENDIAN)
    u_int8_t j:1;		/* Join flag (multicast) */
    u_int8_t r:1;		/* Repair flag */
    u_int8_t g:1;		/* Gratuitous RREP flag */
    u_int8_t d:1;		/* Destination only respond */
    u_int8_t res1:4;
#else
#error "Adjust your <bits/endian.h> defines"
#endif
    u_int8_t res2;
    u_int8_t hcnt;
    u_int32_t rrpr_id;
    u_int32_t dest_addr;
    u_int32_t dest_seqno;
    u_int32_t orig_addr;
    u_int32_t orig_seqno;
} RRPR;
typedef struct {
    u_int32_t dest_addr;
    u_int32_t dest_seqno;
} RRPR_udest;

#define RRPR_SIZE sizeof(RRPR)
#define RRPR_UDEST_SIZE sizeof(RRPR_udest)

#define RRPR_CALC_SIZE(rrpr) (RRPR_SIZE + (rrpr->dest_count)*RRPR_UDEST_SIZE) //这里和rreq 不同

#define RRPR_UDEST_FIRST(rrpr) (RRPR_udest *)((char*)(rrpr)+RRPR_SIZE)

#define RRPR_UDEST_NEXT(udest) ((RRPR_udest *)((char *)udest + RRPR_UDEST_SIZE))

#define RRPR_SIZE sizeof(RRPR)

/* A data structure to buffer information about received RREQ's */
struct rrpr_record {
    list_t l;
    struct in_addr orig_addr;	/* Source of the RREQ */
    u_int32_t rreq_id;		/* RRPR's broadcast ID */
    struct timer rec_timer;


    struct in_addr src_addr;

};

struct blacklist_rrpr {
    list_t l;
    struct in_addr dest_addr;
    struct timer bl_timer;
};
#endif				/* NS_NO_GLOBALS */

#ifndef NS_NO_DECLARATIONS

RRPR *rrpr_create(u_int8_t flags, int dest_addr, u_int32_t dest_seqno, int orig_addr);
void rrpr_send(struct in_addr dest_addr, u_int32_t dest_seqno, int ttl, u_int8_t flags);
void rrpr_forward(RRPR * rreq, int size, int ttl);
void rrpr_process(RRPR * rreq, int rreqlen, struct in_addr ip_src, struct in_addr ip_dst, int ip_ttl, unsigned int ifindex);
void rrpr_route_discovery(struct in_addr dest_addr, u_int8_t flags, struct ip_data *ipd);
void rrpr_record_timeout(void *arg);
void rrpr_blacklist_timeout(void *arg);

void  rrpr_add_udest(RRPR * rrpr, struct in_addr udest,
                             u_int32_t udest_seqno)
{
    RRPR_udest *ud;

    ud = (RRPR_udest *) ((char *)rrpr + RRPR_CALC_SIZE(rrpr));
    ud->dest_addr = udest.s_addr;
    ud->dest_seqno = htonl(udest_seqno);
    rrpr->dest_count++;
    fprintf(stderr,"add udest:dest_addr:%s,dest_seqno:%d\n",ip_to_str(udest),udest_seqno);
}

void rrpr_local_repair(rt_table_t * rt, struct in_addr src_addr,
                       struct ip_data *ipd);




#ifdef NS_PORT
struct rrpr_record *rrpr_record_insert(struct in_addr orig_addr,
				       u_int32_t rreq_id,struct in_addr src_addr);
struct rrpr_record *rrpr_record_find(struct in_addr orig_addr,
				     u_int32_t rreq_id , struct in_addr src_addr);
struct blacklist *rrpr_blacklist_find(struct in_addr dest_addr);
#endif				/* NS_PORT */


#endif /* NS_NO_DECLARATIONS */

#endif //NS_2_35_AODV_RRPR_H
