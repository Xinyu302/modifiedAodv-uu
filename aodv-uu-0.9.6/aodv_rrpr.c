//
// copy adov_rreq
//

#ifdef NS_PORT
#include "ns-2/aodv-uu.h"
#else
#include <netinet/in.h>

#include "aodv_rreq.h"
#include "aodv_rrep.h"
#include "routing_table.h"
#include "aodv_timeout.h"
#include "timer_queue.h"
#include "aodv_socket.h"
#include "params.h"
#include "seek_list.h"
#include "defs.h"
#include "debug.h"

#include "locality.h"

#include "aodv_rrpr.h"
#include "aodv_rret.h"
#endif

/* Comment this to remove packet field output: */

#define DEBUG_OUTPUT

#ifndef NS_PORT
static LIST(rrpr_records);
static LIST(rrpr_blacklist);
static struct rrpr_record *rrpr_record_insert(struct in_addr orig_addr,       u_int32_t rreq_id,struct in_addr src_addr);
static struct rrpr_record *rrpr_record_find(struct in_addr orig_addr,    u_int32_t rreq_id,struct in_addr src_addr);

struct blacklist *rrpr_blacklist_find(struct in_addr dest_addr);

#endif

struct blacklist *NS_CLASS rrpr_blacklist_find(struct in_addr dest_addr)
{
    list_t *pos;

    list_foreach(pos, &rrpr_blacklist) {
        struct blacklist *bl = (struct blacklist *) pos;

        if (bl->dest_addr.s_addr == dest_addr.s_addr)
            return bl;
    }
    return NULL;
}

NS_STATIC struct rrpr_record *NS_CLASS rrpr_record_insert(struct in_addr orig_addr,
							  u_int32_t rreq_id,
                                                          struct in_addr src_addr)
{
    struct rrpr_record *rec;

    rec = rrpr_record_find(orig_addr, rreq_id,src_addr);

    if (rec)
        return rec;

    if ((rec =
                 (struct rrpr_record *) malloc(sizeof(struct rrpr_record))) == NULL) {
        fprintf(stderr, "Malloc failed!!!\n");
        exit(-1);
    }
    rec->orig_addr = orig_addr;
    rec->rreq_id = rreq_id;
    rec->src_addr = src_addr;
    timer_init(&rec->rec_timer, &NS_CLASS rrpr_record_timeout, rec);

    list_add(&rrpr_records, &rec->l);

    DEBUG(LOG_INFO, 0, "Buffering RRPR %s rreq_id=%lu time=%u",
          ip_to_str(orig_addr), rreq_id, PATH_DISCOVERY_TIME);

    timer_set_timeout(&rec->rec_timer, PATH_DISCOVERY_TIME);
    return rec;
}

NS_STATIC struct rrpr_record *NS_CLASS rrpr_record_find(struct in_addr
                                                        orig_addr,
                                                        u_int32_t rreq_id,struct in_addr src_addr)
{
    list_t *pos;

    list_foreach(pos, &rrpr_records) {
        struct rrpr_record *rec = (struct rrpr_record *) pos;
        if (rec->orig_addr.s_addr == orig_addr.s_addr &&
            (rec->rreq_id == rreq_id) &&(rec->src_addr.s_addr == src_addr.s_addr))
            return rec;
    }
    return NULL;
}


RRPR *NS_CLASS rrpr_create(u_int8_t flags, int dest_addr, u_int32_t dest_seqno, int orig_addr)
{
    RRPR *rrpr;

    rrpr = (RRPR *) aodv_socket_new_msg();
    rrpr->type = AODV_RRPR;
    rrpr->res1 = 0;
    rrpr->res2 = 0;
    rrpr->hcnt = 0;
    rrpr->rrpr_id = htonl(this_host.rreq_id++);

    rrpr->dest_seqno = htonl(dest_seqno);

    /* Immediately before a node originates a RREQ flood it must
       increment its sequence number... */
    seqno_incr(this_host.seqno);
    rrpr->orig_seqno = htonl(this_host.seqno);

    rrpr->dest_addr = dest_addr;
    rrpr->orig_addr = orig_addr;

    /// because we know it is a repair message, we have no need to set flags
    rrpr->j = 1;
    rrpr->r = 1;
    rrpr->g = 1;
    rrpr->d = 1;

    fprintf(stderr,"---------------This is the rrpr_create!--------------\n");

#ifdef DEBUG_OUTPUT
    log_pkt_fields((AODV_msg *) rrpr);
#endif

    return rrpr;
}
void NS_CLASS rrpr_send(struct in_addr dest_addr, u_int32_t dest_seqno, int ttl, u_int8_t flags)
{
    fprintf(stderr,"---------------This is the rrpr_send!--------------\n");
    RRPR *rrpr;

    rt_table_t * rt, *rt_dest_addr;
    //u_int32_t dest_seqno;
    struct in_addr dest, orig_addr;
    int i;
    seek_list_t *seek_entry;

    rt_dest_addr = rt_table_find(dest_addr);   //找到路由表上的item
    //dest_seqno = rt_dest_addr->dest_seqno;

    dest.s_addr = AODV_BROADCAST;

    //find current ip
    for (i = 0; i < MAX_NR_INTERFACES; i++) {
        if (DEV_NR(i).enabled) {
            orig_addr = DEV_NR(i).ipaddr;
            break;
        }
    }
    rrpr = rrpr_create(flags, dest_addr.s_addr, dest_seqno, orig_addr.s_addr);



    for (i = 0; i < RT_TABLESIZE; i++) {
        list_t *pos;
        list_foreach(pos, &rt_tbl.tbl[i]) {    //refer to routing_table.c
            rt = (rt_table_t *) pos;

            if ( !seek_list_find(rt->dest_addr) &&
                 rt->next_hop.s_addr == rt_dest_addr->dest_addr.s_addr &&
                 rt->dest_addr.s_addr != rt_dest_addr->dest_addr.s_addr)


                rt->flags |= RT_REPAIR;  //repair
                rt_table_invalidate(rt);

                DEBUG(LOG_DEBUG, 0,
                      "  %s  REPAIR",
                      ip_to_str(rt->dest_addr));
                fprintf(stderr,
                  "  %s  REPAIR",
                  ip_to_str(rt->dest_addr));
                /* If the link that broke are marked for repair,
                   then do the same for all additional unreachable
                   destinations. */



            rrpr_add_udest(rrpr, rt->dest_addr,
                           rt->dest_seqno);

            }
        }
    fprintf(stderr,
            " rrpr_udest_count is %d\n",
            rrpr->dest_count);

    for (i = 0; i < MAX_NR_INTERFACES; i++) {
        if (!DEV_NR(i).enabled)
            continue;
        aodv_socket_send((AODV_msg *) rrpr, dest, RRPR_CALC_SIZE(rrpr),
                         ttl, &DEV_NR(i));
    }
}

void NS_CLASS rrpr_forward(RRPR * rrpr, int size, int ttl)
{
    struct in_addr dest, orig;
    int i;

    dest.s_addr = AODV_BROADCAST;
    orig.s_addr = rrpr->orig_addr;

    /* FORWARD the RRPR if the TTL allows it. */
    DEBUG(LOG_INFO, 0, "forwarding RRPR src=%s, rrpr_id=%lu",
          ip_to_str(orig), ntohl(rrpr->rrpr_id));
    fprintf(stderr, "forwarding RRPR src=%s, rrpr_id=%lu\n",
          ip_to_str(orig), ntohl(rrpr->rrpr_id));
    /* Queue the received message in the send buffer */
    rrpr = (RRPR *) aodv_socket_queue_msg((AODV_msg *) rrpr,
                                           (int)RRPR_CALC_SIZE(rrpr));

    rrpr->hcnt++;		/* Increase hopcount to account for
				 * intermediate route */

    /* Send out on all interfaces */
    for (i = 0; i < MAX_NR_INTERFACES; i++) {
        if (!DEV_NR(i).enabled)
            continue;
        aodv_socket_send((AODV_msg *) rrpr, dest,
                         (int)RRPR_CALC_SIZE(rrpr), ttl, &DEV_NR(i));
    }
}
void NS_CLASS rrpr_process(RRPR * rrpr, int rrprlen, struct in_addr ip_src, struct in_addr ip_dst, int ip_ttl, unsigned int ifindex)
{
    AODV_ext *ext;
    /*RRCP *rrcp = NULL;
    RRCP_udest *udest;*/
    int rrpr_size = RRPR_CALC_SIZE(rrpr);
    rt_table_t *rev_rt = NULL, *fwd_rt = NULL;
    u_int32_t rrpr_orig_seqno, rrpr_dest_seqno;
    u_int32_t rrpr_id, rrpr_new_hcnt, life;
    //unsigned int extlen = 0;
    struct in_addr rrpr_dest, rrpr_orig;


    u_int32_t rrpr_Cost,rrpr_Channel;


    rrpr_dest.s_addr = rrpr->dest_addr;
    rrpr_orig.s_addr = rrpr->orig_addr;
    rrpr_id = ntohl(rrpr->rrpr_id);
    rrpr_dest_seqno = ntohl(rrpr->dest_seqno);
    rrpr_orig_seqno = ntohl(rrpr->orig_seqno);
    rrpr_new_hcnt = rrpr->hcnt + 1;

    rrpr_Channel = rrpr->Channel;
    rrpr_Cost = rrpr->Cost + nb_table_find(ip_src, rrpr_Channel, true)->cost;

    if (rrpr_orig.s_addr == DEV_IFINDEX(ifindex).ipaddr.s_addr)
        return;
    DEBUG(LOG_DEBUG, 0, "ip_src=%s rrpr_orig=%s rrpr_dest=%s ttl=%d",
          ip_to_str(ip_src), ip_to_str(rrpr_orig), ip_to_str(rrpr_dest),
          ip_ttl);
    ///add by BUAA_Yxy
    fprintf(stderr, "ip_src=%s rrpr_orig=%s rrpr_dest=%s ttl=%d\n",
          ip_to_str(ip_src), ip_to_str(rrpr_orig), ip_to_str(rrpr_dest),
          ip_ttl);
    ///add by  BUAA_Yxy
    if (rrprlen < (int)RRPR_CALC_SIZE(rrpr)) {
        alog(LOG_WARNING, 0, __FUNCTION__,
             "IP data too short (%u bytes) from %s to %s. Should be %d bytes.",
             rrprlen, ip_to_str(ip_src), ip_to_str(ip_dst),
             RRPR_CALC_SIZE(rrpr));

        return;
    }

    if (rrpr_blacklist_find(ip_src)) {
        DEBUG(LOG_DEBUG, 0, "prev hop of RRPR blacklisted, ignoring!");
        return;
    }


    /* Ignore already processed RREQs. */
    if (rrpr_record_find(rrpr_orig, rrpr_id,ip_src))
        return;

    /* Now buffer this RRPR so that we don't process a similar RRPR we
       get within PATH_DISCOVERY_TIME. */
    rrpr_record_insert(rrpr_orig, rrpr_id,ip_src);


    struct timeval now;
    gettimeofday(&now,NULL);

#ifdef DEBUG_OUTPUT
    log_pkt_fields((AODV_msg *) rrpr);
#endif


    /* The node always creates or updates a REVERSE ROUTE entry to the
       source of the RREQ. */
    rev_rt = rt_table_find(rrpr_orig);

    /* Calculate the extended minimal life time. */
    life = PATH_DISCOVERY_TIME - 2 * rrpr_new_hcnt * NODE_TRAVERSAL_TIME;


    if (rev_rt == NULL) {
        DEBUG(LOG_DEBUG, 0,
              "Creating REVERSE route entry, RRPR orig: %s",
              ip_to_str(rrpr_orig));

        rev_rt = rt_table_insert(rrpr_orig, ip_src, rrpr_new_hcnt, rrpr_orig_seqno, life,
				INVALID, 0,ifindex,rrpr_Channel,rrpr_Cost);//here to increase
    } else {
        if (rev_rt->dest_seqno == 0 ||
            (int32_t) rrpr_orig_seqno > (int32_t) rev_rt->dest_seqno ||
            (rrpr_orig_seqno == rev_rt->dest_seqno &&
             (rev_rt->state == INVALID
              || rrpr_Cost < rev_rt->LA))) {
            rev_rt =rt_table_update(rev_rt, ip_src, rrpr_new_hcnt,rrpr_orig_seqno, life, INVALID,rev_rt->flags,rrpr_Channel,rrpr_Cost);//here to increase calcount
        }
    }


    if (rrpr_dest.s_addr == DEV_IFINDEX(ifindex).ipaddr.s_addr) {

        if (rrpr_dest_seqno != 0) {
            if ((int32_t) this_host.seqno < (int32_t) rrpr_dest_seqno)
                this_host.seqno = rrpr_dest_seqno;
            else if (this_host.seqno == rrpr_dest_seqno)
                seqno_incr(this_host.seqno);
        }
        fprintf(stderr,"the other side node has recieved the rrpr message ,time to send rret);
        RRET *rret = rret_create(rrpr, 0, MY_ROUTE_TIMEOUT, 0, 0);
        rret_send(rrcp, rev_rt, NULL, RRCP_CALC_SIZE(rrcp));
    }
    else
    {
        if (ip_ttl > 1) {
            rrpr_forward(rrpr,rrprlen ,--ip_ttl);
        }
    }
}


void NS_CLASS rrpr_route_discovery(struct in_addr dest_addr, u_int8_t flags, struct ip_data *ipd)
{
    return ;
}

void NS_CLASS rrpr_record_timeout(void *arg)
{
    fprintf(stderr,"---------------This is the rrpr_send!--------------\n");
    struct rrpr_record *rec = (struct rrpr_record *) arg;

    list_detach(&rec->l);
    free(rec);
}

void NS_CLASS rrpr_blacklist_timeout(void *arg)
{
    struct blacklist *bl = (struct blacklist *) arg;

    list_detach(&bl->l);
    free(bl);
}

void NS_CLASS rrpr_local_repair(rt_table_t * rt, struct in_addr src_addr, struct ip_data *ipd)
{
    struct timeval now;
    seek_list_t *seek_entry;
    rt_table_t *src_entry;
    int ttl;
    u_int8_t flags = 0;

    if (!rt)
        return;

    if (seek_list_find(rt->dest_addr))
        return;

    if (!(rt->flags & RT_REPAIR))
        return;

    gettimeofday(&now, NULL);

    DEBUG(LOG_DEBUG, 0, "REPAIRING route to %s", ip_to_str(rt->next_hop));

    /* Caclulate the initial ttl to use for the RREQ. MIN_REPAIR_TTL
       mentioned in the draft is the last known hop count to the
       destination. */

    src_entry = rt_table_find(src_addr);

    if (src_entry)
        ttl = (int) (Max(rt->hcnt, 0.5 * src_entry->hcnt) + LOCAL_ADD_TTL);
    else
        ttl = rt->hcnt + LOCAL_ADD_TTL;


    ttl = 2;

    DEBUG(LOG_DEBUG, 0, "%s, rrpr ttl=%d, dest_hcnt=%d",
          ip_to_str(rt->dest_addr), ttl, rt->hcnt);

    /* Reset the timeout handler, was probably previously
       local_repair_timeout */
    rt->rt_timer.handler = &NS_CLASS route_expire_timeout;

    if (timeval_diff(&rt->rt_timer.timeout, &now) < (2 * NET_TRAVERSAL_TIME))
        rt_table_update_timeout(rt, 2 * NET_TRAVERSAL_TIME);


    rrpr_send(rt->next_hop, rt->dest_seqno, ttl, flags);
    //to find a local way  :by dormouse

    /* Remember that we are seeking this destination and setup the
       timers */
    seek_entry = seek_list_insert(rt->dest_addr, rt->dest_seqno,
                                  ttl, flags, ipd);

    if (expanding_ring_search)
        timer_set_timeout(&seek_entry->seek_timer,
                          2 * ttl * NODE_TRAVERSAL_TIME);
    else
        timer_set_timeout(&seek_entry->seek_timer, NET_TRAVERSAL_TIME);

    DEBUG(LOG_DEBUG, 0, "Seeking_a %s ttl=%d", ip_to_str(rt->dest_addr), ttl);

    return;
}


