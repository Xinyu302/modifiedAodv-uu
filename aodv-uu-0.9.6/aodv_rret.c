//
// Created by buaa on 12/26/17.
//

#ifdef NS_PORT
#include "ns-2/aodv-uu.h"
#else
#include "aodv_rret.h"
#include <netinet/in.h>
#include "routing_table.h"
#include "aodv_neighbor.h"
#include "aodv_hello.h"
#include "routing_table.h"
#include "aodv_timeout.h"
#include "timer_queue.h"
#include "aodv_socket.h"
#include "defs.h"
#include "debug.h"
#include "params.h"
#include "seek_list.h"
#include "aodv_rrcq.h"
#endif

RRET *NS_CLASS rret_create(RRCQ * rrcq,u_int8_t flags, int hcnt, int cost, u_int32_t life,u_int32_t Channel)
{

    RRET *rret;

    rret = (RRET *) aodv_socket_queue_msg((AODV_msg *) rrcq,RRET_CALC_SIZE(rrcq));

    rret->type = AODV_RRET;
    rret->Cost = 0;
    rret->hcnt = 0;
    rret->lifetime =htonl(life);
    struct in_addr dest_addr,orig_addr;
    dest_addr.s_addr=rrcq->dest_addr;
    orig_addr.s_addr=rrcq->orig_addr;
    DEBUG (LOG_DEBUG ,0,"create rret::  to:%s  from:%s \n",ip_to_str(dest_addr),ip_to_str(orig_addr));
    fprintf(stderr ,"create rret::  to:%s  from:%s \n",ip_to_str(dest_addr),ip_to_str(orig_addr));
    rret->dest_count=rrcq->dest_count;
    seqno_incr(this_host.seqno);//zhe li yao zizeng 1
    rret->dest_seqno = this_host.seqno;



    rret->Channel = Channel;

#ifdef DEBUG_OUTPUT
    if (rret->dest_addr != rret->orig_addr) {
		DEBUG(LOG_DEBUG, 0, "Assembled RRET:");
		log_pkt_fields((AODV_msg *) rret);
	}
#endif

    return rret;
}

AODV_ext *NS_CLASS rret_add_ext(RRET * rret, int type, unsigned int offset,
                                int len, char *data)
{
    AODV_ext *ext = NULL;


    if (offset < RRET_SIZE)
        return NULL;

    ext = (AODV_ext *) ((char *) rret + offset);

    ext->type = type;
    ext->length = len;

    memcpy(AODV_EXT_DATA(ext), data, len);

    return ext;
}

void  NS_CLASS rret_send(RRET * rret, rt_table_t * rev_rt, rt_table_t * fwd_rt, int size)
{
    DEBUG(LOG_DEBUG, 0, " send RRET");

    u_int8_t rret_flags = 0;
    struct in_addr dest;

    if (!rev_rt) {
        DEBUG(LOG_WARNING, 0, "Can't send RRET, rev_rt = NULL!");
        return;
    }

    dest.s_addr = rret->dest_addr;


    DEBUG(LOG_DEBUG, 0, "Sending RRET to next hop %s about %s->%s",
          ip_to_str(rev_rt->next_hop), ip_to_str(rev_rt->dest_addr),
          ip_to_str(dest));

    fprintf(stderr, "Sending RRET to next hop %s about %s->%s\n",
          ip_to_str(rev_rt->next_hop), ip_to_str(rev_rt->dest_addr),
          ip_to_str(dest));
    aodv_socket_send((AODV_msg *) rret, rev_rt->next_hop, size, MAXTTL,
                     &DEV_IFINDEX(rev_rt->ifindex));

    /* Update precursor lists */
    if (fwd_rt) {
        precursor_add(fwd_rt, rev_rt->next_hop);
        precursor_add(rev_rt, fwd_rt->next_hop);
    }

//    if (!llfeedback && optimized_hellos)
//        hello_start();

}

void NS_CLASS rret_forward(RRET * rret,int size, rt_table_t * rev_rt,
                           rt_table_t * fwd_rt, int ttl)
{

    if (!fwd_rt || !rev_rt) {
        DEBUG(LOG_WARNING, 0,
              "Could not forward RRET because of NULL route!");
        return;
    }

    if (!rret) {
        DEBUG(LOG_WARNING, 0, "No RRET to forward!");
        return;
    }

    rret =
            (RRET *) aodv_socket_queue_msg((AODV_msg *) rret,
                                          RRET_CALC_SIZE(rret));
    rret->hcnt = fwd_rt->hcnt;	/* Update the hopcount */

    aodv_socket_send((AODV_msg *) rret, rev_rt->next_hop, size, ttl,
                     &DEV_IFINDEX(rev_rt->ifindex));

    precursor_add(fwd_rt, rev_rt->next_hop);
    precursor_add(rev_rt, fwd_rt->next_hop);

    rt_table_update_timeout(rev_rt, ACTIVE_ROUTE_TIMEOUT);


}

void NS_CLASS rret_process(RRET * rret, int rretlen, struct in_addr ip_src,
                           struct in_addr ip_dst, int ip_ttl,
                           unsigned int ifindex)
{

    u_int32_t rret_lifetime, rret_seqno, rret_new_hcnt, udest_seqno;
    u_int8_t pre_repair_hcnt = 0, pre_repair_flags = 0,rerr_flags=0;
    rt_table_t *fwd_rt, *rev_rt, *rt;
    int rt_flags = 0, rret_dest_cnt;
    RRET_udest *udest;
    unsigned int extlen = 0;
    RERR* rerr=(RERR*)NULL;

    AODV_ext *ext;
    ext = (AODV_ext *) ((char *) rret + RRET_SIZE);
#ifdef CONFIG_GATEWAY
    struct in_addr inet_dest_addr;
    int inet_rret = 0;
#endif
    int start_rerr=0;
    struct in_addr rret_dest, rret_orig, udest_addr;

    u_int32_t rret_Channel,rret_Cost;

    rret_Channel = rret->Channel;
    rret_Cost = rret->Cost + nb_table_find(ip_src, rret_Channel, true)->cost;

    /* Convert to correct byte order on affeected fields: */
    rret_dest.s_addr = rret->dest_addr;
    rret_orig.s_addr = rret->orig_addr;
    rret_seqno = ntohl(rret->dest_seqno);
    rret_lifetime = ntohl(rret->lifetime);
    rret_dest_cnt = rret->dest_count;//
    /* Increment rret hop count to account for intermediate node... */
    rret_new_hcnt = rret->hcnt + 1;

    if (rretlen < (int)RRET_SIZE) {
        alog(LOG_WARNING, 0, __FUNCTION__,
             "IP data field too short (%u bytes)"
                     " from %s to %s", rretlen, ip_to_str(ip_src),
             ip_to_str(ip_dst));
        return;
    }

    /* Ignore messages which aim to a create a route to one self */
    if (rret_dest.s_addr == DEV_IFINDEX(ifindex).ipaddr.s_addr)
        return;

    while ((rretlen - extlen) > RRET_SIZE) {
        switch (ext->type) {
            case RREP_EXT:
                DEBUG(LOG_INFO, 0, "RREP include EXTENSION");
                /* Do something here */
                break;
#ifdef CONFIG_GATEWAY
            case RREP_INET_DEST_EXT:
	    if (ext->length == sizeof(u_int32_t)) {

		/* Destination address in RREP is the gateway address, while the
		 * extension holds the real destination */
		memcpy(&inet_dest_addr, AODV_EXT_DATA(ext), ext->length);

		DEBUG(LOG_DEBUG, 0, "RRET_INET_DEST_EXT: <%s>",
		      ip_to_str(inet_dest_addr));
		/* This was a RREP from a gateway */
		rt_flags |= RT_GATEWAY;
		inet_rret = 1;
		break;
	    }
#endif
            default:
                alog(LOG_WARNING, 0, __FUNCTION__, "Unknown or bad extension %d",
                     ext->type);
                break;
        }
        extlen += AODV_EXT_SIZE(ext);
        ext = AODV_EXT_NEXT(ext);
    }

    DEBUG(LOG_DEBUG, 0,"recv rret:orig_addr:%s,ip_src:%s,channel:%d,dest_addr:%s\n",ip_to_str(rret_orig),ip_to_str(ip_src),ifindex,ip_to_str(rret_dest));
    fprintf(stderr,"recv rret:orig_addr:%s,ip_src:%s,channel:%d,dest_addr:%s\n",ip_to_str(rret_orig),ip_to_str(ip_src),ifindex,ip_to_str(rret_dest));

    fwd_rt = rt_table_find(rret_dest);
    rev_rt = rt_table_find(rret_orig);


    if (!fwd_rt) {
        fwd_rt =
                rt_table_insert(rret_dest, ip_src, rret_new_hcnt,
                                rret_seqno, rret_lifetime, VALID, rt_flags,
                                ifindex,rret_Channel,rret_Cost);
    } else if (fwd_rt->dest_seqno == 0
               || (int32_t) rret_seqno > (int32_t) fwd_rt->dest_seqno
               || (rret_seqno == fwd_rt->dest_seqno
                   && (fwd_rt->state == INVALID || fwd_rt->flags & RT_UNIDIR
                       || rret_Cost < fwd_rt->LA))) {

        pre_repair_hcnt = fwd_rt->hcnt;
        pre_repair_flags = fwd_rt->flags;

        fwd_rt =
                rt_table_update(fwd_rt, ip_src, rret_new_hcnt, rret_seqno,
                                rret_lifetime, VALID,
                                rt_flags | fwd_rt->flags ,rret_Channel, rret_Cost);
    } else {
        if (fwd_rt->hcnt > 1) {
            DEBUG(LOG_DEBUG, 0,
                  "Dropping RRET, fwd_rt->hcnt=%d fwd_rt->seqno=%ld",
                  fwd_rt->hcnt, fwd_rt->dest_seqno);
        }
        return;
    }



    if (rret_orig.s_addr == DEV_IFINDEX(ifindex).ipaddr.s_addr) {

        if (fwd_rt->hcnt > 1 ) {
            start_rerr = 1;
            rerr_flags |= RERR_NODELETE;
            rerr = rerr_create(rerr_flags, fwd_rt->dest_addr,
                               fwd_rt->dest_seqno, 1);
        }
    }

    udest = RRET_UDEST_FIRST(rret);
    fprintf(stderr,"rret_process:dest!!!!!!!!!!!!!,count is %d\n",rret->dest_count);



    while (rret_dest_cnt>0) {


        udest_addr.s_addr = udest->dest_addr;
        udest_seqno = ntohl(udest->dest_seqno);

        DEBUG(LOG_DEBUG, 0, "unreachable dest=%s seqno=%lu",
              ip_to_str(udest_addr), rret_seqno);
        fprintf(stderr, "unreachable dest=%s seqno=%lu\n",
              ip_to_str(udest_addr), rret_seqno);
        rt = rt_table_find(udest_addr);
            if(rt!=NULL)
                 rt_table_update(rt, ip_src, rret_new_hcnt,
                                     udest_seqno, rret_lifetime, VALID,
                                     rt_flags | fwd_rt->flags,rret_Channel, rret_Cost);///

            if(start_rerr){
                rerr_add_udest(rerr, udest_addr,udest_seqno);
            }

        rret_dest_cnt--;
        udest = RRET_UDEST_NEXT(udest);
    }

    //rrdq
    if (rret_orig.s_addr == DEV_IFINDEX(ifindex).ipaddr.s_addr) {

        if(start_rerr&&rerr) {

                //fprintf(stderr,"rret_process:send_rerr\n");
                int i;
                for (i = 0; i < MAX_NR_INTERFACES; i++) {
                    struct in_addr dest;

                    if (!DEV_NR(i).enabled)
                        continue;

                    dest.s_addr = AODV_BROADCAST;
                    aodv_socket_send((AODV_msg *) rerr, dest,
                                     RERR_CALC_SIZE(rerr), 1,
                                     &DEV_NR(i));

                    }

                }


    } else {
        /* --- Here we FORWARD the RRET on the REVERSE route --- */
        if (rev_rt && rev_rt->state == VALID) {
            rret->Cost = rret_Cost;
            rret->Channel = rret_Channel;
            rret_forward(rret, rretlen,rev_rt, fwd_rt, --ip_ttl);
        } else {
            DEBUG(LOG_DEBUG, 0,
                  "Could not forward RREP - NO ROUTE!!!");
        }
    }

}
