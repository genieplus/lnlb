/*
* LNLB - Linux Network Load Balancing
*  Copyright (C) 2007 Primiano Tucci <mail@primianotucci.com>
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*  GNU General Public License for more details.
*
*/
#define DRV_NAME	"lnlb"
#define DRV_VERSION	"0.1.2-beta"
#define DRV_DESCRIPTION	"Linux Network Load Balancing"
#define DRV_AUTHOR	"Primiano Tucci <mail@primianotucci.com>"

#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/jhash.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/sort.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/crc32.h>

//<linux/if_lnlb.h>
#include "if_lnlb.h"
#include <linux/delay.h>
#include <asm/div64.h>

#define IP_ADDRESS_COMPARE(A,B) (((u_int32_t)A)!=((u_int32_t)B))
#define DUMPMAC(x) x[0],x[1],x[2],x[3],x[4],x[5]
#define NEXT_HB_TIMER (HZ*heartbeat_interval+jiffies)
#define NEXT_TO_TIMER (HZ*CONVERGENCE_DTIMEOUT/10+jiffies)
#define PROTO_MODULES_UBOUND (proto_modules_installed ? 0xFF : 1)
#define FRAG_EXPIRE_INTERVAL 2

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
# define IP_HDR(skb) ip_hdr(skb)
# define ARP_HDR(skb) arp_hdr(skb)
#else
# define IP_HDR(skb) ((skb)->nh.iph)
# define ARP_HDR(skb) ((skb)->nh.arph)
#endif

#ifndef MIN
#define MIN(a,b)  (((a) < (b)) ? (a) : (b))
#endif

static int heartbeat_interval=HEARTBEAT_INTERVAL_DEFAULT;
module_param(heartbeat_interval,int,0444);
MODULE_PARM_DESC(heartbeat_interval,"Interval in seconds between each convergence.");

static int mode_unicast=1; 
/* Note actually multicast mode (setting mode_unicast=0) has non sense since there is no IGMP support */
module_param(mode_unicast,int,0444);
MODULE_PARM_DESC(mode_unicast,"Select cluster MAC type: 1: Unicast /  0: Multicast.");

static struct ethtool_ops lnlb_ethtool_ops;
/* List of allocated devices (nlb0,nbl1...) */
static LIST_HEAD(dev_list);
static LIST_HEAD(dev_hook_list);
static struct proc_dir_entry* proc_file;
/*Netfilter hook and arp mangle hook structs*/
static struct nf_hook_ops *netfilter_hook=NULL;
static struct nf_hook_ops *arp_mangle_hook=NULL;
static struct lnlb_protocol_module *proto_modules[0xFF]; /* proto_modules[0] is the default handler */
static int proto_modules_installed=0; /* Tells the driver if any handler module (other than the default) has been installed*/
static DEFINE_RWLOCK(proto_modules_lock);

struct arp_payload
{
	u_int8_t src_hw[ETH_ALEN];
	u_int32_t src_ip;
	u_int8_t dst_hw[ETH_ALEN];
	u_int32_t dst_ip;
} __attribute__ ((packed));

struct dev_hook
{
	struct list_head list;
	struct net_device *dev;
	struct packet_type heartbeat_ptype;
	struct packet_type unicast_ptype;
};

struct lnlb_cluster_msg {
	struct list_head list; /* For linking into frag_list */
	uint32_t timestamp; /* Timestamp set when frame is received (is not sent across network, it's just to avoid frag_list pollution) */
	
	unsigned char sender[ETH_ALEN]; /* Sender MAC address */
	enum lnlb_msg_type type;
	uint32_t len;   /* Len of current frame data */
	uint32_t flags;   /* Optional flags */
	uint8_t id; /* Message ID */
	uint16_t frag_num; /* Fragment num */
	uint16_t frag_total; /* Total fragments */
	uint32_t crc; /* Global Message CRC32 */
	char *data;
};
#define INIT_CLUSTER_MSG(msg) msg=(struct lnlb_cluster_msg) { .len=0,			\
		.id=0,    		\
		.frag_num=0, 		\
		.frag_total=1,	\
		.crc=0,			\
		.data=NULL		}


/*------------------------------------------------------------------------------------------------------------------------
						Prototypes
*------------------------------------------------------------------------------------------------------------------------*/
static int proc_read_callback(char *, char **, off_t, int, int *, void *);
static int proc_write_callback(struct file *, const char __user *, unsigned long , void *);
static int init_procfs(void);
static void cleanup_procfs(void);
static int net_open(struct net_device *);
static int net_close(struct net_device *);
static int net_xmit(struct sk_buff *, struct net_device *);
static struct net_device_stats *net_stats(struct net_device *);
static int ei_get_settings(struct net_device *, struct ethtool_cmd *);
static void ei_get_drvinfo(struct net_device *, struct ethtool_drvinfo *);
static u32 ei_get_link(struct net_device *);
static void setup_dev_callback(struct net_device *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
static unsigned int netfilter_frame_hook(unsigned int , struct sk_buff *, const struct net_device *, const struct net_device *, int (*)(struct sk_buff *));
#else
static unsigned int netfilter_frame_hook(unsigned int , struct sk_buff **, const struct net_device *, const struct net_device *, int (*)(struct sk_buff *));
#endif
static int unicast_frame_hook(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);
static inline void pass_skb_to_vdevice(struct sk_buff *,struct lnlb_struct *);
static int lnlb_by_skb (const struct sk_buff *,const struct net_device *,struct lnlb_struct **);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
static unsigned int arp_mangle(unsigned int, struct sk_buff *,const struct net_device *, const struct net_device *,int(*)(struct sk_buff*));
#else
static unsigned int arp_mangle(unsigned int, struct sk_buff **,const struct net_device *, const struct net_device *,int(*)(struct sk_buff*));
#endif
static int add_interface_hook(struct net_device *);
static void del_interface_hook(struct net_device *);
static int init_netfilter_hook(void);
static void clear_netfilter_hook(void);
static int instantiate_new_device(char*,struct net_device*,struct lnlb_struct**);
static int delete_device(char *);
static int __init drv_init(void);
static void drv_cleanup(void);
static void ip_to_mac(__be32,unsigned char *);
static struct lnlb_struct * lnlbif_by_name(const char *);
static struct lnlb_struct * lnlbif_by_ip(__be32);
static void device_set_ip(struct lnlb_struct *,__be32);
static int convergence_run(struct lnlb_struct *);
static int check_convergence_completed(struct lnlb_struct *);
static int broadcast_my_weigth(struct lnlb_struct *);
static int retrasm_my_weight(struct lnlb_struct *,unsigned char *);
static int broadcast_join(struct lnlb_struct *);
static int broadcast_welcome(struct lnlb_struct *);
static int broadcast_leave(struct lnlb_struct *);
static int broadcast_conntrack_status(struct lnlb_struct *);
static int send_conntrack_status(struct lnlb_struct *,unsigned char *);
static inline int broadcast_msg(struct lnlb_cluster_msg *,struct lnlb_struct *);
static int send_long_eth_msg(struct lnlb_cluster_msg *,struct lnlb_struct *,unsigned char *);
static int send_eth_msg(struct lnlb_cluster_msg *,struct lnlb_struct *,unsigned char *);
static struct lnlb_node_table_entry* seek_node_from_table(struct lnlb_struct *,unsigned char *);
static struct lnlb_node_table_entry* add_node_to_table(struct lnlb_struct *,unsigned char *);
static void delete_dead_nodes_from_table(struct lnlb_struct *);
static void advertise_node_death(struct lnlb_struct *,unsigned char *);
static void heartbeat_timer(unsigned long);
static void cluster_msg_handler(struct lnlb_cluster_msg *,struct lnlb_struct *);
static void convergence_timeout_timer(unsigned long);
static inline void delete_and_free_frag_msg(struct lnlb_cluster_msg *);
static int heartbeat_frame_hook(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);
static int skb_node_affinity(struct lnlb_struct*,struct sk_buff*,int);
//static void dump_table(struct lnlb_struct *);
static int cmp_node_table_entries(const void *,const void *);
static void swap_node_table_entries(void *,void *,int);
static void process_queued_skbuff(struct lnlb_struct *);
static int find_related_node(struct lnlb_struct*,struct sk_buff *,unsigned char *);
int lnlb_register_ph(uint8_t,struct lnlb_protocol_module *);
void lnlb_unregister_ph(uint8_t);

static struct ethtool_ops lnlb_ethtool_ops =
{
	.get_settings	= ei_get_settings,
	.get_drvinfo	= ei_get_drvinfo,
	.get_link		= ei_get_link,
};

/*------------------------------------------------------------------------------------------------------------------------*
						Inline functions
*------------------------------------------------------------------------------------------------------------------------*/

static inline int broadcast_msg(struct lnlb_cluster_msg *iMsg,struct lnlb_struct *iDev)
{
	return send_eth_msg(iMsg,iDev,iDev->cluster_mac);
}

static inline void pass_skb_to_vdevice(struct sk_buff *iSkb,struct lnlb_struct *iDev)
{
	iSkb->dev=iDev->dev;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	skb_reset_mac_header(iSkb);
#else
	iSkb->mac.raw=iSkb->data;
#endif

	iSkb->pkt_type = PACKET_HOST;

	netif_receive_skb(iSkb); //TODO This or netif_rx_ni?

	iDev->stats.rx_packets++;
	iDev->stats.rx_bytes+=iSkb->data_len;
}

/*------------------------------------------------------------------------------------------------------------------------*
							Timers
*------------------------------------------------------------------------------------------------------------------------*/

static void heartbeat_timer(unsigned long iData)
{
	struct lnlb_struct *lnlb=(struct lnlb_struct *)iData;
	write_lock(&(lnlb->node_table.lock));
	convergence_run(lnlb);
	write_unlock(&(lnlb->node_table.lock));
	check_convergence_completed(lnlb); /* Only useful in the case we're the unique node of the cluster*/

	mod_timer(&lnlb->heartbeat_timer,NEXT_HB_TIMER);
}

static void convergence_timeout_timer(unsigned long iData)
{
	int i,found_dead=0,reschedule_timeout=0;
	enum lnlb_node_status status;
	struct lnlb_cluster_msg msg;
	struct lnlb_struct *lnlb=(struct lnlb_struct *)iData;

	write_lock(&(lnlb->node_table.lock));

	for(i=0;i<lnlb->node_table.size;i++)
	{

		status=lnlb->node_table.entry[i].status;

		if(status==LNLB_NS_OK)
		continue;

		if(status==LNLB_NS_WAITING_HEARTBEAT)
		{
			lnlb->node_table.entry[i].status=LNLB_NS_ASKED_RETRASM;
			/* Ask retransmission to the missing node */
			DBG("Asking retrasmission to node %X:%X:%X:%X:%X:%X\n",DUMPMAC(lnlb->node_table.entry[i].hw_addr));
			INIT_CLUSTER_MSG(msg);
			msg.type=LNLB_MSG_ASKRETRASM;

			send_eth_msg(&msg,lnlb,lnlb->node_table.entry[i].hw_addr);
			reschedule_timeout=1;
		}
		else
		{
			DBG("Node %X:%X:%X:%X:%X:%X is dead\n",DUMPMAC(lnlb->node_table.entry[i].hw_addr));
			lnlb->node_table.entry[i].status=LNLB_NS_DEAD;
			found_dead=1;

			/* Advertise protocol modules that node is dead */
			advertise_node_death(lnlb, lnlb->node_table.entry[i].hw_addr);
		}

	}
	if(found_dead)
	delete_dead_nodes_from_table(lnlb);
	write_unlock(&(lnlb->node_table.lock));

	if(reschedule_timeout)
	mod_timer(&lnlb->timeout_timer,NEXT_TO_TIMER);
	else
	check_convergence_completed(lnlb);

}

static void advertise_node_death(struct lnlb_struct *iDev,unsigned char *iNodeAddr)
{
	int n;
	read_lock(&proto_modules_lock);
	for(n=0;n<PROTO_MODULES_UBOUND;n++)
	{
		if(proto_modules[n]==NULL) continue;
		(*(proto_modules[n]->node_died))(iDev,iNodeAddr);
	}
	read_unlock(&proto_modules_lock);
}

/* Retrieve the "weight" for current node (depending on the source user choosed). */
static void get_weight(struct lnlb_struct *iDev)
{
	long long weight=0;

	switch(iDev->weight_mode)
	{
	case WM_MANUAL:
		{
			weight=iDev->weight;
		}
		break; /* In case of manual weight setting, weight is directly feed into dev->weight upon userspace call */
	case WM_LOADAVG:
		{
			weight=avenrun[0];
		}
		break;
	case WM_LOADAVG5:
		{
			weight=avenrun[1];
		}
		break;
	case WM_LOADAVG15:
		{
			weight=avenrun[2];
		}
		break;
	case WM_MEM:
		{
			struct sysinfo si;
			si_meminfo(&si);

			weight=si.totalram - si.freeram;
			weight*=LNLB_WEIGHT_MAX;
			do_div(weight,si.totalram);
		}
		break;
	}

	if(weight<LNLB_WEIGHT_MIN)
	weight=LNLB_WEIGHT_MIN;
	else if(weight>LNLB_WEIGHT_MAX)
	weight=LNLB_WEIGHT_MAX;

	iDev->weight=(lnlb_weight_t)weight;
}

/* Start the convergence phase (if not already running). All nodes are set to WAITING_HEARTBEAT. Current weight is broadcasted to cluster
* Note: always called from softirq.
* Note: this function is NOT node_table safe. Caller must lock the table
*/
static int convergence_run(struct lnlb_struct *iDev)
{
	int i;
	struct lnlb_node_table_entry *node;
	static long last_time=0;
	int i_am_the_first_node=0;

	if(iDev->converging)
	return 1; /* Convergence is already running */
	/* Avoid racing loops */
	if(get_seconds()-last_time<1) 
	{
		printk(KERN_WARNING DRV_NAME "Cluster converging too fast, skipping convergence\n");
		return 1;
	}
	last_time=get_seconds();
	
	iDev->converging=1;
	

	get_weight(iDev);
	iDev->locked_weight=iDev->weight;

	/* Determine if i'm the first (non JOINING) node in list */
	for(i=0;i<iDev->node_table.size;i++){
		node=&iDev->node_table.entry[i];
		if(node->status==LNLB_NS_JOINING) continue;
		i_am_the_first_node=(compare_ether_addr(iDev->bind_dev->dev_addr , node->hw_addr)==0);
		break;
	}
	
	
	for(i=0;i<iDev->node_table.size;i++){
		node=&iDev->node_table.entry[i];
		if(compare_ether_addr(iDev->bind_dev->dev_addr , node->hw_addr)==0){
			/* It's me */
			node->status=LNLB_NS_OK;
			node->weight=iDev->locked_weight;
		}
		else if(node->status == LNLB_NS_JOINING){
			/* Node has just joined, send him the conntrack status (only if i'm the first node of the table)	 */
			node->status=LNLB_NS_WAITING_HEARTBEAT;
			if(i_am_the_first_node && iDev->join_complete)
				send_conntrack_status(iDev,node->hw_addr);	//TODO manda ripetuta
		}
		else {
			/* It's not me, nor a joining node */
			node->status=LNLB_NS_WAITING_HEARTBEAT;
		}
	}
	
	iDev->join_complete=1;

	broadcast_my_weigth(iDev);

	/* Start the timeout timer...all nodes must converge in CONVERGE_MTIMEOUT msec.
	If not, ask missing nodes for a heartbeat duplicate (if still got no reply consider the node dead) */
	mod_timer(&iDev->timeout_timer,NEXT_TO_TIMER);
	return 0;
}

/*
* Handler for received broadcast messages
* iMsg: the received message
* iDev: the virtual lnlbN device which the message is related to
* Note: It's always executed from softirq (the frame hook)
* Note: msg will be freed after this call is ended. msg->data will *NOT* (so we must free it)
*/
static void cluster_msg_handler(struct lnlb_cluster_msg *iMsg,struct lnlb_struct *iDev)
{
	struct lnlb_node_table_entry *node;

	switch(iMsg->type)
	{
	case LNLB_MSG_HEARTBEAT:
	case LNLB_MSG_RETRASM:
		{
			/* Heartbeat received from another node... update its weight in the node table */
			write_lock(&(iDev->node_table.lock));
			node=seek_node_from_table(iDev,iMsg->sender); /* Seek the sender from the node table */
			DBG("Heartbeat received from %X:%X:%X:%X:%X:%X\n",DUMPMAC(iMsg->sender));

			if(iMsg->len<sizeof(lnlb_weight_t))
			{
				/* Malformed packet? */
				DBG("Malformed heartbeat received\n");
				goto heartbeat_err;
			}

			if(node==NULL)
			{
				/* If node is not in the table... add it do the table...this should normally never happen since new nodes executes a repeated JOIN on load */
				if((node=add_node_to_table(iDev,iMsg->sender))==NULL)
				goto heartbeat_err;
			}
			else if(!iDev->converging && iMsg->type==LNLB_MSG_HEARTBEAT)
			{
				
				convergence_run(iDev);
				/* Reschedule the heartbeat timer for next HEARTBEAT_INTERVAL SECONDS (so keep time synchronization between nodes) */
				mod_timer(&iDev->heartbeat_timer,NEXT_HB_TIMER);
			}

			node->weight=ntohs(*((lnlb_weight_t *)iMsg->data));
			node->status=LNLB_NS_OK;

			write_unlock(&(iDev->node_table.lock));
			
			check_convergence_completed(iDev);
			break;

			heartbeat_err:
			write_unlock(&(iDev->node_table.lock));
		}
		break;
		
	case LNLB_MSG_JOIN:
	case LNLB_MSG_WELCOME:{
		write_lock(&(iDev->node_table.lock));
		node=seek_node_from_table(iDev,iMsg->sender);
		if(node==NULL)
		{
			DBG("New node discovered: %X:%X:%X:%X:%X:%X\n",DUMPMAC(iMsg->sender));
			if((node=add_node_to_table(iDev,iMsg->sender))==NULL)
			goto jw_err;
		}
		write_unlock(&(iDev->node_table.lock));
	
		if(iMsg->type==LNLB_MSG_WELCOME)
			break;

		/*... Continue here only in the JOIN case */
		
		broadcast_welcome(iDev);
		
		break;

		jw_err:
		write_unlock(&(iDev->node_table.lock));
		}
		break;

	case LNLB_MSG_CONNTRACK: {
			DBG("Received conntrack dump from %X:%X:%X:%X:%X:%X\n",DUMPMAC(iMsg->sender));
			read_lock(&proto_modules_lock);
			if(iMsg->flags > PROTO_MODULES_UBOUND)
			goto ct_exit;
			if(proto_modules[iMsg->flags]==NULL) 
			goto ct_exit;

			if( (*(proto_modules[iMsg->flags]->load_status))(iDev,iMsg->data,iMsg->len))
			DBG("Error while deserializing conntrack status\n");
			ct_exit:
			read_unlock(&proto_modules_lock);
		}
		break;
		
	case LNLB_MSG_LEAVE:
		{
			DBG("Node is leaving the cluster %X:%X:%X:%X:%X:%X\n",DUMPMAC(iMsg->sender));
			write_lock(&(iDev->node_table.lock));
			node=seek_node_from_table(iDev,iMsg->sender); /* Seek the sender from the node table */

			if(node==NULL) /* We received a "leave" from a node NOT in list... really strange... DROP! */
			goto leave_exit;

			node->status=LNLB_NS_DEAD;

			advertise_node_death(iDev, iMsg->sender);
			delete_dead_nodes_from_table(iDev);

			leave_exit:
			write_unlock(&(iDev->node_table.lock));
		}
		break;

	case LNLB_MSG_ASKRETRASM:
		{
			retrasm_my_weight(iDev,iMsg->sender);
		}
		break;
	default:
		break;
	}
	/* switch(iMsg->type) { */

	/* Free the data previously allocated by heartbeat_frame_hook */
	if(iMsg->data)
	kfree(iMsg->data);
}

/* Update the cut-table using by the hash based distribution algorithm
* Caller must lock only the dev_node table (the function locks only the cut_table)
*/
static inline void update_cut_table(struct lnlb_struct *iDev)
{
	int i,n;
	uint32_t weight_sum=0;
	lnlb_weight_t tmp_weight;

	write_lock(&(iDev->cut_table.lock));

	iDev->cut_table.size=0;
	iDev->cut_table_sum=0;

	for(i=0;i<iDev->node_table.size;i++)
	{
		if(iDev->node_table.entry[i].weight==0) goto exit;
		weight_sum+=iDev->node_table.entry[i].weight;
	}

	for(i=0,n=0;i<iDev->node_table.size;i++)
	{
		if(iDev->node_table.entry[i].status!=LNLB_NS_OK) continue;
		memcpy(iDev->cut_table.entry[n].hw_addr,iDev->node_table.entry[i].hw_addr,ETH_ALEN);

		tmp_weight=weight_sum * MAX_WEIGHT_MUL / iDev->node_table.entry[i].weight;
		//BUG_ON(tmp_weight > LNLB_WEIGHT_MAX);
		iDev->cut_table.entry[n].weight=tmp_weight;
		iDev->cut_table_sum+=tmp_weight;
		n++;
	}

	iDev->cut_table.size=n;

	//BUG_ON(iDev->cut_table_sum==0);
	if(iDev->cut_table_sum==0)
		iDev->cut_table.size=0;
	

exit:
	write_unlock(&(iDev->cut_table.lock));
}

/* Check if we've received heartbeats from all nodes
	Note: called always in softirq */
static int check_convergence_completed(struct lnlb_struct *iDev)
{
	int i;
	int res=0;

	read_lock(&(iDev->node_table.lock));
	for(i=0;i<iDev->node_table.size;i++)
	{
		if(iDev->node_table.entry[i].status!=LNLB_NS_OK)
		{
			res=1;
			break;
		}
	}

	if(!res)
	update_cut_table(iDev); /* Update the cut-table using by the hash based distribution algorithm */

	read_unlock(&(iDev->node_table.lock));
	if(res)
	return 1;
	/* We received heartbeats from all nodes (status is LNLB_NS_OK) ... convergence is ended */

	/* Cancel the timeout check timer */
	del_timer(&iDev->timeout_timer);

	/* Process frames that have been queued in the meanwhile */
	process_queued_skbuff(iDev);

	iDev->converging=0;

	//DBG(":::::::::::::Convergence ended:::::::::::\n");
	//dump_table(iDev);
	return res;
}

/* Process skbuffs that were queued during the convergence phase */
static void process_queued_skbuff(struct lnlb_struct *iDev)
{
	struct sk_buff *skb=NULL;

	while((skb=skb_dequeue(&iDev->rx_queue)))
	{
		if( ! skb_node_affinity(iDev,skb,0))
		pass_skb_to_vdevice(skb,iDev); /* Skb is for this node */
		else
		dev_kfree_skb(skb); /* Skb is for another node */

	}

}

/* Broadcast an ethernet message containing my weight to all nodes in the cluster
* Note: always called from softirq
*/
static int broadcast_my_weigth(struct lnlb_struct *iDev)
{
	struct lnlb_cluster_msg msg;
	lnlb_weight_t weight=htons(iDev->locked_weight);

	INIT_CLUSTER_MSG(msg);
	msg.type=LNLB_MSG_HEARTBEAT;
	msg.len=sizeof(lnlb_weight_t);
	msg.data=(char *)&weight;
	return broadcast_msg(&msg,iDev);

}

static int retrasm_my_weight(struct lnlb_struct *iDev,unsigned char *iDestAddr)
{
	struct lnlb_cluster_msg msg;
	lnlb_weight_t weight=htons(iDev->locked_weight);

	INIT_CLUSTER_MSG(msg);
	msg.type=LNLB_MSG_RETRASM;
	msg.len=sizeof(lnlb_weight_t);
	msg.data=(char *)&weight;
	return send_eth_msg(&msg,iDev,iDestAddr);
}

static int broadcast_join(struct lnlb_struct *iDev)
{
	struct lnlb_cluster_msg msg;

	INIT_CLUSTER_MSG(msg);
	msg.type=LNLB_MSG_JOIN;
	return broadcast_msg(&msg,iDev);
}

static int broadcast_welcome(struct lnlb_struct *iDev)
{
	struct lnlb_cluster_msg msg;

	INIT_CLUSTER_MSG(msg);
	msg.type=LNLB_MSG_WELCOME;
	return broadcast_msg(&msg,iDev);
}

static int send_conntrack_status(struct lnlb_struct *iDev,unsigned char *iDestAddr){
	int i;
	int ret=0;
	struct lnlb_cluster_msg msg;
	
	read_lock(&proto_modules_lock);				
	for(i=0;i<PROTO_MODULES_UBOUND;i++){
		if(proto_modules[i]==NULL) continue;
		DBG("Sending conntrack status\n");
		INIT_CLUSTER_MSG(msg);
		msg.type=LNLB_MSG_CONNTRACK;
		msg.len=(*(proto_modules[i]->save_status))(iDev,&msg.data);
		
		msg.flags=i;
		if(!msg.len) continue;
		ret=send_long_eth_msg(&msg,iDev,iDestAddr); 
		if(ret) break;
		
		DBG("Sent conntrack status %u to %X:%X:%X:%X:%X:%X\n",msg.len,DUMPMAC(iDestAddr));
	}
	read_unlock(&proto_modules_lock);
	return ret;
}


static int broadcast_leave(struct lnlb_struct *iDev)
{
	struct lnlb_cluster_msg msg;

	INIT_CLUSTER_MSG(msg);
	msg.type=LNLB_MSG_LEAVE;
	return broadcast_msg(&msg,iDev);
}

static int broadcast_conntrack_status(struct lnlb_struct *iDev)
{
	return send_conntrack_status(iDev,iDev->cluster_mac);
}

static int send_long_eth_msg(struct lnlb_cluster_msg *iMsg,struct lnlb_struct *iDev,unsigned char *iDestAddr){
	struct lnlb_cluster_msg frag_msg;
	uint32_t free_data_size;
	int res;
	static uint8_t lastid=0;
	
	free_data_size=iDev->dev->mtu
	-ETH_HLEN 
	-sizeof(__be32) /* Cluster IP Address */
	-sizeof(enum lnlb_msg_type) /* Message type */
	-sizeof(uint32_t) /* Data length */
	-sizeof(uint8_t) /* Message ID */
	-sizeof(uint16_t) /* Fragment num */
	-sizeof(uint16_t) /* Total fragments */
	-sizeof(uint32_t) /* Global Message CRC32 */
	;
	
	if(iMsg->len < free_data_size)
	return send_eth_msg(iMsg,iDev,iDestAddr);
	
	frag_msg=*iMsg;
	frag_msg.crc=crc32(0,iMsg->data,iMsg->len);
	frag_msg.frag_total= iMsg->len / free_data_size + ((iMsg->len % free_data_size) ? 1 : 0);
	frag_msg.id=lastid++;
	
	for(frag_msg.frag_num=0;frag_msg.frag_num < frag_msg.frag_total; frag_msg.frag_num++){
		frag_msg.len=MIN(free_data_size ,  iMsg->len - (frag_msg.frag_num * free_data_size));
		res=send_eth_msg(&frag_msg,iDev,iDestAddr); 
		if(res) return res;
		frag_msg.data+=frag_msg.len;
	}
	return 0;  
}


static int send_eth_msg(struct lnlb_cluster_msg *iMsg,struct lnlb_struct *iDev,unsigned char *iDestAddr)
{
	struct sk_buff *skb;
	struct ethhdr *eth;
	__be32 *cluster_ip;
	enum lnlb_msg_type *msg_type;
	uint32_t *data_len,*total_crc,*flags;
	uint8_t *msg_id;
	uint16_t *frag_num,*frag_total;

	void *data;

	skb=dev_alloc_skb(ETH_HLEN	/* Ethernet header */
	+sizeof(__be32) /* Cluster IP Address */
	+sizeof(enum lnlb_msg_type) /* Message type */
	+sizeof(uint32_t) /* Data length */
	+sizeof(uint32_t) /* Flags */
	+sizeof(uint8_t) /* Message ID */
	+sizeof(uint16_t) /* Fragment num */
	+sizeof(uint16_t) /* Total fragments */
	+sizeof(uint32_t) /* Global Message CRC32 */			 
	+iMsg->len /* Data */
	);
	if(skb==NULL)
	{
		DBG("Cannot allocate skbuff\n");
		return -ENOMEM;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
#else
	skb->nh.raw = skb->mac.raw = skb->data;
#endif

	skb->ip_summed = CHECKSUM_NONE;
	skb->protocol = __constant_htons(ETH_P_LNLB);
	skb->priority = 0;
	skb->next = skb->prev = NULL;
	skb->dev = iDev->bind_dev;

	eth = (struct ethhdr *) skb_put(skb, ETH_HLEN);
	memcpy(eth->h_source,iDev->bind_dev->dev_addr,ETH_ALEN);
	memcpy(eth->h_dest,iDestAddr,ETH_ALEN);
	eth->h_proto=__constant_htons(ETH_P_LNLB);

	cluster_ip = (__be32 *) skb_put(skb, sizeof(__be32));
	*cluster_ip = iDev->cluster_ip;
	msg_type = (enum lnlb_msg_type *) skb_put(skb, sizeof(enum lnlb_msg_type));
	*msg_type = htonl(iMsg->type);
	data_len = (uint32_t *) skb_put(skb, sizeof(uint32_t));
	*data_len = htonl(iMsg->len);
	flags = (uint32_t *) skb_put(skb, sizeof(uint32_t));
	*flags = htonl(iMsg->flags);
	msg_id= (uint8_t *) skb_put(skb, sizeof(uint8_t));
	*msg_id=iMsg->id;
	frag_num=(uint16_t *) skb_put(skb, sizeof(uint16_t));
	*frag_num=htons(iMsg->frag_num);
	frag_total=(uint16_t *) skb_put(skb, sizeof(uint16_t));   
	*frag_total=htons(iMsg->frag_total);
	total_crc=(uint32_t *) skb_put(skb, sizeof(uint32_t));   
	*total_crc=htonl(iMsg->crc);

	if(*data_len>0)
	{
		data=skb_put(skb, iMsg->len);
		memcpy(data,iMsg->data,iMsg->len);
	}

	dev_queue_xmit(skb);

	return 0;
}
static inline void delete_and_free_frag_msg(struct lnlb_cluster_msg *iMsg){
	list_del(&iMsg->list);
	if(iMsg->len>0 && iMsg->data)
		kfree(iMsg->data);
	kfree(iMsg);
}

/* Hook function for ETH_P_LNLB frames (set via dev_add_pack) */
//TODO tutta da controllare
static int heartbeat_frame_hook(struct sk_buff *iSkb, struct net_device *iIfp, struct packet_type *iPt, struct net_device *iOrig_dev)
{
	struct sk_buff *skb=NULL;
	struct ethhdr *eth;
	struct lnlb_struct *lnlb,*lptr,*lnxt;
	unsigned char *ptr;
	__be32 cluster_ip;
	struct lnlb_cluster_msg *msg=NULL,*mptr,*mptrloop,*fullmsg;
	struct list_head *addmptr;
	uint32_t total_msg_len=0;
	uint32_t msg_data_offset=0;
	int32_t last_frag;
	int drop=1;

	/* Drop if not directed to me nor to cluster MAC */
	list_for_each_entry_safe(lptr, lnxt , &dev_list, list){
		if(compare_ether_addr(eth_hdr(iSkb)->h_dest,lptr->cluster_mac)==0) {drop=0; break;}
		if(compare_ether_addr(eth_hdr(iSkb)->h_dest,lptr->bind_dev->dev_addr)==0) {drop=0; break;}
	}
	if(drop)
		return 0;

	/* Check the frame is valid */
	if (!pskb_may_pull(iSkb,sizeof(__be32) /* Cluster IP Address */
				+sizeof(enum lnlb_msg_type) /* Message type */
				+sizeof(uint32_t) /* Data length */
				+sizeof(uint32_t) /* Flags  */			  
				+sizeof(uint8_t) /* Message ID */
				+sizeof(uint16_t) /* Fragment num */
				+sizeof(uint16_t) /* Total fragments */
				+sizeof(uint32_t) /* Global Message CRC32 */				  
				))
	return 0;

	msg=(struct lnlb_cluster_msg*)kmalloc(sizeof(struct lnlb_cluster_msg),GFP_ATOMIC);
	if(msg == NULL)
		return 0;
	skb = skb_share_check(iSkb, GFP_ATOMIC);
	if (skb == NULL)
		return 0;

	msg->data=NULL;
	msg->timestamp=get_seconds();
	eth=eth_hdr(skb);
	memcpy(msg->sender,eth->h_source,ETH_ALEN);

	ptr=(char *)eth_hdr(skb)+ETH_HLEN;
	cluster_ip=*((__be32 *)ptr);
	ptr+=sizeof(__be32);
	msg->type=ntohl(*((enum lnlb_msg_type *)ptr));
	ptr+=sizeof(enum lnlb_msg_type);
	msg->len=ntohl(*((uint32_t *)ptr));
	ptr+=sizeof(uint32_t);
	msg->flags=ntohl(*((uint32_t *)ptr));
	ptr+=sizeof(uint32_t);
	msg->id=*((uint8_t *)ptr);
	ptr+=sizeof(uint8_t);
	msg->frag_num=ntohs(*((uint16_t *)ptr));
	ptr+=sizeof(uint16_t);
	msg->frag_total=ntohs(*((uint16_t *)ptr));
	ptr+=sizeof(uint16_t);
	msg->crc=ntohl(*((uint32_t *)ptr));
	ptr+=sizeof(uint32_t);
	


	/* Copy the frame data from skb to msg structure */
	if (!pskb_may_pull(skb,(ptr-((unsigned char *)eth_hdr(skb))-ETH_HLEN)+msg->len))
	{  DBG("Malformed heartbeat frame");
		goto exit;
	}

	if(msg->len > 0)
	{
		msg->data=kmalloc(msg->len,GFP_ATOMIC);
		if(msg->data==NULL)
		goto exit;
		memcpy(msg->data,ptr,msg->len);
		ptr+=msg->len;
	}

	lnlb=lnlbif_by_ip(cluster_ip);
	if(lnlb==NULL) goto exit;
	if(iIfp!=lnlb->bind_dev) goto exit; /*If the frame is received from another iface that is not bound to current VIP drop it*/

	/* If it's a long message (more than 1 fragment), do not parse until all fragments are received */
	dev_kfree_skb(skb);
	skb=NULL;
	
	if(msg->frag_total > 1){
		
		spin_lock(&lnlb->frag_list_lock);
		/* --- Add (ordered) to the frag_lis corresponding to msg->idt  --- */
		addmptr=&lnlb->frag_list[msg->id];
		list_for_each_entry_safe(mptr, mptrloop, &lnlb->frag_list[msg->id], list){
			/* check for expired fragments */
			if(get_seconds() - msg->timestamp > FRAG_EXPIRE_INTERVAL){
				delete_and_free_frag_msg(mptr);
				continue;
			}
			
			if(msg->frag_num > mptr->frag_num) continue;
			if(msg->frag_num == mptr->frag_num) {
				addmptr=mptr->list.next;
				delete_and_free_frag_msg(mptr);	
			}
			else
			addmptr=&mptr->list;
			
			break;
		}
		list_add_tail(&msg->list,addmptr);
		
		/* Check if all fragments has been received */
		last_frag=-1;
		total_msg_len=0;
		list_for_each_entry(mptr, &lnlb->frag_list[msg->id], list){
			if(last_frag+1 < mptr->frag_num) 
			break;	
			total_msg_len+=mptr->len;
			last_frag++;
		}
		
		if(last_frag == msg->frag_total-1){
			/*All fragments received */
			fullmsg=(struct lnlb_cluster_msg *)kmalloc(sizeof(struct lnlb_cluster_msg),GFP_ATOMIC);
			if(!fullmsg) {spin_unlock(&lnlb->frag_list_lock); return 0;}
			INIT_CLUSTER_MSG(*fullmsg);
			fullmsg->type=msg->type;
			fullmsg->len=total_msg_len;
			fullmsg->crc=msg->crc;
			memcpy(fullmsg->sender,msg->sender,ETH_ALEN);

			fullmsg->data=kmalloc(total_msg_len,GFP_ATOMIC);
			if(!fullmsg->data) {
				kfree(fullmsg);
				spin_unlock(&lnlb->frag_list_lock); 
				return 0;
			}
			/* Fragment could mix at this point (e.g. if frag_total is 3 but we received for any reason fragment 1,2,3,4,5, all fragments will be parsed (the CRC check will drop it finally)*/
			
			/* Melt all fragments in list in a single big message (and free the fragments) */
			list_for_each_entry_safe(mptr, mptrloop, &lnlb->frag_list[msg->id], list){	
				if(mptr->len){
					memcpy( (fullmsg->data+msg_data_offset) ,mptr->data,mptr->len);
					msg_data_offset+=mptr->len;
				}
				delete_and_free_frag_msg(mptr);				
			}
			DBG("CRC check %u %u\n",crc32(0,fullmsg->data,fullmsg->len),fullmsg->crc);
			
			msg=fullmsg;
		}
		else
		msg=NULL;

		spin_unlock(&lnlb->frag_list_lock);
	} /* if(msg->frag_total>1) */
	

	/* If we received just a middle fragment, msg is set tu null and nothing shall happen furthermore */
	if(msg){
		cluster_msg_handler(msg,lnlb);
		kfree(msg);
	}

	return 0;

exit:
	if(msg){
		if(msg->data)
		kfree(msg->data);
		kfree(msg);
	}

	if(skb)
	dev_kfree_skb(skb);
	return 0;
}


/*
*Lookup a node from a table by MAC address.
*Note: The function is not table safe... caller must lock the table
*/
static struct lnlb_node_table_entry* seek_node_from_table(struct lnlb_struct *iDev,unsigned char *node_mac)
{
	int i;
	struct lnlb_node_table_entry* res=NULL;

	for(i=0;i<iDev->node_table.size;i++)
	{
		if(compare_ether_addr(node_mac,iDev->node_table.entry[i].hw_addr)==0)
		{
			res=&(iDev->node_table.entry[i]);
			break;
		}
	}

	return res;
}

/* Compare two entries of node table... used for sorting */
static int cmp_node_table_entries(const void *i1,const void *i2)
{

	struct lnlb_node_table_entry *e1=(struct lnlb_node_table_entry *)i1;
	struct lnlb_node_table_entry *e2=(struct lnlb_node_table_entry *)i2;
	return memcmp(e1->hw_addr,e2->hw_addr,ETH_ALEN); /* Treat MAC addresses as string... should be fine for sorting */
}

/* Swap two entries of node table... used for sorting */
static void swap_node_table_entries(void *i1,void *i2,int iSize)
{
	struct lnlb_node_table_entry *e1=(struct lnlb_node_table_entry *)i1;
	struct lnlb_node_table_entry *e2=(struct lnlb_node_table_entry *)i2;
	struct lnlb_node_table_entry t;
	t=*e1;
	*e1=*e2;
	*e2=t;
}

/*
* Add a node to the table.
* Returns a pointer to the new entry (NULL if error)
* The function is not table safe... caller must lock the table
*/
static struct lnlb_node_table_entry* add_node_to_table(struct lnlb_struct *iDev,unsigned char *iNode_mac)
{
	int pos;

	pos=iDev->node_table.size;
	if(pos >= LNLB_MAX_NODES)
	return NULL;

	memcpy(iDev->node_table.entry[pos].hw_addr,iNode_mac,ETH_ALEN);
	iDev->node_table.entry[pos].status=LNLB_NS_JOINING;
	iDev->node_table.entry[pos].weight=LNLB_WEIGHT_DEFAULT;
	iDev->node_table.size++;

	sort(iDev->node_table.entry,iDev->node_table.size,sizeof(struct lnlb_node_table_entry),&cmp_node_table_entries,&swap_node_table_entries);
	return seek_node_from_table(iDev,iNode_mac);
}

static void delete_dead_nodes_from_table(struct lnlb_struct *iDev)
{
	int i;
	struct lnlb_node_table_entry t[LNLB_MAX_NODES];
	int newsize=0;

	for(i=0;i<iDev->node_table.size;i++)
	{
		if(iDev->node_table.entry[i].status==LNLB_NS_DEAD)
		continue;
		t[newsize]=iDev->node_table.entry[i];
		newsize++;
	}
	iDev->node_table.size=newsize;
	for(i=0;i<newsize;i++)
	iDev->node_table.entry[i]=t[i];
}
/*
static void dump_table(struct lnlb_struct *iDev)
{
int i;
unsigned char *h;
DBG("---Node Table Dump---\n");
for(i=0;i<iDev->node_table.size;i++)
	{
	h=iDev->node_table.entry[i].hw_addr;
	DBG("%X:%X:%X:%X:%X:%X -> Weight:%d\tstatus:%d\n",h[0],h[1],h[2],h[3],h[4],h[5],iDev->node_table.entry[i].weight,iDev->node_table.entry[i].status);
	}
DBG("---End of Table Dump---\n");
}
*/
/*------------------------------------------------------------------------------------------------------------------------*
						ProcFS interface
*------------------------------------------------------------------------------------------------------------------------*/
static int proc_read_callback(char *iPage, char **iStart, off_t iOffset,
int iCount, int *iEof, void *iData)
{
	int i,ret;
	struct lnlb_struct *lnlb,*nxt;
	unsigned char *h;
	unsigned long len=0;
	unsigned long entrycount=0;
	char *buf;

	list_for_each_entry_safe(lnlb, nxt, &dev_list, list)
	entrycount+=lnlb->node_table.size;

	buf=(char *)kmalloc(entrycount*64,GFP_KERNEL);
	if(!buf)
	{
		*iEof=1;
		return 0;
	}

	/* We can skip the lock on node_table... entry[] is a fixed sized array... in the worse case we get a dirty entry*/
	list_for_each_entry_safe(lnlb, nxt, &dev_list, list)
	{
		len+=sprintf(buf+len,"Interface: %s\n",lnlb->dev->name);
		for(i=0;i<lnlb->node_table.size;i++)
		{
			h=lnlb->node_table.entry[i].hw_addr;
			len+=sprintf(buf+len,"\t%X:%X:%X:%X:%X:%X -> Weight:%d\tstatus:%d\n",DUMPMAC(h),lnlb->node_table.entry[i].weight,lnlb->node_table.entry[i].status);
		}
		len+=sprintf(buf+len,"\n");
	}

	*iStart=iPage;
	if(iOffset>=len)
	{
		*iEof=1;
		ret=0;
	}
	else if(iOffset+iCount<len)
	{
		memcpy(iPage,buf+iOffset,iCount);
		ret=iCount;
		*iEof=0;
	}
	else
	{
		memcpy(iPage,buf+iOffset,len-iOffset);
		ret=len-iOffset;
		*iEof=1;
	}

	kfree(buf);
	return ret;

}

static int proc_write_callback(struct file *iFile,const char __user * iBuffer,
unsigned long iCount, void *iData)
{
	int ret=0;
	int copy_to_user_ret; /* To make gcc happy */
	struct lnlb_cmd cmd,cmd_reply;
	char *outBuf;

	if(iCount<sizeof(struct lnlb_cmd))
	return -EINVAL;

	if (copy_from_user(&cmd, iBuffer, sizeof(struct lnlb_cmd)))
	return -EINVAL;

	memset(&cmd_reply,0,sizeof(struct lnlb_cmd));
	outBuf=((struct lnlb_cmd *)iBuffer)->reply;

	switch(cmd.cmd)
	{
	case LNLB_CMD_ADDIF:
		{
			struct net_device* bind_dev;
			struct lnlb_struct *newIf=NULL;
			#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
			bind_dev=dev_get_by_name(&init_net,(char *) cmd.parm1);
			#else
			bind_dev=dev_get_by_name(cmd.parm1);
			#endif
			if(bind_dev==NULL) return -EINVAL;
			instantiate_new_device(cmd.parm2,bind_dev,&newIf);
			if(ret)
			return ret;
			device_set_ip(newIf,*((__be32 *)cmd.parm3));

			/*Fill the reply*/
			copy_to_user_ret=copy_to_user(outBuf,newIf->dev->name,strlen(newIf->dev->name)+1); /* IFNAMESIZE always < LNLB_PARM_LEN */
		}
		break;

	case LNLB_CMD_DELIF:
		{
			return delete_device(cmd.parm1);
		}
		break;

	case LNLB_CMD_SETWEIGHT:
		{
			struct lnlb_struct *lnlb=lnlbif_by_name(cmd.parm1);
			if(lnlb==NULL) return -EINVAL;
			if(lnlb->weight_mode!=WM_MANUAL)
			return -EINVAL;
			lnlb->weight=*((lnlb_weight_t*)cmd.parm2);
		}
		break;

	case LNLB_CMD_SETWEIGHTMODE:
		{
			struct lnlb_struct *lnlb=lnlbif_by_name(cmd.parm1);
			if(lnlb==NULL) return -EINVAL;
			lnlb->weight_mode=*((enum lnlb_weight_mode*)cmd.parm2);
		}
		break;
	case LNLB_CMD_RESYNC_CONNTRACK:
		{
			struct lnlb_struct *lnlb=lnlbif_by_name(cmd.parm1);
			if(lnlb==NULL) return -EINVAL;
			local_bh_disable();
			broadcast_conntrack_status(lnlb);
			local_bh_enable();
		}
		break;		
	default:
		{
			DBG("Unknown cmd %d\n",cmd.cmd);
		}
	}

	return iCount;
}

static int init_procfs(void)
{
	
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	       proc_file=create_proc_entry(LNLB_PROC_FILE, 0644, init_net.proc_net);
	#else
	       proc_file=create_proc_entry(LNLB_PROC_FILEPATH, 0644, NULL);
	#endif	
	if(proc_file == NULL)
	return -ENOMEM;

	proc_file->owner=THIS_MODULE;
	proc_file->read_proc = &proc_read_callback;
	proc_file->write_proc = &proc_write_callback;
	return 0;
}

static void cleanup_procfs(void)
{
	remove_proc_entry(LNLB_PROC_FILE, NULL);
}
/*------------------------------------------------------------------------------------------------------------------------*
					Protocol handler interface
*------------------------------------------------------------------------------------------------------------------------*/
/* Register a protocol handler for IP datagram delivery (e.g. TCP handler, UDP handler, etc...) */
int lnlb_register_ph(uint8_t iProto,struct lnlb_protocol_module *iMod)
{
	int ret=1;

	write_lock_bh(&proto_modules_lock);
	if(proto_modules[iProto]!=NULL)
	goto exit;
	proto_modules[iProto]=iMod;
	if(iProto==0)
	DBG("Default protocol handler module registered\n");
	else
	DBG("Protocol handler module registered for protocol %d\n",iProto);
	ret=0;
	proto_modules_installed++;
exit:
	write_unlock_bh(&proto_modules_lock);
	return ret;

}
EXPORT_SYMBOL(lnlb_register_ph);

/* Unregister a protocol handler */
void lnlb_unregister_ph(uint8_t iProto)
{
	write_lock_bh(&proto_modules_lock);
	if(proto_modules[iProto]!=NULL)
	{
		proto_modules[iProto]=NULL;
		proto_modules_installed--;
	}
	write_unlock_bh(&proto_modules_lock);
}
EXPORT_SYMBOL(lnlb_unregister_ph);

/* Return a lnlb_struct looking up its interface name (NULL if not found) */
static struct lnlb_struct * lnlbif_by_name(const char *iName)
{
	struct lnlb_struct *lnlb,*nxt;
	list_for_each_entry_safe(lnlb, nxt, &dev_list, list)
	{
		if(strcmp(iName,lnlb->dev->name)==0)
		return lnlb;
	}
	return NULL;
}

/* Return a lnlb_struct looking up its cluster ip (NULL if not found) */
static struct lnlb_struct * lnlbif_by_ip(__be32 iIp)
{
	struct lnlb_struct *lnlb,*nxt;
	list_for_each_entry_safe(lnlb, nxt, &dev_list, list)
	{
		if(lnlb->cluster_ip==iIp)
		return lnlb;
	}
	return NULL;
}

/* The frame hook function that catches frames in unicast mode */
static int unicast_frame_hook(struct sk_buff *iSkb, struct net_device *iIfp, struct packet_type *iPt, struct net_device *iOrig_dev)
{

	struct lnlb_struct *lnlb;

	iSkb = skb_share_check(iSkb, GFP_ATOMIC);
	if (iSkb == NULL)
	return 0;

	switch(lnlb_by_skb(iSkb,iIfp,&lnlb))
	{
	case 1:
		goto drop_skb;
	case 2:
		goto drop_skb; /* Apparently a bug... remember that dev_add_pack can not filter skb's from the networking stack...
			* we're just freeing the cloned skb */
	}

	switch(skb_node_affinity(lnlb,iSkb,lnlb->converging))
	{
	case 0:
		pass_skb_to_vdevice(iSkb,lnlb);
		return 0;
	case 1:
		goto drop_skb;
	case 2:
		return 0;
	default: /* To make gcc happy */
		goto drop_skb;
	}
	return 0;

	drop_skb:
	dev_kfree_skb(iSkb);
	return 0;

}

/* The netfilter hook that performs sanity check and catches frames if multicast mode */
static unsigned int netfilter_frame_hook
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
(unsigned int iHooknum, struct sk_buff *iSkbPtr, const struct net_device *iIn, const struct net_device *iOut, int (*iOkfn)(struct sk_buff *))
{
	struct sk_buff *iSkb=iSkbPtr;
#else
(unsigned int iHooknum, struct sk_buff **iSkbPtr, const struct net_device *iIn, const struct net_device *iOut, int (*iOkfn)(struct sk_buff *))
{
	struct sk_buff *iSkb=*iSkbPtr;
#endif
	struct lnlb_struct *lnlb;
	struct lnlb_struct *liter,*nxt;

	/* First of all we must assure that no datagram destined to cluster IP is delivered throught the real (e.g. eth0) MAC... this should never happen, except for some strange ARP mess between cluster and remote host*/
	if(eth_hdr(iSkb)->h_proto == __constant_htons(ETH_P_IP))
	{

		list_for_each_entry_safe(liter, nxt, &dev_list, list)
		{
			//DBG("%u.%u.%u.%u  - %u.%u.%u.%u     %X:%X:%X:%X:%X:%X   -  %X:%X:%X:%X:%X:%X\n",NIPQUAD(liter->cluster_ip),NIPQUAD(IP_HDR(iSkb)->daddr),DUMPMAC(liter->cluster_mac),DUMPMAC(eth_hdr(iSkb)->h_dest));
			if(IP_ADDRESS_COMPARE(liter->cluster_ip,IP_HDR(iSkb)->daddr)==0
					&& compare_ether_addr(liter->cluster_mac,eth_hdr(iSkb)->h_dest) )
			{
				return NF_DROP; //Dest IP matches cluster IP, but dest MAC not
			}
		}
	}

	/* Process here only if we're in multicast mode */
	if(!mode_unicast)
	{
		switch(lnlb_by_skb(iSkb,iIn,&lnlb))
		{
		case 1:
			return NF_DROP;
		case 2:
			return NF_ACCEPT;
		}

		switch(skb_node_affinity(lnlb,iSkb,lnlb->converging))
		{
		case 0:
			pass_skb_to_vdevice(iSkb,lnlb);
			return NF_STOLEN;
		case 1:
			return NF_DROP;
		case 2:
			return NF_STOLEN;
		default: /* To make gcc happy */
			return NF_DROP;
		}
	}
	else
	return NF_ACCEPT;
}

/* Parse a sk_buff (typically received by unicast/multicast frame hook) and determine if it's a cluster related frame
* iSkb: the sk_buff to parse
* iNetDev: the net_device where the sk_buff was received on
* oLnlb: the resulting lnlb struct
* Return: 0=sk_buff is cluster related / 1=bad skb (drop it) / 2=sk_buff is anything else (deliver it)
*/
static int lnlb_by_skb (const struct sk_buff *iSkb,const struct net_device *iNetDev,struct lnlb_struct **oLnlb)
{
	struct lnlb_struct *liter,*nxt;

	*oLnlb=NULL;
	list_for_each_entry_safe(liter, nxt, &dev_list, list)
	{
		//DBG("%X:%X:%X:%X:%X:%X  ==  %X:%X:%X:%X:%X:%X   --> %d\n",liter->cluster_mac[0],liter->cluster_mac[1],liter->cluster_mac[2],liter->cluster_mac[3],liter->cluster_mac[4],liter->cluster_mac[5],iSkb->mac.raw[0],iSkb->mac.raw[1],iSkb->mac.raw[2],iSkb->mac.raw[3],iSkb->mac.raw[4],iSkb->mac.raw[5],compare_ether_addr(liter->cluster_mac,eth_hdr(iSkb)->h_dest));
		if(compare_ether_addr(liter->cluster_mac,eth_hdr(iSkb)->h_dest)==0)
		{

			if(liter->bind_dev==iNetDev)
			*oLnlb=liter;
			else
			{
				//DBG("Other if %s %s\n",liter->bind_dev->name,iNetDev->name); 
				return 1; /* Drop if the frame is not arrived on the real device that is bound to current VIP */
			}

			break;
		}
	}

	/* If dst MAC is not one of the virtual interfaces, skip it */
	if(*oLnlb==NULL)
	return 2;

	if(eth_hdr(iSkb)->h_proto != __constant_htons(ETH_P_IP))
	{
		return 1; /* Actually we can't treat other than IP datagrams */

	}

	return 0;
}

/* Process a sk_buff and determine if this node should accept or drop it
Return: 0=Accept the sk_buff  / 1=Drop the sk_buff /  2=Steal the sk_buff
Note: caller must tell if we're under convergence mode or not... it seems strange as it could be determined seeking
		iDev->converging. This function,however, is also called when processing queued sk_buff(s). In that circumstance
		convergence is over but iDev->converging is still 1 (will be 0 *after* the queue process). So we'll manually force
		the convergence condition
*/
static int skb_node_affinity(struct lnlb_struct* iDev,struct sk_buff* iSkb,int iConverging)
{
	struct lnlb_protocol_module *handler_mod;
	unsigned char oNodeAddr[ETH_ALEN];
	int ret=1;

	if(!iDev->join_complete)
		return 1; /* Drop all frames until the join is complete (until the first convergence start) */
		
	read_lock(&proto_modules_lock);
	handler_mod=proto_modules[IP_HDR(iSkb)->protocol];
	if(handler_mod==NULL)
	handler_mod=proto_modules[0]; /* The default protocol handler */
	if(handler_mod==NULL)
	{
		ret=1; /* Drop if there is no handler (nor the default handler) for this protocol */
		goto exit;
	}

	/*  Check if datagram is realted to a node in the cluster */
	if((*(handler_mod->dgram_is_related))(iDev,iSkb,oNodeAddr))
	{ /*  Datagram is related... now: is it related to this node or to another node? */
		if( ! compare_ether_addr(oNodeAddr,iDev->bind_dev->dev_addr))
		{
			/* It's related to this node... pass to the virtual interface */
			ret=0;
			goto exit;
		}
		else
		{
			/* It's related to another node... not me */
			ret=1;
			goto exit;
		}
	}
	else
	{
		/* Datagram is not related to any node. It's an unbounded connection */
		/* Determine if we're under convergence phase or not*/
		if(iConverging)
		{ /* We're under convergence phase... queue the sk_buff for later processing */

			/* If the list if full, dequeue the first skbuff in order to mantain list size */
			if(skb_queue_len(&iDev->rx_queue) >= LNLB_MAX_RXQUEUE)
			{
				struct sk_buff *deq_skb;
				iDev->stats.rx_dropped++;
				deq_skb=skb_dequeue(&iDev->rx_queue);
				
				if(deq_skb)
				dev_kfree_skb(deq_skb);
			}

			skb_queue_tail(&iDev->rx_queue,iSkb);
			ret=2; /* Steal for later processing */
			goto exit;
		}
		else
		{
			/* We can process the sk_buff */

			/* Assign datagram to a node */
			if(find_related_node(iDev,iSkb,oNodeAddr))
			{
				ret=1; /* Some memory error has occoured */
				goto exit;
			}

			(*(handler_mod->dgram_assigned))(iDev,iSkb,oNodeAddr); /*Notify the handling module that the sk_buff has been assigned to oNodeAddr node */

			/* Check if datagram has been assigned to this node or not */
			if(compare_ether_addr(oNodeAddr,iDev->bind_dev->dev_addr))
			ret=1; /* Datagram has been assigned to another node */
			else
			ret=0; /* Datagram has been assigned to this node */
			goto exit;
		}
	}
exit:
	read_unlock(&proto_modules_lock);
	return ret;

}

/* Determine which node "wins the election" for the given iSkb (Node MAC is copied out into oNodeAddr)
* Note: always called from softirq
*/
static int find_related_node(struct lnlb_struct* iDev,struct sk_buff * iSkb,unsigned char *oNodeAddr)
{
	uint32_t hash;
	int i,node_idx=-1;
	hash=jhash2(&(IP_HDR(iSkb)->saddr),1,0); /* Hash the source IP address */

	BUG_ON(iDev->cut_table_sum==0);

	read_lock(&(iDev->cut_table.lock));
	hash=hash % iDev->cut_table_sum; /* This gives an uniformly distributed number between 0 and cut_table_sum-1) */
	for(i=0;i<iDev->cut_table.size;i++)
	{
		lnlb_weight_t w=iDev->cut_table.entry[i].weight;
		if(hash<w)
		{
			node_idx=i;
			break;
		}
		else
		hash-=w;
	}
	read_unlock(&(iDev->cut_table.lock));

	if(node_idx<0)
	{
		BUG_ON(1);
		goto err;
	}

	memcpy(oNodeAddr,iDev->cut_table.entry[node_idx].hw_addr,ETH_ALEN);
	DBG("Src IP %u.%u.%u.%u -> %X:%X:%X:%X:%X:%X\n",NIPQUAD(IP_HDR(iSkb)->saddr),DUMPMAC(oNodeAddr));

	return 0;
err:

	return 1;
}

static unsigned int arp_mangle
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
(unsigned int iHooknum, struct sk_buff *iSkb, const struct net_device *iIn, const struct net_device *iOut, int (*iOkfn)(struct sk_buff *))
{
	struct arphdr *arp = ARP_HDR(iSkb);
#else
(unsigned int iHooknum, struct sk_buff **iSkb, const struct net_device *iIn, const struct net_device *iOut, int (*iOkfn)(struct sk_buff *))
{
	struct arphdr *arp = ARP_HDR(*iSkb);
#endif
	struct arp_payload *payload;
	struct lnlb_struct *liter,*lnlb,*nxt;

	/* skip non-ethernet and non-ipv4 ARP */
	if (arp->ar_hrd != htons(ARPHRD_ETHER)
			|| arp->ar_pro != htons(ETH_P_IP)
			|| arp->ar_pln != 4 || arp->ar_hln != ETH_ALEN)
	return NF_ACCEPT;

	/* Mangle just ARP replies */
	if (arp->ar_op != htons(ARPOP_REPLY))
	return NF_ACCEPT;

	payload = (void *)(arp+1);
	lnlb=NULL;
	/* Check IP to match against any cluster ip on our interfaces */
	list_for_each_entry_safe(liter, nxt, &dev_list, list)
	{

		if(IP_ADDRESS_COMPARE(liter->cluster_ip,payload->src_ip)==0) 
		lnlb=liter;
	}

	if(lnlb==NULL)
	return NF_ACCEPT;

	/* If IP matches our cluster ip, mangle the src MAC address */
	memcpy(payload->src_hw, lnlb->cluster_mac, arp->ar_hln);
	return NF_ACCEPT;
}

/* Set the cluster IPv4 for the device */
static void device_set_ip(struct lnlb_struct *iDev,__be32 iAddr)
{
	int i;
	
	iDev->cluster_ip=iAddr;
	ip_to_mac(iAddr,iDev->cluster_mac);
	memcpy(iDev->dev->dev_addr,iDev->cluster_mac,ETH_ALEN);
	
	printk(KERN_INFO DRV_NAME ": Interface %s binding to IP %u.%u.%u.%u (MAC %X:%X:%X:%X:%X:%X)\n",iDev->dev->name,NIPQUAD(iAddr),DUMPMAC(iDev->cluster_mac));

	iDev->heartbeat_timer.expires = NEXT_HB_TIMER;
	add_timer(&iDev->heartbeat_timer);

	/*Send the join message on the network*/
	for(i=0;i<JOIN_MSG_REPEAT;i++)
	{
		broadcast_join(iDev);
		msleep(JOIN_MSG_MDELAY);
	}
}

/* Add a frame hook for a given network interface (returns if an hook for that interface already exists)
* Note: the function is not SAFE. The caller calls it in a rtln_lock/unlock block
*/
static int add_interface_hook(struct net_device *iDev)
{

	struct lnlb_struct *lnlb,*nxt;
	struct dev_hook *devhook;
	/* If another hook for the same interface exits, just return */
	list_for_each_entry_safe(lnlb, nxt, &dev_list, list)
	{if(lnlb->bind_dev == iDev) return 0;}

	init_netfilter_hook();  /* This can be called more than a time... works only the first time */
	devhook=(struct dev_hook *)kmalloc(sizeof(struct dev_hook),GFP_KERNEL);
	if(!devhook)
	return -ENOMEM;

	devhook->dev=iDev;
	devhook->heartbeat_ptype.type=__constant_htons(ETH_P_LNLB);
	devhook->heartbeat_ptype.func=&heartbeat_frame_hook;
	devhook->heartbeat_ptype.dev = iDev;
	dev_add_pack(&devhook->heartbeat_ptype);

	dev_set_promiscuity(iDev,1);

	/* Netfilter is not able to catch frames not destined to our MAC... even in promiscuous mode ... so a dev_add_pack is needed*/
	if(mode_unicast)
	{
		devhook->unicast_ptype.type = __constant_htons(ETH_P_IP);
		devhook->unicast_ptype.func = &unicast_frame_hook;
		devhook->unicast_ptype.dev=iDev;
		dev_add_pack(&devhook->unicast_ptype);
	}
	list_add(&devhook->list,&dev_hook_list);

	return 0;
}

/*  Delete a hook for an eth device (only if no other dev is hooking on the same interface)
*  Note: the function is not SAFE. The caller calls it in a rtln_lock/unlock block
*/
static void del_interface_hook(struct net_device *iDev)
{
	struct lnlb_struct *lnlb,*nxt;
	struct dev_hook *devhook,*devhookn;

	list_for_each_entry_safe(lnlb, nxt, &dev_list, list)
	{if(lnlb->bind_dev == iDev) return;}

	/* No other interface is using the real device (e.g. eth0) */


	list_for_each_entry_safe(devhook,devhookn,&dev_hook_list,list)
	{
		if(devhook->dev!=iDev) continue;

		dev_remove_pack(&devhook->heartbeat_ptype);
		dev_set_promiscuity(iDev,-1);
		if(mode_unicast)
		{
			dev_remove_pack(&devhook->unicast_ptype);
		}
		list_del(&devhook->list);
		kfree(devhook);
	}

	if(list_empty(&dev_list))
	clear_netfilter_hook(); /* The netfilter hook is unique for all interfaces... so we should remove it when no more virtual interfaces are loaded */
}

/* Delete a virtual device (typically upon nbctl del ...)
*  iName: Name of virtual device (e.g. nlb0).
*/

static int delete_device(char *iName)
{
	struct lnlb_struct *lnlb, *nxt;
	struct lnlb_cluster_msg *mptr,*mptrloop;
	int i;
	int ret=-EINVAL;

	rtnl_lock();
	list_for_each_entry_safe(lnlb, nxt, &dev_list, list)
	{
		if(strncmp(lnlb->dev->name,iName,IFNAMSIZ)==0)
		{
			DBG("Deleting device %s\n",lnlb->dev->name);
			broadcast_leave(lnlb);
			del_timer_sync(&lnlb->heartbeat_timer);
			del_timer_sync(&lnlb->timeout_timer);
			list_del(&lnlb->list);
			del_interface_hook(lnlb->bind_dev);
			skb_queue_purge(&lnlb->rx_queue);

			/* Advertise modules of interface removal */
			read_lock_bh(&proto_modules_lock);
			for(i=0;i<PROTO_MODULES_UBOUND;i++)
			{
				if(proto_modules[i]==NULL) continue;
				(*(proto_modules[i]->interface_deleted))(lnlb);
			}
			read_unlock_bh(&proto_modules_lock);
			
			/* Free the large-heartbeats fragments buffer */
			spin_lock_bh(&lnlb->frag_list_lock);
			for(i=0;i<LNLB_MAX_MSGID;i++){
				list_for_each_entry_safe(mptr, mptrloop, &lnlb->frag_list[i], list){
					list_del(&mptr->list);
					if(mptr->len>0 && mptr->data)
					kfree(mptr->data);
					kfree(mptr);
				}
			}
			spin_unlock_bh(&lnlb->frag_list_lock);
			
			msleep(100); /* For safety reasons... in a SMP environment could avoid races */
			unregister_netdevice(lnlb->dev);
			printk(KERN_INFO DRV_NAME ": Device %s removed\n",lnlb->dev->name);
			ret=0;
		}
	}
	rtnl_unlock();
	return ret;
}

/* Instantiate a new virtual device (typically upon nblctl add ...)
*  iName: Name of virtual device (e.g. nlb0). Supports %d naming (e.g. nlb%d)
*  iBindDev: network device to bind to (e.g. etho)
*  oStruct: resulting lnlb_struct of new device (can be NULL)
*/
static int instantiate_new_device(char* iName,struct net_device* iBindDev,struct lnlb_struct** oStruct)
{
	int err=0;
	int i;
	struct lnlb_struct *lnlb;
	struct net_device *dev;
	struct lnlb_node_table_entry* my_entry;

	rtnl_lock();
	dev=alloc_netdev(sizeof(struct lnlb_struct),iName,setup_dev_callback);
	if (!dev)
	{
		rtnl_unlock();
		return -ENOMEM;
	}
	lnlb=netdev_priv(dev); /* Retrieve the allocated private data pointer where we hold the lnlb_struct*/
	lnlb->dev = dev;
	lnlb->bind_dev=iBindDev;
	lnlb->weight=LNLB_WEIGHT_DEFAULT;
	lnlb->weight_mode=WM_LOADAVG;

	lnlb->join_complete=0;
	lnlb->converging=0;
	lnlb->node_table.size=0;
	lnlb->cut_table.size=0;
	lnlb->node_table.lock=RW_LOCK_UNLOCKED;
	lnlb->cut_table.lock=RW_LOCK_UNLOCKED;
	skb_queue_head_init(&lnlb->rx_queue);
	/* Initialize frag_list to store long heartbeat messages */
	lnlb->frag_list_lock=SPIN_LOCK_UNLOCKED;
	for(i=0;i<LNLB_MAX_MSGID;i++)
	INIT_LIST_HEAD(&lnlb->frag_list[i]);
	/* Initialize the timers */
	setup_timer(&lnlb->heartbeat_timer, &heartbeat_timer, (unsigned long)lnlb);
	setup_timer(&lnlb->timeout_timer, &convergence_timeout_timer, (unsigned long)lnlb);


	my_entry=add_node_to_table(lnlb,lnlb->bind_dev->dev_addr); /* There is no need to lock the table since we're sure at this point no one will use it */
	if(!my_entry){
		rtnl_unlock();
		return -ENOMEM;
	}
	/* Network Device initialization */
	dev->hard_header_len = 0;
	dev->addr_len = ETH_ALEN;
	memcpy(dev->dev_addr,"\0\0\0\0\0\0",6);
	dev->mtu = iBindDev->mtu;
	dev->type = ARPHRD_NONE;	/* Zero header length */
	dev->flags = IFF_NOARP;

	if (strchr(dev->name, '%'))
	{
		err = dev_alloc_name(dev, dev->name);
		if (err < 0)
		{
			rtnl_unlock();
			free_netdev(dev);
			return err;
		}
	}

	err=register_netdevice(dev);

	if(err<0)
	{
		free_netdev(dev);
		DBG("Could not register net device\n");
		rtnl_unlock();
		return err;
	}

	err=add_interface_hook(iBindDev);
	if(err)
	{
		rtnl_unlock();
		return err;
	}

	list_add(&lnlb->list,&dev_list);

	if(oStruct)
	*oStruct=lnlb;

	rtnl_unlock();

	/* Advertise modules of interface creation */

	read_lock_bh(&proto_modules_lock);
	for(i=0;i<PROTO_MODULES_UBOUND;i++)
	{
		if(proto_modules[i]==NULL) continue;
		(*(proto_modules[i]->interface_created))(lnlb);
	}
	read_unlock_bh(&proto_modules_lock);
	return err;
}

static void ip_to_mac(__be32 iIP,unsigned char *oMAC)
{
	if(mode_unicast)
	{
		oMAC[0]=0x02;
		oMAC[1]=0x00;
		memcpy(oMAC+2,&iIP,4);
	}
	else
	{
		oMAC[0]=0x01;
		oMAC[1]=0x00;
		oMAC[2]=0x5E;
		oMAC[3]=0x7F;
		memcpy(oMAC+4,&iIP,2); 
	}
}

static int init_netfilter_hook(void)
{
	int ret=0;
	if(arp_mangle_hook)
	return 0; /*Netfilter hook already initialized */

	DBG("Initializing ARP mangle hook\n");
	arp_mangle_hook=kmalloc(sizeof(struct nf_hook_ops),GFP_KERNEL);
	memset(arp_mangle_hook,0,sizeof(struct nf_hook_ops));
	arp_mangle_hook->hook=arp_mangle;
	arp_mangle_hook->pf=NF_ARP;
	arp_mangle_hook->owner=THIS_MODULE;
	arp_mangle_hook->hooknum=NF_ARP_OUT;
	arp_mangle_hook->priority=INT_MIN; //TODO: it this the right priority?
	ret=nf_register_hook(arp_mangle_hook);
	if(ret)
	return ret;

	DBG("Initializing netfilter hook\n");
	netfilter_hook=kmalloc(sizeof(struct nf_hook_ops),GFP_KERNEL);
	memset(netfilter_hook,0,sizeof(struct nf_hook_ops));
	netfilter_hook->hook=netfilter_frame_hook; /*The callback function */
	netfilter_hook->hooknum = NF_IP_PRE_ROUTING;
	netfilter_hook->pf = PF_INET;
	netfilter_hook->owner = THIS_MODULE;
	netfilter_hook->priority = NF_IP_PRI_FIRST; //TODO: is this the right priority?
	ret=nf_register_hook(netfilter_hook);
	if(ret)
	return ret;

	return 0;
}

static void clear_netfilter_hook(void)
{
	if(!arp_mangle_hook)
	return;
	DBG("Clearing netfilter hook\n");
	nf_unregister_hook(netfilter_hook);
	kfree(netfilter_hook);

	nf_unregister_hook(arp_mangle_hook);
	kfree(arp_mangle_hook);
	netfilter_hook=NULL;
	arp_mangle_hook=NULL;
}

/*------------------------------------------------------------------------------------------------------------------------*
					Network device interface
*------------------------------------------------------------------------------------------------------------------------*/
/* Net device open. */
static int net_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

/* Net device close. */
static int net_close(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

/* Net device start xmit */
static int net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	return 0;
}

/* Net device statistics */
static struct net_device_stats *net_stats(struct net_device *dev)
{
	struct lnlb_struct *lnlb = netdev_priv(dev);
	return &lnlb->stats;
}

/*------------------------------------------------------------------------------------------------------------------------*
											Ethtool interface
*------------------------------------------------------------------------------------------------------------------------*/
static int ei_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->supported= 0;
	cmd->advertising	= 0;
	cmd->speed		= SPEED_1000;
	cmd->duplex		= DUPLEX_FULL;
	cmd->port		= PORT_TP;
	cmd->phy_address	= 0;
	cmd->transceiver	= XCVR_INTERNAL;
	cmd->autoneg		= AUTONEG_DISABLE;
	cmd->maxtxpkt		= 0;
	cmd->maxrxpkt		= 0;
	return 0;
}

static void ei_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strcpy(info->driver, DRV_NAME);
	strcpy(info->version, DRV_VERSION);
	strcpy(info->fw_version, "N/A");
	strcpy(info->bus_info, DRV_NAME);
}

static u32 ei_get_link(struct net_device *dev)
{
	return 1;
}

/* This function is called back by the alloc_netdev function in instantiate_new_device function */
static void setup_dev_callback(struct net_device *iDev)
{
	//SET_MODULE_OWNER(iDev);
	iDev->open = net_open;
	iDev->hard_start_xmit = net_xmit;
	iDev->stop = net_close;
	iDev->get_stats = net_stats;
	iDev->ethtool_ops = &lnlb_ethtool_ops;
	iDev->destructor = free_netdev;
}

static int __init drv_init(void)
{
	printk(KERN_INFO DRV_NAME ": %s, %s\n", DRV_DESCRIPTION, DRV_VERSION);
	printk(KERN_INFO DRV_NAME ": %s\n", DRV_AUTHOR);

	init_procfs();
	return 0;
}

static void drv_cleanup(void)
{
	struct lnlb_struct *lnlb, *nxt;
	cleanup_procfs();
	clear_netfilter_hook();

	list_for_each_entry_safe(lnlb, nxt, &dev_list, list)
	delete_device(lnlb->dev->name);
}

module_init(drv_init);
module_exit(drv_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_AUTHOR);
MODULE_LICENSE("GPL");
