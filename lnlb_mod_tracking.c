/*
* LNLB - Linux Network Load Balancing - Default conntrack module
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
#define DRV_NAME	"lnlb_mod_tracking"
#define DRV_VERSION	"0.1.2-beta"
#define DRV_DESCRIPTION	"LNLB default conntrack module"
#define DRV_AUTHOR	"Primiano Tucci <mail@primianotucci.com>"

#include <linux/module.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/jhash.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/list.h>
#include <linux/in.h>
#include <linux/timer.h>
//<linux/if_lnlb.h>
#include "if_lnlb.h"


#define HASH_TABLE_SIZE 1024
/* Idle Time after  a connection is marked as dead and removed from hash tables */
#define CONNTRACK_IDLE_TIMEOUT_DEFAULT 1800
#define TIMEOUT_CHECK_TIMER 30
/* Max 1 week desyncronization allowed between nodes */
#define TIMEDIFF_MAX 604800
#define PROC_FILE "net/lnlb_conntrack"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
# define IP_HDR(skb) ip_hdr(skb)
#else
# define IP_HDR(skb) ((skb)->nh.iph)
#endif

#ifndef ABS
# define ABS(a) (((a) < 0) ? -(a) : (a))
#endif

static int conntrack_idle_timeout=CONNTRACK_IDLE_TIMEOUT_DEFAULT;
module_param(conntrack_idle_timeout,int,0444);
MODULE_PARM_DESC(conntrack_idle_timeout,"Idle time (in seconds) after a connection is deleted from conntrack tables.");

struct hentry
{
	struct hlist_node hlist;
	__be32 srcip; /* Source ip */
	unsigned char node[ETH_ALEN]; /* Node related to this connection */
	uint32_t last_seen;
};

struct entry_saverestore /* Seems a copy/paste of struct hentry... it's done for optimization */
{
	__be32 srcip; /* Source ip */
	unsigned char node[ETH_ALEN]; /* Node related to this connection */
	time_t last_seen;
};

struct dev_entry
{
	struct list_head list;
	const struct lnlb_struct *ref_lnlb;
	struct hlist_head hash_table[HASH_TABLE_SIZE];
	rwlock_t hash_lock;
};



/*------------------------------------------------------------------------------------------------------------------------
							Prototypes
*------------------------------------------------------------------------------------------------------------------------*/
static int __init drv_init(void);
static void drv_cleanup(void);
static void interface_deleted(const struct lnlb_struct *);
static void interface_created(const struct lnlb_struct *);
static int dgram_is_related(const struct lnlb_struct*,struct sk_buff *,unsigned char *);
static void dgram_assigned(const struct lnlb_struct *,struct sk_buff *,unsigned char *);
static void node_died(const struct lnlb_struct *,unsigned char *);
static uint32_t save_status(const struct lnlb_struct* ,char **);
static int load_status(const struct lnlb_struct* ,char *,uint32_t );
static struct dev_entry* add_interface(const struct lnlb_struct *);
static struct dev_entry* seek_interface(const struct lnlb_struct *);
static int proc_read_callback(char *, char **, off_t, int, int *, void *);
static void cleanup_procfs(void);
static int init_procfs(void);
static inline uint32_t count_entries_in_list(struct hlist_head *);
static inline uint32_t count_hentries(struct dev_entry*);
static inline struct hentry * find_hentry(struct dev_entry *,__be32);
static inline struct hentry * add_hentry(struct dev_entry *,__be32,unsigned char *);
static inline int del_hentries(struct dev_entry *,unsigned char*);
static inline void flush_hentries(struct dev_entry*);
static inline struct hentry* add_hentry_raw(struct dev_entry *,int,struct entry_saverestore *,int32_t);
static void timeout_timer_fcn(unsigned long);


static LIST_HEAD(dev_list);
static struct proc_dir_entry* proc_file;
static DEFINE_RWLOCK(dev_list_lock);
static DEFINE_TIMER(timeout_timer,&timeout_timer_fcn,0,0);

static struct lnlb_protocol_module mod_struct={
	.node_died=&node_died,
	.dgram_is_related=&dgram_is_related,
	.dgram_assigned=&dgram_assigned,
	.interface_created=&interface_created,
	.interface_deleted=&interface_deleted,
	.save_status=&save_status,
	.load_status=&load_status,
};




/* Add an entry in the dev_list table for the current lnlb_struct */
static struct dev_entry* add_interface(const struct lnlb_struct *iDev)
{
	struct dev_entry *dev=NULL,*ptr;
	int i;

	write_lock(&dev_list_lock);
	/* Check if an entry alredy exists in list */
	list_for_each_entry(ptr, &dev_list, list)
	{
		if(ptr->ref_lnlb!=iDev)
		continue;
		
		dev=ptr;
		break;
	}
	/* If found return it without adding to list */
	if(dev)
	goto ret;

	/* Else add a new dev_entry to list */
	dev=kmalloc(sizeof(struct dev_entry),GFP_ATOMIC);
	dev->ref_lnlb=iDev;
	dev->hash_lock=RW_LOCK_UNLOCKED;

	for(i=0;i<HASH_TABLE_SIZE;i++)
	INIT_HLIST_HEAD(&dev->hash_table[i]);
	list_add(&dev->list,&dev_list);
	/* Initialize the timeout timer */
	mod_timer(&timeout_timer,HZ*TIMEOUT_CHECK_TIMER+jiffies);

ret:
	write_unlock(&dev_list_lock);
	return dev;
}

/* (Callback) Delete the entry (if found) related to the passed lnlb_struct from the dev_list */
static void interface_deleted(const struct lnlb_struct *iDev)
{
	struct dev_entry *dev;

	dev=seek_interface(iDev);
	if(!dev) return;
	write_lock(&dev_list_lock);
	list_del(&dev->list);
	kfree(dev);
	write_unlock(&dev_list_lock);
}

/* (Callback) This is a bridge function called from the main module upon new interface created */
static void interface_created(const struct lnlb_struct *iDev)
{
	add_interface(iDev);
}

/* Seek the dev_entry from dev_list related to passed lnlb_struct */
static struct dev_entry* seek_interface(const struct lnlb_struct *iDev)
{ 
	struct dev_entry *ptr,*dev=NULL;


	read_lock(&dev_list_lock);
	list_for_each_entry(ptr, &dev_list, list)
	{
		if(ptr->ref_lnlb==iDev) dev=ptr;
	}
	read_unlock(&dev_list_lock);

	if(!dev)
	dev=add_interface(iDev);

	return dev;
}

/* This function is called every TIMEOUT_CHECK_TIMER seconds and purge timed-out entries from the conntrack tables
Note: there is only a unique timer for all the lnlb interfaces (nlb0,nlb1,...) */
static void timeout_timer_fcn(unsigned long iData)
{
	struct hentry *he;
	struct hlist_node *heloop,*hetmp;
	struct dev_entry *dev,*dev_nxt;
	int i;
	long seconds=get_seconds();

	/* Loop for each virtual device (nlb0,nlb1...) */
	list_for_each_entry_safe(dev, dev_nxt, &dev_list, list)
	{
		write_lock(&dev->hash_lock);
		/* Loop for each element in the hash table */
		for(i=0;i<HASH_TABLE_SIZE;i++)
		{	
			hlist_for_each_entry_safe(he,heloop,hetmp,&dev->hash_table[i],hlist)
			{
				if(seconds-he->last_seen < conntrack_idle_timeout)
				continue;
				hlist_del(&he->hlist);
				kfree(he);
			}
		}
		
		write_unlock(&dev->hash_lock);
	}


	if( ! list_empty(&dev_list) )
	mod_timer(&timeout_timer,HZ*TIMEOUT_CHECK_TIMER+jiffies);

}

/*------------------------------------------------------------------------------------------------------------------------
											Hash table functions
*------------------------------------------------------------------------------------------------------------------------*/
/* Flush all entries in dev->hash table
Note: Function is NOT table safe... caller must properly lock the hash_lock */
static inline void flush_hentries(struct dev_entry* iDev){
	struct hentry *he;
	struct hlist_node *heloop,*hetmp;
	int i;	

	for(i=0;i<HASH_TABLE_SIZE;i++)
	{	
		hlist_for_each_entry_safe(he,heloop,hetmp,&iDev->hash_table[i],hlist)
		{
			hlist_del(&he->hlist);
			kfree(he);	     
		}
	}
}


/* Counts entries in a single hash table
Note: Function is NOT table safe... caller must properly lock the hash_lock */
static inline uint32_t count_entries_in_list(struct hlist_head *iHead){
	struct hentry *he;
	struct hlist_node *heloop;

	uint32_t entries=0;

	hlist_for_each_entry(he,heloop,iHead,hlist){
		entries++;
	}

	return entries;
}


/* Counts entries in dev->hash table
Note: Function is NOT table safe... caller must properly lock the hash_lock */
static inline uint32_t count_hentries(struct dev_entry* iDev){
	int i;
	uint32_t entries=0;

	for(i=0;i<HASH_TABLE_SIZE;i++)
	entries+=count_entries_in_list(&iDev->hash_table[i]);
	
	return entries;
}


/* Search a entry in the hash tables for the given iDev virtual interface
	Returns pointer to entry struct (NULL if not found)
Note: Function is NOT table safe... caller must properly lock the hash_lock */
static inline struct hentry * find_hentry(struct dev_entry* iDev,__be32 iIp)
{
	struct hentry *he;
	struct hlist_node *heloop;
	struct hentry *ret=NULL;

	uint32_t idx=jhash2(&iIp,1,0) & (HASH_TABLE_SIZE -1);


	hlist_for_each_entry(he,heloop,&iDev->hash_table[idx],hlist)
	{
		if(he->srcip==iIp)
		{
			ret=he;
			break;
		}
	}
	
	return ret;
}

/* Delete all entries from the hash table relative to iDev that are related to the iNodeAddr MAC 
Note: Function is NOT table safe... caller must properly lock the hash_lock */
static inline int del_hentries(struct dev_entry *iDev,unsigned char *iNodeAddr)
{
	int i;
	struct hentry *he;
	struct hlist_node *heloop,*hetmp;

	int res=0;

	for(i=0;i<HASH_TABLE_SIZE;i++)
	{
		hlist_for_each_entry_safe(he,heloop,hetmp,&iDev->hash_table[i],hlist)
		{
			if(compare_ether_addr(he->node,iNodeAddr)) continue;
			hlist_del(&he->hlist);
			kfree(he);
			res++;
		}
	}

	return res;

}

/* Add an entry to the hash table.
* Note: Function is NOT table safe... caller must properly lock the hash_lock */
static inline struct hentry* add_hentry(struct dev_entry *iDev,__be32 iSrcIp,unsigned char *iNodeAddr)
{

	struct hentry *he;

	uint32_t idx;

	he=kmalloc(sizeof(struct hentry),GFP_ATOMIC);
	if(he==NULL) return NULL;
	idx=jhash2(&iSrcIp,1,0) & (HASH_TABLE_SIZE -1);
	he->srcip=iSrcIp;
	memcpy(he->node,iNodeAddr,ETH_ALEN);
	he->last_seen=get_seconds();

	hlist_add_head(&he->hlist,&iDev->hash_table[idx]);

	//DBG("Added to tables IP %u.%u.%u.%u\n",NIPQUAD(iSrcIp));
	return he;
}

/* Add an entry to the hash table from a entry_saverestore struct (used when loading table directly from meory).
* Note: Function is NOT table safe... caller must properly lock the hash_lock */
static inline struct hentry* add_hentry_raw(struct dev_entry *iDev,int iHashIdx,struct entry_saverestore *iRaw,int32_t iTimediff)
{
	struct hentry *he;
	he=kmalloc(sizeof(struct hentry),GFP_ATOMIC);
	if(he==NULL) return NULL;
	he->srcip=iRaw->srcip;
	memcpy(he->node,iRaw->node,ETH_ALEN);
	he->last_seen=ntohl(iRaw->last_seen)+iTimediff;
	//memcpy((char *)he+ENTRY_SR_OFFSET,iRaw,sizeof(struct entry_saverestore));
	hlist_add_head(&he->hlist,&iDev->hash_table[iHashIdx]);
	return he;
}
/*------------------------------------------------------------------------------------------------------------------------
						LNLB handler interface
*------------------------------------------------------------------------------------------------------------------------*/
/* (Callback) Save the tracking table of a virtual device to a buffer
Returns: buffer size*/
static uint32_t save_status(const struct lnlb_struct* iDev,char **oPtr){
	struct dev_entry *dev=seek_interface(iDev);
	struct hentry *he;
	struct hlist_node *heloop;
	uint32_t entries=0;
	uint32_t memSize=0;
	int i;
	char *curPtr;
	
	read_lock(&dev->hash_lock);

	entries=count_hentries(dev);
	memSize=entries * sizeof(struct entry_saverestore) + 
			HASH_TABLE_SIZE * sizeof(uint32_t)+ /* Header containing number of list entries per hash table */
			sizeof(uint32_t); /* Sending timestamp */

	*oPtr=(char *)kmalloc(memSize,GFP_ATOMIC); //ATOMIC o KERNEL?
	if( ! *oPtr) {memSize=0; goto exit;}
	
	/* Resulting memory buffer:
		foreach hash table group(0...HASH_TABLE_SIZE)
			------------------------------------------------------
			| uint32_t (number of entries in this group |
			-------------------------------------------------------
			| struct entry_saverestore (Entry1 )             |
			|...                                                                     |  
				| struct entry_saverestore (EntryN )           |			
			-------------------------------------------------------
	*/
	curPtr=(*oPtr);
	
	*((uint32_t *)curPtr)=htonl(get_seconds());
	curPtr+=sizeof(uint32_t);
	
	for(i=0;i<HASH_TABLE_SIZE;i++)
	{
		entries=count_entries_in_list(&dev->hash_table[i]);
		
		*((uint32_t *)curPtr)=entries;
		curPtr+=sizeof(uint32_t);
		
		hlist_for_each_entry(he,heloop,&dev->hash_table[i],hlist){
			((struct entry_saverestore*)curPtr)->srcip=he->srcip;
			((struct entry_saverestore*)curPtr)->last_seen=htonl(he->last_seen);
			memcpy(((struct entry_saverestore*)curPtr)->node, he->node, ETH_ALEN);

			//memcpy(curPtr,(char *)he+ENTRY_SR_OFFSET,sizeof(struct entry_saverestore));
			curPtr+=sizeof(struct entry_saverestore);
		}
	}
	
	BUG_ON(curPtr-*oPtr > memSize);
	
exit:
	read_unlock(&dev->hash_lock);
	return memSize;
}

/* (Callback) Load the tracking table of a virtual device from a buffer */
static int load_status(const struct lnlb_struct* iDev,char *iBuf,uint32_t iBufSize){
	struct dev_entry *dev=seek_interface(iDev);
	uint32_t entries=0,i;
	int hash_idx;
	char *curPtr;
	char *status_backup=NULL;
	uint32_t status_backup_len=0;
	int32_t timediff;

	curPtr=iBuf;
	/* Determine time desynchronization  */
	timediff=(int32_t)(get_seconds()-ntohl(*((uint32_t *)curPtr)));
	curPtr+=sizeof(uint32_t);

	if(ABS(timediff) > TIMEDIFF_MAX){
		printk(KERN_ERR DRV_NAME " Time desynchronization between nodes exceeds maximum value (%d seconds)\n",TIMEDIFF_MAX);
		return 1;
	}
	DBG("Time diff between nodes: %d seconds\n",timediff);
	/* Backup current status... if any occours, the status we will be rolled back */
	status_backup_len=save_status(iDev,&status_backup);
	
	write_lock(&dev->hash_lock);

	flush_hentries(dev);


	for(hash_idx=0;hash_idx<HASH_TABLE_SIZE;hash_idx++){
		entries=*((uint32_t *)curPtr);
		curPtr+=sizeof(uint32_t);
		/* Check for overflows */
		if(entries==0) continue;
		
		if( (curPtr+ sizeof(struct entry_saverestore)*entries -iBuf) > iBufSize){ 
			printk(KERN_ERR DRV_NAME "Corruption in conntrack table");
			flush_hentries(dev);
			goto err;
		}
		
		/* Copy in reverse order to mantain the original hash list */
		for(i=0;i<entries;i++)
		add_hentry_raw(dev,hash_idx,(struct entry_saverestore *)(curPtr + sizeof(struct entry_saverestore)*(entries-i-1)),timediff);
		
		curPtr+=entries*sizeof(struct entry_saverestore);
	}
	write_unlock(&dev->hash_lock);
	kfree(status_backup);
	return 0;
	
err:
	write_unlock(&dev->hash_lock);
	if(status_backup_len>0 && status_backup)
	load_status(iDev,status_backup,status_backup_len); /* Rollback previous status */
	return 1;
}

/* (Callback) The main driver has received a datagram and wants to know if it's already related to any node or not
Returns: 0=is not related / 1=is related (node MAC addr copied out into oNodeAddr) */
static int dgram_is_related(const struct lnlb_struct* iDev,struct sk_buff *iSkb,unsigned char *oNodeAddr)
{
	int res=0;
	struct hentry *he;
	struct dev_entry *dev=seek_interface(iDev);

	read_lock(&dev->hash_lock);

	//iSkb->h.raw=iSkb->nh.raw+((iSkb->nh.iph->ihl)<<2);

	he=find_hentry(dev,IP_HDR(iSkb)->saddr);
	if(he!=NULL)
	{
		if(get_seconds() - he->last_seen < conntrack_idle_timeout)
		{
			res=1;
			if(oNodeAddr)
			memcpy(oNodeAddr,he->node,ETH_ALEN);
			he->last_seen=get_seconds(); /* Update the last_seen field */
		}
		
	}

	read_unlock(&dev->hash_lock);
	return res;
}

/* (Callback) The main driver notifies us that a new unbounded connection has been assigned to node iNodeAddr */
static void dgram_assigned(const struct lnlb_struct *iDev,struct sk_buff *iSkb,unsigned char *iNodeAddr)
{
	struct hentry *he;
	struct dev_entry *dev=seek_interface(iDev);
	
	//iSkb->h.raw=iSkb->nh.raw+((iSkb->nh.iph->ihl)<<2);
	write_lock(&dev->hash_lock);
	he=find_hentry(dev,IP_HDR(iSkb)->saddr);
	if(he==NULL) /* This should *always* be NULL except if it's expired but the timeout process has not flushed it yet*/
	he=add_hentry(dev,IP_HDR(iSkb)->saddr,iNodeAddr);
	else 
	{
		memcpy(he->node,iNodeAddr,ETH_ALEN);
		he->last_seen=get_seconds();
	}
	write_unlock(&dev->hash_lock);

}



/* (Callback) The main driver notifies us that a node is died */
static void node_died(const struct lnlb_struct *iDev,unsigned char *iNodeAddr)
{
	struct dev_entry *dev=seek_interface(iDev);
	
	write_lock(&dev->hash_lock);
	del_hentries(dev,iNodeAddr);
	write_unlock(&dev->hash_lock);
}

/*------------------------------------------------------------------------------------------------------------------------*
						ProcFS interface
*------------------------------------------------------------------------------------------------------------------------*/
static int proc_read_callback(char *iPage, char **iStart, off_t iOffset,
int iCount, int *iEof, void *iData)
{
	struct hentry *he;
	struct hlist_node *heloop;
	struct dev_entry *dev,*dev_nxt;
	int i,ret;
	uint32_t len=0;
	uint32_t entries=0;
	char *buf;
	uint32_t seconds;

	list_for_each_entry_safe(dev,dev_nxt,&dev_list,list)
	{
		read_lock_bh(&dev->hash_lock);
		entries+=count_hentries(dev);
		read_unlock_bh(&dev->hash_lock);
	}

	buf=(char *)kmalloc(entries*64,GFP_KERNEL);
	if(!buf)
	{
		*iEof=1;
		return 0;
	}


	seconds=get_seconds();
	list_for_each_entry_safe(dev,dev_nxt,&dev_list,list)
	{
		
		len+=sprintf(buf+len,"Interface: %s\n",dev->ref_lnlb->dev->name);
		read_lock_bh(&dev->hash_lock);
		for(i=0;i<HASH_TABLE_SIZE;i++)
		{
			hlist_for_each_entry(he,heloop,&dev->hash_table[i],hlist)
			{
				len+=sprintf(buf+len,"\t%u.%u.%u.%u\t>\t%X:%X:%X:%X:%X:%X\t\t( %u s. )\n",NIPQUAD(he->srcip),he->node[0],he->node[1],he->node[2],he->node[3],he->node[4],he->node[5],seconds - he->last_seen);
			}
		}
		len+=sprintf(buf+len,"\n");
		read_unlock_bh(&dev->hash_lock);
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

static int init_procfs(void)
{
	proc_file=create_proc_entry(PROC_FILE, 0444, NULL);
	if(proc_file == NULL)
	return -ENOMEM;

	proc_file->owner=THIS_MODULE;
	proc_file->read_proc = proc_read_callback;
	proc_file->write_proc = NULL;
	return 0;
}

static void cleanup_procfs(void)
{
	remove_proc_entry(PROC_FILE, NULL);
}

/*------------------------------------------------------------------------------------------------------------------------*
					Driver initialization/shutdown
*------------------------------------------------------------------------------------------------------------------------*/
static int __init drv_init(void)
{
	printk(KERN_INFO "lnlb: %s - %s\n", DRV_DESCRIPTION, DRV_VERSION);
	//	printk(KERN_INFO "lnlb: %s\n", DRV_AUTHOR);

	/* Initialize and register as default module */
	lnlb_register_ph(0,&mod_struct);

	init_procfs(); 
	return 0;
}

static void drv_cleanup(void)
{
	struct dev_entry *dev,*dev_nxt;

	lnlb_unregister_ph(0);

	del_timer_sync(&timeout_timer);

	cleanup_procfs();
	/* Cleanup hash tables */
	list_for_each_entry_safe(dev,dev_nxt,&dev_list,list)
	{
		flush_hentries(dev);
		list_del(&dev->list);
		kfree(dev);
	}
}


module_init(drv_init);
module_exit(drv_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_AUTHOR);
MODULE_LICENSE("GPL");
