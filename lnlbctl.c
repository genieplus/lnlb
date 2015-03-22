/*
*  LNLB - Linux Network Load Balancing
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <fcntl.h>

//<linux/if_lnlb.h>
#include "if_lnlb.h"

#define PROC_LNLB_FULLPATH "/proc/"LNLB_PROC_FILEPATH

/* Prototypes */
void show_usage(void);
int cmd_addif(int,char**);
int cmd_delif(int,char**);
int cmd_set_weight_mode(int,char**);
int cmd_set_weight(int,char**);
int cmd_resync(int,char**);
int set_cluster_ip(char *,in_addr_t);
int check_driver_loaded();
int check_interface_exists(char *);
int send_command(struct lnlb_cmd*);
int set_ip_using(const char *, int , unsigned long );
int set_flag(char *, short );

/* Command handlers data */

typedef struct
{
   char command[16];
   int (*handler)(int,char**);
}
command_handler ;

command_handler cmd_handlers[]=
{
     {"addif",cmd_addif},
     {"delif",cmd_delif},
     {"weight_mode",cmd_set_weight_mode},
     {"set_weight",cmd_set_weight},	 
	 {"resync",cmd_resync},
     {"",NULL}
};

int skfd=0;

int main(int argc, char **argv)
{
   int i;
   int ret;
   if(argc<2)
     {
	show_usage();
	return -1;
     }

   if(check_driver_loaded())
     {
	fprintf(stderr,"The LNLB driver is not loaded (maybe you missed a modprobe lnlb?)\n");
	return -2;
     }

   if ((skfd = socket(AF_INET,SOCK_DGRAM,0)) < 0)
     {
	perror("socket");
	return -1;
     }

   for(i=0;strlen(cmd_handlers[i].command);i++)
     {
	if(strcmp(argv[1],cmd_handlers[i].command))
	  continue;
	ret=cmd_handlers[i].handler(argc,argv);
	if(ret)
	  fprintf(stderr,"Error occourred\n");
	return ret;
     
   
     }
   show_usage();
   return -1;
}

void show_usage(void)
{
   printf("Usage: lnlbctl <command> [<params>...]\n"
	  "\nList of available commands :\n"
	  " addif <cluster ip> <dev> [<interface name>]\n"
	  " delif <interface name>\n"
	  " weight_mode <interface_name> < loadavg | loadavg5 | loadavg15 | freemem | manual >\n"
	  " set_weight <interface_name> <%d-%d | stdin> (Only when weight_mode=manual)\n"
	  " resync <interface_name> : Force synchronization of conntrack status\n"	  
	   ,LNLB_WEIGHT_MIN,LNLB_WEIGHT_MAX
	  
	  );

}

int check_driver_loaded()
{
   struct stat buf;
   return stat(PROC_LNLB_FULLPATH,&buf);
}

int check_interface_exists(char *iName)
{
   int res;
   struct ifreq interface;
   strncpy(interface.ifr_ifrn.ifrn_name, iName, IFNAMSIZ);
   int sock=socket(AF_INET,SOCK_STREAM,0);
   res=setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE , (char *)&interface, sizeof(interface));
   close(sock);
	return res;
}


int cmd_delif(int argc,char** argv)
{
   struct lnlb_cmd dcmd;
   if(argc<3)
     {
	show_usage();
	return -1;
     }
   
   dcmd.cmd=LNLB_CMD_DELIF;
   strncpy(dcmd.parm1,argv[2],LNLB_PARM_LEN);
   return send_command(&dcmd);
   
}

int cmd_addif(int argc,char** argv)
{
   struct lnlb_cmd dcmd;	
   in_addr_t clust_addr;
   
   int ret=0;
   if(argc<4)
     {
	show_usage();
	return -1;
     }
   
   if(check_interface_exists(argv[3]))
     {
	fprintf(stderr,"Interface %s not found\n",argv[3]);
	return -2;
     }
   
   clust_addr=inet_addr(argv[2]);
   if(clust_addr==INADDR_NONE)
     {
	fprintf(stderr,"The cluster IP provided is not valid\n");
	return -2;
     }
   
   dcmd.cmd=LNLB_CMD_ADDIF;
   strncpy(dcmd.parm1,argv[3],LNLB_PARM_LEN); /* Copy bind device */
   memcpy(dcmd.parm3,&clust_addr,sizeof(clust_addr)); /* Copy IP address */
   if(argc>=5)
     strncpy(dcmd.parm2,argv[4],LNLB_PARM_LEN);
   else
     strncpy(dcmd.parm2,"nlb%d",LNLB_PARM_LEN);
   
   
   ret=send_command(&dcmd);
   if(ret)
     return ret;
   printf("New interface added: %s\n",dcmd.reply);
   
   return set_cluster_ip(dcmd.reply,clust_addr);
}

int cmd_set_weight_mode(int argc,char **argv)
{
   enum lnlb_weight_mode mode=WM_LOADAVG;
   if(argc<4)
     {
	show_usage();
	return -1;
     }
   struct lnlb_cmd dcmd;
   dcmd.cmd=LNLB_CMD_SETWEIGHTMODE;
   strncpy(dcmd.parm1,argv[2],LNLB_PARM_LEN); /* Copy device */
   if(!strcasecmp(argv[3],"loadavg"))
     mode=WM_LOADAVG;
   else if(!strcasecmp(argv[3],"loadavg5"))
     mode=WM_LOADAVG5;
   else if(!strcasecmp(argv[3],"loadavg15"))
     mode=WM_LOADAVG15;
   else if(!strcasecmp(argv[3],"freemem"))
     mode=WM_MEM;
   else if(!strcasecmp(argv[3],"manual"))
     mode=WM_MANUAL;
   
   *((enum lnlb_weight_mode *)dcmd.parm2)=mode; /* Copy mode */
   return send_command(&dcmd);
   
}

int cmd_set_weight(int argc,char **argv)
{
   lnlb_weight_t weight;
   int weight_l;
   struct lnlb_cmd dcmd;
   if(argc<4)
     {
	show_usage();
	return -1;
     }
   
   dcmd.cmd=LNLB_CMD_SETWEIGHT;
   if(strcmp(argv[3],"stdin")==0)
     {
	if(scanf("%u",&weight_l)<1)
	  weight_l=0;
     } else  {
	weight_l=atoi(argv[3]);	
     }
   
      
   
   if(weight_l<LNLB_WEIGHT_MIN || weight_l>LNLB_WEIGHT_MAX){
      fprintf(stderr,"Invalid weight value. Valid range is [%d - %d]\n",LNLB_WEIGHT_MIN,LNLB_WEIGHT_MAX);
      return -2;
   }
   weight=(lnlb_weight_t)weight_l;
   
   strncpy(dcmd.parm1,argv[2],LNLB_PARM_LEN); /* Copy device */
   *((lnlb_weight_t *)dcmd.parm2)=weight; /* Copy weight */
   
   return send_command(&dcmd);
}

int cmd_resync(int argc,char **argv)
{
   if(argc<3)
     {
	show_usage();
	return -1;
     }
   struct lnlb_cmd dcmd;
   dcmd.cmd=LNLB_CMD_RESYNC_CONNTRACK;
   strncpy(dcmd.parm1,argv[2],LNLB_PARM_LEN); /* Copy device */
   
   return send_command(&dcmd);
}


int set_cluster_ip(char *iIfName,in_addr_t iClustIP)
{
   
   if (set_ip_using(iIfName, SIOCSIFADDR, iClustIP) == -1)
     return -1;
   if (set_ip_using(iIfName, SIOCSIFNETMASK, 0xffffffff) == -1)
     return -1;
   if(set_flag(iIfName, (IFF_UP | IFF_RUNNING)))
     return -1;
   
   return 0;
}

int send_command(struct lnlb_cmd* iCmd)
{
   int ph=open(PROC_LNLB_FULLPATH,O_RDWR);
   int err=0;
   if(ph<0)
     {
	perror("Error ");
	return ph;
     }
   
   if((err=write(ph,iCmd,sizeof(struct lnlb_cmd)))<0)
     {
	perror("Error ");
	return err;
     }
   close(ph);
   return 0;
}

int set_ip_using(const char *name, int c, unsigned long ip)
{
   struct ifreq ifr;
   struct sockaddr_in sin;
   
   strncpy(ifr.ifr_name, name, IFNAMSIZ);
   memset(&sin, 0, sizeof(struct sockaddr));
   sin.sin_family = AF_INET;
   sin.sin_addr.s_addr = ip;
   memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
   if (ioctl(skfd, c, &ifr) < 0)
     return -1;
   return 0;
}

int set_flag(char *ifname, short flag)
{
   struct ifreq ifr;
   
   strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
   if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
     {
	perror("SIOCGIFFLAGS");
	return (-1);
     }
   strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
   ifr.ifr_flags |= flag;
   if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0)
     {
	perror("SIOCSIFFLAGS");
	return -1;
     }
   return (0);
}
