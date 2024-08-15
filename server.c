#include<signal.h>
#include<stdlib.h>
#include<stdio.h>
#include <string.h>  
#include <unistd.h>  
#include <stdint.h>  
#include <inttypes.h>  
#include <endian.h>  
#include <byteswap.h>  
#include <getopt.h>  
#include <sys/time.h>  
#include <arpa/inet.h>  
#include <sys/types.h> 
#include <sys/socket.h>  
#include <netdb.h> 
#include<libibverbs/verbs.h>

//定义CQ超时
#define MAX_POLL_CQ_TIMEOUT 2000  
#define MSG "SEND operation " 
#define RDMAMSGR "RDMA read operation "  
#define RDMAMSGW "RDMA write operation"  
#define MSG_SIZE (strlen(MSG) + 1) 

struct config_t
{
    const char* dev_name;
    char* server_name;
    uint32_t tcp_port;
    int ib_port;
    int gid_idx;
};

struct cm_con_data_t
{
    uint64_t addr;
    uint32_t rkey;
    uint32_t qp_num;
    uint16_t lid;//IB端口的LID
    uint8_t gid[16];

}__attribute__ ((packed));

struct resources 
{  
 struct ibv_device_attr /* Device attributes */  
  device_attr;  
 struct ibv_port_attr port_attr; /* IB port attributes */ 
 struct cm_con_data_t remote_props; /* values to connect to remote side */ 
 struct ibv_context *ib_ctx; /* device handle */ 
 struct ibv_pd *pd; /* PD handle */ 
 struct ibv_cq *cq; /* CQ handle */ 
 struct ibv_qp *qp; /* QP handle */ 
 struct ibv_mr *mr; /* MR handle for buf */ 
 char *buf; /* memory buffer pointer, used for RDMA and send ops */ 
 int sock; /* TCP socket file descriptor */  
};  
struct config_t config = {  
 NULL, /* dev_name */  
 NULL, /* server_name */  
 19875, /* tcp_port */ 
 1, /* ib_port */ 
 -1 /* gid_idx */  
}; 



/*socket operations*/

static int sock_connect(const char*servername,int port){
  struct addrinfo *resolved_addr=NULL;
  struct addrinfo *iterator;
  char service[6];
  int sockfd=-1;
  int listenfd=0;
  int tmp;
  struct addrinfo hints=
  {
    .ai_flags=AI_PASSIVE,
    .ai_family=AF_INET,
    .ai_socktype=SOCK_STREAM
  };
  if(sprintf(service,"%d",port)<0) goto sock_connect_exit;
  //DNS解析
  sockfd=getaddrinfo(servername,service,&hints,&resolved_addr);
  if(sockfd<0){
    fprintf(stderr,"%s for %s:%d\n",gai_strerror(sockfd),servername,port);
    goto sock_connect_exit;
  }
  for(iterator=resolved_addr;iterator;iterator=iterator->ai_socktype)
  {
    sockfd = socket(iterator->ai_family, iterator->ai_socktype, 
iterator->ai_protocol);
    if(sockfd>=0){
      if(servername){
        if((tmp=connect(sockfd,iterator->ai_addr,iterator->ai_addrlen))){
          fprintf(stdout, "failed connect \n");  
          close(sockfd); 
          sockfd = -1;  
        }
      }
      else
      {
        listenfd = sockfd; 
        sockfd = -1; 
        if(bind(listenfd, iterator->ai_addr, iterator->ai_addrlen))  
        goto sock_connect_exit; listen(listenfd, 1); 
        sockfd = accept(listenfd, NULL, 0); 
      }
    }
  }
  
  sock_connect_exit:
  if(listenfd)  
  close(listenfd);  
 if(resolved_addr)  
  freeaddrinfo(resolved_addr);  
 if (sockfd < 0) {  
  if(servername) 
   fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);  
  else {  
   perror("server accept");  
   fprintf(stderr, "accept() failed\n");  
  }  
 }  
 return sockfd; 
}


static void print_config(void)
{
    fprintf(stdout, " ------------------------------------------------\n");  
 fprintf(stdout, " Device name : \"%s\"\n", config.dev_name);  
 fprintf(stdout, "IB port : %u\n",config.ib_port); 
 if (config.server_name)  
  fprintf(stdout, " IP : %s\n", config.server_name);  
 fprintf(stdout, " TCP port :%u\n", config.tcp_port); 
 if (config.gid_idx >= 0)  
  fprintf(stdout, " GID index : %u\n", config.gid_idx);  
 fprintf(stdout, " ------------------------------------------------\n\n");
}

//初始化reosurce
static void resources_init(struct resources *res)
{
    memset(res,0,sizeof *res);
    res->sock=-1;
    
}
//创建并分配系统资源
static int resources_create(struct resources *res)
{
  struct ibv_device **dev_list = NULL;
  struct ibv_device *ib_dev=NULL;
  struct ibv_qp_init_attr qp_init_attr;
  size_t size;
  int i;
  int mr_flags=0;
  int cq_size=0;
  int num_devices;
  int rc=0;
  //client
  if(config.server_name){
    res->sock=sock_connect(config.server_name,config.tcp_port);
    if(res->sock<0){
        fprintf(stderr,"faild to establish TCP connection to server %s,port %d\n",config.server_name,config.tcp_port);
        rc=-1;
        goto resources_create_exit;
    }
  }
  else
  {
    fprintf(stdout,"waiting on port %d for TCP connection\n",config.tcp_port);
    res->sock=sock_connect(NULL,config.tcp_port);
    if(res->sock<0)
    {
      fprintf(stderr,"failed to establish TCP connection with client on port %d\n",config.tcp_port);
      rc=-1;
      goto resources_create_exit;
    }
    
  }
  fprintf(stdout,"TCPconnection was established\n");
  fprintf(stdout,"searching for IB devices in host\n");
  //查找IB设备
  dev_list=ibv_get_device_list(&num_devices);
  if(!dev_list){
    fprintf(stderr,"failed to get IBdevice list\n");
    rc=1;
    goto resources_create_exit;
  }

    
};



int main(int argc,char* argv[]){
    struct resourses res;
    int rc=1;
    char temp_char;
    
    while(1){
        int c;
        static struct option long_options[] = 
    { 
   {.name = "port", .has_arg=1,.val='p'}, 
   {.name = "ib-dev", .has_arg=1,.val='d'}, 
   {.name = "ib-port", .has_arg=1,.val='i'}, 
   {.name = "gid-idx", .has_arg=1,.val='g'}, 
   {.name = NULL, .has_arg=1,.val='\0'}, 
     };  
  c = getopt_long(argc, argv, "p:d:i:g:", long_options, NULL); 
  if(c==-1) break;
  switch (c) {  
    case 'p': 
     config.tcp_port = strtoul(optarg, NULL, 0);  
     break;  
    case 'd': 
     config.dev_name = strdup(optarg);  
     break;  
    case 'i': 
     config.ib_port = strtoul(optarg, NULL, 0);  
     if (config.ib_port < 0) 
     { 
      usage(argv[0]); 
      return 1;  
     } break;  
    case 'g': 
     config.gid_idx = strtoul(optarg, NULL, 0);  
     if (config.gid_idx < 0) 
     { 
      usage(argv[0]); 
      return 1;  
     } break;  
    default:  
     usage(argv[0]);  
     return 1;  
   }  
 
    }

    if (optind == argc - 1)  
  config.server_name = argv[optind];  
 else if (optind < argc) 
 {  
  usage(argv[0]);  
  return 1;  
 }  
print_config();
resources_init(&res);
if(resources_create(&res))
{
  fprintf(stderr,"failed to create resource\n");
  goto main_exit;
}

}
