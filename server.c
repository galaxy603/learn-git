#define _XOPEN_SOURCE 700
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
#include<infiniband/verbs.h>
#include <sys/types.h> 
#include <sys/socket.h>  
#include <netdb.h> 


//定义CQ超时
#define MAX_POLL_CQ_TIMEOUT 2000  
#define MSG "RDMA send operation " 
#define RDMAMSGR "RDMA read operation "  
#define RDMAMSGW "RDMA write operation"  
#define MSG_SIZE 64 


#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

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
  for(iterator=resolved_addr;iterator;iterator=iterator->ai_next)
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

int sock_sync_data(int sock,int xfer_size,char* local_data,char* remote_data)
{
  int rc;
  int read_bytes=0;
  int total_read_bytes=0;
  rc=write(sock,local_data,xfer_size);
  if(rc<xfer_size) fprintf(stderr,"failed writting data during sock_sync_data\n");
  else rc=0;
  while(!rc&& total_read_bytes<xfer_size){
    
    read_bytes=read(sock,remote_data,xfer_size);
    if(read_bytes>0) total_read_bytes+=read_bytes;
    else rc=read_bytes;
    //fprintf(stdout,"read %d bytes\n",total_read_bytes);
  }
  return rc;
}



/*

*/
//poll completion
static int poll_completion(struct resources* res){
  struct ibv_wc wc;
  unsigned long start_time_msec;
  unsigned long cur_time_msec;
  struct timeval cur_time;
  int poll_result;
  int rc=0;
  gettimeofday(&cur_time,NULL);
  start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
  do
  {
  poll_result = ibv_poll_cq(res->cq, 1, &wc);
  gettimeofday(&cur_time, NULL);
  cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
  } while ((poll_result == 0) && ((cur_time_msec - start_time_msec) <MAX_POLL_CQ_TIMEOUT));

  if(poll_result < 0) {
  fprintf(stderr, "poll CQ failed\n");
  rc = 1;
  }
  else if (poll_result == 0)
  {
  fprintf(stderr, "completion wasn't found in the CQ after timeout\n");
  rc = 1; 
  }
  else
  {
  fprintf(stdout, "completion was found in CQ with status 0x%x\n", wc.status);
  if (wc.status != IBV_WC_SUCCESS)
  {
  fprintf(stderr, "got bad completion with status: 0x%x, vendor syndrome:0x%x\n", wc.status, wc.vendor_err);
  rc=1;
  }
}
return rc;

}


//post send
static int post_send(struct resources* res,int opcode){
  struct ibv_send_wr sr;
  struct ibv_sge sge;
  struct ibv_send_wr* bad_wr=NULL;
  int rc;
  memset(&sge,0,sizeof(sge));
  sge.addr=(uintptr_t)res->buf;
  sge.length=MSG_SIZE;
  sge.lkey=res->mr->lkey;
  memset(&sr,0,sizeof(sr));
  sr.next=NULL;
  sr.wr_id=0;
  sr.sg_list=&sge;
  sr.num_sge=1;
  sr.opcode=opcode;
  sr.send_flags=IBV_SEND_SIGNALED;//表示WR完成时将生成WC通知
  if(opcode!=IBV_WR_SEND){
    sr.wr.rdma.remote_addr = res->remote_props.addr;
    sr.wr.rdma.rkey = res->remote_props.rkey;
  }
  rc=ibv_post_send(res->qp,&sr,&bad_wr);
  if(rc)
  fprintf(stderr,"failed to post SR\n");
  else {
    switch(opcode){
      case IBV_WR_SEND:
      fprintf(stdout, "Send Request was posted\n"); break;
      case IBV_WR_RDMA_READ:
      fprintf(stdout, "RDMA Read Request was posted\n"); break;
      case IBV_WR_RDMA_WRITE:
      fprintf(stdout, "RDMA Write Request was posted\n"); break;
      default:
      fprintf(stdout, "Unknown Request was posted\n"); break;
    }
  }
  return rc;
}






//post_receive
static int post_receive(struct resources * res)
{
  struct ibv_recv_wr rr;
  struct ibv_sge sge;
  struct ibv_recv_wr* bad_wr;
  int rc;
  //准备SGE
  memset(&sge,0,sizeof(sge));
  sge.addr=(uintptr_t)res->buf;
  sge.length=MSG_SIZE;
  sge.lkey=res->mr->lkey;
  //准备RR
  memset(&rr,0,sizeof(rr));
  rr.next=NULL;
  rr.wr_id=0;
  rr.sg_list=&sge;
  rr.num_sge=1;//给定这个RR的SGE LIST长度
  //将RR发布到RQ上
  rc=ibv_post_recv(res->qp,&rr,&bad_wr);
  if(rc) fprintf(stderr,"failed to post RR\n");
  else fprintf(stdout,"reveive request was posted\n");
  return rc;
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
static int resources_create(struct resources * res)
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
  fprintf(stdout,"found %d device \n",num_devices);
  //查找特定设备
  for(i=0;i<num_devices;i++){
    if(!config.dev_name){
      config.dev_name=strdup(ibv_get_device_name(dev_list[i]));
      fprintf(stdout,"device no specified,using first one found:%s\n",config.dev_name);

    }
    if(!strcmp(ibv_get_device_name(dev_list[i]),config.dev_name)){
      ib_dev=dev_list[i];
      break;
    }
  }
  //如果没有找到设备
  if(!ib_dev){
    fprintf(stderr,"IBdevice %s no found\n",config.dev_name);
    rc=1;
    goto resources_create_exit;
  }
  //找到设备，开始解析
  res->ib_ctx=ibv_open_device(ib_dev);//打开verbs上下文
  if(!res->ib_ctx){
    fprintf(stderr,"failed to open device %s \n",config.dev_name);
    rc=1;
    goto resources_create_exit;
  }
  //完成设备打开，释放设备列表
  ibv_free_device_list(dev_list);
  dev_list=NULL;
  ib_dev=NULL;
  //查询端口属性
  if(ibv_query_port(res->ib_ctx,config.ib_port,&res->port_attr)){
    fprintf(stderr,"ibv_query_port on port %u failed\n",config.ib_port);
    rc=1;
    goto resources_create_exit;
  }
  //分配保护域
  res->pd=ibv_alloc_pd(res->ib_ctx);
  if(!res->pd){
    fprintf(stderr,"ibv_alloc_pd faild\n");
    rc=1;
    goto resources_create_exit;
  }
  //分配完成队列
  cq_size=1;
  res->cq=ibv_create_cq(res->ib_ctx,cq_size,NULL,NULL,0);//cqsize规定队列的最小大小，cq_context用于指定CC，如果轮询处理CQ，CC是不必要的
  if(!res->cq){
    fprintf(stderr,"failed to create CQ with %u entries\n",cq_size);
    rc=1;
    goto resources_create_exit;
  }
  //分配内存缓存区域
  size=MSG_SIZE;
  res->buf=(char*) malloc(size);
  if(!res->buf){
    fprintf(stderr,"failed to malloc %Zu bytes to memory buffer\n",size);
    rc=1;
    goto resources_create_exit;
  }

  memset(res->buf,0,size);
  //在server侧将发送消息放入内存缓存
  if(!config.server_name){
    strcpy(res->buf,MSG);
    fprintf(stdout,"going to send the message %s\n",res->buf);

  }
  else memset(res->buf,0,size);

  //在保护域中注册缓存区域
  mr_flags= IBV_ACCESS_LOCAL_WRITE|IBV_ACCESS_REMOTE_READ|IBV_ACCESS_REMOTE_WRITE;
  res->mr=ibv_reg_mr(res->pd,res->buf,size,mr_flags);//注册内存区域后会将其与保护域相关联，并分配本地和远程密钥lkey,rkey
  if(!res->mr){
    fprintf(stderr,"ibv_reg_mr failed with mr_flags=0x%x\n",mr_flags);
    rc=1;
    goto resources_create_exit;
  }

  fprintf(stdout,"MR was registered with addr=%p, lkey=0x%x,rkey=0x%x,flags=0x%x\n",res->buf,res->mr->lkey,res->mr->rkey,mr_flags);
  //创建QP
  memset(&qp_init_attr,0,sizeof(qp_init_attr));
  qp_init_attr.qp_type=IBV_QPT_RC;
  qp_init_attr.sq_sig_all=1;//设置为1，所有WR都会产生CQE，设置为0时只有被标记的会产生
  qp_init_attr.send_cq=res->cq;
  qp_init_attr.recv_cq=res->cq;
  qp_init_attr.cap.max_send_wr=1;
  qp_init_attr.cap.max_recv_wr=1;//设置缓存中未完成请求最大数量
  qp_init_attr.cap.max_send_sge=1;
  qp_init_attr.cap.max_recv_sge=1;/*设置一个WR中SGE数量，SGE是分散聚合元素，scatter是将连续内存空间发送到多台目的主机
  gather则是将多个不连续空间发送到目的主机一段连续空间中，一个WR是多个SGE元素的链表
  */
  res->qp=ibv_create_qp(res->pd,&qp_init_attr);
  if(!res->qp){
    fprintf(stderr,"failed to create QP\n");rc=1;
    goto resources_create_exit;
  }
  fprintf(stdout,"QP was created,QP number=0x%x\n",res->qp->qp_num);





   resources_create_exit: 
      if(rc){
        if(res->qp){
          ibv_destroy_qp(res->qp);
          res->qp=NULL;
        }
        if(res->mr){
          ibv_dereg_mr(res->mr);
          res->mr=NULL;
        }
        if(res->buf){
          free(res->buf);
          res->buf=NULL;
        }
        if(res->cq){
          ibv_destroy_cq(res->cq);
          res->cq=NULL;
        }
        if(res->pd){
          ibv_dealloc_pd(res->pd);
          res->pd=NULL;
        }
        if(res->ib_ctx){
          ibv_close_device(res->ib_ctx);
          res->ib_ctx=NULL;
        }
        if(dev_list){
          ibv_free_device_list(dev_list);
          dev_list=NULL;
        }
        if(res->sock>=0){
          if(close(res->sock)) fprintf(stderr,"failed to close socket\n");
          res->sock=-1;
        }
      }
    return rc;
}



/*
QP的状态转换操作
*/
//QP INIT
static int modify_qp_to_init(struct ibv_qp *qp){
  struct ibv_qp_attr  attr;
  int flags;
  int rc;
  memset(&attr,0,sizeof(attr));
  attr.qp_state=IBV_QPS_INIT;
  attr.port_num=config.ib_port;
  attr.pkey_index=0;
  attr.qp_access_flags=IBV_ACCESS_LOCAL_WRITE|IBV_ACCESS_REMOTE_WRITE|IBV_ACCESS_REMOTE_READ;
  flags=IBV_QP_STATE|IBV_QP_PKEY_INDEX|IBV_QP_PORT|IBV_QP_ACCESS_FLAGS;
  rc=ibv_modify_qp(qp,&attr,flags);
  if(rc) fprintf(stderr,"failed to modify qp state to INIT\n");
  return rc;
}

static int modify_qp_to_rtr(struct ibv_qp* qp, uint32_t remote_qpn,uint16_t dlid,uint8_t * dgid)
{
  struct ibv_qp_attr attr;
  int flags;
  int rc;
  memset(&attr,0,sizeof(attr));
  attr.qp_state=IBV_QPS_RTR;
  attr.path_mtu=IBV_MTU_512;
  attr.dest_qp_num=remote_qpn;
  attr.rq_psn=0;//开始接受数据包序列号，要和远端sq_psn匹配
  attr.max_dest_rd_atomic=1;//作为read,atomic的目的地在任意时间能处理的请求数量
  attr.min_rnr_timer=0x12;//NAK计时器
  //创建地址句柄
  attr.ah_attr.is_global=0;
  attr.ah_attr.dlid=dlid;
  attr.ah_attr.sl=0;//服务水平
  attr.ah_attr.src_path_bits=0;//LID由base lid和path bits组成，path bits不为0用来表示不同路径，为0表示使用base lid
  attr.ah_attr.port_num=config.ib_port;
  if(config.gid_idx>=0){
    attr.ah_attr.is_global=1;
    attr.ah_attr.port_num=1;
    memcpy(&attr.ah_attr.grh.dgid,dgid,16);
    attr.ah_attr.grh.flow_label=0;
    attr.ah_attr.grh.hop_limit=5;
    attr.ah_attr.grh.sgid_index=config.gid_idx;
    attr.ah_attr.grh.traffic_class=0;
  }
  flags=IBV_QP_STATE|IBV_QP_AV|IBV_QP_PATH_MTU|IBV_QP_DEST_QPN|IBV_QP_RQ_PSN|IBV_QP_RQ_PSN|IBV_QP_MAX_DEST_RD_ATOMIC|IBV_QP_MIN_RNR_TIMER;
  rc=ibv_modify_qp(qp,&attr,flags);
  if(rc){
    fprintf(stderr,"failed to modify QP state to RTR\n");

  }
  return rc;
}

//to RTS
static int modify_qp_to_rts(struct ibv_qp* qp)
{
  struct ibv_qp_attr attr;
  int flags;
  int rc;
  memset(&attr,0,sizeof(attr));
  attr.qp_state=IBV_QPS_RTS;
  attr.timeout=0x12;
  attr.retry_cnt=6;
  attr.rnr_retry=0;//重传次数
  attr.sq_psn=0;//发送队列起始序列号
  attr.max_rd_atomic=1;//允许未完成的RDMA读和原子操作
  flags=IBV_QP_STATE|IBV_QP_TIMEOUT|IBV_QP_RETRY_CNT|IBV_QP_RNR_RETRY|IBV_QP_SQ_PSN|IBV_QP_MAX_QP_RD_ATOMIC;
  rc=ibv_modify_qp(qp,&attr,flags);
  if(rc){
    fprintf(stderr,"failed to modify QP state to RTS\n");

  }
  return rc;

}


//连接QP
static int connect_qp(struct resources* res){
  struct cm_con_data_t local_con_data;
  struct cm_con_data_t remote_con_data;
  struct cm_con_data_t tmp_con_data;
  int rc=0;
  char temp_char;
  union ibv_gid my_gid;
  if(config.gid_idx>=0){
    rc=ibv_query_gid(res->ib_ctx,config.ib_port,config.gid_idx,&my_gid);
    if(rc){
      fprintf(stderr,"coudnt get gid for port %d, index %d\n",config.ib_port,config.gid_idx);
      return rc;
    }
  }
  else memset(&my_gid,0,sizeof my_gid);

  //通过TCP套接字交换需要的参数
  local_con_data.addr=htonll((uintptr_t)res->buf);//系统内小端转换为网络内大端
  local_con_data.rkey=htonl(res->mr->rkey);
  local_con_data.qp_num=htonl(res->qp->qp_num);
  local_con_data.lid=htons(res->port_attr.lid);
  memcpy(local_con_data.gid,&my_gid,16);
  fprintf(stdout,"\nLocal LID =0x%x\n",res->port_attr.lid);
  if(sock_sync_data(res->sock,sizeof(struct cm_con_data_t),(char*)&local_con_data,(char*)&tmp_con_data)<0){
    fprintf(stderr,"failed to exchange connection data between sides\n");
    rc=1;
    goto connect_qp_exit;
  }
  //远端数据在tmp中，转移到remote_con_data
  remote_con_data.addr=ntohll(tmp_con_data.addr);
  remote_con_data.rkey=ntohl(tmp_con_data.rkey);
  remote_con_data.qp_num=ntohl(tmp_con_data.qp_num);
  remote_con_data.lid=ntohs(tmp_con_data.lid);
  memcpy(remote_con_data.gid,tmp_con_data.gid,16);
  res->remote_props=remote_con_data;
  fprintf(stdout,"remote address= 0x%"PRIx64"\n",remote_con_data.addr);
  fprintf(stdout,"remote rkey= 0x%x\n",remote_con_data.rkey);
  fprintf(stdout,"remote QP number= 0x%x\n",remote_con_data.qp_num);
  fprintf(stdout,"remote LID= 0x%x\n",remote_con_data.lid);
  if(config.gid_idx>=0)
  {
    uint8_t *p = remote_con_data.gid;
    fprintf(stdout,"remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);


  }
//QP init
rc= modify_qp_to_init(res->qp);
if(rc)
{
  fprintf(stderr,"change QP into INIT failed\n");
  goto connect_qp_exit;
}
// 发布RR
if(config.server_name)
{
  rc=post_receive(res);
  if(rc)
  {
    fprintf(stderr,"failed to post RR\n");
    goto connect_qp_exit;
  }

}
// modify to RTR
rc=modify_qp_to_rtr(res->qp,remote_con_data.qp_num,remote_con_data.lid,remote_con_data.gid);
if(rc){
  fprintf(stderr,"failed to modify QP state to RTR\n");
  goto connect_qp_exit;
}
//modify to RTS
rc=modify_qp_to_rts(res->qp);
if(rc){
  fprintf(stderr,"failed to modify QP state into RTS\n");
  goto connect_qp_exit;
}
fprintf(stdout,"QP state change into RTS\n");
//测试同步状况
if(sock_sync_data(res->sock,1,"Q",&temp_char)) 
{fprintf(stderr,"sync error after QPS wer moved to RTS\n");
rc=1;}


connect_qp_exit:
return rc;

}


//资源销毁
static int resources_destroy(struct resources *res) {
int rc = 0;
if (res->qp)
if (ibv_destroy_qp(res->qp))
{
fprintf(stderr, "failed to destroy QP\n"); rc = 1;
}
if (res->mr)
if (ibv_dereg_mr(res->mr)) {
fprintf(stderr, "failed to deregister MR\n");
rc = 1; }
if (res->buf) free(res->buf);
if (res->cq)
if (ibv_destroy_cq(res->cq))
{
fprintf(stderr, "failed to destroy CQ\n"); rc = 1;
}
if (res->pd)
if (ibv_dealloc_pd(res->pd))
{
fprintf(stderr, "failed to deallocate PD\n"); rc = 1;
}
if (res->ib_ctx)
if (ibv_close_device(res->ib_ctx))
{
fprintf(stderr, "failed to close device context\n"); rc = 1;
}
if (res->sock >= 0)
if (close(res->sock))
{
fprintf(stderr, "failed to close socket\n"); rc = 1;
}
return rc; 
}



static void usage(const char *argv0) {
fprintf(stdout, "Usage:\n");
fprintf(stdout, " %s start a server and wait for connection\n", argv0);
fprintf(stdout, " %s <host> connect to server at <host>\n", argv0);
fprintf(stdout, "\n");
fprintf(stdout, "Options:\n");
fprintf(stdout, " -p, --port <port> listen on/connect to port <port> (default 18515)\n"); 
fprintf(stdout, " -d, --ib-dev <dev> use IB device <dev> (default first device found)\n"); 
fprintf(stdout, " -i, --ib-port <port> use port <port> of IB device (default 1)\n"); 
fprintf(stdout, " -g, --gid_idx <git index> gid index to be used in GRH (default not used)\n");
}






int main(int argc,char* argv[]){
    struct resources res;
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
//连接QP
if(connect_qp(&res)){
  fprintf(stderr,"failed toconnect QPS\n");
  goto main_exit;
}
//server post sr,测试从server 执行send到client
if(!config.server_name){
  if(post_send(&res,IBV_WR_SEND)){
    fprintf(stderr,"failed to post sr\n");
    goto main_exit;
  }
}
//轮询是否完成
if(poll_completion(&res)){
  fprintf(stderr,"poll completion failed\n");
  goto main_exit;
}
//此时用户端缓存得到了这条消息
if(config.server_name){
  fprintf(stdout,"Message is : '%s'\n",res.buf);
}
else{
  strcpy(res.buf,RDMAMSGR);//准备接下来client要读的数据

}

if (sock_sync_data(res.sock, 1, "R", &temp_char))
{
fprintf(stderr, "sync error before RDMA ops\n"); rc = 1;
goto main_exit;
}

//现在由client执行read,write操作
if(config.server_name){
  if(post_send(&res,IBV_WR_RDMA_READ)){
    fprintf(stderr,"failed to post SR2 \n");
    rc=1;
    goto main_exit;
  }
  if(poll_completion(&res)){
  fprintf(stderr,"poll completion failed 2\n");
  rc=1;
  goto main_exit;
  }
  fprintf(stdout,"content of server's buffer: '%s' \n",res.buf);
  //read完成，准备write
  strcpy(res.buf,RDMAMSGW);
  fprintf(stdout,"Now replacing it with : '%s' \n",res.buf);
  if(post_send(&res,IBV_WR_RDMA_WRITE)){
    fprintf(stderr,"failed to post SR3 \n");
    rc=1;
    goto main_exit;
  }
  if(poll_completion(&res)){
  fprintf(stderr,"poll completion failed 3\n");
  rc=1;
  goto main_exit;
  }

}

if (sock_sync_data(res.sock, 1, "W", &temp_char))
{
fprintf(stderr, "sync error after RDMA ops\n"); 
rc = 1;
goto main_exit;
}
if(!config.server_name) fprintf(stdout,"content of server buffer: '%s' \n",res.buf);
rc=0;




main_exit:
if(resources_destroy(&res)){
  fprintf(stderr,"failed to destroy resources\n");
  rc=1;
}
if(config.dev_name) free((char*) config.dev_name);
fprintf(stdout,"\ntest result is %d\n",rc);
return rc;
}
