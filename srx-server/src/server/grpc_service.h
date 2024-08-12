#ifndef GRPC_SERVICE_H
#define	GRPC_SERVICE_H

#include "server/command_queue.h"
#include "server/command_handler.h"
#include "server/update_cache.h"
#include "shared/srx_packets.h"
#include "util/log.h"
#include "server/server_connection_handler.h"

typedef struct {
  // Arguments (create)
  CommandQueue*             cmdQueue;
  CommandHandler*           cmdHandler;
  ServerConnectionHandler*  svrConnHandler;
  //BGPSecHandler*            bgpsecHandler;
  //RPKIHandler*              rpkiHandler;
  UpdateCache*              updCache;

  // Argument (start)
  //CommandQueue*             queue;
  uint32_t                  grpc_port;

} GRPC_ServiceHandler;

GRPC_ServiceHandler     grpcServiceHandler;


typedef struct {
    unsigned int size;
    unsigned char *data;
    unsigned char info;
} RET_DATA;

//int responseGRPC (int size);
//int responseGRPC (int size, unsigned char* data);
RET_DATA responseGRPC (int size, unsigned char* data, unsigned int grpcClientID);
void RunQueueCommand(int size, unsigned char *data, RET_DATA *rt, unsigned int grpcClientID);
void RunQueueCommand_uid(int size, unsigned char *data, uint32_t updateId, unsigned int grpcClientID);



#endif /* GRPC_SERVICE_H */




