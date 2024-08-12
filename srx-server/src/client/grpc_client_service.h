#ifndef GRPC_CLIENT_SERVICE_H
#define GRPC_CLIENT_SERVICE_H

#include "client/srx_api.h"
#include "shared/srx_packets.h"
#include "util/log.h"


typedef struct {
    unsigned int size;
    unsigned char *data;
    unsigned char info;
} RET_DATA;

SRxProxy* g_proxy;

void processVerifyNotify_grpc(SRXPROXY_VERIFY_NOTIFICATION* hdr);
void processGoodbye_grpc(SRXPROXY_GOODBYE* hdr);
void processSyncRequest_grpc(SRXPROXY_SYNCH_REQUEST* hdr);
void processSignNotify_grpc(SRXPROXY_SIGNATURE_NOTIFICATION* hdr);
void processError_grpc(SRXPROXY_ERROR* hdr);

#endif
