#include "dcerpc.h"

static uint64_t global_call_id = 1;

#define SRVSVC_UUID_A	0x4b324fc8
#define SRVSVC_UUID_B	0x1670
#define SRVSVC_UUID_C	0x01d3
static const uint8_t SRVSVC_UUID_D[] = { 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 };

#define TRANSFER_SYNTAX_NDR_UUID_A	0x8a885d04
#define TRANSFER_SYNTAX_NDR_UUID_B	0x1ceb
#define TRANSFER_SYNTAX_NDR_UUID_C	0x11c9
static const uint8_t TRANSFER_SYNTAX_NDR_UUID_D[] = { 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 };

uint16_t swap_uint16(uint8_t byte_order, uint16_t i)
{
#ifdef R_ENDIAN_LITTLE
        switch (byte_order)
		{
				case RPC_BYTE_ORDER_LE: return i;
				case RPC_BYTE_ORDER_BE: return (0xff & i) << 8 | (i >> 8);
				default: return i;
		}
#else
		switch (byte_order)
		{
				case RPC_BYTE_ORDER_LE: return (0xff & i) << 8 | (i >> 8);
				case RPC_BYTE_ORDER_BE: return i;
				default: return i;
		}
#endif
}

uint32_t swap_uint32(uint8_t byte_order, uint32_t i)
{
#ifdef R_ENDIAN_LITTLE
        switch (byte_order)
		{
				case RPC_BYTE_ORDER_LE: return i;
				case RPC_BYTE_ORDER_BE:
				        return ((0x000000ff & (i >> 24)) |
                               (0x0000ff00 & (i >>  8)) |
                               (0x00ff0000 & (i <<  8)) |
                               (0xff000000 & (i << 24)));
				default: return i;
		}
#else
		switch (byte_order)
		{
				case RPC_BYTE_ORDER_LE:
						return ((0x000000ff & (i >> 24)) |
                               (0x0000ff00 & (i >>  8)) |
                               (0x00ff0000 & (i <<  8)) |
                               (0xff000000 & (i << 24)));
				case RPC_BYTE_ORDER_BE: return i;
				default: return i;
    }
#endif
}

void
dcerpc_reset_callid(void)
{
        global_call_id = 1;
}

uint8_t get_byte_order_dr(struct rpc_data_representation data)
{
		return data.byte_order;
}

uint8_t get_byte_order_hdr(struct rpc_header hdr)
{
        return hdr.data_rep.byte_order;
}

void set_context_uuid(struct context_uuid *ctx,
                      uint8_t  byte_order,
                      uint32_t a,
                      uint16_t b,
                      uint16_t c,
                      const uint8_t d[8]
                     )
{
		unsigned int i = 0;
        ctx->a = swap_uint32(byte_order, a);
        ctx->b = swap_uint16(byte_order, b);
        ctx->c = swap_uint16(byte_order, c);
        for (i = 0; i < sizeof(ctx->d); ++i)
        {
            (ctx->d)[i] = d[i];
        }
}

void init_rpc_data_representation(struct rpc_data_representation *data)
{
        data->byte_order     = RPC_BYTE_ORDER_LE;
		data->char_encoding  = RPC_CHAR_ENCODING_ASCII;
		data->floating_point = RPC_FLOAT_ENCODING_IEEE;
		data->padding        = 0x00;
}

void init_rpc_header(struct rpc_header *hdr)
{
		hdr->version_major = 5;
		hdr->version_minor = 0;
		hdr->packet_type = 0;
		hdr->packet_flags = 0;
		init_rpc_data_representation(&(hdr->data_rep));
		hdr->frag_length = 0;
		hdr->auth_length = 0;
		hdr->call_id = 0;
}

void init_rpc_bind_request(struct rpc_bind_request *bnd)
{
        /* Constant values from ethereal. */
        init_rpc_header(&(bnd->dceRpcHdr));
		bnd->max_xmit_frag = 32 * 1024; /* was 4280 */
		bnd->max_recv_frag = 32 * 1024; /* was 4280 */
		bnd->assoc_group = 0;
		bnd->num_context_items = 0;
		memset(bnd->padding, 0, sizeof(bnd->padding));
}

void dcerpc_init_context(struct   context_item* ctx,
                         uint8_t  byte_order,
                         uint16_t context_id_number,
                         uint16_t interface_version_major,
                         uint16_t interface_version_minor,
                         uint16_t syntax_version_major,
                         uint16_t syntax_version_minor)
{
		union uuid srvsvc_id;
		union uuid syntax_id;

		ctx->context_id = swap_uint16(byte_order, context_id_number);
		ctx->num_trans_items = swap_uint16(byte_order, 1);

		set_context_uuid(&srvsvc_id.s_id, byte_order, SRVSVC_UUID_A, SRVSVC_UUID_B, SRVSVC_UUID_C, SRVSVC_UUID_D);
		memcpy(&(ctx->interface_uuid), &(srvsvc_id.id), 16);
		ctx->interface_version_major = swap_uint16(byte_order, interface_version_major);
		ctx->interface_version_minor = swap_uint16(byte_order, interface_version_minor);

		set_context_uuid(&syntax_id.s_id, byte_order, TRANSFER_SYNTAX_NDR_UUID_A, TRANSFER_SYNTAX_NDR_UUID_B, TRANSFER_SYNTAX_NDR_UUID_C, TRANSFER_SYNTAX_NDR_UUID_D);
		memcpy(&(ctx->transfer_syntax), &(syntax_id.id), 16);
		ctx->syntax_version_major = swap_uint16(byte_order, syntax_version_major);
		ctx->syntax_version_minor = swap_uint16(byte_order, syntax_version_minor);
}

void dcerpc_create_bind_req(struct rpc_bind_request *bnd, int num_context_items)
{
        init_rpc_bind_request(bnd);
        bnd->dceRpcHdr.packet_type = RPC_PACKET_TYPE_BIND;
        bnd->dceRpcHdr.packet_flags = RPC_FLAG_FIRST_FRAG | RPC_FLAG_LAST_FRAG;
        bnd->dceRpcHdr.frag_length = sizeof(struct rpc_bind_request) + (num_context_items * sizeof(struct context_item));
        bnd->dceRpcHdr.call_id = global_call_id++;
        bnd->num_context_items = num_context_items; /* atleast one context */
}

int
dcerpc_get_response_header(uint8_t *buf,
                           uint32_t buf_len,
                           struct rpc_header *hdr)
{
        if (buf == NULL|| hdr == NULL) {
                return -1;
        }
        if (buf_len < sizeof(struct rpc_header)) {
                return -1;
        }
        memcpy(hdr, buf, sizeof(struct rpc_header));
        return 0;
}

int
dcerpc_get_bind_ack_response(uint8_t *buf, uint32_t buf_len,
                             struct rpc_bind_response *rsp)
{
        if (buf == NULL|| rsp == NULL) {
                return -1;
        }
        if (buf_len < sizeof(struct rpc_bind_response)) {
                return -1;
        }
        memcpy(rsp, buf, sizeof(struct rpc_bind_response));
        return 0;
}

int
dcerpc_get_bind_nack_response(uint8_t *buf,
                              uint32_t buf_len,
                              struct rpc_bind_nack_response *rsp)
{
        if (buf == NULL|| rsp == NULL) {
                return -1;
        }
        if (buf_len < sizeof(struct rpc_bind_nack_response)) {
                return -1;
        }
        memcpy(rsp, buf, sizeof(struct rpc_bind_nack_response));
        return 0;
}

const char *
dcerpc_get_reject_reason(uint16_t reason)
{
        switch (reason)
        {
                case RPC_REASON_NOT_SPECIFIED:
                        return "Reason not specified";
                case RPC_REASON_TEMPORARY_CONGESTION:
                        return "Temporary congestion";
                case RPC_REASON_LOCAL_LIMIT_EXCEEDED:
                        return "Local limit exceeded";
                case RPC_REASON_CALLED_PADDR_UNKNOWN:
                        return "Called paddr unknown";
                case RPC_REASON_BAD_PROTOCOL_VERSION:
                        return "Protocol version not supported";
                case RPC_REASON_DEFAULT_CTX_UNSUPPORTED:
                        return "Default context not supported";
                case RPC_REASON_USER_DATA_UNREADABLE:
                        return "User data not readable";
                case RPC_REASON_NO_PSAP_AVAILABLE:
                        return "No PSAP available";
                case RPC_REASON_AUTH_TYPE_NOT_RECOGNIZED:
                        return "Authentication type not recognized";
                case RPC_REASON_INVALID_CHECKSUM:
                        return "Invalid checksum";
                default: break;
        }
        return "UNKNOWN Reject Reason";
}

/******************************** SRVSVC ********************************/
static void
dcerpc_init_NetrShareEnumRequest(struct NetrShareEnumRequest *netr_req)
{
        init_rpc_header(&(netr_req->dceRpcHdr));
        netr_req->alloc_hint = 0;
        netr_req->context_id = 0;
        /* OPNUM - 15 must be translated */
        netr_req->opnum = swap_uint16(get_byte_order_hdr(netr_req->dceRpcHdr), 15);
}

int
dcerpc_create_NetrShareEnumRequest(struct NetrShareEnumRequest *netr_req,
                                   uint32_t payload_size)
{
        dcerpc_init_NetrShareEnumRequest(netr_req);
        netr_req->dceRpcHdr.packet_type  = RPC_PACKET_TYPE_REQUEST;
        netr_req->dceRpcHdr.packet_flags = RPC_FLAG_FIRST_FRAG | RPC_FLAG_LAST_FRAG;
        netr_req->dceRpcHdr.frag_length  =  sizeof(struct NetrShareEnumRequest) + payload_size;
        netr_req->dceRpcHdr.call_id      =  global_call_id++;

        netr_req->alloc_hint             =  payload_size + 2; // add +2
        return 0;
}

static void
dcerpc_init_stringValue(char     *string,
                        struct   stringValue *stringVal,
                        wchar_t  **buf,
                        uint32_t *buf_len)
{
        wchar_t *nmbuf = NULL;
        uint32_t nmlen = 0;
        uint32_t len = strlen(string)+1;

        stringVal->max_length = swap_uint32(RPC_BYTE_ORDER_LE, len);
        stringVal->offset     = 0;
        stringVal->length     = stringVal->max_length;

        nmlen = len * 2;
        nmbuf = (wchar_t *) malloc (nmlen);
        memset(nmbuf, 0, nmlen);
        mbstowcs(nmbuf, string, nmlen);

        *buf = nmbuf;
        *buf_len = nmlen;
}

static void
dcerpc_init_serverName(uint32_t refid,
                       char     *name,
                       struct   serverName *srv,
                       wchar_t  **buf,
                       uint32_t *buf_len)
{
        srv->referent_id = swap_uint32(RPC_BYTE_ORDER_LE, refid);
        dcerpc_init_stringValue(name, &srv->server, buf, buf_len);
}

static void
dcerpc_init_InfoStruct(uint32_t infolevel, uint32_t id,
                       uint32_t entries, uint32_t arrayId,
                       struct InfoStruct *info)
{
        info->info_level   = swap_uint32(RPC_BYTE_ORDER_LE, infolevel);
        info->switch_value = info->info_level;
        info->referent_id  = swap_uint32(RPC_BYTE_ORDER_LE, id);
        info->num_entries  = swap_uint32(RPC_BYTE_ORDER_LE, entries);
        info->array_referent_id = swap_uint32(RPC_BYTE_ORDER_LE, arrayId);
        // TODO sarat : what is this SharesDef::setMaxCount doing ??
}

int
dcerpc_create_NetrShareEnumRequest_payload(/*IN*/char      *server_name,
                                           /*IN*/uint32_t  resumeHandlePtr,
                                           /*IN*/uint32_t  resumeHandle,
                                           /*OUT*/uint8_t  **buffer,
                                           /*OUT*/uint32_t *buffer_len)
{
        uint8_t   *payload = NULL;
        uint32_t  payloadlen = 0;
        uint32_t  offset = 0;
        struct    serverName srv;
        uint32_t  name_struct_len = 0;
        wchar_t   *name_buf = NULL; /* to be freed here */
        uint32_t  name_buf_len = 0;
        int       padlen = 0;
        uint8_t   zero_bytes[7] = {0};
        struct    InfoStruct info_struct;
        uint32_t  preferred_max_length = 0xffffffff;

        uint32_t resumeHandlePtr_odr = 0;
        uint32_t resumeHandle_odr = 0;

        name_struct_len = (uint32_t) sizeof(struct serverName);

        dcerpc_init_serverName(0x0026e53c, server_name, &srv, &name_buf, &name_buf_len);

        /* padding of 0 or more bytes are needed after the name buf */
        if (((name_struct_len+ name_buf_len) & 0x07) != 0) {
                padlen = (8 - ((name_struct_len + name_buf_len) & 0x07));
        }
        payload = (uint8_t *) malloc(name_struct_len + name_buf_len + padlen);
        if (payload == NULL) {
                free(name_buf); name_buf = NULL;
                return -1;
        }

        memcpy(payload, &srv, name_struct_len);
        offset += name_struct_len;
        memcpy(payload+offset, name_buf, name_buf_len);
        offset += name_buf_len;
        if (padlen) {
                memcpy(payload+offset, zero_bytes, padlen);
                offset += padlen;
        }

        //free(name_buf); name_buf = NULL; // TODO sarat crashes with this line
        dcerpc_init_InfoStruct(2, 0x01fbf3e8, 0, 0, &info_struct);

        payloadlen = offset + sizeof(struct InfoStruct)
                      + sizeof(preferred_max_length)
                      + sizeof(resumeHandlePtr);
        if (resumeHandlePtr)
                payloadlen += sizeof(resumeHandle);

        payload = (uint8_t *)realloc(payload, payloadlen);
        if (payload == NULL) {
                return -1;
        }

        memcpy(payload+offset, &info_struct, sizeof(struct InfoStruct));
        offset += sizeof(struct InfoStruct);

        preferred_max_length = swap_uint32(RPC_BYTE_ORDER_LE, preferred_max_length);
        memcpy(payload+offset, &preferred_max_length, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        resumeHandlePtr_odr = swap_uint32(RPC_BYTE_ORDER_LE, resumeHandlePtr);
        memcpy(payload+offset, &resumeHandlePtr_odr, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        if (resumeHandlePtr) {
                resumeHandle_odr = swap_uint32(RPC_BYTE_ORDER_LE, resumeHandle);
                memcpy(payload+offset, &resumeHandle_odr, sizeof(uint32_t));
                offset += sizeof(uint32_t);
        }

        *buffer = payload;
        *buffer_len = payloadlen;

        return 0;
}
