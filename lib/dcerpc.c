#include "dcerpc.h"


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

uint8_t get_byte_order_dr(struct rpc_data_representation data)
{
		return data.byte_order;
}

uint8_t get_byte_order_hdr(struct rpc_header hdr)
{
        return hdr.data_rep.byte_order;
}

uint8_t get_byte_order_dcehdr(struct dcerpc_header dce_hdr)
{
        return dce_hdr.rpc_header.data_rep.byte_order;
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

void init_dcerpc_header(struct dcerpc_header *dcehdr, uint16_t opnum, size_t dcerpc_payload_size)
{

		init_rpc_header(&dcehdr->rpc_header);
		dcehdr->rpc_header.packet_type = RPC_PACKET_TYPE_REQUEST;
		dcehdr->rpc_header.packet_flags = RPC_FLAG_FIRST_FRAG | RPC_FLAG_LAST_FRAG;
		dcehdr->rpc_header.frag_length = sizeof(struct dcerpc_header) + dcerpc_payload_size;
		dcehdr->rpc_header.call_id = 1;

		dcehdr->alloc_hint = dcerpc_payload_size;
		dcehdr->context_id = 0;
		dcehdr->opnum = opnum;

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
        struct context_item ctx;

        init_rpc_bind_request(bnd);
        bnd->dceRpcHdr.packet_type = RPC_PACKET_TYPE_BIND;
        bnd->dceRpcHdr.packet_flags = RPC_FLAG_FIRST_FRAG | RPC_FLAG_LAST_FRAG;
        bnd->dceRpcHdr.frag_length = sizeof(struct rpc_bind_request) + (num_context_items * sizeof(struct context_item));
        bnd->dceRpcHdr.call_id = 1;
        bnd->num_context_items = num_context_items; /* atleast one context */

        dcerpc_init_context(&ctx,
                            get_byte_order_hdr(bnd->dceRpcHdr),
                            1,
                            INTERFACE_VERSION_MAJOR,
                            INTERFACE_VERSION_MINOR,
                            TRANSFER_SYNTAX_VERSION_MAJOR,
                            TRANSFER_SYNTAX_VERSION_MINOR);
}
