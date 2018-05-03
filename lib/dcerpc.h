
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _DCERPC_H_
#define _DCERPC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

#ifdef __linux__
#ifndef __KERNEL__
#include <endian.h>
#else
#include <asm/byteorder.h>
#endif
#endif

#ifdef __FreeBSD__
#include <sys/endian.h>
#endif

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
# define R_ENDIAN_LITTLE
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
# define R_ENDIAN_BIG
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN
# define R_ENDIAN_LITTLE
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN
# define R_ENDIAN_BIG
#elif defined(__LITTLE_ENDIAN) && !defined(__BIG_ENDIAN)
# define R_ENDIAN_LITTLE
#elif !defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN)
# define R_ENDIAN_BIG
#endif

#if !defined(R_ENDIAN_BIG) && !defined(R_ENDIAN_LITTLE)
  #error "Endian macro undefined"
#endif

/* MACRO definitions */
#define RPC_BYTE_ORDER_LE			0x10
#define RPC_BYTE_ORDER_BE			0x01

#define RPC_PACKET_TYPE_REQUEST		0x00
#define RPC_PACKET_TYPE_RESPONSE	0x02
#define RPC_PACKET_TYPE_FAULT		0x03
#define RPC_PACKET_TYPE_BIND		0x0b
#define RPC_PACKET_TYPE_BINDACK		0x0c
#define RPC_PACKET_TYPE_BINDNACK	0x0d
#define RPC_PACKET_TYPE_ALTCONT		0x0e
#define RPC_PACKET_TYPE_AUTH3		0x0f
#define RPC_PACKET_TYPE_BINDCONT	0x10

#define RPC_FLAG_FIRST_FRAG			0x01
#define RPC_FLAG_LAST_FRAG			0x02
#define RPC_FLAG_CANCEL_PENDING		0x04
#define RPC_FLAG_RESERVED			0x08
#define RPC_FLAG_MULTIPLEX			0x10
#define RPC_FLAG_DID_NOT_EXECUTE	0x20
#define RPC_FLAG_MAYBE				0x40
#define RPC_FLAG_OBJECT				0x80


#define RPC_CHAR_ENCODING_ASCII		0x00
#define RPC_FLOAT_ENCODING_IEEE		0x00

/* Structs */
struct rpc_data_representation
{
        uint8_t byte_order;
		uint8_t char_encoding;
		uint8_t floating_point;
		uint8_t padding;
} __attribute__((packed));

struct rpc_header
{
		uint8_t version_major;       /* Always 5 */
		uint8_t version_minor;       /* Always 0 */
		uint8_t packet_type;
		uint8_t packet_flags;
		struct rpc_data_representation data_rep;

		/* Total size of the header (i.e. 16 bytes plus the following data
		   up to (but not including) the next header. */
		uint16_t frag_length;
		/* Size of the optional authentication (normally zero) */
		uint16_t auth_length;
		/* Incremental sequent numbers. Used to match up responses and requests. */
		uint32_t call_id;
} __attribute__((packed));

/* To be sent and received as part of SMB Transact and/or SMB2_IOCTL */
struct dcerpc_header
{
		struct rpc_header    rpc_header;
		uint32_t             alloc_hint;
		uint16_t             context_id;
		uint16_t             opnum;     /* doubles as cancel count in reply */
} __attribute__((packed));

/* RPC contexts*/
#define CONTEXT_ID_NUMBER	0
#define INTERFACE_VERSION_MAJOR	3
#define INTERFACE_VERSION_MINOR	0

#define TRANSFER_SYNTAX_VERSION_MAJOR	2
#define TRANSFER_SYNTAX_VERSION_MINOR	0

struct context_uuid
{
    uint32_t           a;
    uint16_t           b;
    uint16_t           c;
    uint8_t            d[8];
} __attribute__((packed));

union uuid {
	uint8_t id[16];
	struct context_uuid s_id;
};

struct context_item
{
		uint16_t context_id;
		uint16_t num_trans_items;
		uint8_t interface_uuid[16];
		uint16_t interface_version_major;
		uint16_t interface_version_minor;
		uint8_t transfer_syntax[16];
		uint16_t syntax_version_major;
		uint16_t syntax_version_minor;
} __attribute__((packed));

#define RPC_REASON_NOT_SPECIFIED			0
#define RPC_REASON_TEMPORARY_CONGESTION		1
#define RPC_REASON_LOCAL_LIMIT_EXCEEDED		2
#define RPC_REASON_CALLED_PADDR_UNKNOWN		3
#define RPC_REASON_BAD_PROTOCOL_VERSION		4
#define RPC_REASON_DEFAULT_CTX_UNSUPPORTED	5
#define RPC_REASON_USER_DATA_UNREADABLE		6
#define RPC_REASON_NO_PSAP_AVAILABLE		7
#define RPC_REASON_AUTH_TYPE_NOT_RECOGNIZED	8
#define RPC_REASON_INVALID_CHECKSUM			9

struct rpc_bind_request
{
		struct rpc_header dceRpcHdr;
		uint16_t max_xmit_frag;
		uint16_t max_recv_frag;
		uint32_t assoc_group;
		uint8_t num_context_items;
		uint8_t padding[3];
} __attribute__((packed));

struct rpc_bind_response
{
		struct rpc_header dceRpcHdr;
		uint16_t max_xmit_frag;
		uint16_t max_recv_frag;
} __attribute__((packed));


struct rpc_bind_nack_response
{
		struct rpc_header dceRpcHdr;
		uint16_t reject_reason;
} __attribute__((packed));

/* APIs */
uint16_t swap_uint16(uint8_t byte_order, uint16_t i);
uint32_t swap_uint32(uint8_t byte_order, uint32_t i);

uint8_t get_byte_order_dr(struct rpc_data_representation data);
uint8_t get_byte_order_hdr(struct rpc_header hdr);
uint8_t get_byte_order_dcehdr(struct dcerpc_header dce_hdr);

void set_context_uuid(struct context_uuid *ctx,
                      uint8_t  byte_order,
                      uint32_t a,
                      uint16_t b,
                      uint16_t c,
                      const uint8_t d[8]
                     );

void init_rpc_data_representation(struct rpc_data_representation *data);
void init_rpc_header(struct rpc_header *hdr);
void init_rpc_bind_request(struct rpc_bind_request *bnd);
void init_dcerpc_header(struct dcerpc_header *dcehdr, uint16_t opnum, size_t dcerpc_payload_size);

#ifdef __cplusplus
}
#endif


#endif /* _DCERPC_H_ */
