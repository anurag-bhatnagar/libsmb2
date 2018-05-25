/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>

#include <errno.h>
#include <poll.h>
#include <strings.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"
#include "dcerpc.h"

#include <unistd.h>
struct sync_cb_data {
	int is_finished;
	int status;
	void *ptr;
};

static int wait_for_reply(struct smb2_context *smb2,
                          struct sync_cb_data *cb_data)
{
        while (!cb_data->is_finished) {
                struct pollfd pfd;

		pfd.fd = smb2_get_fd(smb2);
		pfd.events = smb2_which_events(smb2);

		if (poll(&pfd, 1, 1000) < 0) {
			smb2_set_error(smb2, "Poll failed");
			return -1;
		}
                if (pfd.revents == 0) {
                        continue;
                }
		if (smb2_service(smb2, pfd.revents) < 0) {
			smb2_set_error(smb2, "smb2_service failed with : "
                                       "%s\n", smb2_get_error(smb2));
                        return -1;
		}
	}

        return 0;
}

static void connect_cb(struct smb2_context *smb2, int status,
                       void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->status = status;
}

/*
 * Connect to the server and mount the share.
 */
int smb2_connect_share(struct smb2_context *smb2,
                       const char *server,
                       const char *share,
                       const char *user)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_connect_share_async(smb2, server, share, user,
                                     connect_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_connect_share_async failed. %s",
                               smb2_get_error(smb2));
		return -ENOMEM;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -EIO;
        }

	return cb_data.status;
}

/*
 * Disconnect from share
 */
int smb2_disconnect_share(struct smb2_context *smb2)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_disconnect_share_async(smb2, connect_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_disconnect_share_async failed");
		return -ENOMEM;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -EIO;
        }

	return cb_data.status;
}

/*
 * opendir()
 */
static void opendir_cb(struct smb2_context *smb2, int status,
                       void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->ptr = command_data;
}

struct smb2dir *smb2_opendir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_opendir_async(smb2, path,
                               opendir_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_opendir_async failed");
		return NULL;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

	return cb_data.ptr;
}

/*
 * open()
 */
static void open_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->ptr = command_data;
}

struct smb2fh *smb2_open(struct smb2_context *smb2, const char *path, int flags)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_open_async(smb2, path, flags,
                               open_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_open_async failed");
		return NULL;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

	return cb_data.ptr;
}

/* open_pipe()
 */
struct smb2fh *smb2_open_pipe(struct smb2_context *smb2, const char *pipe)
{
        struct sync_cb_data cb_data;
        struct smb2_create_request req;
        uint32_t desired_access = 0;
        uint32_t create_options = 0;
        uint32_t impersonation_level = 0;
        uint32_t share_access = 0;

	    cb_data.is_finished = 0;

        if (pipe == NULL) {
		        smb2_set_error(smb2, "smb2_open_async failed");
		        return NULL;
        }

        create_options = SMB2_FILE_OPEN_NO_RECALL | SMB2_FILE_NON_DIRECTORY_FILE;
        desired_access |= SMB2_FILE_WRITE_DATA | SMB2_FILE_WRITE_EA | SMB2_FILE_WRITE_ATTRIBUTES;

        if (strcasecmp(pipe, "srvsvc") == 0) {
                impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
                desired_access = 0x0012019f;
                share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
        } else if (strcasecmp(pipe, "wkssvc") == 0) {
                impersonation_level = SMB2_IMPERSONATION_IDENTIFICATION;
                desired_access = 0x0012019f;
                share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
        } else if (strcasecmp(pipe, "lsarpc") == 0) {
                impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
                desired_access = 0x0002019f;
                share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
                create_options = 0x00000000;
        }

        memset(&req, 0, sizeof(struct smb2_create_request));
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level = impersonation_level;
        req.desired_access = desired_access;
        req.share_access = share_access;
        req.create_disposition = SMB2_FILE_OPEN;
        req.create_options = create_options;
        req.name = pipe;

	    if (smb2_open_pipe_async(smb2, &req, open_cb, &cb_data) != 0) {
		        smb2_set_error(smb2, "smb2_open_async failed");
		        return NULL;
	    }

	    if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

	    return cb_data.ptr;
}

/*
 * close()
 */
static void close_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->status = status;
}

int smb2_close(struct smb2_context *smb2, struct smb2fh *fh)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_close_async(smb2, fh, close_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_close_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

/*
 * fsync()
 */
static void fsync_cb(struct smb2_context *smb2, int status,
                     void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->status = status;
}

int smb2_fsync(struct smb2_context *smb2, struct smb2fh *fh)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_fsync_async(smb2, fh, fsync_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_fsync_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

/*
 * pread()
 */
static void generic_status_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->status = status;
}

int smb2_pread(struct smb2_context *smb2, struct smb2fh *fh,
               uint8_t *buf, uint32_t count, uint64_t offset)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_pread_async(smb2, fh, buf, count, offset,
                             generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_pread_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_pwrite(struct smb2_context *smb2, struct smb2fh *fh,
                uint8_t *buf, uint32_t count, uint64_t offset)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_pwrite_async(smb2, fh, buf, count, offset,
                              generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_pwrite_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_read(struct smb2_context *smb2, struct smb2fh *fh,
              uint8_t *buf, uint32_t count)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_read_async(smb2, fh, buf, count,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_read_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_write(struct smb2_context *smb2, struct smb2fh *fh,
               uint8_t *buf, uint32_t count)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_write_async(smb2, fh, buf, count,
                             generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_write_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_unlink(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_unlink_async(smb2, path,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_unlink_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_rmdir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_rmdir_async(smb2, path,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_rmdir_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_mkdir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_mkdir_async(smb2, path,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_mkdir_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_fstat(struct smb2_context *smb2, struct smb2fh *fh,
               struct smb2_stat_64 *st)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_fstat_async(smb2, fh, st,
                             generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_fstat_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_stat(struct smb2_context *smb2, const char *path,
              struct smb2_stat_64 *st)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_stat_async(smb2, path, st,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_stat_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_statvfs(struct smb2_context *smb2, const char *path,
                 struct smb2_statvfs *st)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_statvfs_async(smb2, path, st,
                               generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_statvfs_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }
	return cb_data.status;
}

int smb2_truncate(struct smb2_context *smb2, const char *path,
                  uint64_t length)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_truncate_async(smb2, path, length,
                                generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_truncate_async failed. %s",
                               smb2_get_error(smb2));
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_ftruncate(struct smb2_context *smb2, struct smb2fh *fh,
                   uint64_t length)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_ftruncate_async(smb2, fh, length,
                                 generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_ftruncate_async failed. %s",
                               smb2_get_error(smb2));
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

static void echo_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
    struct sync_cb_data *cb_data = private_data;

    cb_data->is_finished = 1;
    cb_data->status = status;
}

/*
 * Send SMB2_ECHO command to the server
 */
int smb2_echo(struct smb2_context *smb2)
{
    struct sync_cb_data cb_data;

    if (smb2->is_connected == 0)
    {
        smb2_set_error(smb2, "Not Connected to Server");
        return -ENOMEM;
    }

	cb_data.is_finished = 0;

    if (smb2_echo_async(smb2, echo_cb, &cb_data) != 0)
    {
        smb2_set_error(smb2, "smb2_echo failed");
        return -ENOMEM;
    }

    if (wait_for_reply(smb2, &cb_data) < 0)
    {
        return -EIO;
    }

    return cb_data.status;
}

/* share_enum()
 */
int smb2_list_shares(struct smb2_context *smb2,
                     const char *server,
                     const char *user,
                     struct smb2_shareinfo **shares,
                     int *numshares
                    )
{
        int status = 0;
        struct smb2fh *fh = NULL;
        uint8_t *write_buf = NULL;
        uint32_t write_count = 0;
        uint8_t read_buf[1024];
        struct rpc_bind_request bind_req;
        struct context_item dcerpc_ctx;

        struct rpc_header rsp_hdr;
        struct rpc_bind_response ack;
        struct rpc_bind_nack_response nack;

        uint16_t max_xmit_frag;
        uint16_t max_recv_frag;

        char *serverName = NULL;

        if (server == NULL) {
                smb2_set_error(smb2, "smb2_list_shares:server not specified");
                return -1;
        }
        if (user == NULL) {
                smb2_set_error(smb2, "smb2_list_shares:user not specified");
                return -1;
        }

        if (shares == NULL || numshares == NULL) {
                smb2_set_error(smb2, "smb2_list_shares:No memory allocated for share listing");
                return -1;
        }

        smb2->use_cached_creds = 1;
	    if (smb2_connect_share(smb2, server, "IPC$", user) !=0) {
		        smb2_set_error(smb2, "smb2_connect_share_async failed. %s",
                                      smb2_get_error(smb2));
		        return -ENOMEM;
	    }

        fh = smb2_open_pipe(smb2, "srvsvc");
        if (fh == NULL) {
                smb2_set_error(smb2, "smb2_list_shares: failed to open SRVSVC pipe: %s", smb2_get_error(smb2));
                return -1;
        }

        dcerpc_create_bind_req(&bind_req, 1);
        dcerpc_init_context(&dcerpc_ctx, get_byte_order_hdr(bind_req.dceRpcHdr), 1,
                            INTERFACE_VERSION_MAJOR,
                            INTERFACE_VERSION_MINOR,
                            TRANSFER_SYNTAX_VERSION_MAJOR,
                            TRANSFER_SYNTAX_VERSION_MINOR);

        write_count = sizeof(struct rpc_bind_request) + sizeof(struct context_item);
        write_buf = (uint8_t *) malloc(write_count);
        if (write_buf == NULL) {
		        smb2_set_error(smb2, "failed to allocate dcerpc bind buffer");
		        return -ENOMEM;
        }
        memcpy(write_buf, &bind_req, sizeof(struct rpc_bind_request));
        memcpy(write_buf+sizeof(struct rpc_bind_request), &dcerpc_ctx, sizeof(struct context_item));
        status = smb2_write(smb2, fh, write_buf, write_count);
        if (status < 0) {
		        smb2_set_error(smb2, "failed to send dcerpc bind request");
		        return -1;
        }
        free(write_buf); write_buf = NULL;

        status = smb2_read(smb2, fh, read_buf, 1024);
        if (status < 0) {
		        smb2_set_error(smb2, "dcerpc bind failed");
		        return -1;
        }

        if (dcerpc_get_response_header(read_buf, status, &rsp_hdr) < 0) {
		        smb2_set_error(smb2, "failed to parse dcerpc response header");
		        return -1;
        }

        if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDNACK) {
                if (dcerpc_get_bind_nack_response(read_buf, status, &nack) < 0) {
		                smb2_set_error(smb2, "failed to parse dcerpc BINDNACK response");
                        return -1;
                }
                smb2_set_error(smb2, "dcerpc BINDNACK reason : %s", dcerpc_get_reject_reason(nack.reject_reason));
                return -1;
        } else if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDACK) {
                if (dcerpc_get_bind_ack_response(read_buf, status, &ack) < 0) {
		                smb2_set_error(smb2, "failed to parse dcerpc BINDACK response");
                        return -1;
                }
                /* save the max xmit and recv frag details */
                max_xmit_frag = ack.max_xmit_frag;
                max_recv_frag = ack.max_recv_frag;
max_xmit_frag = max_xmit_frag +1; // sarat remove this line
max_recv_frag = max_recv_frag +1; // sarat remove this line
        }

        if (asprintf(&serverName, "\\\\%s", server) < 0) {
		        smb2_set_error(smb2, "Failed to create NetrShareEnum request");
                return -1;
        }

        free(serverName); serverName = NULL;
        /* close the pipe  & disconnect */
        smb2_close(smb2, fh);
        smb2_disconnect_share(smb2);
        return status;
}
