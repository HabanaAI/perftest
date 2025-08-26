/******************************************************************************
 * Copyright (C) 2021 Habana Labs, Ltd. an Intel Company
 * All Rights Reserved.
 *
 * Unauthorized copying of this file or any element(s) within it, via any medium
 * is strictly prohibited.
 * This file contains Habana Labs, Ltd. proprietary and confidential information
 * and is subject to the confidentiality and license agreements under which it
 * was provided.
 * @file hbl_lib.h
 * @author Fahim Bellan (fahim.bellan@intel.com)
 * @date 2024-09-01
 *
 ******************************************************************************/

#ifndef __HBL_LIB_H__
#define __HBL_LIB_H__
#include "common.h"

STATUS init_device(char* dev_name, int rx_depth, int ib_port, struct test_context* test_ctx);
STATUS cleanup_device(struct test_context* test_ctx);
STATUS map_host_memory(struct test_context* test_ctx,
                       void*                host_virt_address,
                       size_t               data_size,
                       uint64_t*            dev_virt_address_out,
                       uint64_t             hint_addr);
STATUS alloc_dev_mem(struct test_context* test_ctx, uint64_t data_size, uint64_t* handle);
STATUS free_dev_mem(struct test_context* test_ctx, uint64_t handle);
STATUS unmap_dev_memory(struct test_context* test_ctx, uint64_t handle);
STATUS map_dev_memory(struct test_context* test_ctx, uint64_t handle, uint64_t* dev_virt_address_out);
STATUS set_local_dest(struct test_context* test_ctx, int ib_port, int gid_idx, struct test_dest* dst);
STATUS connect_qp_ctx(struct test_context* test_ctx, const struct test_dest* my_dst, struct test_dest* remote_dst);
void   send_msg(struct test_context* test_ctx, struct test_dest* remote_dst);
void   read_cq_req(struct test_context* test_ctx, int* sent_packets_cnt);
void   read_cq_res(struct test_context* test_ctx, int* received_packets_cnt);

BOOL   is_dev_habanalabs(char* dev_name);
void   free_device();
STATUS hbl_open_dev(int dev_id, int* fd);
void   hbl_close_dev(int fd);
#endif // __HBL_LIB_H__
