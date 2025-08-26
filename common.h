/******************************************************************************
 * Copyright (C) 2021 Habana Labs, Ltd. an Intel Company
 * All Rights Reserved.
 *
 * Unauthorized copying of this file or any element(s) within it, via any medium
 * is strictly prohibited.
 * This file contains Habana Labs, Ltd. proprietary and confidential information
 * and is subject to the confidentiality and license agreements under which it
 * was provided.
 * @file common.h
 * @author Fahim Bellan (fahim.bellan@intel.com)
 * @date 2024-09-01
 *
 ******************************************************************************/

#ifndef __COMMON_H__
#define __COMMON_H__
#include <infiniband/verbs.h>
#include <infiniband/hbldv.h>

#define STATUS int
#define OK 0
#define ERROR (-1)
#define BOOL int
#define FALSE 0
#define TRUE 1

extern BOOL g_print_logs; // use this flag to turn on/off logs

/**
 * @brief Print error message
 * Note: No need to add new line "\\n"
 * @param format Text
 * @param ... arguments
 */
void print_err(const char* format, ...);

/**
 * @brief Print info message
 * Note: No need to add new line '\\n'
 * @param format Text
 * @param ... arguments
 */
void print_info(const char* format, ...);

/**
 * @brief Print User Output
 * Note: No need to add new line '\\n'
 * @param format Text
 * @param ... arguments
 */
void print(const char* format, ...);

/**
 * @brief convert MTU number to ibv__mtu enum
 *  to use it in the qp attributes
 * @param mtu regular numbers e.g. 1024
 * @return enum ibv_mtu
 */
enum ibv_mtu mtu_to_ibv_enum(int mtu);

//------------------------ Declaring Structs -------------------
struct hbl_wq
{
    uint64_t s_wq; // send WQ
    uint64_t r_wq; // receive WQ
    uint64_t wq_offset;
    uint32_t pi;
    uint32_t ci;
    uint32_t max_wqes;
    uint32_t wrap_size;
};

struct hbl_cq_fifo
{
    struct ibv_cq*             ibv_cq;
    struct hbldv_query_cq_attr user_cq;
    uint32_t                   pi;
    uint32_t                   ci;
    uint32_t                   rx_depth;
};

typedef enum
{
    DEV_TYPE_GAUDI2 = 2,
    DEV_TYPE_GAUDI3,

    DEV_TYPE_UNKNOWN
} device_type_t;

typedef enum
{
    MEM_HOST,
    MEM_DEV

} test_mem_location_t;

/**
 * @brief Buffer descriptor that contains the actual buffer and the mapped buffer
 */
struct buffer_descriptor
{
    uint64_t* host_data_addr; // Buffer allocated in the Host.
                              // If test has multiple addresses, this will be the first one
    uint64_t handle; // When allocating memory on device we receive handle and not address

    uint64_t dev_va_data_add; // The mapped address in the device of host_data_addr.
    uint64_t host_va_data_add; // The mapped address in the host of dev_va_data_add.

    size_t data_payload_size; // Data size per buffer
    BOOL   is_mapped;
};

struct hbl_db_fifo
{
    struct hbldv_usr_fifo* ibv_db_fifo;
    uint32_t               pi; // producer index
    uint32_t               ci; // consumer index
    uint32_t               wrap_size;
    uint32_t               entry_size;
};

/**
 * @brief This is the main test context, that will be used to store
 * all the ibv components created by the HW Initializer, as well will be
 * used as the main data transaction between the tests module and the HBL Lib module
 *
 */
struct test_context
{
    struct ibv_context*      context;
    struct ibv_comp_channel* channel;
    struct ibv_pd*           pd;
    struct ibv_mr*           mr;
    struct ibv_qp*           qp;
    int                      rx_depth;
    int                      pending;
    struct ibv_port_attr     port_info;
    int                      dev_fd;
    device_type_t            dev_type;
    uint8_t                  dev_port_num;
    uint8_t                  dev_id;
    uint8_t                  ib_port_num;
    uint32_t                 qp_num;
    enum ibv_mtu             mtu;

    struct buffer_descriptor buff;

    struct hbl_cq_fifo cq_req_fifo;
    struct hbl_cq_fifo cq_res_fifo;
    struct hbl_db_fifo db_fifo;
    struct hbl_wq      wq;
    uint64_t           sent_packets;

    test_mem_location_t mem_loc; // Buffer Memory Location
};

struct test_dest
{
    int           qpn; // QP Number
    int           psn; // A 24 bits value of the Packet Sequence Number of the received packets for RC and UC QPs
    union ibv_gid gid; // Global Identifier
    int           gid_index;
    char          gid_str[33];
    uint64_t      dev_va_mem_address; // Device Virtual memory Address
    int           dev_port_num;
};

void gid_to_wire_gid(const union ibv_gid* gid, char wgid[]);
void wire_gid_to_gid(const char* wgid, union ibv_gid* gid);
#endif // __COMMON_H__
