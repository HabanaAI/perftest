/******************************************************************************
 * Copyright (C) 2021 Habana Labs, Ltd. an Intel Company
 * All Rights Reserved.
 *
 * Unauthorized copying of this file or any element(s) within it, via any medium
 * is strictly prohibited.
 * This file contains Habana Labs, Ltd. proprietary and confidential information
 * and is subject to the confidentiality and license agreements under which it
 * was provided.
 * @file hbl_lib.c
 * @author Fahim Bellan (fahim.bellan@intel.com)
 * @date 2024-09-01
 *
 ******************************************************************************/

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include "hbl_lib.h"
#include <infiniband/hbldv.h>
#include <infiniband/verbs.h>
#include <drm/habanalabs_accel.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define HBL_DEV_NAME_PRIMARY "/dev/accel/accel%d"
#define DEV_PATH_SIZE 20

static struct ibv_device** g_available_devices = NULL;

#define MAX_NUM_OF_WQES 128
#define MIN_NUM_OF_WQS 2

#define WQ_WRAP_SIZE_G3 0x400000
#define DB_FIFO_SIZE_G3 (1 << 11) // In Gaudi 3 it's free run
#define DB_FIFO_ENTRY_SIZE_BYTE_G3 2

#define DB_FIFO_SIZE_G2 64
#define DB_FIFO_ENTRY_SIZE_BYTE_G2 1

//---- For device types ----
#define PCI_IDS_GAUDI2 0x1020
#define PCI_IDS_GAUDI2_HL_288 0x1021
#define PCI_IDS_GAUDI3 0x1060
#define PCI_IDS_GAUDI3_HL_338 0x1063

#define MAX_NUM_OF_DEVICES 8
#define PCI_ADDRESS_LENGTH 15

#define IBV_NIC_DFLT_PSN 0

#define NIC_TMR_TIMEOUT_GRAN_DEFAULT 13 // 13 in HW 0.0335 sec
#define QP_NUM_RETRIES_CNT 7 // retry to send 7 times
#define QP_NUM_RETRIES_RNR                                                                                             \
    7 // The value 7 is special and specify to retry infinite times in case of RNR (Receiver Not Ready)
#define QOS_PRIORITY 1 // QoS Traffic Priority

#define user_db_pkt(port, qpn, wq_pi) ((wq_pi) | ((uint64_t)(qpn | (port << 24)) << 32))

#define Q_FILL(prod, cons, q_size) (((prod) - (cons) + (q_size)) & ((q_size) - 1))
#define Q_SPACE(prod, cons, q_size) ((q_size) - Q_FILL((prod), (cons), (q_size)) - 1)

#define rmb() asm volatile("lfence" ::: "memory")
#define wmb() asm volatile("sfence" ::: "memory")

enum wqe_opcode
{
    WQE_NOP                        = 0,
    WQE_SEND                       = 1,
    WQE_LINEAR                     = 2,
    WQE_STRIDE                     = 3,
    WQE_MULTI_STRIDE               = 4,
    WQE_RENDEZVOUS_WRITE           = 5,
    WQE_RENDEZVOUS_READ            = 6,
    WQE_ATOMIC_FETCH_ADD           = 7,
    WQE_MULTI_STRIDE_DUAL          = 8,
    WQE_ATOMIC_FETCH_AND_ADD_WRITE = 9,
    WQE_ATOMIC_FETCH_AND_ADD_READ  = 0xa,
    WQE_FIFO_ALLOCATION            = 0xb,
    WQE_FIFO_PUSH                  = 0xc,
    WQE_INVALID_OPCODE             = 0xf,
    WQE_ABOVE_15_OPCODE            = 0x1f
};

enum HWComletionType
{
    NO_COMPLETION         = 0,
    SOB_ONLY_COMPLETION   = 1,
    CQ_ONLY_COMPLETION    = 2,
    SOB_AND_CQ_COMPLETION = 3
};

struct sq_wqe_g2
{
    uint64_t opcode : 5;
    uint64_t trace_event_data : 1;
    uint64_t trace_event : 1;
    uint64_t reserved7 : 1;
    uint64_t wqe_index : 8;
    uint64_t reduction_opcode : 13;
    uint64_t se : 1;
    uint64_t in_line : 1;
    uint64_t ackreq : 1;
    uint64_t size : 32;
    uint64_t local_address_31_0 : 32;
    uint64_t local_address_63_32 : 32;
    uint64_t remote_address_31_0 : 32;
    uint64_t remote_address_63_32 : 32;
    uint64_t tag : 32;
    uint64_t remote_sync_object : 27;
    uint64_t remote_sync_object_data : 2;
    uint64_t sob_command : 1;
    uint64_t completion_type : 2;
} __attribute__((packed));

struct rq_wqe_g2
{
    uint64_t opcode : 5;
    uint64_t reserved_5_7 : 3;
    uint64_t wqe_index : 8;
    uint64_t reserved_16_30 : 15;
    uint64_t sob_command : 1;
    uint64_t local_sync_object : 27;
    uint64_t local_sync_object_data : 3;
    uint64_t completion_type : 2;
    uint64_t size : 32;
    uint64_t tag : 32;
} __attribute__((packed));

struct sq_wqe_g3
{
    uint64_t opcode : 5;
    uint64_t local_class : 2;
    uint64_t sob_ctl : 1;
    uint64_t local_mcid : 7;
    uint64_t local_alloch : 1;
    uint64_t reduction_opcode : 12;
    uint64_t rc : 1;
    uint64_t se_or_compress : 1;
    uint64_t in_line : 1;
    uint64_t ackreq : 1;
    uint64_t size : 32;
    uint64_t local_address_31_0 : 32;
    uint64_t local_address_63_32 : 32;
    uint64_t remote_address_31_0 : 32;
    uint64_t remote_address_63_32 : 32;
    uint64_t tag : 32;
    uint64_t remote_sob_id : 13;
    uint64_t remote_sub_sm : 1;
    uint64_t remote_sm_id : 3;
    uint64_t remote_mcid : 7;
    uint64_t remote_alloch : 1;
    uint64_t remote_class : 2;
    uint64_t long_sync_object : 1;
    uint64_t sob_command : 2;
    uint64_t completion_type : 2;
} __attribute__((packed)); /*No Padding*/

struct rq_wqe_g3
{
    uint64_t opcode : 5;
    uint64_t reserved_5_7 : 3;
    uint64_t wqe_index : 8;
    uint64_t reserved_16_31 : 16;
    uint64_t local_sob_id : 13;
    uint64_t local_sub_sm : 1;
    uint64_t local_sm_id : 3;
    uint64_t reserved_17_24 : 8;
    uint32_t sob_fifo : 2;
    uint64_t long_sync_object : 1;
    uint64_t sob_command : 2;
    uint64_t completion_type : 2;
    uint64_t size : 32;
    uint64_t tag : 32;
} __attribute__((packed));

struct cqe_raw_descriptor
{
    uint32_t data[4];
};

#define CQE_IS_VALID(cqe) (((cqe)->data[0] >> 31) & 1)
#define CQE_IS_REQ(cqe) (((cqe)->data[0] >> 24) & 1)
#define CQE_QPN(cqe) ((cqe)->data[0] & 0xFFFFFF)
#define CQE_SET_INVALID(cqe) ((cqe)->data[0] &= ~(1ull << 31))
#define CQE_WQE_IDX(cqe) ((cqe)->data[1])
#define CQE_TAG(cqe) ((cqe)->data[2])
#define CQE_RAW_PKT_SIZE(cqe) ((cqe)->data[3])
#define CQE_CLEAR(cqe) ((cqe)->data[0] &= 0)
//------------------- Declaring internal functions for the module -----------
struct ibv_device* find_device(char* dev_name, uint8_t* dev_id);
uint64_t           hbl_map_dev_memory(int fd, uint64_t handle, uint64_t hint_addr);
int                hbl_unmap_dev_memory(int fd, uint64_t handle);
uint64_t           hbl_dev_mem_alloc(int fd, uint64_t size, uint64_t page_size, BOOL contiguous, BOOL shared);
int                hbl_free_dev_mem(int fd, uint64_t handle);

device_type_t get_dev_type(struct ibv_context* ibv_context);
BOOL          is_port_link_status_up(uint8_t dev_id, int ib_port_number);

STATUS create_wq(int ib_port, struct ibv_context* ibv_context);
int    hbl_clear_wq_arr(int fd, uint8_t ib_port, uint32_t type);
extern int
hlibv_query_gid_type(struct ibv_context* context, uint8_t port_num, unsigned int index, enum ibv_gid_type* type);

typedef STATUS (*fill_wqe_cb)(struct test_context* test_ctx, struct test_dest* remote_dst);
STATUS             fill_wqe_g3(struct test_context* test_ctx, struct test_dest* remote_dst);
STATUS             fill_wqe_g2(struct test_context* test_ctx, struct test_dest* remote_dst);
static fill_wqe_cb fill_wqe = fill_wqe_g3;

typedef void (*update_ci_cb)(struct hbl_cq_fifo* cq_fifo);
void                update_ci_g3(struct hbl_cq_fifo* cq_fifo);
void                update_ci_g2(struct hbl_cq_fifo* cq_fifo);
static update_ci_cb update_ci = update_ci_g3;

STATUS submit_doorbell_fifo(struct test_context* test_ctx);
static STATUS
config_responder_q(struct test_context* test_ctx, const struct test_dest* my_dst, struct test_dest* remote_dst);
static STATUS
config_requester_q(struct test_context* test_ctx, const struct test_dest* my_dst, struct test_dest* remote_dst);
static void read_cq(struct test_context* test_ctx, struct hbl_cq_fifo* cq_fifo, int* cqe_read_cnt);

/**
 * @brief This function open the device and initiate it by creating pd, cq, qp, wq.
 * need to provide allocated test_ctx, the func will fill it.
 * when finish need to call cleanup_device.
 * @param dev_name HabanaLabs device name
 * @param rx_depth number of entries in CQ
 * @param ib_port port number #NIC number
 * @param test_ctx [Output] The function will fill the test_context
 * @return STATUS
 */
STATUS init_device(char* dev_name, int rx_depth, int ib_port, struct test_context* test_ctx)
{
    struct ibv_device*  device      = NULL;
    struct ibv_context* ibv_context = NULL;
    struct ibv_pd*      pd          = NULL; // Protection domain
    struct ibv_cq*      cq_req      = NULL;
    struct ibv_cq*      cq_res      = NULL;
    struct ibv_qp*      qp          = NULL; // Queue Pair
    int                 err_code    = 0; // 0 = OK
    STATUS              res         = ERROR;

    if (test_ctx == NULL) {
        print_err("CRITICAL: test_ctx is NULL");
        return ERROR;
    }

    device = find_device(dev_name, &(test_ctx->dev_id));
    if (device == NULL) {
        print_err("Failed to find device");
        return ERROR;
    }

    // Open the ibv device
    if (hbl_open_dev(test_ctx->dev_id, &(test_ctx->dev_fd)) != OK) {
        print_err("Failed to open device");
        return ERROR;
    }

    struct hbldv_ucontext_attr dev_attr = {};
    dev_attr.core_fd                    = test_ctx->dev_fd;
    print_info("dev_attr.core_fd =%d ", dev_attr.core_fd);

    ibv_context = hbldv_open_device(device, &dev_attr);
    if (ibv_context == NULL) {
        print_err("Failed to open device: %s", device->name);
        return ERROR;
    }

    print_info("Opened device");

    // check port link status
    if (!is_port_link_status_up(test_ctx->dev_id, ib_port)) {
        print_err("ib port %02d status is DOWN ", ib_port);
        return ERROR;
    }

    pd = hlibv_alloc_pd(ibv_context);
    if (!pd) {
        print_err("Couldn't allocate PD");
    }
    print_info("hlibv_alloc_pd Done");

    test_ctx->dev_type = get_dev_type(ibv_context);
    if (test_ctx->dev_type == DEV_TYPE_UNKNOWN) {
        print_err("Failed to get device type or device is not supported");
        goto clean_pd;
    }

    print_info("Device is Gaudi %d", test_ctx->dev_type);

    res = create_wq(ib_port, ibv_context);
    if (res != OK) {
        print_err("Failed to create wq");
        goto clean_pd;
    }

    //----------------------- Create a Completion Queues CQs --------------------------

    struct hbldv_cq_attr cq_attr = {0};
    cq_attr.port_num             = ib_port;

    //------------------------- Responder CQ -------------------------

    cq_res = hbldv_create_cq(ibv_context, rx_depth, NULL /*cq_context*/, 0 /*Channel*/, &cq_attr);
    if (cq_res == NULL) {
        print_err("Couldn't create Responder CQ");
        goto clean_pd;
    }

    memset(&test_ctx->cq_res_fifo.user_cq, 0, sizeof(test_ctx->cq_res_fifo.user_cq));
    err_code = hbldv_query_cq(cq_res, &test_ctx->cq_res_fifo.user_cq);
    if (err_code) {
        print_err("Failed to query responder cq err = %d", err_code);
        goto clean_cq_res;
    }
    test_ctx->cq_res_fifo.ci       = 0;
    test_ctx->cq_res_fifo.pi       = 0;
    test_ctx->cq_res_fifo.rx_depth = rx_depth;

    if (test_ctx->dev_type == DEV_TYPE_GAUDI2) {
        update_ci = update_ci_g2;
    }

    print_info("CQ Created: "
               "\ncq_res_fifo.pi_cpu_addr = %p "
               "\ncq_res_fifo.mem_cpu_addr = %p "
               "\ncq_res_fifo.regs_cpu_addr = %p "
               "\ncq_res_fifo.regs_offset = %u "
               "\ncq_res_fifo.cq_num = %u",
               (void*)test_ctx->cq_res_fifo.user_cq.pi_cpu_addr,
               (void*)test_ctx->cq_res_fifo.user_cq.mem_cpu_addr,
               (void*)test_ctx->cq_res_fifo.user_cq.regs_cpu_addr,
               test_ctx->cq_res_fifo.user_cq.regs_offset,
               test_ctx->cq_res_fifo.user_cq.cq_num);

    //------------------------- Requester CQ-------------------------

    cq_req = hbldv_create_cq(ibv_context, rx_depth, NULL /*cq_context*/, 0 /*Channel*/, &cq_attr);
    if (cq_req == NULL) {
        print_err("Couldn't create Requester CQ");
        goto clean_cq_res;
    }

    memset(&test_ctx->cq_req_fifo.user_cq, 0, sizeof(test_ctx->cq_req_fifo.user_cq));
    err_code = hbldv_query_cq(cq_req, &test_ctx->cq_req_fifo.user_cq);
    if (err_code) {
        print_err("Failed to query requester cq err = %d", err_code);
        goto clean_cqs;
    }
    test_ctx->cq_req_fifo.ci       = 0;
    test_ctx->cq_req_fifo.pi       = 0;
    test_ctx->cq_req_fifo.rx_depth = rx_depth;

    print_info("CQ Created: "
               "\ncq_req_fifo.pi_cpu_addr = %p "
               "\ncq_req_fifo.mem_cpu_addr = %p "
               "\ncq_req_fifo.regs_cpu_addr = %p "
               "\ncq_req_fifo.regs_offset = %u "
               "\ncq_req_fifo.cq_num = %u",
               (void*)test_ctx->cq_req_fifo.user_cq.pi_cpu_addr,
               (void*)test_ctx->cq_req_fifo.user_cq.mem_cpu_addr,
               (void*)test_ctx->cq_req_fifo.user_cq.regs_cpu_addr,
               test_ctx->cq_req_fifo.user_cq.regs_offset,
               test_ctx->cq_req_fifo.user_cq.cq_num);
    //------------------ Create Queue Pair QP ---------------------

    struct ibv_qp_init_attr init_attr = {
        .send_cq = cq_req,
        .recv_cq = cq_res,
        // TBD: The assigning style might be change later, during the development project
        .cap     = {.max_send_wr = MAX_NUM_OF_WQES, .max_recv_wr = 1, .max_send_sge = 1, .max_recv_sge = 1},
        .qp_type = IBV_QPT_RC}; // RC= Reliable  Connection

    qp = hlibv_create_qp(pd, &init_attr);
    if (!qp) {
        print_err("Couldn't create QP");
        goto clean_cqs;
    }

    struct ibv_qp_attr qp_attr = {0};
    qp_attr.qp_state           = IBV_QPS_INIT;
    qp_attr.port_num           = ib_port;
    qp_attr.pkey_index         = 0;
    qp_attr.qp_access_flags    = IBV_ACCESS_REMOTE_WRITE;

    struct hbldv_qp_attr dv_qp_init_attr = {0};

    dv_qp_init_attr.wq_type        = HBLDV_WQ_WRITE;
    dv_qp_init_attr.wq_granularity = HBLDV_SWQE_GRAN_32B;

    err_code = hbldv_modify_qp(
        qp, &qp_attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS, &dv_qp_init_attr);
    if (err_code) {
        print_err("Failed to modify_qp err=%d", err_code);
        goto clean_qp;
    }

    test_ctx->ib_port_num        = ib_port;
    test_ctx->context            = ibv_context;
    test_ctx->pd                 = pd;
    test_ctx->cq_req_fifo.ibv_cq = cq_req;
    test_ctx->cq_res_fifo.ibv_cq = cq_res;
    test_ctx->qp                 = qp;
    test_ctx->rx_depth           = rx_depth;
    print_info("Init device finished successfully ");

    return OK;

clean_qp:
    hlibv_destroy_qp(qp);
    test_ctx->qp = NULL;

clean_cqs:
    hlibv_destroy_cq(cq_req);
    test_ctx->cq_req_fifo.ibv_cq = NULL;

clean_cq_res:
    hlibv_destroy_cq(cq_res);
    test_ctx->cq_res_fifo.ibv_cq = NULL;

clean_pd:
    hlibv_dealloc_pd(pd);
    test_ctx->pd = NULL;

    hlibv_close_device(ibv_context);

    hbl_close_dev(test_ctx->dev_fd);
    test_ctx->dev_fd = -1;

    return ERROR;
}

STATUS cleanup_device(struct test_context* test_ctx)
{
    STATUS res = OK;
    if (test_ctx == NULL) {
        print_err("CRITICAL: test_ctx is NULL");
        return ERROR;
    }

    if (test_ctx->qp != NULL && hlibv_destroy_qp(test_ctx->qp)) {
        print_err("Couldn't destroy QP");
        res |= ERROR;
    }
    test_ctx->qp = NULL;

    if (test_ctx->cq_res_fifo.ibv_cq != NULL && hlibv_destroy_cq(test_ctx->cq_res_fifo.ibv_cq)) {
        print_err("Couldn't destroy Responder CQ");
        res |= ERROR;
    }
    test_ctx->cq_res_fifo.ibv_cq = NULL;

    if (test_ctx->cq_req_fifo.ibv_cq != NULL && hlibv_destroy_cq(test_ctx->cq_req_fifo.ibv_cq)) {
        print_err("Couldn't destroy Requester CQ");
        res |= ERROR;
    }
    test_ctx->cq_req_fifo.ibv_cq = NULL;

    if (test_ctx->db_fifo.ibv_db_fifo != NULL && hbldv_destroy_usr_fifo(test_ctx->db_fifo.ibv_db_fifo)) {
        print_err("Couldn't destroy db FIFO");
        res |= ERROR;
    }
    test_ctx->db_fifo.ibv_db_fifo = NULL;

    if (test_ctx->pd != NULL && hlibv_dealloc_pd(test_ctx->pd)) {
        print_err("Couldn't deallocate PD");
        res |= ERROR;
    }
    test_ctx->pd = NULL;

    if (test_ctx->context != NULL && hlibv_close_device(test_ctx->context)) {
        print_err("Couldn't release context");
        res |= ERROR;
    }
    test_ctx->context = NULL;

    free_device();

    return res;
}

/**
 * @brief This function unmap the device memory address that was mapped
 *  by map_host_memory or map_dev_memory
 *
 * @param test_ctx test context
 * @param host_virt_address the pre-allocated buffer address in host
 * @param data_size
 * @param dev_virt_address_out[Output] The mapped device virtual address
 * @return STATUS
 */
int hbl_unmap_dev_memory(int fd, uint64_t handle)
{
    union hl_mem_args ioctl_args;

    memset(&ioctl_args, 0, sizeof(ioctl_args));
    ioctl_args.in.unmap.device_virt_addr = handle;
    ioctl_args.in.op                     = HL_MEM_OP_UNMAP;

    return ioctl(fd, DRM_IOCTL_HL_MEMORY, &ioctl_args);
}

/**
 * @brief Unmap device virtual address
 *
 * @param test_ctx
 * @param handle[In] device address handle
 * @return STATUS
 */
STATUS unmap_dev_memory(struct test_context* test_ctx, uint64_t handle)
{
    if (test_ctx->dev_fd < 0) {
        print_err("Wrong fd");
        return ERROR;
    }

    if (hbl_unmap_dev_memory(test_ctx->dev_fd, handle) != 0) {
        print_err("Couldn't unmap memory on device");
        return ERROR;
    }

    return OK;
}
uint64_t hbl_dev_mem_alloc(int fd, uint64_t size, uint64_t page_size, BOOL contiguous, BOOL shared)
{
    union hl_mem_args ioctl_args;
    int               rc;

    memset(&ioctl_args, 0, sizeof(ioctl_args));

    ioctl_args.in.alloc.mem_size  = size;
    ioctl_args.in.alloc.page_size = page_size;
    if (contiguous)
        ioctl_args.in.flags |= HL_MEM_CONTIGUOUS;
    if (shared)
        ioctl_args.in.flags |= HL_MEM_SHARED;
    ioctl_args.in.op = HL_MEM_OP_ALLOC;

    rc = ioctl(fd, DRM_IOCTL_HL_MEMORY, &ioctl_args);
    if (rc) {
        print_err("ioctl failed with result code = %d", rc);
        return 0;
    }

    return ioctl_args.out.handle;
}

/**
 * @brief Allocate buffer on device memory HBM
 *
 * @param test_ctx
 * @param data_size
 * @param handle[Out] device address handle (1,2,3,..)
 * @return STATUS
 */
STATUS alloc_dev_mem(struct test_context* test_ctx, uint64_t data_size, uint64_t* handle)
{

    if (test_ctx->dev_fd < 0) {
        print_err("Wrong fd");
        return ERROR;
    }

    *handle = hbl_dev_mem_alloc(test_ctx->dev_fd, data_size, 0, TRUE, FALSE);
    if (*handle == 0) {
        print_err("Couldn't allocate memory on device");
        return ERROR;
    }

    return OK;
}

int hbl_free_dev_mem(int fd, uint64_t handle)
{
    union hl_mem_args ioctl_args;

    memset(&ioctl_args, 0, sizeof(ioctl_args));
    ioctl_args.in.free.handle = handle;
    ioctl_args.in.op          = HL_MEM_OP_FREE;

    return ioctl(fd, DRM_IOCTL_HL_MEMORY, &ioctl_args);
}
/**
 * @brief free pre-allocated buffer on device memory
 *
 * @param test_ctx
 * @param handle[In] device address handle
 * @return STATUS
 */
STATUS free_dev_mem(struct test_context* test_ctx, uint64_t handle)
{

    if (test_ctx->dev_fd < 0) {
        print_err("Wrong fd");
        return ERROR;
    }

    if (hbl_free_dev_mem(test_ctx->dev_fd, handle) != 0) {
        print_err("Couldn't free memory on device");
        return ERROR;
    }

    return OK;
}

uint64_t hbl_map_dev_memory(int fd, uint64_t handle, uint64_t hint_addr)
{
    union hl_mem_args ioctl_args;
    int               rc;

    memset(&ioctl_args, 0, sizeof(ioctl_args));
    ioctl_args.in.map_device.hint_addr = hint_addr;
    ioctl_args.in.map_device.handle    = handle;
    ioctl_args.in.op                   = HL_MEM_OP_MAP;

    rc = ioctl(fd, DRM_IOCTL_HL_MEMORY, &ioctl_args);
    if (rc) {
        print_err("ioctl failed with result code = %d", rc);
        return 0;
    }

    return ioctl_args.out.device_virt_addr;
}

/**
 * @brief Map device handle to a device virtual address
 *
 * @param test_ctx
 * @param handle[In]
 * @param dev_virt_address_out[Out] device virtual address
 * @return STATUS
 */
STATUS map_dev_memory(struct test_context* test_ctx, uint64_t handle, uint64_t* dev_virt_address_out)
{
    if (test_ctx->dev_fd < 0) {
        print_err("Wrong fd");
        return ERROR;
    }

    *dev_virt_address_out = hbl_map_dev_memory(test_ctx->dev_fd, handle, 0);
    if (*dev_virt_address_out == 0) {
        print_err("Couldn't map memory on device");
        return ERROR;
    }
    return OK;
}

uint64_t hbl_map_host_memory(int fd, void* host_virt_addr, uint64_t hint_addr, uint64_t host_size)
{
    union hl_mem_args ioctl_args;
    int               rc;

    memset(&ioctl_args, 0, sizeof(ioctl_args));
    ioctl_args.in.map_host.host_virt_addr = (uint64_t)host_virt_addr;
    ioctl_args.in.map_host.mem_size       = host_size;
    ioctl_args.in.map_host.hint_addr      = hint_addr;
    ioctl_args.in.flags                   = HL_MEM_USERPTR;
    ioctl_args.in.op                      = HL_MEM_OP_MAP;

    rc = ioctl(fd, DRM_IOCTL_HL_MEMORY, &ioctl_args);
    if (rc) {
        print_err("ioctl failed with result code = %d", rc);
        return 0;
    }

    return ioctl_args.out.device_virt_addr;
}

/**
 * @brief map host virtual address to device virtual address
 *
 * @param test_ctx test context
 * @param host_virt_address the pre-allocated buffer address in host
 * @param data_size
 * @param dev_virt_address_out[Output] The mapped device virtual address
 * @param hint_addr hint address if already allocated memory on device
 * @return STATUS
 */
STATUS map_host_memory(struct test_context* test_ctx,
                       void*                host_virt_address,
                       size_t               data_size,
                       uint64_t*            dev_virt_address_out,
                       uint64_t             hint_addr)
{
    if (host_virt_address == NULL) {
        print_err("CRITICAL: host_virt_address pointer is NULL!");
        return ERROR;
    }

    if (test_ctx->dev_fd < 0) {
        print_err("Wrong fd");
        return ERROR;
    }

    uint64_t mapped_addr = 0;
    mapped_addr          = hbl_map_host_memory(test_ctx->dev_fd, host_virt_address, hint_addr, data_size);
    if (mapped_addr == 0) {
        print_err("Couldn't map host address!");
        return ERROR;
    }

    *dev_virt_address_out = mapped_addr;
    print_info("Address mapped successfully host_virt_address = 0x%lx dev_virt_address_out = 0x%lx",
               (uintptr_t)host_virt_address,
               mapped_addr);
    return OK;
}

/**
 * @brief Get the port link status object from the device port number and device id.
 *
 * @param dev_id  device id hbl_0, hbl_1, hbl_2, ...
 * @param ib_port_number  device port number  1, 2, ...
 * @return BOOL TRUE if the port is up, FALSE otherwise
 */
BOOL is_port_link_status_up(uint8_t dev_id, int ib_port_number)
{
    // read the result from the linux command cat /sys/class/infiniband/hbl_0/ports/19/phys_state

    char cmd[100];
    snprintf(cmd, sizeof(cmd), "cat /sys/class/infiniband/hbl_%d/ports/%d/phys_state", dev_id, ib_port_number);
    FILE* fp = popen(cmd, "r");
    if (fp == NULL) {
        print_err("Failed to run command");
        return FALSE;
    }

    char   buf[128];
    size_t len = fread(buf, 1, sizeof(buf), fp);
    if (len == 0) {
        print_err("Failed to read command output");
        pclose(fp);
        return FALSE;
    }
    pclose(fp);

    buf[len] = '\0';

    print_info("The port link status is: %s", buf);
    return (strcmp(buf, "5: LinkUp\n") == 0);
}

/**
 * @brief Set the local destination. To communicate two QPs together we need to fill qp number, gid and address
 * destination
 *
 * @param test_ctx Test context
 * @param ib_port device port
 * @param gid_idx gid index (0 - L2 MAC), (1 - L3 based on IPv4)
 * @param dst[Output] destination object output to exchange it with the other side
 * @return STATUS
 */
STATUS set_local_dest(struct test_context* test_ctx, int ib_port, int gid_idx, struct test_dest* dst)
{
    // We do not support LID, LID is not RoCE V2, no LID configuration in set_local_dest

    struct hbldv_query_qp_attr qp_attr = {0};
    // get connection ID of the QP
    if (hbldv_query_qp(test_ctx->qp, &qp_attr)) {
        print_err("Couldn't get QP attribute\n");
        return ERROR;
    }
    dst->qpn         = qp_attr.qp_num;
    test_ctx->qp_num = qp_attr.qp_num;

    // TBD need to retrieve the ipv4 from the machine and convert it to gid, instead of doing hlibv_query_gid
    if (gid_idx >= 0) {
        if (hlibv_query_gid(test_ctx->context, ib_port, gid_idx, &dst->gid)) {
            print_err("can't read sgid of index %d\n", gid_idx);
            return ERROR;
        }
    } else
        memset(&dst->gid, 0, sizeof dst->gid);
    dst->gid_index = gid_idx;

    // we don't want to use the gid query because some system has ipv6 and will not work on our system since we do not
    // support ipv6 we will create our gid from the ipv4

    // check what is the type of the gid
    enum ibv_gid_type type = IBV_GID_TYPE_IB;
    hlibv_query_gid_type(test_ctx->context, ib_port, gid_idx, &type);

    /*  @note
        IBV_GID_TYPE_ROCE_V1 is non-routable works only on layer 2 MAC Address only,
        it means it can't work with switch
    */
    print_info("The GID Type is: %d = %s",
               type,
               type == IBV_GID_TYPE_ROCE_V1 || type == IBV_GID_TYPE_IB
                   ? "IBV_GID_TYPE_ROCE_V1=1 /TYPE_IB=0 - (is non-routable works only on layer 2 MAC Address only)"
                   : "IBV_GID_TYPE_ROCE_V2 - can work with switch");
    // convert gid to string
    inet_ntop(AF_INET6, &dst->gid, dst->gid_str, sizeof(dst->gid_str));

    dst->psn = IBV_NIC_DFLT_PSN; // currently the driver does not support PSN

    // attaching the created destination buffer address to the destination exchange object
    dst->dev_va_mem_address = test_ctx->buff.dev_va_data_add;
    print_info("Setting destination of the device address to send it to the remote side dev_addr= 0x%lX",
               dst->dev_va_mem_address);

    dst->dev_port_num = ib_port;

    return OK;
}

/**
 * @brief Create a Work Queue to submit to WQEs
 *
 * @param ib_port hbl device port
 * @param ibv_context ibv opened device context
 * @return STATUS
 */
STATUS create_wq(int ib_port, struct ibv_context* ibv_context)
{
    int                         err_code = 0;
    struct hbldv_wq_array_attr* wq_arr_attr;
    struct hbldv_port_ex_attr   port_attr = {0};

    port_attr.port_num = ib_port;
    port_attr.caps     = HBLDV_PORT_CAP_ADVANCED;

    // attach port to work queue array
    wq_arr_attr = &port_attr.wq_arr_attr[HBLDV_WQ_ARRAY_TYPE_GENERIC];

    // TBD: assigning values to max_num_of_wqs, max_num_of_wqes_in_wq might change during project development
    wq_arr_attr->max_num_of_wqs        = MIN_NUM_OF_WQS; // one WQ per each QP
    wq_arr_attr->max_num_of_wqes_in_wq = MAX_NUM_OF_WQES; // max_qp_wq_size per each work queue
    wq_arr_attr->mem_id                = HBLDV_MEM_HOST; // Work Queue location
    wq_arr_attr->swq_granularity       = HBLDV_SWQE_GRAN_32B;

    err_code = hbldv_set_port_ex(ibv_context, &port_attr);
    if (err_code != OK) {
        print_err("Failed to set_port_ex err =%d", err_code);
        return ERROR;
    }

    if (get_dev_type(ibv_context) == DEV_TYPE_GAUDI2) {
        fill_wqe = fill_wqe_g2;
    }
    return OK;
}

/**
 * @brief need to be called after find_device() at the end of the program
 */
void free_device()
{
    if (g_available_devices != NULL)
        hlibv_free_device_list(g_available_devices);
    g_available_devices = NULL;
}

/**
 * @brief This function will find and return the hbl requested device.
 * if the no name were provided it will return the first hbl device found.
 * @note find_device will allocate ibv context need to be freed by free_device()
 * @param dev_name hbl device name "hbl_X" / NULL
 * @param dev_id [Output] device id
 * @return struct ibv_device*
 */
struct ibv_device* find_device(char* dev_name, uint8_t* dev_id)
{
    int  available_devices_size = 0;
    BOOL flag_found             = FALSE;

    struct ibv_device* device = NULL;

    // this list should not be freed until the device is open
    g_available_devices = hlibv_get_device_list(&available_devices_size);

    if (g_available_devices == NULL || available_devices_size == 0) {
        print_err("No available devices!");
        return NULL;
    }

    //------------------ debug ----------------
    {
        for (int devId = 0; devId < available_devices_size; devId++) {
            if (g_available_devices[devId] == NULL) {
                print_info("skipping device in array not available index_id=%d", devId);
                continue;
            }

            print_info("Device %d: Name: %s dev_name: %s dev_path: %s ibdev_path: %s Kernel Device Name: %s",
                       devId,
                       g_available_devices[devId]->name,
                       g_available_devices[devId]->dev_name,
                       g_available_devices[devId]->dev_path,
                       g_available_devices[devId]->ibdev_path,
                       hlibv_get_device_name(g_available_devices[devId]));
        }
    }
    //------------------ end debug -------------

    // User can enter an empty name, and we should find the first Habana-lab device

    for (int idx = 0; idx < available_devices_size; idx++) {
        // In order to choose the default first device found (@TODO: what if this device is mlx ??)
        if (strcmp(dev_name, "") == 0 || strcmp(g_available_devices[idx]->name, dev_name) == 0) {
            if (!is_dev_habanalabs(g_available_devices[idx]->name)) {
                continue;
            }
            device     = g_available_devices[idx];
            flag_found = TRUE;
            break;
        }
    }

    if (!flag_found) {
        if (dev_name == NULL) {
            print_err("Couldn't find any HabanaLabs device");
        } else
            print_err("Couldn't find device: %s", dev_name);

        goto clean_list;
    }

    if (sscanf(device->name, "hbl_%hhu", dev_id) != 1) {
        print_err("Failed to get Device ID from device name %s", device->name);
        goto clean_list;
    }
    print_info("Device ID is %d", *dev_id);
    print_info("Device Name is %s", device->name);
    print_info("ibv dev pointer is %p", device);
    return device;

clean_list:
    free_device();
    return NULL;
}

BOOL is_dev_habanalabs(char* dev_name)
{
    if (dev_name == NULL) {
        return FALSE;
    }

    if (strncmp(dev_name, "hbl", 3) == 0) {
        return TRUE;
    }
    return FALSE;
}

/**
 * @brief This function open the device by device id and return the file descriptor
 *
 * @param dev_id device id
 * @param fd [Output] file descriptor
 * @return STATUS
 */
STATUS hbl_open_dev(int dev_id, int* fd)
{
    char dev_path[DEV_PATH_SIZE];
    snprintf(dev_path, sizeof(dev_path), HBL_DEV_NAME_PRIMARY, dev_id);

    *fd = open(dev_path, O_RDWR | O_CLOEXEC, 0);
    if (*fd < 0) {
        print_err("Failed to open device %s", dev_path);
        return ERROR;
    }

    return OK;
}

void hbl_close_dev(int fd)
{
    close(fd);
}

/**
 * @brief Get the dev type Gaudi2, Gaudi3, ...
 * this function is crucial for the system because different type of devices has
 * different configuration based on their architecture.
 * @param ibv_context
 * @return device_type_t
 */
device_type_t get_dev_type(struct ibv_context* ibv_context)
{

    struct ibv_device_attr attr;
    int                    err_code = 0;

    if (ibv_context == NULL) {
        print_err("CRITICAL: *ibv_context is NULL ");
        return DEV_TYPE_UNKNOWN;
    }

    err_code = hlibv_query_device(ibv_context, &attr);

    if (err_code) {
        print_err("Failed to do hlibv_query_device error=%d", err_code);
        return DEV_TYPE_UNKNOWN;
    }

    switch (attr.vendor_part_id) {

        case PCI_IDS_GAUDI2_HL_288:
        case PCI_IDS_GAUDI2: return DEV_TYPE_GAUDI2; break;
        case PCI_IDS_GAUDI3_HL_338:
        case PCI_IDS_GAUDI3: return DEV_TYPE_GAUDI3; break;

        default: return DEV_TYPE_UNKNOWN; break;
    }
}

STATUS config_responder_q(struct test_context* test_ctx, const struct test_dest* my_dst, struct test_dest* remote_dst)
{
    struct ibv_qp_attr   ibv_qp_attr = {0};
    struct hbldv_qp_attr hl_qp_attr  = {0};
    int                  attr_mask   = 0;
    STATUS               res         = OK;

    ibv_qp_attr.qp_state           = IBV_QPS_RTR; // ready to receive
    ibv_qp_attr.path_mtu           = test_ctx->mtu;
    ibv_qp_attr.dest_qp_num        = remote_dst->qpn;
    ibv_qp_attr.rq_psn             = remote_dst->psn;
    ibv_qp_attr.max_dest_rd_atomic = 1;
    ibv_qp_attr.ah_attr.port_num   = test_ctx->ib_port_num;
    /*ah_attr AV= Address Vector */
    if (remote_dst->gid.global.interface_id) {

        ibv_qp_attr.ah_attr.is_global     = 1;
        ibv_qp_attr.ah_attr.grh.hop_limit = 0xff;
        memcpy(&ibv_qp_attr.ah_attr.grh.dgid, &remote_dst->gid, sizeof(remote_dst->gid));
        print_info("my_dst->gid_index =%d", my_dst->gid_index);
        ibv_qp_attr.ah_attr.grh.sgid_index = my_dst->gid_index;
    }

    hl_qp_attr.wq_granularity = HBLDV_SWQE_GRAN_32B; // not multi cast for MS use 64B
    hl_qp_attr.priority       = QOS_PRIORITY;

    attr_mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    res = hbldv_modify_qp(test_ctx->qp, &ibv_qp_attr, attr_mask, &hl_qp_attr);
    if (res != OK) {
        print_err("Failed to modify QP to RTR err=%d", res);
        return ERROR;
    }

    return OK;
}

STATUS config_requester_q(struct test_context* test_ctx, const struct test_dest* my_dst, struct test_dest* remote_dst)
{
    struct hbldv_query_qp_attr dv_qp_attr  = {0};
    struct ibv_qp_attr         ibv_qp_attr = {0};
    struct hbldv_qp_attr       hl_qp_attr  = {0};
    int                        attr_mask   = 0;
    STATUS                     res         = OK;

    hl_qp_attr.wq_type        = HBLDV_WQ_WRITE;
    hl_qp_attr.priority       = QOS_PRIORITY;
    hl_qp_attr.wq_granularity = HBLDV_SWQE_GRAN_32B; // no support for MS so far

    ibv_qp_attr.qp_state      = IBV_QPS_RTS;
    ibv_qp_attr.dest_qp_num   = remote_dst->qpn;
    ibv_qp_attr.timeout       = NIC_TMR_TIMEOUT_GRAN_DEFAULT;
    ibv_qp_attr.retry_cnt     = QP_NUM_RETRIES_CNT;
    ibv_qp_attr.rnr_retry     = QP_NUM_RETRIES_RNR;
    ibv_qp_attr.sq_psn        = my_dst->psn;
    ibv_qp_attr.max_rd_atomic = 1;

    attr_mask =
        IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    res = hbldv_modify_qp(test_ctx->qp, &ibv_qp_attr, attr_mask, &hl_qp_attr);
    if (res != OK) {
        print_err("Failed to modify QP to RTS err=%d", res);
        return ERROR;
    }

    // Only for requester. Get the WQ addresses
    res = hbldv_query_qp(test_ctx->qp, &dv_qp_attr);
    if (res != OK) {
        print_err("Failed to get WQ addresses (hbldv_query_qp) err=%d", res);
        return ERROR;
    }

    test_ctx->wq.s_wq      = (uint64_t)dv_qp_attr.swq_cpu_addr;
    test_ctx->wq.r_wq      = (uint64_t)dv_qp_attr.rwq_cpu_addr;
    test_ctx->wq.wq_offset = 0;
    test_ctx->wq.max_wqes  = MAX_NUM_OF_WQES;

    switch (test_ctx->dev_type) {
        case DEV_TYPE_GAUDI2: test_ctx->wq.wrap_size = MAX_NUM_OF_WQES; break;
        case DEV_TYPE_GAUDI3: test_ctx->wq.wrap_size = WQ_WRAP_SIZE_G3; break;

        default: break;
    }

    print_info("Doorbell FIFO is created");
    print_info("test_ctx->wq.r_wq =0x%lx", test_ctx->wq.r_wq);
    print_info("test_ctx->wq.s_wq =0x%lx", test_ctx->wq.s_wq);

    return OK;
}
/**
 * @brief connect two QP collections local and remote
 * This function it will also create a db_fifo
 * @param test_ctx the whole test context
 * @param my_dst the current destination
 * @param remote_dst the remote side destination
 * @return STATUS
 */
STATUS connect_qp_ctx(struct test_context* test_ctx, const struct test_dest* my_dst, struct test_dest* remote_dst)
{
    STATUS res = OK;

    res = config_responder_q(test_ctx, my_dst, remote_dst);
    if (res != OK) {
        print_err("Failed to Configure Responder Queue");
        return ERROR;
    }

    res = config_requester_q(test_ctx, my_dst, remote_dst);
    if (res != OK) {
        print_err("Failed to Configure Requester Queue");
        return ERROR;
    }

    struct hbldv_usr_fifo_attr db_attr = {0};
    struct hbldv_usr_fifo*     hbldv_usr_fifo;

    db_attr.port_num      = test_ctx->ib_port_num;
    db_attr.usr_fifo_type = HBLDV_USR_FIFO_TYPE_DB;

    hbldv_usr_fifo = hbldv_create_usr_fifo(test_ctx->context, &db_attr);
    if (hbldv_usr_fifo == NULL) {
        print_err("Failed to create user fifo!");
        return ERROR;
    }

    test_ctx->db_fifo.ibv_db_fifo = hbldv_usr_fifo;
    test_ctx->db_fifo.pi          = 0;
    test_ctx->db_fifo.ci          = 0;

    switch (test_ctx->dev_type) {
        case DEV_TYPE_GAUDI2:
            test_ctx->db_fifo.entry_size = DB_FIFO_ENTRY_SIZE_BYTE_G2;
            test_ctx->db_fifo.wrap_size  = DB_FIFO_SIZE_G2;
            break;
        case DEV_TYPE_GAUDI3:
            test_ctx->db_fifo.entry_size = DB_FIFO_ENTRY_SIZE_BYTE_G3;
            test_ctx->db_fifo.wrap_size  = DB_FIFO_SIZE_G3;
            break;
        default: break;
    }

    return OK;
}

STATUS fill_wqe_g3(struct test_context* test_ctx, struct test_dest* remote_dst)
{
    uint64_t wqe_size           = test_ctx->buff.data_payload_size;
    uint64_t dev_local_src_add  = test_ctx->buff.dev_va_data_add;
    uint64_t dev_remote_dst_add = remote_dst->dev_va_mem_address;

    struct sq_wqe_g3* swq = (struct sq_wqe_g3*)test_ctx->wq.s_wq + test_ctx->wq.wq_offset;
    struct rq_wqe_g3* rwq = (struct rq_wqe_g3*)test_ctx->wq.r_wq + test_ctx->wq.wq_offset;

    memset(swq, 0, sizeof(*swq));
    memset(rwq, 0, sizeof(*rwq));

    swq->opcode  = WQE_LINEAR;
    rwq->opcode  = WQE_LINEAR;
    swq->size    = wqe_size;
    rwq->size    = wqe_size;
    swq->in_line = FALSE;

    swq->local_address_31_0   = (dev_local_src_add) & 0xffff;
    swq->local_address_63_32  = (uint32_t)(dev_local_src_add >> 32);
    swq->remote_address_31_0  = (dev_remote_dst_add) & 0xffff;
    swq->remote_address_63_32 = (uint32_t)(dev_remote_dst_add >> 32);
    swq->completion_type      = CQ_ONLY_COMPLETION;
    swq->tag                  = test_ctx->sent_packets;
    rwq->wqe_index            = test_ctx->wq.wq_offset;

    rwq->completion_type = CQ_ONLY_COMPLETION;

    wmb(); // Making sure that we have finish writing the WQE to the memory

    test_ctx->wq.wq_offset++;
    if (test_ctx->wq.wq_offset >= test_ctx->wq.max_wqes)
        test_ctx->wq.wq_offset = 0;

    test_ctx->wq.pi = (test_ctx->wq.pi + 1) & (test_ctx->wq.wrap_size - 1);
    print_info("WQE has been filled");
    return OK;
}

STATUS fill_wqe_g2(struct test_context* test_ctx, struct test_dest* remote_dst)
{
    uint64_t wqe_size           = test_ctx->buff.data_payload_size;
    uint64_t dev_local_src_add  = test_ctx->buff.dev_va_data_add;
    uint64_t dev_remote_dst_add = remote_dst->dev_va_mem_address;

    struct sq_wqe_g2* swq = (struct sq_wqe_g2*)test_ctx->wq.s_wq + test_ctx->wq.wq_offset;
    struct rq_wqe_g2* rwq = (struct rq_wqe_g2*)test_ctx->wq.r_wq + test_ctx->wq.wq_offset;

    memset(swq, 0, sizeof(*swq));
    memset(rwq, 0, sizeof(*rwq));

    swq->opcode  = WQE_LINEAR;
    rwq->opcode  = WQE_LINEAR;
    swq->size    = wqe_size;
    rwq->size    = wqe_size;
    swq->in_line = FALSE;

    swq->local_address_31_0   = (dev_local_src_add) & 0xffff;
    swq->local_address_63_32  = (uint32_t)(dev_local_src_add >> 32);
    swq->remote_address_31_0  = (dev_remote_dst_add) & 0xffff;
    swq->remote_address_63_32 = (uint32_t)(dev_remote_dst_add >> 32);
    swq->completion_type      = CQ_ONLY_COMPLETION;
    swq->tag                  = test_ctx->sent_packets;
    rwq->wqe_index            = test_ctx->wq.wq_offset;
    swq->wqe_index            = rwq->wqe_index;
    rwq->completion_type      = CQ_ONLY_COMPLETION;

    wmb(); // Making sure that we have finish writing the WQE to the memory

    test_ctx->wq.wq_offset++;
    if (test_ctx->wq.wq_offset >= test_ctx->wq.max_wqes)
        test_ctx->wq.wq_offset = 0;

    test_ctx->wq.pi = (test_ctx->wq.pi + 1) & (test_ctx->wq.wrap_size - 1);
    print_info("WQE has been filled");
    return OK;
}

/**
 * @brief
 *
 * @param db_fifo
 * @return BOOL return TRUE if db_fifo is full
 */
BOOL db_fifo_back_pressure(struct hbl_db_fifo* db_fifo)
{
    volatile uint32_t ci_val = *(uint32_t*)db_fifo->ibv_db_fifo->ci_cpu_addr;
    print_info("db_fifo ci %u pi %u", ci_val, db_fifo->pi);
    ci_val &= (db_fifo->wrap_size - 1);
    print_info("DB FIFO: ci_val = %u, db_fifo->pi = %u, db_fifo->ibv_db_fifo->size = %u",
               ci_val,
               db_fifo->pi,
               db_fifo->ibv_db_fifo->size);
    print_info("DB FIFO: entry_size = %u, wrap_size = %u", db_fifo->entry_size, db_fifo->wrap_size);
    print_info("Q_SPACE(ci_val, db_fifo->pi, db_fifo->ibv_db_fifo->size) = %d",
               Q_SPACE(ci_val, db_fifo->pi, db_fifo->ibv_db_fifo->size));
    if (Q_SPACE(db_fifo->pi, ci_val, db_fifo->ibv_db_fifo->size) < db_fifo->entry_size) {
        print_info("DB FIFO IS full Skipping...");
        return TRUE;
    }
    return FALSE;
}

STATUS submit_doorbell_fifo(struct test_context* test_ctx)
{
    uint8_t   ib_port = (uint8_t)test_ctx->ib_port_num;
    uint32_t  conn_id = (uint32_t)test_ctx->qp_num;
    uint64_t* db_cpu_ptr;

    db_cpu_ptr = (uint64_t*)((uint64_t*)test_ctx->db_fifo.ibv_db_fifo->regs_cpu_addr +
                             test_ctx->db_fifo.ibv_db_fifo->regs_offset);

    // writing to the CPU address a value
    *db_cpu_ptr = user_db_pkt(ib_port, conn_id, (uint64_t)test_ctx->wq.pi);
    print_info("Submitted doorbell FIFO, wrote to the CPU val %lx",
               user_db_pkt(ib_port, conn_id, (uint64_t)test_ctx->wq.pi));
    test_ctx->db_fifo.pi = (test_ctx->db_fifo.pi + test_ctx->db_fifo.entry_size) & (test_ctx->db_fifo.wrap_size - 1);

    return OK;
}

/**
 * @brief Send an RDMA packet a write operation, it will fill a wqe request and submit a door bell fifo
 * if there was a space in WQ and DB
 * @param test_ctx
 * @param remote_dst The remote destination the will write the source buffer of the test context to remote_dst.dva_addr
 */
void send_msg(struct test_context* test_ctx, struct test_dest* remote_dst)
{
    // Before we submit to the doorbell we need to check if there is space in WQ
    if (!Q_SPACE(test_ctx->wq.pi, test_ctx->wq.ci, test_ctx->wq.max_wqes)) {
        print_info("WQ is full, skipping...");
        return; // wq busy
    }

    // We need to back pressure of db_fifo
    if (db_fifo_back_pressure(&test_ctx->db_fifo)) {
        print_info("DB FIFO is full, skipping...");
        return; // db busy
    }

    fill_wqe(test_ctx, remote_dst);
    submit_doorbell_fifo(test_ctx);
    test_ctx->sent_packets++;
}

/**
 * @brief This function read CQ and return output a cqe_read_cnt, the amount of cq entries
 * have been read from the CQ. CQ can be Requester or Responder depend on the cq_fifo input.
 * if a requestor CQ were provided the function will also increase the ci (consumer index)
 * of Work Queue
 * @param test_ctx Test Context to update WQ CI
 * @param cq_fifo CQ fifo pointer (Requestor / Responder)
 * @param cqe_read_cnt[Out] counters that count how many CQEs got
 */
void read_cq(struct test_context* test_ctx, struct hbl_cq_fifo* cq_fifo, int* cqe_read_cnt)
{
    struct cqe_raw_descriptor* cqe_hw;
    static BOOL                flag_print_onetime = FALSE;

    uint64_t pi_hw = *(uint64_t*)cq_fifo->user_cq.pi_cpu_addr;
    if (pi_hw == cq_fifo->ci) {
        if (!flag_print_onetime) {
            print_info("CQ is empty pi_hw=%lu", pi_hw);
            flag_print_onetime = TRUE;
        }
        return;
    }
    flag_print_onetime = FALSE;

    rmb(); // Needed to make sure we read the correct cqe
    // reading all the cqe
    while (pi_hw != cq_fifo->ci) {

        /*NOTE: test_ctx->rx_depth must be to the power of 2*/
        uint32_t cqe_idx = cq_fifo->ci & ((cq_fifo->rx_depth) - 1); // Cyclic Buffer
        print_info("cq_fifo pi = %lu cqe_idx = %u", pi_hw, cqe_idx);

        cqe_hw = &((struct cqe_raw_descriptor*)cq_fifo->user_cq.mem_cpu_addr)[cqe_idx];
        if (!(CQE_IS_VALID(cqe_hw))) {
            print_err("CQ Entry is INVALID  hw_pi: %ld, sw_ci: %d", pi_hw, cq_fifo->ci);
            print_info("CQE: data[0]=%x   data[1]=%x   data[2]=%x   data[3]=%x",
                       cqe_hw->data[0],
                       cqe_hw->data[1],
                       cqe_hw->data[2],
                       cqe_hw->data[3]);
            cq_fifo->ci++;

            goto UPDATE_CI;
        }
        print_info(" VALID CQE: data[0]=0x%x   data[1]=%x   data[2]=%x   data[3]=%x",
                   cqe_hw->data[0],
                   cqe_hw->data[1],
                   cqe_hw->data[2],
                   cqe_hw->data[3]);
        if (CQE_IS_REQ(cqe_hw)) {
            print_info("Packet sent successfully CQE: type = REQ, WQE_idx = 0x%x, QP_num = 0x%x",
                       CQE_WQE_IDX(cqe_hw),
                       CQE_QPN(cqe_hw));
            *cqe_read_cnt += 1;
            test_ctx->wq.ci = (test_ctx->wq.ci + 1) & (test_ctx->wq.wrap_size - 1);

        } else {
            print_info("Received a packet successfully CQE: type = RES, Tag = 0x%x QP_num = 0x%x",
                       CQE_TAG(cqe_hw),
                       CQE_QPN(cqe_hw));
            *cqe_read_cnt += 1;
        }
        /* Clear this WQE for next round */
        CQE_CLEAR(cqe_hw);
        cq_fifo->ci++;
    }

UPDATE_CI:
    print_info("Updating CI = 0x%x in HW", cq_fifo->ci);
    // after reading all the Queue we need to update the ci in HW
    update_ci(cq_fifo);
}

void update_ci_g2(struct hbl_cq_fifo* cq_fifo)
{
    uint64_t* ci_hw_cpu_addr = (uint64_t*)((char*)cq_fifo->user_cq.regs_cpu_addr + cq_fifo->user_cq.regs_offset);
    uint64_t  ci_hw_val      = ((uint64_t)cq_fifo->ci) << 32 | cq_fifo->user_cq.cq_num;
    *ci_hw_cpu_addr          = ci_hw_val;
    print_info("CI val = 0x%lx is updated in HW (Gaudi 2)", ci_hw_val);
}

void update_ci_g3(struct hbl_cq_fifo* cq_fifo)
{
    uint64_t* ci_hw_cpu_addr = (uint64_t*)((char*)cq_fifo->user_cq.regs_cpu_addr + cq_fifo->user_cq.regs_offset);
    *ci_hw_cpu_addr          = cq_fifo->ci;
    print_info("CI is updated in HW (Gaudi 3)");
}

/**
 * @brief Read the Requestor CQ and count how many packets sent successfully (CQE Requester)
 * The function will not reset the counter sent_packets_cnt, it will only increment it by one
 *
 * @param test_ctx          Test Context
 * @param sent_packets_cnt[Out] Counter of the sent packets successfully
 */
void read_cq_req(struct test_context* test_ctx, int* sent_packets_cnt)
{
    read_cq(test_ctx, &test_ctx->cq_req_fifo, sent_packets_cnt);
}

/**
 * @brief Read the Responder CQ and count how many packets received successfully (CQE Responder)
 * The function will not reset the counter received_packets_cnt, it will only increment it by one
 *
 * @param test_ctx          Test Context
 * @param sent_packets_cnt[Out] Counter of the received packets successfully
 */
void read_cq_res(struct test_context* test_ctx, int* received_packets_cnt)
{
    read_cq(test_ctx, &test_ctx->cq_res_fifo, received_packets_cnt);
}