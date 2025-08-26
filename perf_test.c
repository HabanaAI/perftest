/******************************************************************************
 * Copyright (C) 2021 Habana Labs, Ltd. an Intel Company
 * All Rights Reserved.
 *
 * Unauthorized copying of this file or any element(s) within it, via any medium
 * is strictly prohibited.
 * This file contains Habana Labs, Ltd. proprietary and confidential information
 * and is subject to the confidentiality and license agreements under which it
 * was provided.
 * @file perf_test.c
 * @author Fahim Bellan (fahim.bellan@intel.com)
 * @date 2024-09-01
 *
 ******************************************************************************/

#ifndef __PERF_TEST_H__
#define __PERF_TEST_H__
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include "common.h"
#include "hbl_lib.h"
#include <malloc.h>
#include <sys/time.h>
#include <signal.h>
#include "version.h"

#define FLAG_REQUIRED_ARG 2
#define FLAG_NOT_REQUIRED_ARG 0

#define APP_DFLT_PORT_SOCKET 18515
#define APP_DFLT_IB_PORT 1
#define APP_DFLT_MSG_SIZE 4096
#define APP_DFLT_MTU 8192
#define APP_DFLT_RX_DEPTH 128
#define APP_DFLT_ITERS 1000
#define APP_DFLT_SL 0
#define APP_DFLT_GIDX 2 /* IPv4 GID */

#define NAME_SIZE 100
#define SRV_CLNT_MSG_SIZE 100
#define MSG_ELEMENTS_SIZE 5
#define GID_STR_SIZE 33

#define SOCKET_PORT_STR_LEN 7
#define SOCKET_CONN_TIMEOUT_SEC 10

#define CLIENT_DATA_BUFFER 0xA5
#define SERVER_DATA_BUFFER 0xA6
#define TX_DONE_TIMEOUT_SEC 5
#define PULL_PKT_TIMEOUT_SEC 10
#define MAX_BUFF_BYTES_TO_PRINT 10
#define MAX_BUFF_LEN_TO_PRINT 256

#define MICROSECONDS_IN_A_SECOND 1000000
#define MILLISECONDS_IN_A_SECOND 1000
#define MILLISECONDS_IN_A_MINUTE 60000 // 1000 * 60
#define MILLISECONDS_IN_AN_HOUR 3600000 // 1000 * 60 * 60
#define BITS_IN_BYTE 8
#define GBPS (1000000000)

// The current app version Major.Minor.Patch.commit
#define PERF_TEST_APP_VERSION PERF_TEST_APP_VERSION_CI

#define unlikely(x) __builtin_expect((x), 0)
#define likely(x) __builtin_expect((x), 1)

typedef enum
{
    TST_PING_PONG,
    TST_BANDWIDTH,
    TST_LATENCY
} test_type_t;

typedef enum
{
    TEST_STATUS_PASS,
    TEST_STATUS_FAILED,

    TEST_STATUS_ERROR_ACK_TIMEOUT,
    TEST_STATUS_ERROR_POLL_PKT_TIMEOUT,

    TEST_STATUS_ERROR = 255

} test_status_t;

struct app_args_t
{
    char         server_name[NAME_SIZE]; // used by client app server_name = <Server IP/name>
    int          is_server;
    char         ib_dev_name[NAME_SIZE]; // Device Name hbl_x
    unsigned int port_socket;
    int          ib_port; // external port number (we receive from the user as ibv_port)
    unsigned int size; // message size in bytes
    enum ibv_mtu mtu; // enum ibv_mtu in verbs.h
    unsigned int rx_depth;
    uint64_t     iters;
    int          sl;
    int          gid_idx;
    int          chk_en;
    test_type_t  test_type;
    uint64_t     alignment_size;
};

static struct app_args_t app_args = {0};

//---------------------- Functions Declaration -----------------------

static void usage(const char* argv0);
void        init_default_params(struct app_args_t* app_args, struct test_context* ctx);
STATUS      read_user_input(int argc, char* argv[]);
STATUS      create_buffers(struct test_context* test_ctx);
STATUS      generate_buffer_descriptors(struct test_context* ctx, struct buffer_descriptor* buff_d, uint64_t data_size);
STATUS      cleanup(struct test_context* ctx);
STATUS      server_exch_dest(struct test_context*    ctx,
                             const struct test_dest* my_dest,
                             struct app_args_t*      app_args,
                             struct test_dest*       remote_dest);
STATUS      client_exch_dest(char*                   server_name,
                             const struct test_dest* my_dest,
                             struct app_args_t*      app_args,
                             struct test_dest*       remote_dest);
BOOL        poll_packet(struct test_context* ctx);
BOOL        wait_for_ack(struct test_context* ctx);
BOOL        compare_buffers(struct test_context* ctx);
BOOL        is_power_of_2(int num);
void        set_pattern_to_data_buffer(uint64_t* buffer);

test_status_t ping_pong_test(struct test_context* ctx, struct test_dest* remote_dest);
test_status_t run_test(struct test_context* ctx, struct test_dest* remote_dest);
void          register_signal_handlers();
void          handle_sigint(int sig);

struct test_context* p_g_test_ctx_err_handle = NULL;

int main(int argc, char* argv[])
{
    STATUS               res = OK;
    struct test_context* ctx = NULL;
    struct test_dest     my_dest;
    struct test_dest     remote_dest;
    test_status_t        test_result = TEST_STATUS_ERROR;

    ctx = (struct test_context*)malloc(sizeof(struct test_context));
    if (ctx == NULL) {
        print_err("Failed to allocate test context");
        return ERROR;
    }
    p_g_test_ctx_err_handle = ctx;
    register_signal_handlers();

    init_default_params(&app_args, ctx);

    res = read_user_input(argc, argv);
    if (res == ERROR) {
        exit(test_result);
    }
    ctx->mem_loc = (app_args.test_type == TST_BANDWIDTH) ? MEM_DEV : MEM_HOST;

    res = init_device(app_args.ib_dev_name, app_args.rx_depth, app_args.ib_port, ctx);
    if (res != OK) {
        print_err("Failed to Init device dev_name = %s", app_args.ib_dev_name);
        exit(test_result);
    }
    print_info("init_device Successfully");

    if (ctx->dev_type == DEV_TYPE_GAUDI2 && app_args.test_type == TST_PING_PONG) {
        ctx->mem_loc = MEM_DEV;
    }

    res = create_buffers(ctx);
    if (res != OK) {
        print_err("Failed to create buffers");
        goto ERROR_HANDLE;
    }

    res = set_local_dest(ctx, app_args.ib_port, app_args.gid_idx, &my_dest);
    if (res != OK) {
        print_err("Failed to set_local_dest dev_name = %s ib_port = %d, gid_idx = %d",
                  app_args.ib_dev_name,
                  app_args.ib_port,
                  app_args.gid_idx);
        goto ERROR_HANDLE;
    }

    print("Local address: ib_port 0x%x Device address 0x%lx, QPN 0x%06x, GID %s\n",
          my_dest.dev_port_num,
          my_dest.dev_va_mem_address,
          my_dest.qpn,
          my_dest.gid_str);

    // Connect Server and Client
    if (app_args.is_server) {
        res = server_exch_dest(ctx, &my_dest, &app_args, &remote_dest);
        if (res != OK) {
            print_err("The Server failed to exchange context with Client");
            goto ERROR_HANDLE;
        }
    } else {
        res = client_exch_dest(app_args.server_name, &my_dest, &app_args, &remote_dest);
        if (res != OK) {
            print_err("The Client failed to exchange context with Server");
            goto ERROR_HANDLE;
        }

        // client connect QP after Server
        ctx->mtu = app_args.mtu;
        if (connect_qp_ctx(ctx, &my_dest, &remote_dest) != OK) {
            print_err("Failed to connect to QP's Server");
            goto ERROR_HANDLE;
        }
    }

    test_result = run_test(ctx, &remote_dest);

    if (test_result > TEST_STATUS_FAILED) {
        print_err("Error Occurred during the test");
        goto ERROR_HANDLE;
    }

    res = cleanup(ctx);
    if (res != OK) {
        print_err("Failed to clean-up");
        goto ERROR_HANDLE;
    }
    print_info("cleanup Successfully");
    print("Exiting OK");
    free(ctx);
    return test_result; // here return 0 or 1, PASS or FAIL

ERROR_HANDLE:

    if (cleanup(ctx) != OK) {
        print_err("Couldn't clean-up on error handler!");
    }
    print("Exiting with ERROR");
    free(ctx);
    return test_result; // return the error type or 255 in case of error occurred
}

void init_default_params(struct app_args_t* test_args, struct test_context* ctx)
{
    strcpy(test_args->server_name, "");
    test_args->is_server = TRUE;
    strcpy(test_args->ib_dev_name, "");
    test_args->port_socket = APP_DFLT_PORT_SOCKET;
    test_args->ib_port     = APP_DFLT_IB_PORT;
    test_args->size        = APP_DFLT_MSG_SIZE;
    test_args->mtu         = mtu_to_ibv_enum(APP_DFLT_MTU);
    test_args->rx_depth    = APP_DFLT_RX_DEPTH;
    test_args->iters       = APP_DFLT_ITERS;
    test_args->sl          = APP_DFLT_SL;
    test_args->gid_idx     = APP_DFLT_GIDX;
    test_args->chk_en      = FALSE;
    test_args->test_type   = TST_PING_PONG;

    int long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0 || !is_power_of_2(page_size)) {
        print_err("Failed to get page size %ld", page_size);
        exit(ERROR);
    }
    test_args->alignment_size = page_size;

    memset(ctx, 0, sizeof(*ctx));

    ctx->context                           = NULL;
    ctx->channel                           = NULL;
    ctx->pd                                = NULL;
    ctx->mr                                = NULL;
    ctx->cq_req_fifo.ibv_cq                = NULL;
    ctx->cq_res_fifo.ibv_cq                = NULL;
    ctx->qp                                = NULL;
    ctx->rx_depth                          = test_args->rx_depth;
    ctx->dev_fd                            = -1;
    ctx->cq_res_fifo.user_cq.mem_cpu_addr  = NULL;
    ctx->cq_res_fifo.user_cq.pi_cpu_addr   = NULL;
    ctx->cq_res_fifo.user_cq.regs_cpu_addr = NULL;
    ctx->buff.host_data_addr               = NULL;
    ctx->mem_loc                           = MEM_HOST;
}

void usage(const char* argv0)
{
    printf("Perf Test %s\n", PERF_TEST_APP_VERSION);
    printf("Usage:\n");
    printf("  %s [Opts]           start a server and wait for connection\n", argv0);
    printf("  %s [Opts] <host>    connect to server at <host>\n", argv0);
    printf("\n");
    printf("Options:\n");
    printf("  -p, --port=<port>         listen on/connect to port <port> (default %d)\n", APP_DFLT_PORT_SOCKET);
    printf("  -d, --ib-dev=<dev>        use IB device <dev> (default first device found)\n");
    printf("  -i, --ib-port=<port>      use port <port> of IB device (default %d)\n", APP_DFLT_IB_PORT);
    printf("  -s, --size=<size>         size of message to exchange 32bits (default %d)\n", APP_DFLT_MSG_SIZE);
    printf("  -m, --mtu=<size>          path MTU (default %d)\n", APP_DFLT_MTU);
    printf("  -r, --rx-depth=<dep>      number of receives to post at a time (default %d)\n", APP_DFLT_RX_DEPTH);
    printf("  -n, --iters=<iters>       number of exchanges (default %d)\n", APP_DFLT_ITERS);
    printf("  -l, --sl=<sl>             service level value (default %d)\n", APP_DFLT_SL);
    printf("  -g, --gid-idx=<gid index> local port gid index (default %d)\n", APP_DFLT_GIDX);
    printf("  -c, --chk                 validate received buffer\n");
    printf("  -x, --logs	            print additional log information\n");
    printf("  -t, --test-type           'pp' = Ping-Pong Test <default>"
           "\n\t\t\t    'bw' = Bandwidth Test"
           "\n\t\t\t    'lt' = Latency Test\n");
    printf("  -h, --help	        help \n");
}

STATUS read_user_input(int argc, char* argv[])
{

    while (1) {
        static struct option long_options[] = {
            {.name = "port", .has_arg = FLAG_REQUIRED_ARG, .flag = NULL, .val = 'p'},
            {.name = "ib-dev", .has_arg = FLAG_REQUIRED_ARG, .flag = NULL, .val = 'd'},
            {.name = "ib-port", .has_arg = FLAG_REQUIRED_ARG, .flag = NULL, .val = 'i'},
            {.name = "size", .has_arg = FLAG_REQUIRED_ARG, .flag = NULL, .val = 's'},
            {.name = "mtu", .has_arg = FLAG_REQUIRED_ARG, .flag = NULL, .val = 'm'},
            {.name = "rx-depth", .has_arg = FLAG_REQUIRED_ARG, .flag = NULL, .val = 'r'},
            {.name = "iters", .has_arg = FLAG_REQUIRED_ARG, .flag = NULL, .val = 'n'},
            {.name = "sl", .has_arg = FLAG_REQUIRED_ARG, .flag = NULL, .val = 'l'},
            {.name = "gid-idx", .has_arg = FLAG_REQUIRED_ARG, .flag = NULL, .val = 'g'},
            {.name = "chk", .has_arg = FLAG_NOT_REQUIRED_ARG, .flag = NULL, .val = 'c'},
            {.name = "logs", .has_arg = FLAG_NOT_REQUIRED_ARG, .flag = NULL, .val = 'x'},
            {.name = "test-type", .has_arg = FLAG_REQUIRED_ARG, .flag = NULL, .val = 't'},
            {.name = "help", .has_arg = FLAG_NOT_REQUIRED_ARG, .flag = NULL, .val = 'h'},
            {}};

        int c = getopt_long(argc, argv, "p:d:i:s:m:r:n:l:g:cxht:", long_options, NULL);

        if (c == -1)
            break;

        switch (c) {
            case 'p':
                app_args.port_socket = strtoul(optarg, NULL, 0); /*Note: optarg is a external param from getopt module*/
                if (app_args.port_socket > 65535) {
                    print_err("Wrong port input, port can't be bigger than 65535");
                    usage(argv[0]);
                    return ERROR;
                }
                break;

            case 'd':
                strncpy(app_args.ib_dev_name, optarg, NAME_SIZE - 1);

                int len = strlen(optarg) > NAME_SIZE - 1 ? NAME_SIZE - 1 : strlen(optarg);

                app_args.ib_dev_name[len] = '\0';
                break;

            case 'i':
                app_args.ib_port = strtol(optarg, NULL, 0);
                if (app_args.ib_port < 1) {
                    print_err("Wrong port input, port can't be less than 1, ib ports start from 1");
                    usage(argv[0]);
                    return ERROR;
                }
                break;

            case 's': app_args.size = strtoul(optarg, NULL, 0); break;

            case 'm':
                app_args.mtu = mtu_to_ibv_enum(strtol(optarg, NULL, 0));
                if (app_args.mtu == 0) {
                    print_err("Invalid MTU input. MTU can only be one of the following values: 256, 512, 1024, 2048, "
                              "4096, 8192.");
                    usage(argv[0]);
                    return ERROR;
                }
                break;

            case 'r':
                app_args.rx_depth = strtoul(optarg, NULL, 0);
                if (!is_power_of_2(app_args.rx_depth)) {
                    print_err("rx-depth must be a power of 2");
                    return ERROR;
                }
                break;

            case 'n': app_args.iters = strtoul(optarg, NULL, 0); break;

            case 'l':
                app_args.sl = 0;
                print_err("service level is not supported");
                return ERROR;
                break;

            case 'g': app_args.gid_idx = strtol(optarg, NULL, 0); break;

            case 'c': app_args.chk_en = 1; break;

            case 'x': g_print_logs = TRUE; break;

            case 't':
                if (strcmp(optarg, "pp") == 0)
                    app_args.test_type = TST_PING_PONG;
                else if (strcmp(optarg, "bw") == 0) {
                    app_args.test_type = TST_BANDWIDTH;
                } else if (strcmp(optarg, "lt") == 0) {
                    app_args.test_type = TST_LATENCY;
                } else {
                    print_err("Test type Unknown %s. type must be: 'pp'/'bw'/'lt'", optarg);
                    return ERROR;
                }
                break;

            case 'h':
                usage(argv[0]);
                exit(OK);
                break;
            case '?': // Error Handnling or missing a required argument
                print_err("Wrong Input or Unkown Option");
                usage(argv[0]);
                return ERROR;
                break;
        }
    }

    if (optind == argc - 1) {
        strncpy(app_args.server_name, argv[optind], NAME_SIZE - 1);
        app_args.server_name[NAME_SIZE - 1] = '\0';
        app_args.is_server = 0;
    } else if (optind < argc) {
        usage(argv[0]);
        return ERROR;
    }

    print_info("Arguments: \n"
               "\n server_name = %s"
               "\n is_server = %d"
               "\n ib_dev_name = %s"
               "\n port_socket = %d"
               "\n ib_port = %d"
               "\n size = %d"
               "\n mtu = %d"
               "\n rx_depth = %d"
               "\n iters = %ld"
               "\n sl = %d"
               "\n gid_idx = %d"
               "\n chk_en = %d"
               "\n test_type = %d",
               app_args.server_name,
               app_args.is_server,
               app_args.ib_dev_name,
               app_args.port_socket,
               app_args.ib_port,
               app_args.size,
               app_args.mtu,
               app_args.rx_depth,
               app_args.iters,
               app_args.sl,
               app_args.gid_idx,
               app_args.chk_en,
               app_args.test_type);

    if (app_args.chk_en && app_args.test_type != TST_PING_PONG) {
        print_err("--chk flag (Validate Buffer) is only supported for Ping-Pong test");
        return ERROR;
    }
    return OK;
}

BOOL is_power_of_2(int num)
{
    return num > 0 && (num & (num - 1)) == 0;
}

/**
 * @brief Create a buffer in HW and fill the descriptor
 *
 * @param ctx Test Context
 * @return STATUS
 */
STATUS create_buffers(struct test_context* ctx)
{
    /**
     * @note The client and server each create only one buffer.
     * In the Ping Pong Test: the client/server uses its own buffer as both source and destination.
     * The client initializes the data in the buffer and writes a pattern to it, and the server
     * validates the received buffer against the pattern.
     *
     * In the Bandwidth Test: we create the buffers in device memory to achieve maximum
     * performance.
     */
    STATUS res = OK;
    int    data_to_set = 0;

    res = generate_buffer_descriptors(ctx, &ctx->buff, app_args.size);
    if (res != OK) {
        print_err("Failed to generate source buffer");
        return ERROR;
    }
    ctx->buff.is_mapped = TRUE;

    // We write to the buffer only if it is located on the host.
    if (ctx->mem_loc == MEM_HOST) {
        print_info("Buffer in Host: ctx->buff.host_data_addr = %p , ctx->buff.dev_va_data_add = %p",
                   (void*)ctx->buff.host_data_addr,
                   (void*)ctx->buff.dev_va_data_add);

        // Initialize the data in the buffer to send to the server
        data_to_set = (app_args.is_server) ? SERVER_DATA_BUFFER : CLIENT_DATA_BUFFER;
        memset(ctx->buff.host_data_addr, data_to_set, ctx->buff.data_payload_size);
    } else {
        print_info("Buffer in Device: ctx->buff.handle = 0x%lx , ctx->buff.dev_va_data_add = 0x%p",
                   ctx->buff.handle,
                   (void*)ctx->buff.dev_va_data_add);
    }

    return OK;
}

/**
 * @brief Generate buffer descriptor according to the memory location
 *
 * @param ctx Test Context
 * @param buff_d[In/Out] pre allocated buffer descriptor
 * @param data_size
 * @return STATUS
 */
STATUS generate_buffer_descriptors(struct test_context* ctx, struct buffer_descriptor* buff_d, uint64_t data_size)
{
    STATUS res            = OK;
    void*  host_data_addr = NULL;
    memset(buff_d, 0, sizeof(struct buffer_descriptor));
    buff_d->data_payload_size = data_size; // same  data size if in host or device

    switch (ctx->mem_loc) {
        case MEM_HOST:
            host_data_addr = aligned_alloc(app_args.alignment_size, data_size);
            if (host_data_addr == NULL) {
                print_err("Failed to allocate memory in host");
                return ERROR;
            }
            buff_d->host_data_addr = (uint64_t*)host_data_addr;
            print_info("page_size for memory alignment = %lu", app_args.alignment_size);

            res = map_host_memory(ctx, host_data_addr, data_size, &buff_d->dev_va_data_add, 0);
            if (res != OK) {
                print_err("Failed to map host memory");
                return ERROR;
            }
            break;

        case MEM_DEV:
            if (alloc_dev_mem(ctx, data_size, &buff_d->handle) != OK) {
                print_err("alloc_dev_mem Failed");
                return ERROR;
            }
            print_info("Allocated data in device handle =%lu", buff_d->handle);
            buff_d->data_payload_size = data_size;

            if (map_dev_memory(ctx, buff_d->handle, &buff_d->dev_va_data_add) != OK) {
                print_err("Failed to map host memory");
                return ERROR;
            }

            if (app_args.chk_en) { // this flag will be turned on only in Ping Pong test
                // We need to map the device memory to the host address space if we need to write or read the data
                host_data_addr = aligned_alloc(app_args.alignment_size, data_size);
                if (host_data_addr == NULL) {
                    print_err("Failed to allocate memory in host");
                    return ERROR;
                }
                buff_d->host_data_addr = (uint64_t*)host_data_addr;
                print_info("dev_addr = %p, befor mapping ", (void*)buff_d->dev_va_data_add);

                set_pattern_to_data_buffer(buff_d->host_data_addr);
                buff_d->host_va_data_add = buff_d->dev_va_data_add;

                res =
                    map_host_memory(ctx, host_data_addr, data_size, &buff_d->dev_va_data_add, buff_d->dev_va_data_add);
                if (res != OK) {
                    print_err("Failed to map host memory");
                    return ERROR;
                }
            }

            print_info("after mapping buffer allocated in device = %p, mapped to host = %p",
                       (void*)buff_d->dev_va_data_add,
                       (void*)buff_d->host_data_addr);

            break;

        default:
            print_err("Unkown memory location %d", ctx->mem_loc);
            return ERROR;
            break;
    }

    return OK;
}

STATUS cleanup(struct test_context* ctx)
{
    STATUS res = OK;

    res = cleanup_device(ctx);
    if (res != OK) {
        print_err("Failed to clean-up device");
        res |= ERROR;
    }

    // we need to unmap first and then do free
    if (ctx->buff.is_mapped) {

        if (ctx->mem_loc == MEM_DEV && ctx->buff.host_va_data_add != 0 &&
            unmap_dev_memory(ctx, ctx->buff.host_va_data_add)) {
            print_err("Couldn't unmap Memory Data Buffer");
            res |= ERROR;
        } else
            print_info("Unmap data buffer Successfully");

        if (unmap_dev_memory(ctx, ctx->buff.dev_va_data_add)) {
            print_err("Couldn't unmap Memory Data Buffer");
            res |= ERROR;
        } else
            print_info("Unmap data buffer Successfully");

        ctx->buff.is_mapped = FALSE;
    }

    if (ctx->buff.host_data_addr != NULL) {
        free(ctx->buff.host_data_addr);
        ctx->buff.host_data_addr = NULL;
    }

    if (ctx->mem_loc == MEM_DEV) {
        res = free_dev_mem(ctx, ctx->buff.handle);
        if (res != OK) {
            print_err("Failed to free memory on device");
            res |= ERROR;
        }
    }

    if (ctx->dev_fd >= 0) {
        hbl_close_dev(ctx->dev_fd);
        ctx->dev_fd = -1;
    }

    return res;
}

/**
 * @brief Create a socket object and bind / connect
 *
 * @param server_name NULL to create a server socket
 * @param port socket port
 * @param socket_fd [Output] the created socket
 * @return STATUS
 */
STATUS create_socket(char* server_name, int port, int* socket_fd)
{
    struct addrinfo *sock_res, *node;
    struct addrinfo  hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    char             service[SOCKET_PORT_STR_LEN]; // used to convert port to string
    int              _socket_fd = -1, res = 0;
    BOOL             flag_found = FALSE;
    time_t           start_time, current_time;

    if (app_args.is_server) {
        hints.ai_flags = AI_PASSIVE;
    }

    if (sprintf(service, "%d", port) <= 0) {
        print_err("Failed to convert Port to string.");
        return ERROR;
    }

    print_info("server_name =%s ", server_name);
    // If it is server the server_name will be NULL and will initialize the socket as a server
    res = getaddrinfo(server_name, service, &hints, &sock_res);
    if (res != OK) {
        print_err("Failed to getaddrinfo() error: %s on port %d", gai_strerror(res), port);
        return ERROR;
    }

    for (node = sock_res; node != NULL; node = node->ai_next) {
        // try to create a socket from the addrinfo results
        _socket_fd = socket(node->ai_family, node->ai_socktype, node->ai_protocol);
        print_info("node->ai_family=%d, node->ai_socktype=%d, node->ai_protocol=%d",
                   node->ai_family,
                   node->ai_socktype,
                   node->ai_protocol);

        if (_socket_fd < 0) {
            // Failed to create a socket for this node
            continue;
        }

        if (app_args.is_server) {
            int opt_val = 1;
            res         = setsockopt(_socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt_val, sizeof(opt_val));
            if (res) {
                close(_socket_fd);
                freeaddrinfo(sock_res);
                print_err("Failed to set socket options");
                return ERROR;
            }
            // Try to listen to a port
            if (!bind(_socket_fd, node->ai_addr, node->ai_addrlen))
                break; // Found a good socket
            else {
                close(_socket_fd);
                continue; // Failed to bind, check the next node
            }
        }

        flag_found = FALSE;

        time(&start_time);
        while (!flag_found) {
            // Try to connect
            if (!connect(_socket_fd, node->ai_addr, node->ai_addrlen)) {
                flag_found = TRUE; // Found a good socket
                break;
            }

            time(&current_time);

            if (difftime(current_time, start_time) >= SOCKET_CONN_TIMEOUT_SEC)
                break; // Timeout, check the next node
        }

        if (flag_found)
            break;
        else
            print_err("Connection timed out after %d seconds\n", SOCKET_CONN_TIMEOUT_SEC);

        close(_socket_fd);
        _socket_fd = -1;
    }

    freeaddrinfo(sock_res);

    if (_socket_fd < 0) {
        print_err("Failed to create socket and bind on Port = %d", port);
        return ERROR;
    }

    *socket_fd = _socket_fd;
    return OK;
}

/**
 * @brief The Server exchange the destination information with the Client
 * And initiate a QP connection after receiving the information
 * @param ctx
 * @param my_dest The local destination
 * @param app_args (make sure mtu and port_socket are configured before)
 * @param remote_dest The Client destination
 * @return STATUS
 */
STATUS server_exch_dest(struct test_context*    ctx,
                        const struct test_dest* my_dest,
                        struct app_args_t*      app_args,
                        struct test_dest*       remote_dest)
{
    int    socket_fd = -1, conn_fd = 0, received_bytes = 0, scanned_vars = 0;
    char   msg[SRV_CLNT_MSG_SIZE], gid[GID_STR_SIZE];
    STATUS res;

    res = create_socket(NULL, app_args->port_socket, &socket_fd);
    if (res != OK)
        return ERROR;

    print("Server started on port = %d", app_args->port_socket);

    int n1 = listen(socket_fd, 1);
    if (n1 < 0) {
        print_err("Listen Failed !");
        return ERROR;
    }
    print_info("Server is Listening...");
    conn_fd = accept(socket_fd, NULL, NULL);
    // Wait for a client
    close(socket_fd);

    if (conn_fd < 0) {
        print_err("Failed to accept connection");
        return ERROR;
    }

    received_bytes = read(conn_fd, msg, sizeof msg);
    if (received_bytes != sizeof msg) {
        print_err("%d/%d: Couldn't read remote address\n", received_bytes, (int)sizeof msg);
        goto ERR_HNDL;
    }

    print_info("Received message from client: %s", msg);

    // filling the remote message
    scanned_vars = sscanf(msg,
                          "%x:%lx:%x:%x:%s",
                          &remote_dest->dev_port_num,
                          &remote_dest->dev_va_mem_address,
                          &remote_dest->qpn,
                          &remote_dest->psn,
                          gid);
    if (scanned_vars != MSG_ELEMENTS_SIZE) {
        print_err("Failed To parse message from remote side");
    }

    wire_gid_to_gid(gid, &remote_dest->gid);

    ctx->mtu = app_args->mtu;

    // The server should connect to the client first
    res = connect_qp_ctx(ctx, my_dest, remote_dest);
    if (res != OK) {
        print_err("Couldn't connect to remote QP");
        goto ERR_HNDL;
    }

    // send my destination to the client
    gid_to_wire_gid(&my_dest->gid, gid);
    sprintf(msg,
            "%x:%lx:%06x:%06x:%s",
            my_dest->dev_port_num,
            my_dest->dev_va_mem_address,
            my_dest->qpn,
            my_dest->psn,
            gid);
    if (write(conn_fd, msg, sizeof msg) != sizeof msg) {
        print_err("Couldn't send/recv local address");
        goto ERR_HNDL;
    }

    if (read(conn_fd, msg, sizeof msg) != sizeof "done") {
        print_err("Couldn't recv 'done' from client");
        goto ERR_HNDL;
    }

    close(conn_fd);
    return OK;

ERR_HNDL:
    close(conn_fd);
    return ERROR;
}

/**
 * @brief The Client exchange the destination information with the Server
 *
 * @param server_name server IP or actual server name
 * @param ctx
 * @param my_dest local destination (Client)
 * @param app_args (make sure port_socket is configured before)
 * @param remote_dest Server destination
 * @return STATUS
 */
STATUS client_exch_dest(char*                   server_name,
                        const struct test_dest* my_dest,
                        struct app_args_t*      app_args,
                        struct test_dest*       remote_dest)
{

    int    socket_fd = -1;
    STATUS res;
    char   msg[SRV_CLNT_MSG_SIZE], gid[GID_STR_SIZE];
    res = create_socket(server_name, app_args->port_socket, &socket_fd);
    if (res != OK)
        return ERROR;

    gid_to_wire_gid(&my_dest->gid, gid);
    sprintf(msg,
            "%x:%lx:%06x:%06x:%s",
            my_dest->dev_port_num,
            my_dest->dev_va_mem_address,
            my_dest->qpn,
            my_dest->psn,
            gid);

    if (write(socket_fd, msg, sizeof msg) != sizeof msg) {
        print_err("Couldn't send local address");
        goto ERROR_HNDL;
    }

    print_info("Client send: %s", msg);

    if (read(socket_fd, msg, sizeof msg) != sizeof msg) {
        print_err("Couldn't read Server address");
        goto ERROR_HNDL;
    }

    if (write(socket_fd, "done", sizeof "done") != sizeof "done") {
        print_err("Couldn't write 'done' to the server");
        goto ERROR_HNDL;
    }

    // Filling the remote dest struct
    int scanned_vars = sscanf(msg,
                              "%x:%lx:%x:%x:%s",
                              &remote_dest->dev_port_num,
                              &remote_dest->dev_va_mem_address,
                              &remote_dest->qpn,
                              &remote_dest->psn,
                              gid);
    if (scanned_vars != MSG_ELEMENTS_SIZE) {
        print_err("Failed To parse message from remote side");
    }
    wire_gid_to_gid(gid, &remote_dest->gid);

    print_info("Received message from server: %s", msg);

    close(socket_fd);
    return OK;

ERROR_HNDL:
    close(socket_fd);
    return ERROR;
}

/**
 * @brief Waiting for an approval the packet has been sent successfully and reach the remote side
 * waiting for requester CQE, waiting for Acknowledgment
 * @param ctx
 * @return BOOL True if packet sent successfully before the timeout, false otherwise
 */
BOOL wait_for_ack(struct test_context* ctx)
{
    time_t op_start_time, op_current_time;
    time(&op_start_time);
    int count_sent_pkts = 0;

    while (count_sent_pkts == 0) {
        read_cq_req(ctx, &count_sent_pkts);
        time(&op_current_time);
        if (difftime(op_current_time, op_start_time) >= TX_DONE_TIMEOUT_SEC) {
            print_err("ACK Timeout, didn't receive ACK from the remote side");
            return FALSE; // stop the test
        }
    }

    return TRUE;
}

/**
 * @brief Waiting for a packet received successfully, waiting for requester CQE.
 *
 * @param ctx
 * @return BOOL True if packet received successfully before the timeout, false otherwise
 */
BOOL poll_packet(struct test_context* ctx)
{
    time_t op_start_time, op_current_time;
    time(&op_start_time);
    int count_received_pkts = 0;

    while (count_received_pkts == 0) {
        read_cq_res(ctx, &count_received_pkts);
        time(&op_current_time);
        if (difftime(op_current_time, op_start_time) >= PULL_PKT_TIMEOUT_SEC) {
            print_err("Waited too long for an RDMA packet timeout %d sec", PULL_PKT_TIMEOUT_SEC);
            return FALSE; // stop the test
        }
    }

    return TRUE;
}

BOOL compare_buffers(struct test_context* ctx)
{

    unsigned int i = 0, mismatch_count = 0;
    uint8_t*     byte_ptr;
    uint8_t      expected_pattern;
    char         buff_mismatch_data[MAX_BUFF_BYTES_TO_PRINT][MAX_BUFF_LEN_TO_PRINT] = {0};

    for (i = 0; i < app_args.size && mismatch_count < MAX_BUFF_BYTES_TO_PRINT; i += app_args.alignment_size) {
        byte_ptr         = (uint8_t*)ctx->buff.host_data_addr + i;
        expected_pattern = (i / app_args.alignment_size) % CLIENT_DATA_BUFFER;
        if (*byte_ptr == expected_pattern)
            continue;

        sprintf(buff_mismatch_data[mismatch_count++],
                "Mismatch at address 0x%p. Expected: %x, Got: %x.",
                byte_ptr,
                expected_pattern,
                *byte_ptr);
    }

    if (!mismatch_count)
        return TRUE;

    print_err("Buffers do not match!");
    for (i = 0; i < mismatch_count; i++)
        print_err("%s", buff_mismatch_data[i]);

    return FALSE;
}

void set_pattern_to_data_buffer(uint64_t* buffer)
{
    unsigned int i;
    uint8_t*     byte_ptr;

    for (i = 0; i < app_args.size; i += app_args.alignment_size) {
        byte_ptr  = (uint8_t*)buffer + i;
        *byte_ptr = (i / app_args.alignment_size) % CLIENT_DATA_BUFFER;
    }
}

test_status_t ping_pong_test(struct test_context* ctx, struct test_dest* remote_dest)
{
    unsigned int current_iteration = 0;

    print("Ping Pong Test Started!");
    if (app_args.is_server) {
        // The Server Wait for a received packet to re send it back

        while (current_iteration < app_args.iters) {
            print_info("Reading Packet");

            if (!poll_packet(ctx)) {
                return TEST_STATUS_ERROR_POLL_PKT_TIMEOUT;
            }
            print_info("Packet Received");

            current_iteration++;
            print_info("current_iteration =%d", current_iteration);
            print_info("Sending Packet..");

            send_msg(ctx, remote_dest);
            if (!wait_for_ack(ctx)) {
                return TEST_STATUS_ERROR_ACK_TIMEOUT;
            }
            print_info("Packet Sent!");
        }

        // Need to validate the written buffer
        if (app_args.chk_en) {
            if (!compare_buffers(ctx)) {
                return TEST_STATUS_FAILED;
            }
        }

    } else {
        if (app_args.chk_en) {
            set_pattern_to_data_buffer(ctx->buff.host_data_addr);
        }

        // The Client will send the first packet
        print_info("Sending Packet..");
        send_msg(ctx, remote_dest);
        if (!wait_for_ack(ctx)) {
            return TEST_STATUS_ERROR_ACK_TIMEOUT;
        }
        print_info("Packet Sent!");

        while (current_iteration < app_args.iters) {
            print_info("Reading Packet");

            if (!poll_packet(ctx)) {
                return TEST_STATUS_ERROR_POLL_PKT_TIMEOUT;
            }
            print_info("Packet Received");
            current_iteration++;
            send_msg(ctx, remote_dest);
            if (!wait_for_ack(ctx)) {
                return TEST_STATUS_ERROR_ACK_TIMEOUT;
            }
        }
    }

    print("Finish Test Successfully");
    print("Packets Sent: %ld", ctx->sent_packets);

    return TEST_STATUS_PASS;
}

uint64_t get_current_time_us()
{
    struct timeval curr_time;
    gettimeofday(&curr_time, NULL);
    return (curr_time.tv_sec * MICROSECONDS_IN_A_SECOND) + curr_time.tv_usec;
}

/**
 * @brief Calculates the bandwidth in Gbps based on the total data sent and the elapsed time.
 *
 * @param total_packets Number of packets transmitted during the test.
 * @param size Size of each packet in bytes.
 * @param start_time_us Start time of the test in microseconds.
 * @param end_time_us End time of the test in microseconds.
 * @return float Calculated bandwidth in Gbps.
 */
float calc_bw_gbps(uint64_t total_packets, uint64_t size, uint64_t start_time_us, uint64_t end_time_us)
{
    uint64_t total_time_us    = end_time_us - start_time_us;
    uint64_t total_data_bytes = size * total_packets;

    print("Total data sent: %lu Bytes, total_packets = %lu, size = %lu, total microsec = %lu\n",
          total_data_bytes,
          total_packets,
          size,
          total_time_us);

    // Calculate hours, minutes, seconds, and milliseconds for the elapsed time
    int64_t total_milliseconds = total_time_us / MILLISECONDS_IN_A_SECOND;
    int     hh                 = total_milliseconds / MILLISECONDS_IN_AN_HOUR;
    total_milliseconds %= MILLISECONDS_IN_AN_HOUR;
    int mm = total_milliseconds / MILLISECONDS_IN_A_MINUTE;
    total_milliseconds %= MILLISECONDS_IN_A_MINUTE;
    int ss           = total_milliseconds / MILLISECONDS_IN_A_SECOND;
    int milliseconds = total_milliseconds % MILLISECONDS_IN_A_SECOND;

    print("Elapsed Time: %02d:%02d:%02d.%03d\n", hh, mm, ss, milliseconds);

    // Check for zero time to avoid division by zero
    if (total_time_us == 0) {
        fprintf(stderr, "Error: Total time is zero, can't calculate bandwidth.\n");
        return 0.0;
    }

    // Calculate bandwidth in Gbps
    float data_in_bits = total_data_bytes * (float)BITS_IN_BYTE;
    float time_in_sec  = total_time_us / (float)MICROSECONDS_IN_A_SECOND;
    float bw_gbps      = (data_in_bits / time_in_sec) / (float)GBPS;

    return bw_gbps;
}

test_status_t bandwidth_test(struct test_context* ctx, struct test_dest* remote_dest)
{
    int      packets_received = 0, packets_sent = 0;
    uint64_t start_time_us = 0, end_time_us = 0;
    float    bw_result    = 0.0;
    BOOL     is_first_pkt = TRUE;
    BOOL     is_last_pkt  = TRUE;

    print("BW Test Started ...");

    while (packets_received < (int)app_args.iters || packets_sent < (int)app_args.iters) {

        if (ctx->sent_packets < app_args.iters)
            send_msg(ctx, remote_dest);

        read_cq_req(ctx, &packets_sent);
        read_cq_res(ctx, &packets_received);

        if (unlikely(packets_received >= 1 && is_first_pkt)) {
            start_time_us = get_current_time_us();
            is_first_pkt  = FALSE;
        }

        if (unlikely(packets_received == (int)app_args.iters && is_last_pkt)) {
            end_time_us = get_current_time_us();
            is_last_pkt = FALSE;
        }
    }

    bw_result = calc_bw_gbps((uint64_t)packets_received, (uint64_t)app_args.size, start_time_us, end_time_us);
    print("Packets      Sent: %d", packets_sent);
    print("Packets  Received: %d", packets_received);
    print("Test RX Bandwidth: %.2f [Gbps]", bw_result);

    // The BW test is a tool to measure the device's bandwidth (BW). It does not have criteria to determine if the test
    // passes or fails; results depend on the setup configurations.

    return TEST_STATUS_PASS;
}

/**
 * @brief Measure the latency of the packet from a given start time.
 *
 * @param total_latency_us[Out] Total latency of all packets
 * @param min_latency_us[Out] Minimum latency of all packets
 * @param max_latency_us[Out] Maximum latency of all packets
 * @param start_time_us[In] Start time of the measurement
 * @param end_time_us[Out] End time of the measurement
 * @return int 0 on success, 1 on failure
 */
int measure_latency(uint64_t* total_latency_us,
                    uint64_t* min_latency_us,
                    uint64_t* max_latency_us,
                    uint64_t  start_time_us,
                    uint64_t* end_time_us)
{
    uint64_t current_latency_us = 0;
    if (likely(start_time_us != 0)) {
        *end_time_us = get_current_time_us();

        if (unlikely(*end_time_us < start_time_us)) {
            print_err("End time is smaller than start time in latency measurement");
            return 1;
        }

        current_latency_us = *end_time_us - start_time_us;
        *total_latency_us += current_latency_us;

        if (current_latency_us < *min_latency_us)
            *min_latency_us = current_latency_us;
        if (current_latency_us > *max_latency_us)
            *max_latency_us = current_latency_us;
    }
    return 0;
}

/**
 * @brief This function will measure the Host to Host latency.
 * measuring RTT (Round Trip Time) between the client and the server.
 *
 * @param ctx
 * @param remote_dest
 * @return test_status_t
 */
test_status_t latency_test(struct test_context* ctx, struct test_dest* remote_dest)
{
    uint64_t total_latency_us = 0, min_latency_us = UINT64_MAX, max_latency_us = 0;
    uint64_t start_time_us = 0, end_time_us = 0;
    uint64_t fault_packets  = 0;
    float    avg_latency_us = 0;

    if (app_args.iters == 0) {
        print_err("Number of iterations must be greater than 0");
        return TEST_STATUS_ERROR;
    }

    print("RTT Latency Test Started ...");
    BOOL is_first_time = TRUE;
    if (app_args.is_server) {
        while (ctx->sent_packets < app_args.iters) {

            // The server will keep waiting for the client to send a packet, then it will send it back
            if (!poll_packet(ctx)) {
                print_err("Failed to receive packet");
                return TEST_STATUS_ERROR_POLL_PKT_TIMEOUT;
            }

            // We measure the latency only after the server have sent the first packet
            if (likely(!is_first_time))
                fault_packets +=
                    measure_latency(&total_latency_us, &min_latency_us, &max_latency_us, start_time_us, &end_time_us);
            is_first_time = FALSE;

            start_time_us = get_current_time_us();
            send_msg(ctx, remote_dest);
            if (!wait_for_ack(ctx)) {
                print_err("Failed to send packet");
                return TEST_STATUS_ERROR_ACK_TIMEOUT;
            }
        }

    } else {
        while (ctx->sent_packets < app_args.iters) {
            start_time_us = get_current_time_us();
            send_msg(ctx, remote_dest);

            if (!wait_for_ack(ctx)) {
                print_err("Failed to send packet");
                return TEST_STATUS_ERROR_ACK_TIMEOUT;
            }

            // Now the server should send back the packet. Waiting for it...
            if (poll_packet(ctx)) {
                fault_packets +=
                    measure_latency(&total_latency_us, &min_latency_us, &max_latency_us, start_time_us, &end_time_us);
            } else {
                print_err("Failed to receive packet");
                return TEST_STATUS_ERROR_POLL_PKT_TIMEOUT;
            }
        }
    }

    // Server measurements are one less since the first packet isn't measured
    uint64_t total_packets = app_args.iters - (app_args.is_server ? 1 : 0);
    if (total_packets == 0 || fault_packets >= total_packets) {
        print_err("No packets were received successfully");
        return TEST_STATUS_ERROR;
    }

    total_packets -= fault_packets;

    avg_latency_us = (float)total_latency_us / (float)total_packets;
    print("RTT Latency");
    print("Average Latency: %.2f [us]", avg_latency_us / 2.0);
    print("Min     Latency: %.2f [us]", (float)min_latency_us / 2.0);
    print("Max     Latency: %.2f [us]", (float)max_latency_us / 2.0);

    return TEST_STATUS_PASS;
}

test_status_t run_test(struct test_context* ctx, struct test_dest* remote_dest)
{
    test_status_t test_result = TEST_STATUS_ERROR;
    switch (app_args.test_type) {
        case TST_PING_PONG:
            test_result = ping_pong_test(ctx, remote_dest);
            if (test_result == TEST_STATUS_FAILED) {
                print("Test Failed");
            } else if (test_result == TEST_STATUS_PASS)
                print("Test PASS");
            return test_result;
            break;
        case TST_BANDWIDTH: return bandwidth_test(ctx, remote_dest); break;
        case TST_LATENCY: return latency_test(ctx, remote_dest); break;

        default: return TEST_STATUS_ERROR; break;
    }
}

void register_signal_handlers()
{
    // Set up the signal handler to end the program gracefully
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sa.sa_flags   = 0; // or SA_RESTART to restart certain interrupted functions
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        print_err("sigaction erro on SIGINT");
        exit(-ERROR);
    }

    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        print_err("sigaction erro on SIGTERM");
        exit(-ERROR);
    }

    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        // To enable core dumps for SIGSEGV, make sure your system allows them: ulimit -c unlimited
        print_err("sigaction erro on SIGSEGV");
        exit(-ERROR);
    }

    if (sigaction(SIGABRT, &sa, NULL) == -1) {
        print_err("sigaction erro on SIGABRT");
        exit(-ERROR);
    }
}

void handle_sigint(int sig)
{
    printf("\nCaught signal %d . Exiting gracefully...\n", sig);

    if (cleanup(p_g_test_ctx_err_handle) != OK) {
        print_err("Couldn't clean-up on error handler!");
    }

    print("Exiting with ERROR");
    free(p_g_test_ctx_err_handle);
    exit(-ERROR); // Exit the program gracefully
}

#endif // __PERF_TEST_H__
