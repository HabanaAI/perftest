/******************************************************************************
 * Copyright (C) 2021 Habana Labs, Ltd. an Intel Company
 * All Rights Reserved.
 *
 * Unauthorized copying of this file or any element(s) within it, via any medium
 * is strictly prohibited.
 * This file contains Habana Labs, Ltd. proprietary and confidential information
 * and is subject to the confidentiality and license agreements under which it
 * was provided.
 * @file ibv_dev_port_mapping.c
 * @author Fahim Bellan (fahim.bellan@intel.com)
 * @date 2024-09-01
 *
 ******************************************************************************/

#include <stdio.h>
#include <infiniband/verbs.h>
#include <infiniband/hbldv.h>
#include "hbl_lib.h"
#include "common.h"

#define NAME_SIZE 6
#define MAX_IB_PORTS 24
#define MAX_DEV_PORTS 24
#define FILE_NAME_SIZE 1024

char csv_file_name[FILE_NAME_SIZE];

static int is_link_local_gid(const union ibv_gid* gid)
{
    return gid->global.subnet_prefix == htobe64(0xfe80000000000000ULL);
}

static int set_mac_from_gid(const union ibv_gid* gid, __u8 mac[6])
{
    if (is_link_local_gid(gid)) {
        /*
         * The MAC is embedded in GID[8-10,13-15] with the
         * 7th most significant bit inverted.
         */
        memcpy(mac, gid->raw + 8, 3);
        memcpy(mac + 3, gid->raw + 13, 3);
        mac[0] ^= 2;

        return 0;
    }

    return 1;
}

static int ibv_port_to_dev(struct ibv_context* ctx, int ibv_port_num)
{
    struct hbldv_device_attr attr;
    int                      dev_port = 0;
    int                      rc       = 0;

    if (ibv_port_num < 1 || ibv_port_num > MAX_IB_PORTS) {
        print_err("Invalid ibv port number %d port must be between 1 and %d", ibv_port_num, MAX_IB_PORTS);
        return -1;
    }

    rc = hbldv_query_device(ctx, &attr);
    if (rc) {
        print_err("Failed to do hbldv_query_device error=%d", rc);
        return -1;
    }

    for (int i = 0; i < MAX_DEV_PORTS; i++) {
        if (attr.hw_ports_mask & (1 << i)) {
            if (ibv_port_num == 1) {
                dev_port = i;
                break;
            }
            ibv_port_num--;
        }
    }
    return dev_port;
}

int parse_arguments(int argc, char* argv[])
{
    if (argc < 2) {
        print_err("Usage: %s <csv_file_name>", argv[0]);
        return -1;
    }

    size_t arg_len = strnlen(argv[1], FILE_NAME_SIZE - 1);
    if (arg_len >= FILE_NAME_SIZE) {
        print_err("File name too long");
        return -1;
    }
    strncpy(csv_file_name, argv[1], arg_len);
    csv_file_name[arg_len] = '\0';

    return 0;
}

struct ibv_context* open_ib_device(struct ibv_device* device, int dev_id)
{
    struct hbldv_ucontext_attr dev_attr = {};

    if (hbl_open_dev(dev_id, &dev_attr.core_fd)) {
        print_err("Failed to open device driver %s", device->name);
        NULL;
    }

    struct ibv_context* ibv_context = hbldv_open_device(device, &dev_attr);
    if (ibv_context == NULL) {
        print_err("Failed to open device: %s", device->name);
        return NULL;
    }

    printf("Device %s ports:\n", device->name);
    return ibv_context;
}

void handle_all_ib_ports(FILE* fp, int hbl_dev_idx, struct ibv_context* ibv_context)
{
    for (int ib_port = 1; ib_port <= MAX_IB_PORTS; ib_port++) {
        union ibv_gid      gid;
        unsigned char      eth_mac[ETHERNET_LL_SIZE] = {0};
        struct ibv_ah_attr attr                      = {0};
        BOOL               is_scaleout               = FALSE;

        int dev_port = ibv_port_to_dev(ibv_context, ib_port);
        if (dev_port < 0) {
            print_err("Failed to get dev port for ib port %d", ib_port);
            continue; // skipping to the next port
        }

        // get MAC address of ib port
        if (hlibv_query_gid(ibv_context, ib_port, 0, &gid)) {
            print_err("Failed to get gid for ib port %d", ib_port);
            continue; // skipping to the next port
        }

        attr.port_num       = ib_port;
        attr.grh.dgid       = gid;
        attr.grh.sgid_index = 0; // mac

        printf("dev port %2d --> ib port %2d ", dev_port, ib_port);
        fprintf(fp, "%d,%d,%d,", hbl_dev_idx, dev_port, ib_port);

        if (!hlibv_resolve_eth_l2_from_gid(ibv_context, &attr, eth_mac, 0))
            is_scaleout = TRUE;
        if (!is_scaleout && !set_mac_from_gid(&gid, eth_mac))
            is_scaleout = TRUE;

        if (is_scaleout) {
            printf("(external) MAC %02x:%02x:%02x:%02x:%02x:%02x \n",
                   eth_mac[0],
                   eth_mac[1],
                   eth_mac[2],
                   eth_mac[3],
                   eth_mac[4],
                   eth_mac[5]);
            fprintf(fp,
                    "%02x:%02x:%02x:%02x:%02x:%02x\n",
                    eth_mac[0],
                    eth_mac[1],
                    eth_mac[2],
                    eth_mac[3],
                    eth_mac[4],
                    eth_mac[5]);
        } else {

            printf("internal\n");
            fprintf(fp, "--\n");
        }
    }
}

/**
 * @brief handel device opening if it is a habanalabs device.
 *
 * @param device[input] ibv device
 * @param hbl_dev_idx [Output] HBL device index
 * @param ibv_context [Output] ibv context
 * @return STATUS ERROR if need to skip to the next device, OK if the device is handled successfully
 */
STATUS handel_device(struct ibv_device* device, int* hbl_dev_idx, struct ibv_context** ibv_context)
{
    if (device == NULL) {
        print_err("Error Device is NULL");
        return ERROR; // skipping to the next device
    }

    if (!is_dev_habanalabs(device->name)) {
        return ERROR; // skipping to the next device,, this is not an error
    }

    if (1 != sscanf(device->name, "hbl_%d", hbl_dev_idx)) {
        print_err("Failed to get Device ID from device name %s", device->name);
        return ERROR; // skipping to the next device
    }

    *ibv_context = open_ib_device(device, *hbl_dev_idx);
    if (*ibv_context == NULL) {
        print_err("Failed to open device: %s", device->name);
        return ERROR; // skipping to the next device
    }

    return OK;
}

int main(int argc, char* argv[])
{
    int                        available_devices_size = 0;
    static struct ibv_device** available_devices      = NULL;
    struct ibv_context*        ibv_context_ptr        = NULL; // for initialization
    struct ibv_context**       ibv_context            = &ibv_context_ptr;
    int                        hbl_dev_idx;

    if (parse_arguments(argc, argv) != 0) {
        return -1;
    }

    FILE* fp = fopen(csv_file_name, "w");
    if (fp == NULL) {
        print_err("Failed to open file %s", csv_file_name);
        return -1;
    }

    available_devices = hlibv_get_device_list(&available_devices_size);
    if (available_devices == NULL || available_devices_size == 0) {
        printf("No available devices!\n");
        return 0;
    }

    for (int idx = 0; idx < available_devices_size; idx++) {

        if (handel_device(available_devices[idx], &hbl_dev_idx, ibv_context) != OK) {
            continue; // skipping to the next device
        }

        handle_all_ib_ports(fp, hbl_dev_idx, *ibv_context);
        printf("\n");
        hbl_close_dev(((struct ibv_context*)(*ibv_context))->cmd_fd);
        free_device();
    }

    fclose(fp);

    if (available_devices != NULL)
        hlibv_free_device_list(available_devices);

    printf("Done\n");

    return 0;
}