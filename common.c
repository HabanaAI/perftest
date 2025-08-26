/******************************************************************************
 * Copyright (C) 2021 Habana Labs, Ltd. an Intel Company
 * All Rights Reserved.
 *
 * Unauthorized copying of this file or any element(s) within it, via any medium
 * is strictly prohibited.
 * This file contains Habana Labs, Ltd. proprietary and confidential information
 * and is subject to the confidentiality and license agreements under which it
 * was provided.
 * @file common.c
 * @author Fahim Bellan (fahim.bellan@intel.com)
 * @date 2024-09-01
 *
 ******************************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include "common.h"

BOOL g_print_logs = FALSE;

void print_err(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    printf("\033[1;31mERROR: \033[0m"); // Red Error Alert before the message
    vprintf(format, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

void print_info(const char* format, ...)
{
    if (!g_print_logs)
        return;

    va_list args;
    va_start(args, format);
    printf("\033[1;34mInfo: \033[0m"); // Blue Info Alert before the message
    vprintf(format, args);
    va_end(args);
    printf("\n");
    fflush(stdout);

}

void print(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    printf("\033[32mOut: \033[0m"); // Green 'Out' before the message
    vprintf(format, args);
    va_end(args);
    printf("\n");
    fflush(stdout);

}

enum ibv_mtu mtu_to_ibv_enum(int mtu)
{
    switch (mtu) {
        case 256: return IBV_MTU_256;
        case 512: return IBV_MTU_512;
        case 1024: return IBV_MTU_1024;
        case 2048: return IBV_MTU_2048;
        case 4096: return IBV_MTU_4096;
        case 8192: return HBL_IB_MTU_8192; // Habanalab extension
        default: return 0;
    }
}

void gid_to_wire_gid(const union ibv_gid* gid, char wgid[])
{
    uint32_t tmp_gid[4];
    int      i;

    memcpy(tmp_gid, gid, sizeof(tmp_gid));
    for (i = 0; i < 4; ++i)
        sprintf(&wgid[i * 8], "%08x", htobe32(tmp_gid[i]));
}

void wire_gid_to_gid(const char* wgid, union ibv_gid* gid)
{
    char     tmp[9];
    __be32   v32;
    int      i;
    uint32_t tmp_gid[4];

    for (tmp[8] = 0, i = 0; i < 4; ++i) {
        memcpy(tmp, wgid + i * 8, 8);
        sscanf(tmp, "%x", &v32);
        tmp_gid[i] = be32toh(v32);
    }
    memcpy(gid, tmp_gid, sizeof(*gid));
}
