/*
* Copyright (c) 2018 ARM Limited. All rights reserved.
* SPDX-License-Identifier: Apache-2.0
* Licensed under the Apache License, Version 2.0 (the License); you may
* not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an AS IS BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "mbed.h"
#include "StorageLite.h"
#include "HeapBlockDevice.h"
#include "FlashSimBlockDevice.h"
#include "SPIFBlockDevice.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const size_t bd_size = 8192;
static const size_t bd_erase_size = 4096;
static const size_t bd_prog_size = 16;
static const size_t bd_read_size = 1;

static const uint16_t name_size = 512;

// Entry point for the example
int main() {

    printf("\n--- Mbed OS StorageLite example ---\n");

#if STORAGELITE_ENABLED

#if defined(TARGET_K82F)
    SPIFBlockDevice bd(PTE2, PTE4, PTE1, PTE5);
    SlicingBlockDevice flash_bd(&bd, 0*4096, 4*4096);
    printf("TARGET_K82F\n");
#else
    HeapBlockDevice bd(bd_size, bd_read_size, bd_prog_size, bd_erase_size);
    FlashSimBlockDevice flash_bd(&bd);
    printf("TARGET_all\n");
#endif

    StorageLite stlite;

    int rc = STORAGELITE_SUCCESS;
    size_t data_buf_size = 6, file_name_size = 1;;
    uint8_t data_buf[6] = {'H','e','l','l','o'};
    static const uint8_t file_name = 1;
    static const char* file_name_1 = "file1";
    static const char* file_name_2 = "file2";
    static const char* file_name_3 = "file3";

    // Initialize StorageLite
    rc = stlite.init(&flash_bd);
    printf("Init StorageLite. ");
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    // Show StorageLite size, area addresses and sizes
    printf("StorageLite size is %d\n", stlite.size());
    printf("StorageLite areas:\n");
    for (uint8_t area = 0; area < STORAGELITE_NUM_AREAS; area++) {
        uint32_t area_address;
        size_t area_size;
        stlite.get_area_params(area, area_address, area_size);
        printf("Area %d: address 0x%08lx, size %d (0x%x)\n", area, area_address, area_size, area_size);
    }

    // Clear StorageLite data. Should only be done once at factory configuration
    rc = stlite.reset();
    printf("Reset StorageLite. ");
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    // Now set some values to the same file
    rc = stlite.set(&file_name, file_name_size, data_buf, data_buf_size, 0);
    printf("Set file %d to data %s. ", file_name, data_buf);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    data_buf[0] = 'M';
    rc = stlite.set(&file_name, file_name_size, data_buf, data_buf_size, 0);
    printf("Set file %d to data %s. ", file_name, data_buf);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    data_buf[0] = 'L';
    rc = stlite.set(&file_name, file_name_size, data_buf, data_buf_size, 0);
    printf("Set file %d to data %s. ", file_name, data_buf);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    // check if this file exist
    rc = stlite.file_exists(&file_name, file_name_size);
    printf("Get file %d. ", file_name);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    // Get the data of this file (should be the last set() value)
    size_t actual_data_size = 0;
    rc = stlite.get(&file_name, file_name_size, data_buf, data_buf_size, actual_data_size);
    printf("Get file %d. data is %s. ", file_name, data_buf);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    // Get the data size of this file (should be data_buf_size)
    rc = stlite.get_file_size(&file_name, file_name_size, actual_data_size);
    printf("Get file %d. data size is %d. ", file_name, actual_data_size);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    // Now remove the file
    rc = stlite.remove(&file_name, file_name_size);
    printf("Delete file %d. ", file_name);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    // Get the file again, now it should not exist
    rc = stlite.get(&file_name, file_name_size, data_buf, data_buf_size, actual_data_size);
    printf("Get file %d (after removed). ", file_name);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_NOT_FOUND);

    //add more files
    rc = stlite.set((const uint8_t *) file_name_1, strlen(file_name_1), data_buf, data_buf_size, 0);
    printf("Set file \"%s\" to data %s. ", file_name_1, data_buf);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    rc = stlite.set((const uint8_t *) file_name_2, strlen(file_name_2), data_buf, data_buf_size, 0);
    printf("Set file \"%s\" to data %s. ", file_name_2, data_buf);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    rc = stlite.set((const uint8_t *) file_name_3, strlen(file_name_3), data_buf, data_buf_size, 0);
    printf("Set file \"%s\" to data %s. ", file_name_3, data_buf);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    //iterate through the files
    uint32_t handle = 0;
    size_t actual_name_size = 0;
    uint8_t get_buf[256];
    rc = stlite.get_first_file(get_buf, sizeof(get_buf), actual_name_size, handle);
    printf("file \"%s\" retrieved. ", get_buf);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    rc =  stlite.get_next_file(get_buf, sizeof(get_buf), actual_name_size, handle);
    printf("file \"%s\" retrieved. ", get_buf);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

    rc =  stlite.get_next_file(get_buf, sizeof(get_buf), actual_name_size, handle);
    printf("file \"%s\" retrieved. ", get_buf);
    printf("Return code is %d, return code expected is %d\n", rc, STORAGELITE_SUCCESS);

#else
    printf("StorageLite is disabled for this board\n");
#endif
    printf("\n--- Mbed OS StorageLite example done. ---\n");

    return 0;
}

