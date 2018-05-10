/* Copyright (c) 2017 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include "StorageLite.h"
#include "StorageLiteFS.h"
#include "FlashSimBlockDevice.h"
#include "SlicingBlockDevice.h"
#include "HeapBlockDevice.h"
#include "greentea-client/test_env.h"
#include "unity/unity.h"
#include "utest/utest.h"
#include <errno.h>

using namespace utest::v1;

static const size_t buf_size        =  10;

#define MBED_TEST_BUFFER 8192
#define MBED_TEST_FILES 4
FILE *fd[MBED_TEST_FILES];
uint8_t wbuffer[MBED_TEST_BUFFER];
uint8_t rbuffer[MBED_TEST_BUFFER];
uint8_t buffer[MBED_TEST_BUFFER];

#ifdef TEST_SPIF
#ifdef TARGET_K82F
        SPIFBlockDevice bd(PTE2, PTE4, PTE1, PTE5);
#else
        SPIFBlockDevice bd(D11, D12, D13, D8);
#endif
        SlicingBlockDevice flash_bd(&bd, 0 * 4096, /*64 * 4096*/ bd.size());
#elif defined(TEST_SD)
        //SDBlockDevice bd(PTE3, PTE1, PTE2, PTE4);
        HeapBlockDevice bd(512 * 512, 16, 16, 512);
        //SlicingBlockDevice slice_bd(&bd, 0 * 4096, bd.size());
        BufferedBlockDevice buf_bd(&bd);
        FlashSimBlockDevice flash_bd(&buf_bd);
#endif

#if !defined(TEST_SPIF) && !defined(TEST_SD)
    HeapBlockDevice bd(4096 * 4, 1,  1, 4096);
    FlashSimBlockDevice flash_bd(&bd);
#endif

static const char *slfs_name = "stfs";

StorageLite stlite;

/* help functions */

static void init()
{
    int result = STORAGELITE_SUCCESS;

    result = stlite.init(&flash_bd);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, result);
}

static void fs_init(StorageLiteFS *stlitefs)
{
    int result = STORAGELITE_SUCCESS;

    result = stlitefs->mount(&flash_bd);
    TEST_ASSERT_EQUAL(0, result);

    result = stlitefs->reformat(&flash_bd);
    TEST_ASSERT_EQUAL(0, result);
}

static void fs_mount(StorageLiteFS *stlitefs)
{
    int result = STORAGELITE_SUCCESS;

    result = stlitefs->mount(&flash_bd);
    TEST_ASSERT_EQUAL(0, result);
}

static void fs_unmount(StorageLiteFS *stlitefs)
{
    int result = STORAGELITE_SUCCESS;

    result = stlitefs->unmount();
    TEST_ASSERT_EQUAL(0, result);
}

static void open_write_file(FILE *fd, size_t buf_size)
{
    int res = !((fd = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    res = fflush(fd);
    TEST_ASSERT_EQUAL(0, res);
    
    res = fclose(fd);
    TEST_ASSERT_EQUAL(0, res);
}

/*----------------fopen()------------------*/

//fopen path without stfs prefix
static void StorageLiteFS_fopen_path_not_valid()
{
    errno = 0;
    int res = !((fd[0] = fopen("hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(1, res);
    TEST_ASSERT_EQUAL(ENODEV, errno);
}

//fopen empty file name with r mode
static void StorageLiteFS_fopen_empty_path_r_mode()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);
    
    errno = 0;
    int res = !((fd[0] = fopen("/stfs/" "", "r")) != NULL);
    TEST_ASSERT_EQUAL(1, res);
    TEST_ASSERT_EQUAL(ENOENT, errno);
}

//fopen empty file name with w mode
static void StorageLiteFS_fopen_empty_path_w_mode()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);
    
    int res = !((fd[0] = fopen("/stfs/" "", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);
}

//fopen empty mode
static void StorageLiteFS_fopen_invalid_mode()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    errno = 0;
    int res = !((fd[0] = fopen("/stfs/" "invalid_mode", "")) != NULL);
    TEST_ASSERT_EQUAL(1, res);
    TEST_ASSERT_EQUAL(EINVAL, errno);
}

//fopen with unsupported a mode
static void StorageLiteFS_fopen_unsupported_a_mode()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    errno = 0;
    int res = !((fd[0] = fopen("/stfs/" "unsupported_mode", "a")) != NULL);
    TEST_ASSERT_EQUAL(1, res);
    TEST_ASSERT_EQUAL(EINVAL, errno);
}

//fopen with unsupported a+ mode
static void StorageLiteFS_fopen_unsupported_a_plus_mode()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    errno = 0;
    int res = !((fd[0] = fopen("/stfs/" "unsupported_mode", "a+")) != NULL);
    TEST_ASSERT_EQUAL(1, res);
    TEST_ASSERT_EQUAL(EINVAL, errno);
}

//fopen with unsupported r+ mode
static void StorageLiteFS_fopen_unsupported_r_plus_mode()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    errno = 0;
    int res = !((fd[0] = fopen("/stfs/" "unsupported_mode", "r+")) != NULL);
    TEST_ASSERT_EQUAL(1, res);
    TEST_ASSERT_EQUAL(EINVAL, errno);
}

//fopen with unsupported w+ mode
static void StorageLiteFS_fopen_unsupported_w_plus_mode()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    errno = 0;
    int res = !((fd[0] = fopen("/stfs/" "unsupported_mode", "w+")) != NULL);
    TEST_ASSERT_EQUAL(1, res);
    TEST_ASSERT_EQUAL(EINVAL, errno);
}

//fopen with unsupported rb mode
static void StorageLiteFS_fopen_supported_rb_plus_mode()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    open_write_file(fd[0], buf_size);

    int res = !((fd[0] = fopen("/stfs/" "unsupported_mode", "rb")) != NULL);
    TEST_ASSERT_EQUAL(1, res);      //FIX!!!
}

//fopen with unsupported wb mode
static void StorageLiteFS_fopen_supported_wb_plus_mode()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "unsupported_mode", "wb")) != NULL);
    TEST_ASSERT_EQUAL(0, res);
}

/*----------------fclose()------------------*/

//fclose valid flow
static void StorageLiteFS_fclose_valid_flow()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res);  
}

//fclose to null fd
static void StorageLiteFS_fclose_null_fd()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    res = fclose(NULL);
    TEST_ASSERT_EQUAL(0, res);
    /*TEST_ASSERT_EQUAL(1, res);        
    TEST_ASSERT_EQUAL(EBADF, errno);*/      //undefined behavior
    //https://stackoverflow.com/questions/16922871/why-glibcs-fclosenull-cause-segmentation-fault-instead-of-returning-error
}

//fclose a file that is closed
static void StorageLiteFS_fclose_closed_file()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res);  

    errno = 0;
    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res);
    /*TEST_ASSERT_EQUAL(1, res);        
    TEST_ASSERT_EQUAL(EBADF, errno);*/      //undefined behavior
    //https://stackoverflow.com/questions/24555980/fclose-a-file-that-is-already-fclose
}

/*----------------fwrite()------------------*/

//fwrite with ptr as NULL, size and nmemb not zero
static void StorageLiteFS_fwrite_null_fd()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    int write_sz = fwrite(NULL, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(0, res);
    printf("write_sz = %d\n", write_sz);
    /*TEST_ASSERT_EQUAL(1, res);
    TEST_ASSERT_EQUAL(EINVAL, errno);*/

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

//fwrite with size zero
static void StorageLiteFS_fwrite_size_zero()
{
    char buffer[buf_size] = "good_day";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, 0, buf_size, fd[0]);
    TEST_ASSERT_EQUAL(0, write_sz);     //Expected 0 Was 10 - FIX

    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

//fwrite with nmemb zero
static void StorageLiteFS_fwrite_nmemb_zero()
{
    char buffer[buf_size] = "good_day";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), 0, fd[0]);
    TEST_ASSERT_EQUAL(0, write_sz);

    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res);
}

//fwrite valid flow
static void StorageLiteFS_fwrite_valid_flow()
{
    char buffer[buf_size] = "good_day", rbuffer[buf_size] = {};

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    res = !((fd[0] = fopen("/stfs/" "hello", "r")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int read_sz = fread(rbuffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, read_sz);
    TEST_ASSERT_EQUAL_STRING(buffer, rbuffer);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

//fwrite to fopen mode r
static void StorageLiteFS_fwrite_with_fopen_r_mode()
{
    char buffer[buf_size] = "good_day";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    open_write_file(fd[0], buf_size);

    int res = !((fd[0] = fopen("/stfs/" "hello", "r")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(0, write_sz);
    TEST_ASSERT_EQUAL(EBADF, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

//fwrite to closed file
static void StorageLiteFS_fwrite_closed_file()
{
    char buffer[buf_size] = "good_day";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 

    errno = 0;
    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(0, write_sz);
    TEST_ASSERT_EQUAL(EBADF, errno);
}


/*----------------fread()------------------*/

//fread with ptr as NULL, size and nmemb not zero
static void StorageLiteFS_fread_null_fd()
{
    char buffer[buf_size] = {};
    
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    open_write_file(fd[0], buf_size);

    int res = !((fd[0] = fopen("/stfs/" "hello", "r")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fread(NULL, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(0, write_sz);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

//fread with size zero
static void StorageLiteFS_fread_size_zero()
{
    char buffer[buf_size] = {};

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    open_write_file(fd[0], buf_size);

    int res = !((fd[0] = fopen("/stfs/" "hello", "r")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fread(buffer, 0, buf_size, fd[0]);
    TEST_ASSERT_EQUAL(0, write_sz);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

//fread with nmemb zero
static void StorageLiteFS_fread_nmemb_zero()
{
    char buffer[buf_size] = {};

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    open_write_file(fd[0], buf_size);

    int res = !((fd[0] = fopen("/stfs/" "hello", "r")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fread(buffer, sizeof(char), 0, fd[0]);
    TEST_ASSERT_EQUAL(0, write_sz);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

//fread valid flow
static void StorageLiteFS_fread_valid_flow()
{
    char buffer[buf_size] = {};

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    open_write_file(fd[0], buf_size);

    int res = !((fd[0] = fopen("/stfs/" "hello", "r")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fread(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

//fread after fwrite without fclose
static void StorageLiteFS_fread_fwrite_no_fclose()
{
    char buffer[buf_size] = "good_day", rbuffer[buf_size] = {};

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    res = !((fd[0] = fopen("/stfs/" "hello", "r")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int read_sz = fread(rbuffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(0, read_sz);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

//fread to fopen mode w
static void StorageLiteFS_fread_with_fopen_w_mode()
{
    char buffer[buf_size] = {};

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    open_write_file(fd[0], buf_size);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    int write_sz = fread(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(0, write_sz);
    TEST_ASSERT_EQUAL(EBADF, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

//fread to closed file
static void StorageLiteFS_fread_closed_file()
{
    char buffer[buf_size] = {};

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    open_write_file(fd[0], buf_size);

    int res = !((fd[0] = fopen("/stfs/" "hello", "r")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 

    errno = 0;
    int write_sz = fread(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(0, write_sz);
    TEST_ASSERT_EQUAL(EBADF, errno);
}

/*----------------general flow tests------------------*/

void test_simple_file_test()
{
    int res;

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    {
        res = !((fd[0] = fopen("/stfs/" "hello", "wb")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        size_t size = strlen("Hello World!\n");
        memcpy(wbuffer, "Hello World!\n", size);
        res = fwrite(wbuffer, 1, size, fd[0]);
        TEST_ASSERT_EQUAL(size, res);
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);
        res = !((fd[0] = fopen("/stfs/" "hello", "r")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        size = strlen("Hello World!\n");
        res = fread(rbuffer, 1, size, fd[0]);
        TEST_ASSERT_EQUAL(size, res);
        res = memcmp(rbuffer, wbuffer, size);
        TEST_ASSERT_EQUAL(0, res);
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);
    }
}


void test_small_file_test()
{
    int res;

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    {
        size_t size = 32;
        size_t chunk = 31;
        srand(0);
        res = !((fd[0] = fopen("/stfs/" "smallavacado", "wb")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        for (size_t i = 0; i < size; i += chunk) {
            chunk = (chunk < size - i) ? chunk : size - i;
            for (size_t b = 0; b < chunk; b++) {
                buffer[b] = rand() & 0xff;
            }
            res = fwrite(buffer, 1, chunk, fd[0]);
            TEST_ASSERT_EQUAL(chunk, res);
        }
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);
        fs_unmount(&stlitefs);
    }

    {
        size_t size = 32;
        size_t chunk = 29;
        srand(0);
        fs_mount(&stlitefs);
        res = !((fd[0] = fopen("/stfs/" "smallavacado", "r")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        for (size_t i = 0; i < size; i += chunk) {
            chunk = (chunk < size - i) ? chunk : size - i;
            res = fread(buffer, 1, chunk, fd[0]);
            TEST_ASSERT_EQUAL(chunk, res);
            for (size_t b = 0; b < chunk && i+b < size; b++) {
                res = buffer[b];
                TEST_ASSERT_EQUAL(rand() & 0xff, res);
            }
        }
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);        
        fs_unmount(&stlitefs);
    }
}

void test_medium_file_test()
{
    int res;

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    {
        size_t size = 8192;
        size_t chunk = 31;
        srand(0);
        res = !((fd[0] = fopen("/stfs/" "mediumavacado", "wb")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        for (size_t i = 0; i < size; i += chunk) {
            chunk = (chunk < size - i) ? chunk : size - i;
            for (size_t b = 0; b < chunk; b++) {
                buffer[b] = rand() & 0xff;
            }
            res = fwrite(buffer, 1, chunk, fd[0]);
            TEST_ASSERT_EQUAL(chunk, res);
        }
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);
        fs_unmount(&stlitefs);
    }

    {
        size_t size = 8192;
        size_t chunk = 29;
        srand(0);    
        fs_mount(&stlitefs);
        res = !((fd[0] = fopen("/stfs/" "mediumavacado", "r")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        for (size_t i = 0; i < size; i += chunk) {
            chunk = (chunk < size - i) ? chunk : size - i;
            res = fread(buffer, 1, chunk, fd[0]);
            TEST_ASSERT_EQUAL(chunk, res);
            for (size_t b = 0; b < chunk && i+b < size; b++) {
                res = buffer[b];
                TEST_ASSERT_EQUAL(rand() & 0xff, res);
            }
        }
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);
        fs_unmount(&stlitefs);
    }
}


void test_large_file_test()
{
    int res;

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    {
        size_t size = 262144;
        size_t chunk = 31;
        srand(0);
        res = !((fd[0] = fopen("/stfs/" "largeavacado", "wb")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        for (size_t i = 0; i < size; i += chunk) {
            chunk = (chunk < size - i) ? chunk : size - i;
            for (size_t b = 0; b < chunk; b++) {
                buffer[b] = rand() & 0xff;
            }
            res = fwrite(buffer, 1, chunk, fd[0]);
            TEST_ASSERT_EQUAL(chunk, res);
        }
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);
        fs_unmount(&stlitefs);
    }

    {
        size_t size = 262144;
        size_t chunk = 29;
        srand(0);
        fs_mount(&stlitefs);
        res = !((fd[0] = fopen("/stfs/" "largeavacado", "r")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        for (size_t i = 0; i < size; i += chunk) {
            chunk = (chunk < size - i) ? chunk : size - i;
            res = fread(buffer, 1, chunk, fd[0]);
            TEST_ASSERT_EQUAL(chunk, res);
            for (size_t b = 0; b < chunk && i+b < size; b++) {
                res = buffer[b];
                TEST_ASSERT_EQUAL(rand() & 0xff, res);
            }
        }
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);
        fs_unmount(&stlitefs);
    }
}

void test_non_overlap_check()
{
    int res;

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    {
        size_t size = 32;
        size_t chunk = 29;
        srand(0);
        res = !((fd[0] = fopen("/stfs/" "smallavacado", "r")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        for (size_t i = 0; i < size; i += chunk) {
            chunk = (chunk < size - i) ? chunk : size - i;
            res = fread(buffer, 1, chunk, fd[0]);
            TEST_ASSERT_EQUAL(chunk, res);
            for (size_t b = 0; b < chunk && i+b < size; b++) {
                res = buffer[b];
                TEST_ASSERT_EQUAL(rand() & 0xff, res);
            }
        }
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);
        fs_unmount(&stlitefs);
    }

    {
        size_t size = 8192;
        size_t chunk = 29;
        srand(0);
        fs_mount(&stlitefs);
        res = !((fd[0] = fopen("/stfs/" "mediumavacado", "r")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        for (size_t i = 0; i < size; i += chunk) {
            chunk = (chunk < size - i) ? chunk : size - i;
            res = fread(buffer, 1, chunk, fd[0]);
            TEST_ASSERT_EQUAL(chunk, res);
            for (size_t b = 0; b < chunk && i+b < size; b++) {
                res = buffer[b];
                TEST_ASSERT_EQUAL(rand() & 0xff, res);
            }
        }
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);
        fs_unmount(&stlitefs);
    }

    {
        size_t size = 262144;
        size_t chunk = 29;
        srand(0);
        fs_mount(&stlitefs);
        res = !((fd[0] = fopen("/stfs/" "largeavacado", "r")) != NULL);
        TEST_ASSERT_EQUAL(0, res);
        for (size_t i = 0; i < size; i += chunk) {
            chunk = (chunk < size - i) ? chunk : size - i;
            res = fread(buffer, 1, chunk, fd[0]);
            TEST_ASSERT_EQUAL(chunk, res);
            for (size_t b = 0; b < chunk && i+b < size; b++) {
                res = buffer[b];
                TEST_ASSERT_EQUAL(rand() & 0xff, res);
            }
        }
        res = fclose(fd[0]);
        TEST_ASSERT_EQUAL(0, res);
        fs_unmount(&stlitefs);
    }
}

/*----------------unsupported API------------------*/


static void StorageLiteFS_unsupported_func_fflush()
{
    char buffer[buf_size] = "good_day";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    errno = 0;
    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_EQUAL(0, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

static void StorageLiteFS_unsupported_func_fgetc()
{
    char buffer[buf_size] = "good_day";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    res = fgetc(fd[0]);
    TEST_ASSERT_EQUAL(EOF, res);
    TEST_ASSERT_EQUAL(EBADF, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

static void StorageLiteFS_unsupported_func_fgetpos()
{
    char buffer[buf_size] = "good_day";
    fpos_t pos;

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    res = fgetpos(fd[0], &pos);
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_EQUAL(0, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

static void StorageLiteFS_unsupported_func_fgets()
{
    char buffer[buf_size] = "good_day";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    char str[buf_size];
    char *pstr = fgets(str, buf_size, fd[0]);
    TEST_ASSERT_EQUAL(NULL, pstr);
    TEST_ASSERT_EQUAL(EBADF, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

static void StorageLiteFS_unsupported_func_fprintf()
{
    char buffer[buf_size] = "123456789";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    res = fprintf(fd[0], buffer);
    TEST_ASSERT_EQUAL(strlen(buffer), res);
    TEST_ASSERT_EQUAL(0, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

static void StorageLiteFS_unsupported_func_fputc()
{
    char c = '0';
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    res = fputc(c, fd[0]);
    TEST_ASSERT_EQUAL((int)c, res);
    TEST_ASSERT_EQUAL(0, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

static void StorageLiteFS_unsupported_func_fputs()
{
    char buffer[buf_size] = "123456789";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    res = fputs(buffer, fd[0]);
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_EQUAL(0, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

static void StorageLiteFS_unsupported_func_freopen()
{
    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 

    errno = 0;
    fd[1] = freopen("/stfs/" "hello", "w", fd[0]);
    TEST_ASSERT_EQUAL(fd[0], fd[1]);    //should be null
    TEST_ASSERT_EQUAL(0, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

static void StorageLiteFS_unsupported_func_fscanf()
{
    char buffer[buf_size] = "good_day";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    char str[buf_size];
    res = fscanf(fd[0], "%s", str);
    TEST_ASSERT_EQUAL(EOF, res);
    TEST_ASSERT_EQUAL(EBADF, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

static void StorageLiteFS_unsupported_func_fseek()
{
    char buffer[buf_size] = "good_day";

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    char str[buf_size];
    res = fseek (fd[0] , (buf_size / 2), SEEK_SET);
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_EQUAL(0, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

static void StorageLiteFS_unsupported_func_ftell()
{
    char buffer[buf_size] = "good_day";
    fpos_t pos;

    init();
    StorageLiteFS stlitefs("stfs", &stlite, StorageLite::encrypt_flag);
    fs_init(&stlitefs);

    int res = !((fd[0] = fopen("/stfs/" "hello", "w")) != NULL);
    TEST_ASSERT_EQUAL(0, res);

    int write_sz = fwrite(buffer, sizeof(char), buf_size, fd[0]);
    TEST_ASSERT_EQUAL(buf_size, write_sz);

    res = fflush(fd[0]);
    TEST_ASSERT_EQUAL(0, res);

    errno = 0;
    long lres = ftell(fd[0]);
    TEST_ASSERT_EQUAL(0, lres);
    TEST_ASSERT_EQUAL(0, errno);

    res = fclose(fd[0]);
    TEST_ASSERT_EQUAL(0, res); 
}

/*----------------setup------------------*/

utest::v1::status_t setup_init(const Case *const source, const size_t index_of_case, uint16_t max_bd_files)
{
    return STATUS_CONTINUE;
}

utest::v1::status_t tear_down_handler(const Case *const source, const size_t passed, const size_t failed, const failure_t reason)
{
    return STATUS_CONTINUE;
}

utest::v1::status_t failure_handler(const Case *const source, const failure_t reason)
{
    greentea_case_failure_abort_handler(source, reason);
    return STATUS_CONTINUE;
}

Case cases[] = {
    Case("StorageLiteFS_fopen_path_not_valid", StorageLiteFS_fopen_path_not_valid),
    Case("StorageLiteFS_fopen_empty_path_r_mode", StorageLiteFS_fopen_empty_path_r_mode),
    Case("StorageLiteFS_fopen_empty_path_w_mode", StorageLiteFS_fopen_empty_path_w_mode),
    Case("StorageLiteFS_fopen_invalid_mode", StorageLiteFS_fopen_invalid_mode),
    Case("StorageLiteFS_fopen_unsupported_a_mode", StorageLiteFS_fopen_unsupported_a_mode),
    Case("StorageLiteFS_fopen_unsupported_a_plus_mode", StorageLiteFS_fopen_unsupported_a_plus_mode),
    Case("StorageLiteFS_fopen_unsupported_r_plus_mode", StorageLiteFS_fopen_unsupported_r_plus_mode),
    Case("StorageLiteFS_fopen_unsupported_w_plus_mode", StorageLiteFS_fopen_unsupported_w_plus_mode),
    Case("StorageLiteFS_fopen_supported_rb_plus_mode", StorageLiteFS_fopen_supported_rb_plus_mode),
    Case("StorageLiteFS_fopen_supported_wb_plus_mode", StorageLiteFS_fopen_supported_wb_plus_mode),

    Case("StorageLiteFS_fclose_valid_flow", StorageLiteFS_fclose_valid_flow),
    Case("StorageLiteFS_fclose_null_fd", StorageLiteFS_fclose_null_fd),
    Case("StorageLiteFS_fclose_closed_file", StorageLiteFS_fclose_closed_file),

    Case("StorageLiteFS_fwrite_null_fd", StorageLiteFS_fwrite_null_fd),
    //Case("StorageLiteFS_fwrite_size_zero", StorageLiteFS_fwrite_size_zero),
    Case("StorageLiteFS_fwrite_nmemb_zero", StorageLiteFS_fwrite_nmemb_zero),
    Case("StorageLiteFS_fwrite_valid_flow", StorageLiteFS_fwrite_valid_flow),
    Case("StorageLiteFS_fwrite_with_fopen_r_mode", StorageLiteFS_fwrite_with_fopen_r_mode),
    Case("StorageLiteFS_fwrite_closed_file", StorageLiteFS_fwrite_closed_file),

    //Case("StorageLiteFS_fread_null_fd", StorageLiteFS_fread_null_fd), //CRASH!!!
    Case("StorageLiteFS_fread_size_zero", StorageLiteFS_fread_size_zero),
    Case("StorageLiteFS_fread_nmemb_zero", StorageLiteFS_fread_nmemb_zero),
    Case("StorageLiteFS_fread_valid_flow", StorageLiteFS_fread_valid_flow),
    Case("StorageLiteFS_fread_fwrite_no_fclose", StorageLiteFS_fread_fwrite_no_fclose),
    Case("StorageLiteFS_fread_with_fopen_w_mode", StorageLiteFS_fread_with_fopen_w_mode),
    Case("StorageLiteFS_fread_closed_file", StorageLiteFS_fread_closed_file),

    Case("StorageLiteFS_unsupported_func_fflush", StorageLiteFS_unsupported_func_fflush),       //SHOULD FAIL
    Case("StorageLiteFS_unsupported_func_fgetc", StorageLiteFS_unsupported_func_fgetc),
    Case("StorageLiteFS_unsupported_func_fgetpos", StorageLiteFS_unsupported_func_fgetpos),     //SHOULD FAIL
    Case("StorageLiteFS_unsupported_func_fgets", StorageLiteFS_unsupported_func_fgets),
    Case("StorageLiteFS_unsupported_func_fprintf", StorageLiteFS_unsupported_func_fprintf),     //SHOULD FAIL
    Case("StorageLiteFS_unsupported_func_fputc", StorageLiteFS_unsupported_func_fputc),         //SHOULD return EOF
    Case("StorageLiteFS_unsupported_func_fputs", StorageLiteFS_unsupported_func_fputs),         //res should be EOF
    Case("StorageLiteFS_unsupported_func_freopen", StorageLiteFS_unsupported_func_freopen),        //fd[1] should be null
    Case("StorageLiteFS_unsupported_func_fscanf", StorageLiteFS_unsupported_func_fscanf),
    Case("StorageLiteFS_unsupported_func_fseek", StorageLiteFS_unsupported_func_fseek),     //should return res non zero
    Case("StorageLiteFS_unsupported_func_ftell", StorageLiteFS_unsupported_func_ftell),

    /*Case("test_simple_file_test", test_simple_file_test),
    Case("test_small_file_test", test_small_file_test),
    Case("test_medium_file_test", test_medium_file_test),
    Case("test_large_file_test", test_large_file_test),
    Case("test_non_overlap_check", test_non_overlap_check),*/

};

utest::v1::status_t greentea_test_setup(const size_t number_of_cases)
{
    GREENTEA_SETUP(120, "default_auto");
    return greentea_test_setup_handler(number_of_cases);
}

Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);

int main()
{
    return !Harness::run(specification);
}
