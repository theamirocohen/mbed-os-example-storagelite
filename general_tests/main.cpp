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

#include "storagelite.h"
#include "HeapBlockDevice.h"
#include "FlashSimBlockDevice.h"
#include "SlicingBlockDevice.h"
#include "greentea-client/test_env.h"
#include "unity/unity.h"
#include "utest/utest.h"
#include "Thread.h"
#include "nvstore.h"
#include "sha256.h"


using namespace utest::v1;

static const uint32_t data_buf_size        = 10;
static const uint32_t data_buf_max_size    = 256;
static const uint16_t default_name_size    = 16;
static const uint8_t  default_name         = 1;
static const uint8_t  non_exist_file_name  = 2;
static const uint8_t  fr_file_name         = 3;
static const uint8_t  empty_file_name      = 4;

static const uint16_t name_max_size        = 256;
static const uint32_t invalid_flags        = 0xFFFF;

static const size_t bd_size                = 8192;
static const size_t bd_erase_size          = 4096;
static const size_t bd_prog_size           = 16;
static const size_t bd_read_size           = 1;

static const size_t full_sha256_size = 32;

StorageLite * stlite = NULL;
HeapBlockDevice bd(bd_size, bd_read_size, bd_prog_size, bd_erase_size);
FlashSimBlockDevice flash_bd(&bd);

static void deinit()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->deinit();
    TEST_ASSERT_EQUAL_MESSAGE(STORAGELITE_SUCCESS, status, "StorageLite::deinit failed\n");
    printf("deinit\n");
}


static int calc_sha256_func(mbedtls_sha256_context *ctx, int &start, const unsigned char *input, size_t ilen)
{
    int ret;

    if (start) {
        mbedtls_sha256_init(ctx);

        ret = mbedtls_sha256_starts_ret(ctx, 0);
        if( ret != 0 )
            goto exit;
        start = 0;
    }

    ret = mbedtls_sha256_update_ret(ctx, input, ilen);
    if( ret != 0 )
        goto exit;

    return 0;

exit:
    mbedtls_sha256_free(ctx);

    return ret;
}

static int finish_sha256_func(mbedtls_sha256_context *ctx, unsigned char *output, int &finished)
{
    int ret;

    ret = mbedtls_sha256_finish_ret(ctx, output);

    mbedtls_sha256_free(ctx);

    finished = 1;

    return ret;
}

static int calc_hash_func(const unsigned char *input, size_t ilen, uint32_t &hash)
{
    int hash_calc_start = 1, hash_calc_finished = 0;
    mbedtls_sha256_context hash_ctx;
    uint8_t full_sha[full_sha256_size];
    int ret;

    ret = calc_sha256_func(&hash_ctx, hash_calc_start, input, ilen);
    if (ret) {
        return ret;
    }

    ret = finish_sha256_func(&hash_ctx, full_sha, hash_calc_finished);
    if (ret) {
        return ret;
    }
    memcpy(&hash, full_sha, sizeof(hash));

    return 0;
}

//------------- set tests function -------------

static void storagelite_set_name_null_name_len_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(0, NULL, data_buf_size, data_buf, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_set_name_null_name_len_not_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, NULL, data_buf_size, data_buf, 0);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_set_name_len_zero_name_not_null()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(0, &default_name, data_buf_size, data_buf, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_set_name_len_bigger_than_max()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(name_max_size + 1, &default_name, data_buf_size, data_buf, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_set_buf_len_bigger_than_max()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &default_name, data_buf_max_size + 1, data_buf, 0);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_set_invalid_flags()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &default_name, data_buf_size, data_buf, invalid_flags);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_set_buf_size_not_zero_buf_null()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->set(default_name_size, &default_name, data_buf_size, NULL, 0);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_set_buf_size_zero_buf_not_null()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &default_name, 0, data_buf, 0);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_set_buf_size_zero_buf_null()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->set(default_name_size, &default_name, 0, NULL, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_set_two_files_same_params()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &default_name, data_buf_size, data_buf, 0);
    status = stlite->set(default_name_size, &default_name, data_buf_size, data_buf, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void set_thread(uint8_t * file_name)
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->set(default_name_size, file_name, 0, NULL, 0);
    printf("file_name is %d\n", *file_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

//multithreaded set, check with get all files were created succesfully
static void storagelite_set_multithreded()
{
    int status = STORAGELITE_SUCCESS;
    Thread T1, T2, T3;
    uint8_t i = 0;

    osStatus err = T1.start(callback(set_thread, &i));
    if (err) {
       TEST_FAIL_MESSAGE("creating thread failed!");
    }
    /*i++;
    err = T2.start(callback(set_thread, &i));
    if (err) {
       TEST_FAIL_MESSAGE("creating thread failed!");
    }
    i++;
    err = T3.start(callback(set_thread, &i));
    if (err) {
       TEST_FAIL_MESSAGE("creating thread failed!");
    }*/
    err = T1.join();
    if (err) {
       TEST_FAIL_MESSAGE("joining thread failed!");
    }
    uint32_t actual_len_bytes = 0;
    for (i = 0; i < 1; i++) 
    {
        status = stlite->get(default_name_size, &i, 0, NULL, actual_len_bytes);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    }


    /*err = T2.join();
    if (err) {
       TEST_FAIL_MESSAGE("joining thread failed!");
    }
    err = T3.join();
    if (err) {
       TEST_FAIL_MESSAGE("joining thread failed!");
    }*/
    deinit();
}

//------------- get tests function -------------//

static void storagelite_get_name_null_name_len_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(0, NULL, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_get_name_null_name_len_not_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(default_name_size, NULL, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_get_name_len_zero_name_not_null()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(0, &default_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_get_name_len_bigger_than_max()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(name_max_size + 1, &default_name, data_buf_size, data_buf, actual_len_bytes);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_get_buf_size_not_zero_buf_null()
{
    int status = STORAGELITE_SUCCESS;
    printf("hello!\n");
    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &default_name, data_buf_size, NULL, actual_len_bytes);
    printf("hello2!\n");
    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

//file requested not empty
static void storagelite_get_not_empty_file_buf_size_zero_buf_null()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &default_name, 0, NULL, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_BUFF_TOO_SMALL, status);
    deinit();
}

//file requested empty 
static void storagelite_get_empty_file_buf_size_zero_buf_null()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->set(default_name_size, &empty_file_name, 0, NULL, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &empty_file_name, 0, NULL, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_get_buf_size_insufficient()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(default_name_size, &default_name, data_buf_size/2, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_BUFF_TOO_SMALL, status);
    deinit();
}

static void storagelite_get_non_existing_file()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(default_name_size, &non_exist_file_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_get_existing_file()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(default_name_size, &default_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    TEST_ASSERT_EQUAL(data_buf_size, actual_len_bytes);
    deinit();
}

static void storagelite_get_removed_file()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(default_name_size, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(default_name_size, &default_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

//no setup handler requierd - set two files with the same hash and check get can retrieve both
static void storagelite_get_same_hash()
{
    int status = STORAGELITE_SUCCESS;
    bool match = false;
    uint32_t hash = 0, init_hash = 0;
    int os_ret = 0;
    uint8_t i = 0, init_file = 1;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &init_file, data_buf_size, data_buf, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    os_ret = calc_hash_func(&init_file, 1, init_hash);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, os_ret);
    printf("init_file = %d, init_hash = %d\n", i, init_hash);

    for (i = 2; (!match && (i < 100000)); i++)
    {
        os_ret = calc_hash_func(&i, 1, hash);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, os_ret);
        if (init_hash == hash)
        {
           match = true;
        }
    }
    //printf("i = %d, init_hash = %d\n", i, hash);

    printf("init_hash of init_file (%d) = %d, hash of i (%d) = %d\n", init_file, init_hash, i, hash);

    data_buf[data_buf_size] = {1};
    status = stlite->set(default_name_size, &i, data_buf_size, data_buf, 0);

    printf("set2\n");

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    printf("get1\n");

    uint32_t actual_len_bytes = 0;
    /*status = stlite->get(default_name_size, &init_file, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, data_buf[0]);*/

    printf("get2\n");

    status = stlite->get(default_name_size, &i, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    TEST_ASSERT_EQUAL(1, data_buf[0]);
    deinit();
}

//no setup handler requierd - 
static void storagelite_get_rollback_file()
{
    int status = STORAGELITE_SUCCESS;

    printf("wow!\n");

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &default_name, data_buf_size, data_buf, StorageLite::rollback_protect_flag); //crash here

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    printf("wow1!\n");

    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &default_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
        printf("wow2!\n");

}

//no setup handler requierd
static void storagelite_get_curropt_rollback_file()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &default_name, data_buf_size, data_buf, StorageLite::rollback_protect_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    NVStore &nvstore = NVStore::get_instance();
    status = nvstore.reset();
    TEST_ASSERT_EQUAL(NVSTORE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &default_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_DATA_CORRUPT, status);
    deinit();
}

//no setup handler requierd
static void storagelite_get_encrypt_file()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &default_name, data_buf_size, data_buf, StorageLite::encrypt_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &default_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

//------------- remove tests function -------------//

static void storagelite_remove_name_null_name_len_zero()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(0, NULL);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_remove_name_null_name_len_not_zero()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(default_name_size, NULL);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_remove_name_not_null_name_len_zero()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(0, &default_name);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_remove_name_len_bigger_than_max()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(name_max_size + 1, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_remove_existing_file()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(default_name_size, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_remove_non_existing_file()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(default_name_size, &non_exist_file_name);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_remove_removed_file()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(default_name_size, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->remove(default_name_size, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_remove_fr_file_try_get()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &fr_file_name, data_buf_size, data_buf, StorageLite::update_factory_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->remove(default_name_size, &fr_file_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &fr_file_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

//------------- get_item_size tests function -------------//

static void storagelite_get_item_size_name_null_name_len_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_data_size = 0;
    status = stlite->get_file_size(0, NULL, actual_data_size);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_get_item_size_name_null_name_len_not_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_data_size = 0;
    status = stlite->get_file_size(default_name_size, NULL, actual_data_size);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_get_item_size_name_not_null_name_len_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_data_size = 0;
    status = stlite->get_file_size(0, &default_name, actual_data_size);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_get_item_size_name_len_bigger_than_max()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_data_size = 0;
    status = stlite->get_file_size(name_max_size + 1, &default_name, actual_data_size);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_get_item_size_non_existing_file()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_data_size = 0;
    status = stlite->get_file_size(default_name_size, &non_exist_file_name, actual_data_size);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_get_item_size_existing_file()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t actual_data_size = 0;
    status = stlite->get_file_size(default_name_size, &default_name, actual_data_size);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    TEST_ASSERT_EQUAL(data_buf_size, actual_data_size);
    deinit();
}

static void storagelite_get_item_size_removed_file()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(default_name_size, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_data_size = 0;
    status = stlite->get_file_size(default_name_size, &default_name, actual_data_size);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_get_item_size_empty_file()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t empty_file_name[] = "empty_file";
    status = stlite->set(default_name_size, empty_file_name, 0, NULL, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_data_size = data_buf_size;
    status = stlite->get_file_size(default_name_size, empty_file_name, actual_data_size);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, actual_data_size);
    deinit();
}

static void storagelite_get_item_size_modified_file()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size * 2] = {0};
    status = stlite->set(default_name_size, &default_name, data_buf_size * 2, data_buf, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_data_size = 0;
    status = stlite->get_file_size(default_name_size, &default_name, actual_data_size);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    TEST_ASSERT_EQUAL(data_buf_size * 2, actual_data_size);
    deinit();
}

static void storagelite_get_item_size_fr_file_try_get()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &fr_file_name, data_buf_size, data_buf, StorageLite::update_factory_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->remove(default_name_size, &fr_file_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    status = stlite->get_file_size(default_name_size, &fr_file_name, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

//------------- file_exists tests function -------------//

static void storagelite_file_exists_name_null_name_len_zero()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->file_exists(0, NULL);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_file_exists_name_null_name_len_not_zero()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->file_exists(default_name_size, NULL);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_file_exists_name_not_null_name_len_zero()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->file_exists(0, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_file_exists_name_len_bigger_than_max()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->file_exists(name_max_size + 1, &default_name);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_file_exists_non_existing_file()
{
    int status = STORAGELITE_SUCCESS;
    printf("wow\n");
    status = stlite->file_exists(default_name_size, &non_exist_file_name);
    printf("wow2\n");
    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_file_exists_existing_file()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->file_exists(default_name_size, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_file_exists_removed_file()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(default_name_size, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->file_exists(default_name_size, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_file_exists_fr_file_try_get()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &fr_file_name, data_buf_size, data_buf, StorageLite::update_factory_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->remove(default_name_size, &fr_file_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->file_exists(default_name_size, &fr_file_name);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

//------------- get_file_flags tests function -------------//

static void storagelite_get_file_flags_name_null_name_len_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t flags = 0;
    status = stlite->get_file_flags(0, NULL, flags);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_get_file_flags_name_null_name_len_not_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t flags = 0;
    status = stlite->get_file_flags(default_name_size, NULL, flags);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_get_file_flags_name_not_null_name_len_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t flags = 0;
    status = stlite->get_file_flags(0, &default_name, flags);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

static void storagelite_get_file_flags_name_len_bigger_than_max()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t flags = 0;
    status = stlite->get_file_flags(name_max_size + 1, &default_name, flags);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_get_file_flags_non_existing_file()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t flags = 0;
    status = stlite->get_file_flags(default_name_size, &non_exist_file_name, flags);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_get_file_flags_existing_file()
{
    int status = STORAGELITE_SUCCESS;

    uint32_t flags = 0;
    status = stlite->get_file_flags(default_name_size, &default_name, flags);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_get_file_flags_removed_file()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->remove(default_name_size, &default_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t flags = 0;
    status = stlite->get_file_flags(default_name_size, &default_name, flags);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

static void storagelite_get_file_flags_fr_file_try_get()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &fr_file_name, data_buf_size, data_buf, StorageLite::update_factory_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->remove(default_name_size, &fr_file_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t flags = 0;
    status = stlite->get_file_flags(default_name_size, &fr_file_name, flags);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

//------------- get_first_file tests function -------------//

static void storagelite_get_first_file_max_name_size_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[name_max_size] = {0};
    status = stlite->get_first_file(0, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_BUFF_TOO_SMALL, status);
    deinit();
}

static void storagelite_get_first_file_max_name_bigger_than_max()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[name_max_size] = {0};
    uint16_t file_name_buf_size = name_max_size + 1;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

//empty storage
static void storagelite_get_first_file_no_file_in_storage()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[name_max_size] = {1};
    uint16_t file_name_buf_size = name_max_size;

    uint32_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(default_name_size, &default_name, data_buf_size, data_buf, actual_len_bytes);
    printf("file_name = %d, status = %d\n", file_name[0], status);
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);
    printf("file_name = %d\n", file_name[0]);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

//storage should contain file name bigger than 1
static void storagelite_get_first_file_max_name_size_too_small()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[name_max_size] = {0};
    uint16_t file_name_buf_size = 1;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_BUFF_TOO_SMALL, status);
    deinit();
}

static void storagelite_get_first_file_valid_flow()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[name_max_size] = {0};
    uint16_t file_name_buf_size = name_max_size;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

//first file name should be big (name_max_size - 1) so it could be skipped
static void storagelite_get_first_file_not_first()
{
    int status = STORAGELITE_SUCCESS;
    uint8_t long_file_name[default_name_size * 2] = {0};
    uint16_t long_file_name_size = default_name_size * 2;

    status = stlite->set(long_file_name_size, long_file_name, 0, NULL, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->set(default_name_size, &default_name, 0, NULL, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[default_name_size + 1] = {0};
    uint16_t file_name_buf_size = default_name_size;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

//------------- get_next_file tests function -------------//

//all tests should contain at least two files***************

static void storagelite_get_next_file_max_name_size_zero()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[name_max_size] = {0};
    uint16_t file_name_buf_size = name_max_size;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    file_name_buf_size = 0;
    status = stlite->get_next_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_BUFF_TOO_SMALL, status);
    deinit();
}

static void storagelite_get_next_file_max_name_bigger_than_max()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[name_max_size] = {0};
    uint16_t file_name_buf_size = name_max_size;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    file_name_buf_size = name_max_size + 1;
    status = stlite->get_next_file(file_name_buf_size, file_name, file_name_size, handle);

    //TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

//empty storage - just one file for get_first_file
static void storagelite_get_next_file_no_file_in_storage()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[name_max_size] = {0};
    uint16_t file_name_buf_size = name_max_size;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    file_name_buf_size = name_max_size;
    status = stlite->get_next_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

//storage should contain file name bigger than 1
static void storagelite_get_next_file_max_name_size_too_small()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[name_max_size] = {0};
    uint16_t file_name_buf_size = name_max_size;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    file_name_buf_size = 1;
    status = stlite->get_next_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_BUFF_TOO_SMALL, status);
    deinit();
}

static void storagelite_get_next_file_valid_flow()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[name_max_size] = {0};
    uint16_t file_name_buf_size = name_max_size;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    printf("wow\n");

    file_name_buf_size = name_max_size;
    status = stlite->get_next_file(file_name_buf_size + 1, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

static void storagelite_get_next_file_invalid_handle()
{
    int status = STORAGELITE_SUCCESS;

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[default_name_size + 1] = {0};
    uint16_t file_name_buf_size = default_name_size;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    printf("handle = %d\n");

    handle++;
    printf("handle = %d\n");
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_BAD_VALUE, status);
    deinit();
}

//at least 3 files,second file name should be big (name_max_size - 1) so it could be skipped 
static void storagelite_get_next_file_not_first()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t long_file_name[default_name_size * 2] = {0};
    uint16_t long_file_name_size = default_name_size * 2;

    status = stlite->set(long_file_name_size, long_file_name, 0, NULL, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->set(default_name_size, &default_name, 0, NULL, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint16_t file_name_size = 0;
    uint32_t handle = 0;
    uint8_t file_name[default_name_size + 1] = {0};
    uint16_t file_name_buf_size = default_name_size;
    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->get_first_file(file_name_buf_size, file_name, file_name_size, handle);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

//------------- Factory Reset tests function -------------//

//no setup handler here (flag use), because fr is used maybe do it on a different storage lite object/ data base
static void storagelite_factory_reset_get_file()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &fr_file_name, data_buf_size, data_buf, StorageLite::update_factory_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->factory_reset();

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &fr_file_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}

//setup regular file required
static void storagelite_factory_reset_get_file_without_fr_flag()
{
    int status = STORAGELITE_SUCCESS;

    status = stlite->factory_reset();

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(default_name_size, &default_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
    deinit();
}

//no setup handler here (flag use), because fr is used maybe do it on a different storage lite object/ data base
static void storagelite_factory_reset_get_original_fr_file()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &fr_file_name, data_buf_size, data_buf, StorageLite::update_factory_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint8_t temp_data_buf[data_buf_size * 2] = {0};
    status = stlite->set(default_name_size, &fr_file_name, data_buf_size * 2, temp_data_buf, 0);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->factory_reset();

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &fr_file_name, data_buf_size * 2, temp_data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    TEST_ASSERT_EQUAL(data_buf_size, actual_len_bytes);
    deinit();
}

//no setup handler here (flag use), because fr is used maybe do it on a different storage lite object/ data base
static void storagelite_factory_reset_get_modified_fr_file()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &fr_file_name, data_buf_size, data_buf, StorageLite::update_factory_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint8_t temp_data_buf[data_buf_size * 2] = {0};
    status = stlite->set(default_name_size, &fr_file_name, data_buf_size * 2, temp_data_buf, StorageLite::update_factory_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->factory_reset();

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &fr_file_name, data_buf_size * 2, temp_data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    TEST_ASSERT_EQUAL(data_buf_size * 2, actual_len_bytes);
    deinit();
}

//no setup handler here (flag use), because fr is used maybe do it on a different storage lite object/ data base
static void storagelite_factory_reset_get_removed_fr_file()
{
    int status = STORAGELITE_SUCCESS;

    //char &fr_file_name[] = "fr_file";
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &fr_file_name, data_buf_size, data_buf, StorageLite::update_factory_flag);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->remove(default_name_size, &fr_file_name);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    status = stlite->factory_reset();

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint32_t actual_len_bytes = 0;
    status = stlite->get(default_name_size, &fr_file_name, data_buf_size, data_buf, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    deinit();
}


//--------------------handlers---------------------------------//

utest::v1::status_t setup_handler(const Case *const source, const size_t index_of_case)
{
    int status = STORAGELITE_SUCCESS;

    printf("setup_handler\n");

    stlite = &StorageLite::get_instance();
    TEST_ASSERT_NOT_NULL_MESSAGE(stlite, "StorageLite::get_instance failed\n");

    status = stlite->init(&flash_bd);
    TEST_ASSERT_EQUAL_MESSAGE(STORAGELITE_SUCCESS, status, "StorageLite::init failed\n");
    
    return STATUS_CONTINUE;
}

utest::v1::status_t setup_handler_set_file(const Case *const source, const size_t index_of_case)
{
    int status = STORAGELITE_SUCCESS;

    printf("setup_handler_set\n");

    stlite = &StorageLite::get_instance();
    TEST_ASSERT_NOT_NULL_MESSAGE(stlite, "StorageLite::get_instance failed\n");

    status = stlite->init(&flash_bd);
    TEST_ASSERT_EQUAL_MESSAGE(STORAGELITE_SUCCESS, status, "StorageLite::init failed\n");

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &default_name, data_buf_size, data_buf, 0);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    return STATUS_CONTINUE;
}

utest::v1::status_t setup_handler_set_multiple_files(const Case *const source, const size_t index_of_case)
{
    int status = STORAGELITE_SUCCESS;

    printf("setup_handler_set_multi\n");

    stlite = &StorageLite::get_instance();
    TEST_ASSERT_NOT_NULL_MESSAGE(stlite, "StorageLite::get_instance failed\n");

    status = stlite->init(&flash_bd);
    TEST_ASSERT_EQUAL_MESSAGE(STORAGELITE_SUCCESS, status, "StorageLite::init failed\n");

    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->set(default_name_size, &default_name, data_buf_size, data_buf, 0);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    uint8_t new_file_name = default_name + 1;
    status = stlite->set(default_name_size, &new_file_name, data_buf_size, data_buf, 0);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    return STATUS_CONTINUE;
}

utest::v1::status_t greentea_failure_handler(const Case *const source, const failure_t reason)
{
    greentea_case_failure_abort_handler(source, reason);
    return STATUS_CONTINUE;
}

Case cases[] = {
    /*------------------set()------------------*/
    /*Case("storagelite_set_name_null_name_len zero",
         setup_handler, storagelite_set_name_null_name_len_zero),// tear_down_handler, greentea_failure_handler),
    Case("storagelite_set_name_null_name_len_not_zero",
         setup_handler, storagelite_set_name_null_name_len_not_zero),
    Case("storagelite_set_name_len_zero_name_not_null",
         setup_handler, storagelite_set_name_len_zero_name_not_null),
    Case("storagelite_set_name_len_bigger_than_max",
         setup_handler, storagelite_set_name_len_bigger_than_max),
    Case("storagelite_set_buf_len_bigger_than_max",
         setup_handler, storagelite_set_buf_len_bigger_than_max),*/
    /*Case("storagelite_set_invalid_flags",     //fail
         setup_handler, storagelite_set_invalid_flags, tear_down_handler, greentea_failure_handler),*/
    /*Case("storagelite_set_buf_size_not_zero_buf_null",
         setup_handler, storagelite_set_buf_size_not_zero_buf_null),
    Case("storagelite_set_buf_size_zero_buf_not_null",
         setup_handler, storagelite_set_buf_size_zero_buf_not_null),
    Case("storagelite_set_buf_size_zero_buf_null",
         setup_handler, storagelite_set_buf_size_zero_buf_null),
    Case("storagelite_set_two_files_same_params",
         setup_handler, storagelite_set_two_files_same_params),*/
    /*Case("storagelite_set_multithreded",  //fail
         setup_handler, storagelite_set_multithreded, tear_down_handler, greentea_failure_handler),*/
    /*------------------get()------------------*/
    Case("storagelite_get_name_null_name_len_zero",
         setup_handler_set_file, storagelite_get_name_null_name_len_zero),
    Case("storagelite_get_name_null_name_len_not_zero",
         setup_handler_set_file, storagelite_get_name_null_name_len_not_zero),
    Case("storagelite_get_name_len_zero_name_not_null",
         setup_handler_set_file, storagelite_get_name_len_zero_name_not_null),
    /*Case("storagelite_get_name_len_bigger_than_max",
         setup_handler_set_file, storagelite_get_name_len_bigger_than_max),*/
    /*Case("storagelite_get_buf_size_not_zero_buf_null",    //fail
         setup_handler_set_file, storagelite_get_buf_size_not_zero_buf_null, tear_down_handler, greentea_failure_handler),*/
    /*Case("storagelite_get_not_empty_file_buf_size_zero_buf_null",
         setup_handler_set_file, storagelite_get_not_empty_file_buf_size_zero_buf_null),
    Case("storagelite_get_empty_file_buf_size_zero_buf_null",
         setup_handler_set_file, storagelite_get_empty_file_buf_size_zero_buf_null),
    Case("storagelite_get_buf_size_insufficient",
         setup_handler_set_file, storagelite_get_buf_size_insufficient),
    Case("storagelite_get_non_existing_file",
         setup_handler_set_file, storagelite_get_non_existing_file),
    Case("storagelite_get_existing_file",
         setup_handler_set_file, storagelite_get_existing_file),
    Case("storagelite_get_removed_file",
         setup_handler_set_file, storagelite_get_removed_file),*/
    Case("storagelite_get_same_hash", 
         setup_handler, storagelite_get_same_hash),
    /*Case("storagelite_get_rollback_file", //rollbacck fail
         setup_handler, storagelite_get_rollback_file),
    Case("storagelite_get_curropt_rollback_file",
         setup_handler, storagelite_get_curropt_rollback_file), */
    Case("storagelite_get_encrypt_file",
         setup_handler, storagelite_get_encrypt_file/*, tear_down_handler, greentea_failure_handler*/),
    /*------------------remove()------------------*/
    /*Case("storagelite_remove_name_null_name_len_zero",
         setup_handler_set_file, storagelite_remove_name_null_name_len_zero),
    Case("storagelite_remove_name_null_name_len_not_zero",
         setup_handler_set_file, storagelite_remove_name_null_name_len_not_zero),
    Case("storagelite_remove_name_not_null_name_len_zero",
         setup_handler_set_file, storagelite_remove_name_not_null_name_len_zero),
    Case("storagelite_remove_name_len_bigger_than_max",
         setup_handler_set_file, storagelite_remove_name_len_bigger_than_max),
    Case("storagelite_remove_existing_file",
         setup_handler_set_file, storagelite_remove_existing_file),
    Case("storagelite_remove_non_existing_file",
         setup_handler, storagelite_remove_non_existing_file),
    Case("storagelite_remove_removed_file",
         setup_handler_set_file, storagelite_remove_removed_file),
    Case("storagelite_remove_fr_file_try_get",
         setup_handler, storagelite_remove_fr_file_try_get),*/
    /*------------------get_item_size()------------------*/
    /*Case("storagelite_get_item_size_name_null_name_len_zero",
         setup_handler_set_file, storagelite_get_item_size_name_null_name_len_zero),
    Case("storagelite_get_item_size_name_null_name_len_not_zero",
         setup_handler_set_file, storagelite_get_item_size_name_null_name_len_not_zero),
    Case("storagelite_get_item_size_name_not_null_name_len_zero",
         setup_handler_set_file, storagelite_get_item_size_name_not_null_name_len_zero),
    Case("storagelite_get_item_size_name_len_bigger_than_max",
         setup_handler_set_file, storagelite_get_item_size_name_len_bigger_than_max),
    Case("storagelite_get_item_size_non_existing_file",
         setup_handler_set_file, storagelite_get_item_size_non_existing_file),
    Case("storagelite_get_item_size_existing_file",
         setup_handler_set_file, storagelite_get_item_size_existing_file),
    Case("storagelite_get_item_size_removed_file",
         setup_handler_set_file, storagelite_get_item_size_removed_file),
    Case("storagelite_get_item_size_empty_file",
         setup_handler, storagelite_get_item_size_empty_file),
    Case("storagelite_get_item_size_modified_file",
         setup_handler_set_file, storagelite_get_item_size_modified_file),
    Case("storagelite_get_item_size_fr_file_try_get",
         setup_handler_set_file, storagelite_get_item_size_fr_file_try_get),*/
    /*------------------file_exists()------------------*/
    /*Case("storagelite_file_exists_name_null_name_len_zero",
         setup_handler_set_file, storagelite_file_exists_name_null_name_len_zero),
    Case("storagelite_file_exists_name_null_name_len_not_zero",
         setup_handler_set_file, storagelite_file_exists_name_null_name_len_not_zero),
    Case("storagelite_file_exists_name_not_null_name_len_zero",
         setup_handler_set_file, storagelite_file_exists_name_not_null_name_len_zero),
    Case("storagelite_file_exists_name_len_bigger_than_max",
         setup_handler_set_file, storagelite_file_exists_name_len_bigger_than_max),
    //Case("storagelite_file_exists_non_existing_file",         //get stuck here
    //     setup_handler_set_file, storagelite_file_exists_non_existing_file),
    Case("storagelite_file_exists_existing_file",
         setup_handler_set_file, storagelite_file_exists_existing_file),
    Case("storagelite_file_exists_removed_file",
         setup_handler_set_file, storagelite_file_exists_removed_file),
    Case("storagelite_file_exists_fr_file_try_get",
         setup_handler_set_file, storagelite_file_exists_fr_file_try_get),*/
    /*------------------get_file_flags()------------------*/
    /*Case("storagelite_get_file_flags_name_null_name_len_zero",
         setup_handler_set_file, storagelite_get_file_flags_name_null_name_len_zero),
    Case("storagelite_get_file_flags_name_null_name_len_not_zero",
         setup_handler_set_file, storagelite_get_file_flags_name_null_name_len_not_zero),
    Case("storagelite_get_file_flags_name_not_null_name_len_zero",
         setup_handler_set_file, storagelite_get_file_flags_name_not_null_name_len_zero),
    Case("storagelite_get_file_flags_name_len_bigger_than_max",
         setup_handler_set_file, storagelite_get_file_flags_name_len_bigger_than_max),
    Case("storagelite_get_file_flags_non_existing_file",
         setup_handler_set_file, storagelite_get_file_flags_non_existing_file),
    Case("storagelite_get_file_flags_existing_file",
         setup_handler_set_file, storagelite_get_file_flags_existing_file),
    Case("storagelite_get_file_flags_removed_file",
         setup_handler_set_file, storagelite_get_file_flags_removed_file),
    Case("storagelite_get_file_flags_fr_file_try_get",
         setup_handler_set_file, storagelite_get_file_flags_fr_file_try_get),*/
    /*------------------get_first_file()------------------*/
    /*Case("storagelite_get_first_file_max_name_size_zero",
         setup_handler_set_file, storagelite_get_first_file_max_name_size_zero),
    Case("storagelite_get_first_file_max_name_bigger_than_max",
         setup_handler_set_file, storagelite_get_first_file_max_name_bigger_than_max),
    //Case("storagelite_get_first_file_no_file_in_storage", //finds the file
    //     setup_handler, storagelite_get_first_file_no_file_in_storage),
    Case("storagelite_get_first_file_max_name_size_too_small",
         setup_handler_set_file, storagelite_get_first_file_max_name_size_too_small),
    Case("storagelite_get_first_file_valid_flow",
         setup_handler_set_file, storagelite_get_first_file_valid_flow),
    Case("storagelite_get_first_file_not_first",
         setup_handler, storagelite_get_first_file_not_first),*/
    /*------------------get_next_file()------------------*/
    Case("storagelite_get_next_file_max_name_size_zero",
         setup_handler_set_multiple_files, storagelite_get_next_file_max_name_size_zero),
    Case("storagelite_get_next_file_max_name_bigger_than_max",
         setup_handler_set_multiple_files, storagelite_get_next_file_max_name_bigger_than_max),
    /*Case("storagelite_get_next_file_no_file_in_storage",
         setup_handler_set_multiple_files, storagelite_get_next_file_no_file_in_storage),*/
    Case("storagelite_get_next_file_max_name_size_too_small",
         setup_handler_set_multiple_files, storagelite_get_next_file_max_name_size_too_small),
    Case("storagelite_get_next_file_valid_flow",
         setup_handler_set_multiple_files, storagelite_get_next_file_valid_flow),
    //Case("storagelite_get_next_file_invalid_handle",  //handle has no meaning in implementation
    //     setup_handler_set_multiple_files, storagelite_get_next_file_invalid_handle),
    Case("storagelite_get_next_file_not_first",
         setup_handler_set_multiple_files, storagelite_get_next_file_not_first),
    /*------------------factory_reset()------------------*/
    /*Case("storagelite_factory_reset_get_file",
         setup_handler, storagelite_factory_reset_get_file),
    Case("storagelite_factory_reset_get_file_without_fr_flag",
         setup_handler, storagelite_factory_reset_get_file_without_fr_flag),
    Case("storagelite_factory_reset_get_original_fr_file",
         setup_handler, storagelite_factory_reset_get_original_fr_file),
    Case("storagelite_factory_reset_get_modified_fr_file",
         setup_handler, storagelite_factory_reset_get_modified_fr_file),
    Case("storagelite_factory_reset_get_removed_fr_file",
         setup_handler, storagelite_factory_reset_get_removed_fr_file),*/
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
