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
 
/*
create single file, set it multiple times to exceed area size
create multiple files to exceed area size
reach max of files allowed
Set Max Files, Remove all files – then check you can still add MAX files
add many files (even max files), remove them, try to Get/Remove
*/

#include "StorageLite.h"
#include "HeapBlockDevice.h"
#include "FlashSimBlockDevice.h"
#include "greentea-client/test_env.h"
#include "unity/unity.h"
#include "utest/utest.h"

using namespace utest::v1;

static const size_t   data_buf_size      = 512;
static const uint8_t  default_name       = 255;
static const uint16_t max_files          = STORAGELITE_MAX_FILES;
static const uint16_t header_size        = 32;
static const uint16_t name_size          = 16;
static const uint16_t byte_name_size     = 1;

static const size_t bd_size = 8192;
static const size_t bd_erase_size = 4096;
static const size_t bd_prog_size = 1;
static const size_t bd_read_size = 1;

StorageLite * stlite = NULL;
HeapBlockDevice bd(bd_size, bd_read_size, bd_prog_size, bd_erase_size);
FlashSimBlockDevice flash_bd(&bd);

/*------------------utility functions------------------*/

static void terminated()
{
    int status = STORAGELITE_SUCCESS;

    stlite->reset();
    status = stlite->deinit();
    TEST_ASSERT_EQUAL_MESSAGE(STORAGELITE_SUCCESS, status, "StorageLite::deinit failed\n");
    
    delete stlite;
}

static void set_max_files()
{
    int status = STORAGELITE_SUCCESS;
    uint8_t *file_name, name_count = 1;

    file_name = &name_count;
    do 
    {
        status = stlite->set(file_name, byte_name_size, NULL, 0, 0);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
        name_count++;
    }
    while(name_count < max_files);
}

static void remove_max_files()
{
    int status = STORAGELITE_SUCCESS;
    uint8_t *file_name, name_count = 1;

    file_name = &name_count;
    do 
    {
        status = stlite->remove(file_name, byte_name_size);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

        name_count++;
    }
    while(name_count < max_files);
}

/*------------------tests------------------*/

static void storagelite_stress_single_file_exceed_area()
{
    int status = STORAGELITE_SUCCESS;
    uint8_t in_data_buff[data_buf_size] = {0};
    size_t last_size = 0;

    do 
    {
        last_size = stlite->free_size();
        status = stlite->set(&default_name, sizeof(default_name), in_data_buff, data_buf_size, 0);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    }
    while(stlite->free_size() <= last_size);

    size_t actual_len_bytes = 0;
    uint8_t out_data_buf[data_buf_size] = {0};
    status = stlite->get(&default_name, sizeof(default_name), out_data_buf, data_buf_size, actual_len_bytes);
    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);

    terminated();
}

static void storagelite_stress_multiple_files_exceed_area()
{
    int status = STORAGELITE_SUCCESS;
    uint8_t *file_name, name_count = 1;
    uint8_t in_data_buff[data_buf_size] = {0};
    file_name = &name_count;

    do 
    {
        status = stlite->set(file_name, sizeof(file_name), in_data_buff, data_buf_size, 0);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
        name_count++;
    }
    while(stlite->free_size() > (data_buf_size + name_size + header_size));

    status = stlite->set(file_name, sizeof(file_name), in_data_buff, data_buf_size, 0);
    TEST_ASSERT_EQUAL(STORAGELITE_NO_SPACE_ON_BD, status);

    terminated();
}

static void storagelite_stress_max_files_allowed()
{
    int status = STORAGELITE_SUCCESS;

    set_max_files();

    status = stlite->set(&default_name, sizeof(default_name), NULL, 0, 0);
    TEST_ASSERT_EQUAL(STORAGELITE_MAX_FILES_REACHED, status);
    terminated();
}

static void storagelite_stress_max_files_set_remove_set()
{
    set_max_files();

    remove_max_files();

    set_max_files();
    
    terminated();
}

static void storagelite_stress_max_files_set_remove_get()
{
    int status = STORAGELITE_SUCCESS;

    uint8_t *file_name, name_count = 1;

    file_name = &name_count;

    set_max_files();

    remove_max_files();

    size_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite->get(file_name, byte_name_size, data_buf, data_buf_size, actual_len_bytes);
    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);

    terminated();
}

/*------------------handlers------------------*/

utest::v1::status_t setup_init(const Case *const source, const size_t index_of_case, uint16_t max_bd_files)
{
    int status = STORAGELITE_SUCCESS;

    stlite = new StorageLite();

    status = stlite->init(&flash_bd, max_bd_files);
    TEST_ASSERT_EQUAL_MESSAGE(STORAGELITE_SUCCESS, status, "StorageLite::init failed\n");

    return STATUS_CONTINUE;
}

utest::v1::status_t setup_handler(const Case *const source, const size_t index_of_case)
{
    int status = STORAGELITE_SUCCESS;

    stlite = new StorageLite();

    status = stlite->init(&flash_bd, max_files);
    TEST_ASSERT_EQUAL_MESSAGE(STORAGELITE_SUCCESS, status, "StorageLite::init failed\n");

    return STATUS_CONTINUE;
}

utest::v1::status_t tear_down_handler(const Case *const source, const size_t passed, const size_t failed, const failure_t reason)
{
    stlite->deinit();
    return STATUS_CONTINUE;
}

utest::v1::status_t failure_handler(const Case *const source, const failure_t reason)
{
    greentea_case_failure_abort_handler(source, reason);
    return STATUS_CONTINUE;
}

Case cases[] = {
    Case("storagelite_stress_single_file_exceed_area", 
         setup_handler, storagelite_stress_single_file_exceed_area),
    Case("storagelite_stress_multiple_files_exceed_area", 
         setup_handler, storagelite_stress_multiple_files_exceed_area),
    Case("storagelite_stress_max_files_allowed", 
         setup_handler, storagelite_stress_max_files_allowed),
    Case("storagelite_stress_max_files_set_remove_set", 
         setup_handler, storagelite_stress_max_files_set_remove_set),
    Case("storagelite_stress_max_files_set_remove_get", 
         setup_handler, storagelite_stress_max_files_set_remove_get),
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
