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
#include "greentea-client/test_env.h"
#include "unity/unity.h"
#include "utest/utest.h"

using namespace utest::v1;

static const size_t data_buf_size        =  10;
static const size_t default_name_size    =  16;
static const uint8_t default_name         = 123;
static const uint16_t max_files            = 5;

static const size_t bd_size = 8192;
static const size_t bd_erase_size = 4096;
static const size_t bd_prog_size = 1;
static const size_t bd_read_size = 1;

StorageLite stlite;


/**************help functions*****************/

static void set_max_files()
{
    int status = STORAGELITE_SUCCESS;
    uint16_t i = 0;
    do 
    {
        status = stlite.set(&default_name, i++, NULL, 0, 0);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    }
    while(i < max_files);
}

static void remove_max_files()
{
    int status = STORAGELITE_SUCCESS;
    uint16_t i = 0;
    do
    {
        status = stlite.remove(&default_name, i++);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    }
    while(i < max_files);
}

static void storagelite_stress_single_file_exceed_area()
{
    int status = STORAGELITE_SUCCESS;
    bool area_wasnt_swaped = false;
    printf("in test\n");

    do 
    {
        status = stlite.set(&default_name, default_name_size, NULL, 0, 0);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    }
    while(area_wasnt_swaped);

    size_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite.get(&default_name, default_name_size, data_buf, data_buf_size, actual_len_bytes);

    TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
}

static void storagelite_stress_multiple_files_exceed_area()
{
    int status = STORAGELITE_SUCCESS;
    uint16_t i = 0;
    bool area_wasnt_swaped = false;
    
    do 
    {
        status = stlite.set( &default_name, i++, NULL, 0, 0);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    }
    while(area_wasnt_swaped);

    int number_of_files_in_area = i;

    size_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    i = 0;
    do
    {
        status = stlite.get(&default_name, i++, data_buf, data_buf_size, actual_len_bytes);
        TEST_ASSERT_EQUAL(STORAGELITE_SUCCESS, status);
    }
    while(i < number_of_files_in_area);
}

static void storagelite_stress_max_files_allowed()
{
    int status = STORAGELITE_SUCCESS;
    uint16_t i = 0;

    set_max_files();

    status = stlite.set(&default_name, i, NULL, 0, 0);
    TEST_ASSERT_EQUAL(STORAGELITE_MAX_FILES_REACHED, status);
}

static void storagelite_stress_max_files_set_remove_set()
{
    set_max_files();

    remove_max_files();

    set_max_files();
}

static void storagelite_stress_max_files_set_remove_get()
{
    int status = STORAGELITE_SUCCESS;
    uint16_t i = 0;

    set_max_files();

    remove_max_files();

    size_t actual_len_bytes = 0;
    uint8_t data_buf[data_buf_size] = {0};
    status = stlite.get(&default_name, i, data_buf, data_buf_size, actual_len_bytes);
    TEST_ASSERT_EQUAL(STORAGELITE_NOT_FOUND, status);
}

/*----------------setup------------------*/

utest::v1::status_t setup_init(const Case *const source, const size_t index_of_case, uint16_t max_bd_files)
{
    HeapBlockDevice bd(bd_size, bd_read_size, bd_prog_size, bd_erase_size);
    //StorageLite stlite;
    /*if (!stlite) {
        printf("no stlite!\n");
        return STATUS_ABORT;
    }*/
    printf("stlite addr = %p\n", stlite);
    if (stlite.init(&bd, max_bd_files) != STORAGELITE_SUCCESS) 
    {
        printf("no init!\n");
    }
    printf("finished init\n");
    return STATUS_CONTINUE;
}

utest::v1::status_t setup_handler(const Case *const source, const size_t index_of_case)
{
    return setup_init(source, index_of_case, STORAGELITE_MAX_FILES);
}

utest::v1::status_t tear_down_handler(const Case *const source, const size_t passed, const size_t failed, const failure_t reason)
{
    stlite.deinit();
    return STATUS_CONTINUE;
}

utest::v1::status_t max_files_setup_handler(const Case *const source, const size_t index_of_case)
{
    return setup_init(source, index_of_case, max_files);
}

utest::v1::status_t failure_handler(const Case *const source, const failure_t reason)
{
    greentea_case_failure_abort_handler(source, reason);
    return STATUS_CONTINUE;
}

Case cases[] = {
    Case("storagelite_stress_single_file_exceed_area", 
         setup_handler, storagelite_stress_single_file_exceed_area, tear_down_handler, failure_handler),
    Case("storagelite_stress_multiple_files_exceed_area", 
         setup_handler, storagelite_stress_multiple_files_exceed_area, tear_down_handler, failure_handler),
    Case("storagelite_stress_max_files_allowed", 
         max_files_setup_handler, storagelite_stress_max_files_allowed, tear_down_handler, failure_handler),
    Case("storagelite_stress_max_files_set_remove_set", 
         max_files_setup_handler, storagelite_stress_max_files_set_remove_set, tear_down_handler, failure_handler),
    Case("storagelite_stress_max_files_set_remove_get", 
         max_files_setup_handler, storagelite_stress_max_files_set_remove_get, tear_down_handler, failure_handler),
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
