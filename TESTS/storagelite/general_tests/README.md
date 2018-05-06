# mbed-os-example-storagelite

StorageLite general tests for Mbed OS

## Getting started with StorageLite general tests ##

This is the general tests of StorageLite APIs.

The application invokes the StorageLite APIs and prints the results after each such invocation. 

## Required hardware
These tests are performed on a flash memory adapter which simulate an external memory, we'll use K64F:
* An [FRDM-K64F](http://os.mbed.com/platforms/FRDM-K64F/) development board.
* A micro-USB cable.

### Other hardware
Although the board shown in this examples is K64F, the example should work on any Mbed enabled hardware supporting the internal flash driver (has "FLASH" in the "device_has" in targets/target.json file).

##  Getting started ##

 1. Import the repository.

    ```
    mbed import mbed-os-example-storagelite
    cd mbed-os-example-storagelite
    ```

 2. Copy main.cpp to the root folder (mbed-os-example-storagelite).

 3. Compile and generate binary.

    For example, for `GCC`:

    ```
    mbed compile -t GCC_ARM -m K64F
    ```
   
 4. Open a serial console session with the target platform using the following parameters:

    * **Baud rate:** 115200
    * **Data bits:** 8
    * **Stop bits:** 1
    * **Parity:** None

 5. Copy the application `mbed-os-example-storagelite.bin` in the folder `mbed-os-example-storagelite/BUILD/<TARGET NAME>/<PLATFORM NAME>` onto the target board.

 6. Press the **RESET** button on the board to run the program

 7. The serial console should now display a series of results following the StorageLite API invocations. 
 
## Troubleshooting

If you have problems, you can review the [documentation](https://os.mbed.com/docs/latest/tutorials/debugging.html) for suggestions on what could be wrong and how to fix it.