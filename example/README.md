# mbed-os-example-storagelite

StorageLite example for Mbed OS

## Getting started with StorageLite ##

This is an example of an application that uses the StorageLite APIs.

The application invokes the StorageLite APIs and prints the results after each such invocation. 

## Required hardware
StorageLite is an solution for persistent memory, this example focus on 2 different platforms:
### external built in flash driver
* An [FRDM-K82F](http://os.mbed.com/platforms/FRDM-K82F/) development board (using SPI Flash Driver)
* A micro-USB cable.
### external flash card (SD card)
* An [FRDM-K64F](http://os.mbed.com/platforms/FRDM-K64F/) development board.
* An SD card.
* A micro-USB cable.

### Other hardware

Although the boards shown in this examples are K64F and K82F, the example should work on any Mbed enabled hardware supporting external flash driver (through built in memory or an SD card).

##  Getting started ##

 1. Import the example.

    ```
    mbed import mbed-os-example-storagelite
    cd mbed-os-example-storagelite
    ```
   
 2. Keep the default StorageLite configuration, which uses the last two sectors (4KB each) as StorageLite areas.

 3. Compile and generate binary.

    For example, for `K64F` with `GCC`:

    ```
    mbed compile -t GCC_ARM -m K64F
    ```
   
   And for `K82F` with `GCC`:

    ```
    mbed compile -t GCC_ARM -m K82F
    ```
 4. Open a serial console session with the target platform using the following parameters:

    * **Baud rate:** 115200
    * **Data bits:** 8
    * **Stop bits:** 1
    * **Parity:** None

 5. Copy the application `mbed-os-example-nvstore.bin` in the folder `mbed-os-example-storagelite/BUILD/<TARGET NAME>/<PLATFORM NAME>` onto the target board.

 6. Press the **RESET** button on the board to run the program

 7. The serial console should now display a series of results following the StoragLite API invocations. 
 
## Troubleshooting

If you have problems, you can review the [documentation](https://os.mbed.com/docs/latest/tutorials/debugging.html) for suggestions on what could be wrong and how to fix it.
