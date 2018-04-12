# mbed-os-example-storagelite

StorageLite example for Mbed OS

## Getting started with StorageLite ##

This is the test set of the StorageLite APIs.

The application invokes the StorageLite APIs and prints the results after each such invocation. 

## Required hardware
StorageLite is an solution for persistent memory, we will use K82F in our example:
### external built in flash driver
* An [FRDM-K82F](http://os.mbed.com/platforms/FRDM-K82F/) development board (using SPI Flash Driver)
* A micro-USB cable.

### Other hardware
Although the board in the example is K82F, the example should work on any Mbed enabled hardware supporting external flash driver (through built in memory).

##  Getting started ##

 1. Import the repository.

    ```
    mbed import mbed-os-example-storagelite
    cd mbed-os-example-storagelite
    ```

 2. Copy main.cpp to the root folder (mbed-os-example-storagelite).

 3. Deploy mbed os (needs to be done once).

    ```
    mbed deploy
    ```

 4. Deploy mbed os (needs to be done once).

    ```
    mbed deploy
    ```

 5. Compile and generate binary.

    for `K82F` with `GCC`:

    ```
    mbed compile -t GCC_ARM -m K82F
    ```
 6. Open a serial console session with the target platform using the following parameters:

    * **Baud rate:** 115200
    * **Data bits:** 8
    * **Stop bits:** 1
    * **Parity:** None

 7. Copy the application `mbed-os-example-nvstore.bin` in the folder `mbed-os-example-storagelite/BUILD/<TARGET NAME>/<PLATFORM NAME>` onto the target board.

 8. Press the **RESET** button on the board to run the program

 9. The serial console should now display a series of results following the StoragLite API invocations. 
 
## Troubleshooting

If you have problems, you can review the [documentation](https://os.mbed.com/docs/latest/tutorials/debugging.html) for suggestions on what could be wrong and how to fix it.
