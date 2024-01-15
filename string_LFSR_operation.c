#include <stdio.h>
#include <stdlib.h>
#include <string.h>



// Global variables to store my keyValues for decryption and the XOR results in an array
unsigned int* keyValues;
unsigned int* xorResultArray;



// Function prototypes
unsigned char* Crypt(unsigned char *data, int dataLength, unsigned int initialValue);
unsigned char* DeCrypt(int dataLength);



/**
 * @brief Main function to run the program
 * 
 * @param argc the number of arguments passed to the program
 * @param argv the arguments passed to the program
 *
 * @return 0 if the program runs successfully
 */
int main(int argc, char** argv){


    unsigned char* inputData;

    // Checking for argument data to make sure the program has an input string
    if (argc != 2){
        printf("This program requires a string argument\nPlease restart the program as follows: ./string_LFSR_operation <InputString>\n");
        exit(1);
    }

    inputData = (unsigned char*)argv[1];

    // I am hardcoding an intial value
    unsigned long int initialValue = 0x478e29a4;

    // Using strlen() to get the number of bytes/chars
    int dataLength = strlen((const char*)inputData);

    // Because I am implementing a DeCrypt function and I want to just save the key values
    // from the Crypt function, I am going to create a global variable to hold
    // the keys
    // -----------------
    keyValues = (unsigned int*)malloc(sizeof(unsigned int) * dataLength);
    xorResultArray = (unsigned int*)malloc(sizeof(unsigned int) * dataLength);
    // -----------------


    // Calling the Crypt function now
    unsigned char* retVal = Crypt(inputData, dataLength, initialValue);

    printf("The encoded string: %s\n", retVal); // printing the encoded string
    printf("This is using an initial value of 0x%08lX\n", initialValue); // printing the initial value used for the LFSR

    // Below is additional code to decrypt the string
    // ---------------------

    // In this case I know that if my length is 4 for example
    // 0x12 that this is one byte of data. I need to therefore
    // divide the length by 4 to get the number of bytes
    int dataLength2 = strlen((const char*)retVal) / 4;

    // Calling the DeCrypt function now
    unsigned char* originalString = DeCrypt(dataLength2);

    printf("\n%s\n", originalString); // printing the decoded string to stdout

    // ---------------------

    // freeing the data in the heap
    free(retVal); // this is the malloced cipher array 
    free(keyValues);
    free(xorResultArray);
    free(originalString);

    return 0;
}



/**
 * @brief Crypt function perform a LFSR operation on the input data to encrypt.
 * 
 * @param data the string to be encrypted
 * @param dataLength the length of the data variable
 * @param initialValue the state of the LFSR used for encryption calculations
 *
 * @return the encrypted data 
 */
unsigned char* Crypt(unsigned char *data, int dataLength, unsigned int initialValue){

    unsigned long int feedbackValue = 0x7fe00ae3;

    int offsetAdjust = 0; // This is for the outter for loop and index for the char* data

    // I am multiplying dataLength by 4 because cipher is a char array and my hex values have 2 leading chars \x followed by
    // the two chars for the hex byte
    // Example "\xCD" is one byte  which represents an encrypted input letter but is 4 chars in length
    unsigned char* cipher = (unsigned char *)malloc(sizeof(char) * ((dataLength * 4) + 1));

    // This outter loop will run for as many loops as the length of the string
    // I am incrementing i + 4 here because I only want this to run the number of loops as the length of the data
    for (int i = 0; i < (dataLength * 4); i += 4){

        // Stepping the LFSR 8 times to find the key
        // This inner for loop is calculating the the key to use for the single data index
        for (int j = 0; j < 8; j++){

            // When I use the bitwise & operator with 1 I can determine if the lowest order bit is a 1 or 0
            unsigned long int lowBit = initialValue & 1;

            if (lowBit) { // if this returns true then I perform the bitshift and XOR

                initialValue = (initialValue >> 1) ^ feedbackValue;

            } else if(!lowBit){ // if this returns false then I just perform the bitshift

                initialValue = initialValue >> 1;

            }

            // At the end of this section when the inner for loop is completly done the lower order byte will have the key
            // initialValue will already be overwritten to calculate the next key
        }

        // Storing the keyValue
        keyValues[offsetAdjust] = initialValue & 0xFF;

        // At this point I have my first key value so I must now XOR this value with the offsetAdjust index of my input string
        // The key is the lower ordered byte of the variable initialValue
        unsigned int xorResult = (initialValue & 0xFF) ^ data[offsetAdjust];

        // Storing the XOR result in an array to help with decryption
        xorResultArray[offsetAdjust] = xorResult;

        // Adding the result to my cipher string
        // I am using the ith index for cipher, this is why I needed the offsetAdjust variable and i to be different values
        sprintf((char *)&cipher[i], "\\x%02X", xorResult);


        // I need this to get the correct index of the unsigned char* data
        if(!(i % 4)){ // if i is evenly divisable by 4 increment the offsetAdjust
            offsetAdjust++;
        }
    }

    // Finally, adding the null terminator to the string
    cipher[(dataLength * 4)] = '\0';

    printf("\nThe feedback value used for the LFSR is: 0x%08lX\n", feedbackValue); // printing the feedback value used for the LFSR

    return cipher;
}



/**
 * @brief DeCrypt function performs a reverse LFSR operation on the input data to decrypt.
 *        keyValues are stored from the Crypt function in order to ease the decryption process.
 *        xorResultArray is also stored from the Crypt function in order to ease the decryption process.
 * 
 * @param dataLength the length of the data variable
 *
 * @return the decrypted data
 */
unsigned char* DeCrypt(int dataLength){

    // I was having an issue converting the string containing the \x chars and parsing the
    // actual hex values back into a string.
    // Instead I decided to store the xor results from the Crypt function in an array

    // I am then using the stored key values and the xor results to perform the decryption

    unsigned char* newString = (unsigned char*)malloc(sizeof(char) * (dataLength + 1));

    for(int i = 0; i < dataLength; i++){

        newString[i] = xorResultArray[i] ^ keyValues[i];    
    }

    return newString;

}