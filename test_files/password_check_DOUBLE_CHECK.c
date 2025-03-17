#include <stdio.h>
#include <stdlib.h>  // Required for the exit() function
#include <stdbool.h> 
#include <string.h>
// Below provides "EXIT_SUCCESS"
#include <stdbool.h>
#include <stdint.h>

// Correct password:
#define PASSWORD "pass" 

// Password input max length:
#define MAX_LENGTH 10

/*
* int main
*   A sample program to that has a user enter a password and sees if it's correct
*/
int main() {

    // Buffer to store user input (extra byte for null terminator)
    char input[MAX_LENGTH + 1];  
    printf("Enter the password (max %d characters): ", MAX_LENGTH);

    uint8_t password_correct = 0;

    // fgets takes arguments: (buffer, buffer_size, input) 
    // this assures that the input is no longer than the size of the buffer
    if (fgets(input, sizeof(input), stdin) != NULL) {
        // If the entered password exceeds the 
        // buffer it's incorrect
        if (strchr(input, '\n') == NULL) {
            password_correct = 0;
        }
        else {
            // Remove the newling character
            input[strcspn(input, "\n")] = '\0';

            // NOTICE: fgets and strchr make sure the passowrd
            //      is the correct length so strcmp is safe :)
            if (strcmp(input, PASSWORD) == 0) {
                password_correct = 1;
            }
        }
    }
    else {
        printf("no input");
    }


    // Compare the input with the predefined password
    if (password_correct == 1){

        // DOUBLE CHECK
        if ( ((~password_correct) & 0x01) != 0){
            printf("Fault detected \n");
            return 97;
        };

        // Exit with 0 when exit is correct!
        printf("Correct\n");
        return EXIT_SUCCESS;
    } else {
        printf("Wrong\n");
        return 97;
    }

    return 84;
}

