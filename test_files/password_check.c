#include <stdio.h>
#include <stdlib.h>  // Required for the exit() function
#include <stdbool.h> 
#include <string.h>
// Below provides "EXIT_SUCCESS"
#include <stdbool.h>

// Correct password:
#define PASSWORD "pass" 

// Password input max length:
#define MAX_LENGTH 10

/*
* int main
*   A sample program to that has a user enter a password and sees if it's correct
*/
bool password_check(char input[]) {
    bool flag = false;
    if (strncmp(input, PASSWORD, MAX_LENGTH) == 0) {
        flag = true;
    }
    return flag;
}

int main(){
    // Buffer to store user input (extra byte for null terminator)
    char input[MAX_LENGTH + 1];  
    printf("Enter the password (max %d characters): ", MAX_LENGTH);

    bool flag = false;

    // fgets takes arguments: (buffer, buffer_size, input) 
    // this assures that the input is no longer than the size of the buffer
    if (fgets(input, sizeof(input), stdin) != NULL) {
        // If the entered password exceeds the 
        // buffer it's incorrect
        if (strchr(input, '\n') == NULL) {
            flag = false;
        }
        else {
            // Remove the newling character
            input[strcspn(input, "\n")] = '\0';
        };
        flag = password_check(input);
    };

    // Compare the input with the predefined password
    if (flag == 1)  {
        printf("Correct\n");
        return EXIT_SUCCESS;
    } else {
        printf("Wrong\n");
        return 97;
    }

    return 84;



}
