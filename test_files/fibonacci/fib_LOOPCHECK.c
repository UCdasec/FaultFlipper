#include <stdio.h>
int main(void) {
    // The number of iterations in fibonnaci to run
    int n = 20;

    // Run Fib

    // Handle simple edge cases upfront:
    if ((n == 0) || (n<0)) {
        return 0;
    }
    if (n == 1) {
        return 1;
    }

    unsigned long long prev = 0;
    unsigned long long curr = 1;
    unsigned long long next;
    
    // Run the loop
    int i =2;
    for (i; i <= n; i++) {
        next = prev + curr;
        prev = curr;
        curr = next;
    }

    // MITIGATION: Check that completed all iterations of the for loop
    if ( i != n+1) {
        printf("%d", i);
        printf("Early Exit Detected! Exiting Program");
        return 10;
    }

    // Print the results
    // The corret value for n = 20 is 
    printf("Fibonacci of %d is: %llu\n", n, curr);
    return 0;
}

