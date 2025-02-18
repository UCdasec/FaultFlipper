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
    for (int i = 2; i <= n; i++) {
        next = prev + curr;
        prev = curr;
        curr = next;
    }

    // Print the results 6765
    printf("Fibonacci of %d is: %llu\n", n, curr);
    return 0;
}

