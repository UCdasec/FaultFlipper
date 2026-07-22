#include <stdio.h>
unsigned long long fib(int a ) {
    // The number of iterations in fibonnaci to run
    int n = a;

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
    if (curr == 6765 ){
        printf("[CORRECT] Fibonacci of %d is: %llu\n", n, curr);
    } else {
        printf("[INCORRECT] Fibonacci of %d is: %llu\n", n, curr);
    };


    return curr;
}


int main(){

    int a = 20;

    unsigned long long b = fib(a);

    return 0;

}
