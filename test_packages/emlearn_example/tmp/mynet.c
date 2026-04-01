
        #include "mynet.h"
        #include <eml_test.h>

        static void classify(const float *values, int length, int row) {
            printf("%d,%f\n", row, (double)eml_net_predict(&mynet, values, length));
        }
        int main() {
            eml_test_read_csv(stdin, classify);
        }
        