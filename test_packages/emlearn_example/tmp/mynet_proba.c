
        #include "mynet_proba.h"
        #include <eml_test.h>

        #define N_CLASSES 10
        float outputs[N_CLASSES] = {0.0};

        static void classify_proba(const float *values, int length, int row) {
            eml_net_predict_proba(&mynet, values, length, outputs, 10); // TODO: handle error
            for (int class_no=0; class_no<N_CLASSES; class_no++) {
                const float prob = outputs[class_no];
                printf("%d,%d,%f\n", row, class_no, (double)prob);
            }
        }
        int main() {
            eml_test_read_csv(stdin, classify_proba);
        }
        