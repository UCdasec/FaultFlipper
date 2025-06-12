#include <stdio.h>
#include <stdlib.h>
#include "dt_model.h"     // from emlearn.export
#include "test_data.h" // your generated data
//
// Number of features (load_digits is 8×8=64)
#define N_FEATURES 64

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <test_index>\n", argv[0]);
        return 1;
    }

    // parse the requested index
    char *end;
    long idx = strtol(argv[1], &end, 10);
    if (*end != '\0' || idx < 0) {
        fprintf(stderr, "Invalid index: %s\n", argv[1]);
        return 1;
    }

    const int n_samples = sizeof(y_test) / sizeof(y_test[0]);
    if (idx >= n_samples) {
        fprintf(stderr, "Index out of range (0–%d)\n", n_samples-1);
        return 1;
    }

    // pick the sample
    const float *sample = X_test[idx];
    int true_label = y_test[idx];

    // run prediction
    int pred = dt_predict(sample, N_FEATURES);

    // report
    if (pred == true_label) {
        printf("IDX %ld | LABEL %d | PREDICTION %d | CORRECT\n", idx, true_label, pred);
    }
    else {
        printf("IDX %ld | LABEL %d | PREDICTION %d | WRONG\n", idx, true_label, pred);
    }

    return 0;
}
