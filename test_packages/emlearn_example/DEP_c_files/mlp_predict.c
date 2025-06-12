#include <stdio.h>
#include "mlp_model.h"     // from emlearn.export
#include "test_data.h" // your generated data

int main(void) {
    const int n_samples = sizeof(y_test) / sizeof(y_test[0]);
    int correct = 0;

    for (int i = 0; i < n_samples; ++i) {
        // emlearn’s C wrapper provides a predict function, e.g.:
        float *sample = (float*)X_test[i];   // pointer to the i-th feature vector
        int pred = mlp_predict(sample, 64);

        if (pred == y_test[i]) {
            ++correct;
        }
        printf(" Sample %3d: true=%d   pred=%d\n", i, y_test[i], pred);
    }

    printf("\nAccuracy: %.1f%% (%d/%d)\n",
           100.0f * correct / n_samples, correct, n_samples);
    return 0;
}

