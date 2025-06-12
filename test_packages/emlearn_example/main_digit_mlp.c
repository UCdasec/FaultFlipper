/* main_raw.c  ------------------------------------------------------------
   gcc -O2 -std=c99 main_raw.c \
       export_raw/model_digits/model.c \
       export_raw/model_faces/model.c \
       -lm -o img_classifier_raw
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

//#include "export_raw/model_digits/model.h"
//k#include "export_raw/model_faces/model.h"
#include "digit_mlp_model.h"

/* Buffer large enough for 64×64 = 4096 floats */
static float feats[4096];

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <img.png>\n", argv[0]);
        return 1;
    }

    int w,h,c;
    uint8_t *pix = stbi_load(argv[1], &w, &h, &c, 1);
    if (!pix) { fputs(stbi_failure_reason(), stderr); return 1; }

    int pred = -1;
    for (int i=0;i<64;++i) feats[i] = (float)pix[i];      // 0-16
    pred = digit_mlp_predict(feats, 64);

    printf("PREDICTION: %d\n", pred);
    stbi_image_free(pix);
    return 0;
}

