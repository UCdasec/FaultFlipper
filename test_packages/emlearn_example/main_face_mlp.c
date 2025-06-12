#include <stdio.h>
#include <stdint.h>
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include "face_mlp_model.h"

static float feats[4096];

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <img.png>\n", argv[0]);
        return 1;
    }

    int w,h,c;
    uint8_t *pix = stbi_load(argv[1], &w, &h, &c, 1);
    if (!pix) { 
        fputs(stbi_failure_reason(), stderr); 
        printf("FILE READ ERRPR");
        return 1; 
    }

    int pred = -1;
    for (int i=0;i<4096;++i) {
        feats[i] = (float)pix[i] * 0.0039215686f;;    // divide by 255 to get between 0 and 1
    }
    pred = face_mlp_predict(feats, 4096);
    printf("PREDICTION: %d\n", pred);

    stbi_image_free(pix);
    return 0;
}

