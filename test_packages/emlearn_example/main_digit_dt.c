//#include <stdio.h>
//#include <stdlib.h>
//#include <stdint.h>
//#define STB_IMAGE_IMPLEMENTATION
//#include "stb_image.h"
//
////#include "export_raw/model_digits/model.h"
////#include "export_raw/model_faces/model.h"
//
//#include "digit_dt_model.h"
//
///* Buffer large enough for 64×64 = 4096 floats */
//static float feats[4096];
//
//int main(int argc, char **argv)
//{
//    // Read inpts
//    if (argc != 2) {
//        fprintf(stderr, "usage: %s <img.png>\n", argv[0]);
//        return 1;
//    }
//
//    // Load the image
//    int w,h,c;
//    uint8_t *pix = stbi_load(argv[1], &w, &h, &c, 1);
//    if (!pix) { fputs(stbi_failure_reason(), stderr); return 1; }
//
//    int pred = -1;
//
//    // Fill in array from image
//    for (int i=0;i<64;++i) feats[i] = (float)pix[i];      // 0-16
//
//    // Predict
//    pred = digit_dt_predict(feats, 64);
//    printf("PREDICTION: %d\n", pred);
//
//    stbi_image_free(pix);
//    return 0;
//}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

//#include "export_raw/model_digits/model.h"
//k#include "export_raw/model_faces/model.h"
#include "digit_dt_model.h"

/* Buffer large enough for 64×64 = 4096 floats */
static float feats[4096];

int prediction(uint8_t pix[]){
	
    int label = -1;
    for (int i=0;i<64;++i){
    	feats[i] = (float)pix[i];      // 0-16
    }
    label = digit_dt_predict(feats, 64);

	return label; 
}

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
    pred = prediction(pix);
    printf("PREDICTION: %d\n", pred);
	
    stbi_image_free(pix);
    return 0;
}

