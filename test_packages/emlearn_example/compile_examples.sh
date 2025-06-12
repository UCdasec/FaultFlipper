gcc main_digit_mlp.c -o digit_mlp_x86.o -I generated_models -I../emlearn/emlearn -lm -static -O2 -ffp-contract=off -fno-fast-math -fsingle-precision-constant -frounding-math -std=c99 -lm 
