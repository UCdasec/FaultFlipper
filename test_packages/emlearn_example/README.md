# EMLEARN EXAMPLE 

In this example we train *two classifiers* on *two datasets* 
and convert all classifiers to *c implementations* and run 
inference using compiled binaries! 


# 1. Installation 

```bash
pip install emlearn
```

```bash
git clone https://github.com/emlearn/emlearn
```

# 2. Usage 

To train all classifiers, and generate corresponding c files with emlearn: 
```bash
python main.py
```


To compile a classifier:

Example for arm, with static linking (ARM32):
```bash
arm-linux-gnueabi-gcc main_face_mlp.c -o STATIC_face_mlp_arm32.o -Igenerated_models -I../emlearn/emlearn -lm  -static
```

To run the classifier on a single example (ARM32):
```bash
qemu-arm-static ./STATIC_face_mlp_arm32.o image_dir/test/faces/YOUR_CHOICE_HERE
```

To test a classifier on the whole dataset (ARM32):
```bash
python c_model_tester.py test-bin STATIC_face_mlp_arm32.o True image_dir/test/faces
```




