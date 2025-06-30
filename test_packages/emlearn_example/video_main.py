from sklearn.datasets import load_digits, fetch_olivetti_faces
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score

import emlearn
from pathlib import Path

import numpy as np
from PIL import Image


def convert_model(model, out_file:Path, model_name):

    cmodel = emlearn.convert(model, dtype='float')

    code = cmodel.save(file=str(out_file.absolute()), name=model_name)

    return cmodel

def face_model_mlp(X_train, y_train):
    """
    Train a model for the olivetta face dataset, and use emlearn 
    to save
    """

    print(f"X_train shape: {X_train.shape}")
    mlp =  MLPClassifier(
            hidden_layer_sizes=(60,),
            solver="adam",
            learning_rate_init=1e-4,
            max_iter=500,
            random_state=0
        )
    
    # Force numpy to ignore underflows
    with np.errstate(under='ignore'):
        mlp.fit(X_train, y_train) 


    cmodel = convert_model(mlp, Path("generated_models/face_mlp_model.h"), "face_mlp")

    print(f"Saved face_mlp_model.h")

    return mlp, cmodel


def save_images(imgs, lbls, dir:Path, size):
    """
    Save images to the given directory
    """
    dir.mkdir(exist_ok=True, parents=True)
    for i, (flat, label) in enumerate(zip(imgs,lbls)):
        arr = (flat.reshape(size).astype(np.uint8))     # **no rescale**
        Image.fromarray(arr, mode="L").save(dir.joinpath(f"image{i:04d}_lbl_{label}.png"))
    print(f"Saved images to {dir}")
    return



if __name__ == "__main__":

    # Make image directories
    image_dir = Path("image_dir_tmp")
    image_dir.mkdir(exist_ok=True)

    # Load data - Face
    Xf, yf = fetch_olivetti_faces(return_X_y=True, shuffle=False)

    # Force the type of hte data
    cur_type = np.float32
    Xf = Xf.astype(cur_type)

    Xf_train, Xf_test, yf_train, yf_test = train_test_split(
        Xf, yf, stratify=yf, test_size=0.2, random_state=0)

    # To save the data we need it clipped to unint8, so 0-255
    # Currently itse between 0 and 1, so multiple by 255 and clip 
    Xf_train_u8 = (Xf_train * 255).round().astype(np.uint8)
    Xf_test_u8 = (Xf_test * 255).round().astype(np.uint8)

    # BUT... to actually train / test the model we need data between 0 and 1 
    Xq_train = Xf_train_u8.astype(cur_type) / 255.0
    Xq_test = Xf_test_u8.astype(cur_type) / 255.0

    
    # Save splits -face - save the 0 to 255 version
    save_images(Xf_test_u8, yf_test, image_dir.joinpath('test/faces'), (64,64))
    save_images(Xf_train_u8, yf_train, image_dir.joinpath('train/faces'), (64,64))

    # Face - mlp
    mlp_face, cmodel = face_model_mlp(Xq_train, yf_train)
    y_pred = mlp_face.predict(Xq_test)          # shape (n_samples,)
    acc  = accuracy_score(yf_test, y_pred)
    f1   = f1_score(yf_test, y_pred, average='weighted')   # multi-class friendly
    print(f"[FACE - MLP]: Accuracy: {acc}")
    print(f"[FACE - MLP]: F1 {f1}")



