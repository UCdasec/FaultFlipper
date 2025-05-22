from sklearn.datasets import load_digits, fetch_olivetti_faces
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, f1_score

import emlearn
from pathlib import Path

import numpy as np
from PIL import Image

def tree_structure_stats(dt):
    n_nodes   = dt.tree_.node_count
    n_leaves  = dt.tree_.n_leaves
    max_depth = dt.tree_.max_depth
    return n_nodes, n_leaves, max_depth

def mlp_param_count(mlp):
    return sum(w.size + b.size for w, b in zip(mlp.coefs_, mlp.intercepts_))

def convert_model(model, out_file:Path, model_name):
    cmodel = emlearn.convert(model, dtype='float')
    code = cmodel.save(file=str(out_file.absolute()), name=model_name)
    return cmodel


def digit_model_dt(X_train, y_train):
    dt = DecisionTreeClassifier(max_depth=8, random_state=0).fit(X_train, y_train)
    convert_model(dt, Path("generated_models/digit_dt_model.h"), "digit_dt")
    print(f"Saved digit_dt_model.h")
    return  dt
    
def digit_model_mlp(X_train, y_train):
    """
    Train a mlp with 50 hidden units to classiyy faces 
    and convert to c file with emlearn
    """

    mlp = MLPClassifier(hidden_layer_sizes=(50,), max_iter=500, random_state=0).fit(X_train, y_train)
    convert_model(mlp, Path("generated_models/digit_mlp_model.h"), "digit_mlp")
    print(f"Saved mlp_model.h")

    return mlp

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
    image_dir = Path("image_dir")
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

    # These should show data between 0 and 255
    print(f"Min u8 face: {Xf_train_u8.min()}")
    print(f"Max u8 face: {Xf_train_u8.max()}")

    # BUT... to actually train / test the model we need data between 0 and 1 
    Xq_train = Xf_train_u8.astype(cur_type) / 255.0
    Xq_test = Xf_test_u8.astype(cur_type) / 255.0

    # This should be between 0 and 1
    print(f"Min u8->float32 face: {Xq_train.min()}")
    print(f"Max u8->float32 face: {Xq_test.max()}")

    # Load data - digit
    Xd, yd = load_digits(return_X_y=True)
    Xd_train, Xd_test, yd_train, yd_test = train_test_split(
        Xd, yd, test_size=0.2, random_state=0)

    print(f"Digits type: {Xd.dtype}")
    print(f"Digits min: {Xd.min()}")
    print(f"Digits max: {Xd.max()}")
    print(Xd[0])

    
    # Save splits -face - save the 0 to 255 version
    save_images(Xf_test_u8, yf_test, image_dir.joinpath('test/faces'), (64,64))
    save_images(Xf_train_u8, yf_train, image_dir.joinpath('train/faces'), (64,64))

    # Save splits - digit 
    save_images(Xd_test, yd_test, image_dir.joinpath('test/digits'), (8,8))
    save_images(Xd_train, yd_train, image_dir.joinpath('train/digits'), (8,8))

    # Face - mlp
    print(f"Xq_test shape: {Xq_test.shape}")
    mlp_face, cmodel = face_model_mlp(Xq_train, yf_train)
    y_pred = mlp_face.predict(Xq_test)          # shape (n_samples,)
    acc  = accuracy_score(yf_test, y_pred)
    f1   = f1_score(yf_test, y_pred, average='weighted')   # multi-class friendly
    print(f"[FACE - MLP]: Accuracy: {acc}")
    print(f"[FACE - MLP]: F1 {f1}")


    params = mlp_param_count(mlp_face)
    print(f"The mlp face has {params} parameters")

    # Digit - mlp
    clf = digit_model_mlp(Xd_train, yd_train)

    y_pred = clf.predict(Xd_test)          # shape (n_samples,)
    acc  = accuracy_score(yd_test, y_pred)
    f1   = f1_score(yd_test, y_pred, average='weighted')   # multi-class friendly
    print(f"[DIGIT - MLP]: Accuracy: {acc}")
    print(f"[DIGIT - MLP]: F1 {f1}")

    params = mlp_param_count(clf)
    print(f"The mlp digits has {params} parameters")

    # Digit - dt
    dt_dig= digit_model_dt(Xd_train, yd_train)
    y_pred = dt_dig.predict(Xd_test)          # shape (n_samples,)
    acc  = accuracy_score(yd_test, y_pred)
    f1   = f1_score(yd_test, y_pred, average='weighted')   # multi-class friendly
    print(f"[DIGIT - DT]: Accuracy: {acc}")
    print(f"[DIGIT - DT]: F1 {f1}")
    print(f"DIGIT - DT]: Corerct: {(y_pred==yd_test).sum()}")

    nodes, leaves, md = tree_structure_stats(dt_dig)
    print(f"n_nodes  : {nodes}") 
    print(f"n_leaves : {leaves}")  
    print(f"max_depth: {md}")  


    # At this point we have trained and saved 3 models, and tested
    # The python version of them

    # Face - dt
    #face_model_dt(Xf_train_u8, yf)

