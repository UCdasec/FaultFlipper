from sklearn.datasets import load_digits, fetch_olivetti_faces
from sklearn.preprocessing  import StandardScaler
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, f1_score

import emlearn
from pathlib import Path

import numpy as np
from PIL import Image

def convert_model(model, out_file:Path, model_name):
    cmodel = emlearn.convert(model, dtype='float')
    code = cmodel.save(file=str(out_file.absolute()), name=model_name)
    return 


def to_c_array(name, arr, dtype="float"):
    """Return a C declaration for a 2D (or 1D) array."""
    shape = arr.shape
    if arr.ndim == 2:
        rows, cols = shape
        flat = arr.flatten()
        lines = []
        for i in range(rows):
            row = flat[i*cols:(i+1)*cols]
            lines.append("    { " + ", ".join(f"{v:.6g}" for v in row) + " }")
        body = ",\n".join(lines)
        return f"static const {dtype} {name}[{rows}][{cols}] = {{\n{body}\n}};"
    elif arr.ndim == 1:
        body = ", ".join(f"{v:.6g}" for v in arr)
        return f"static const {dtype} {name}[{shape[0]}] = {{ {body} }};"
    else:
        raise ValueError("Only 1D or 2D arrays supported")


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
    convert_model(mlp, Path("generated_models/face_mlp_model.h"), "face_mlp")
    print(f"Saved face_mlp_model.h")

    return mlp


def save_images(imgs, lbls, dir:Path, size):
    """
    Save images to the given directory
    """
    dir.mkdir(exist_ok=True)
    for i, (flat, label) in enumerate(zip(imgs,lbls)):
        arr = (flat.reshape(size).astype(np.uint8))     # **no rescale**
        Image.fromarray(arr, mode="L").save(dir.joinpath(f"image{i:04d}_lbl_{label}.png"))
    print(f"Saved images to {dir}")
    return



if __name__ == "__main__":


    image_dir = Path("test_images")
    image_dir.mkdir(exist_ok=True)


    # Load data - Face
    Xf, yf = fetch_olivetti_faces(return_X_y=True, shuffle=False)

    print(f"Tpye of data: {Xf.dtype}")
    cur_type = np.float32
    Xf = Xf.astype(cur_type)

    Xf_train, Xf_test, yf_train, yf_test = train_test_split(
        Xf, yf, stratify=yf, test_size=0.2, random_state=0)

    # Scale the data to avoid overflow issues when training 
    # NOTICE - We 'learn' the scale from the training dataset 
    #           and apply the same scale to training and testing 
    #           This scaled version of the dataset is then saved
    #scaler = StandardScaler().fit(Xf_train.astype(np.float64))
    #scaler = StandardScaler().fit(Xf_train)
    #print(f"Min face: {Xf_train.min()}")
    #print(f"Max face: {Xf_train.max()}")
    #Xf_train = scaler.transform(Xf_train)
    #Xf_test= scaler.transform(Xf_test)

    print(f"Min face: {Xf_train.min()}")
    print(f"Max face: {Xf_train.max()}")

    # Normalize between 0 and 1 
    Xf_train = (Xf_train - Xf_train.min())/ (Xf_train.max() - Xf_train.min())
    Xf_test = (Xf_test - Xf_test.min())/ (Xf_test.max() - Xf_test.min())
    print(f"Min normed face: {Xf_train.min()}")
    print(f"Max normed face: {Xf_train.max()}")

    # Multiply by 255 to get the data into uint8 range, then when 
    # we load it in c we'll devide by 255.
    Xf_train_u8 = (Xf_train * 255).round().astype(np.uint8)
    Xf_test_u8 = (Xf_test * 255).round().astype(np.uint8)

    # Quantize the training data 
    # make its range 0 to 255, round and truncate to uint8 so its 8 bits. 
    # Then convert back to float and divide by 255... this is exactly how the 
    # c version will see the data
    Xq_train = Xf_train_u8.round().astype(np.uint8).astype(cur_type) / 255.0
    Xq_test = Xf_test_u8.round().astype(np.uint8).astype(cur_type) / 255.0


    # These should show data between 0 and 255
    print(f"Min u8 face: {Xf_train_u8.min()}")
    print(f"Max u8 face: {Xf_train_u8.max()}")

    print(f"Min Xq face: {Xq_train.min()}")
    print(f"Max Xq face: {Xq_train.max()}")

    # Load data - digit
    Xd, yd = load_digits(return_X_y=True)
    Xd_train, Xd_test, yd_train, yd_test = train_test_split(
        Xd, yd, test_size=0.2, random_state=0)

    
    # Save splits -face - save the 0 to 255 version
    save_images(Xf_test_u8, yd_test, image_dir.joinpath('faces'), (64,64))

    # Save splits - digit 
    save_images(Xd_test, yd_test, image_dir.joinpath('digits'), (8,8))

    # Face - mlp
    #mlp_face = face_model_mlp(Xf_train_u8, yf_train)
    # Train on the 0-1 norm data 

    #mlp_face = face_model_mlp(Xf_train, yf_train)
    mlp_face = face_model_mlp(Xq_train, yf_train)
    y_pred = mlp_face.predict(Xf_test)          # shape (n_samples,)
    acc  = accuracy_score(yf_test, y_pred)
    f1   = f1_score(yf_test, y_pred, average='weighted')   # multi-class friendly
    print(f"[FACE - MLP]: Accuracy: {acc}")
    print(f"[FACE - MLP]: F1 {f1}")
    y_pred = mlp_face.predict(Xq_test)          # shape (n_samples,)
    acc  = accuracy_score(yf_test, y_pred)
    f1   = f1_score(yf_test, y_pred, average='weighted')   # multi-class friendly
    print(f"[FACE - MLP Q]: Accuracy: {acc}")
    print(f"[FACE - MLP Q]: F1 {f1}")



    # Digit - mlp
    clf = digit_model_mlp(Xd_train, yd_train)

    y_pred = clf.predict(Xd_test)          # shape (n_samples,)
    acc  = accuracy_score(yd_test, y_pred)
    f1   = f1_score(yd_test, y_pred, average='weighted')   # multi-class friendly
    print(f"[DIGIT - MLP]: Accuracy: {acc}")
    print(f"[DIGIT - MLP]: F1 {f1}")


    # Digit - dt
    dt_dig= digit_model_dt(Xd_train, yd_train)
    y_pred = dt_dig.predict(Xd_test)          # shape (n_samples,)
    acc  = accuracy_score(yd_test, y_pred)
    f1   = f1_score(yd_test, y_pred, average='weighted')   # multi-class friendly
    print(f"[DIGIT - DT]: Accuracy: {acc}")
    print(f"[DIGIT - DT]: F1 {f1}")



    # At this point we have trained and saved 3 models, and tested
    # The python version of them

    # Face - dt
    #face_model_dt(Xf_train_u8, yf)

