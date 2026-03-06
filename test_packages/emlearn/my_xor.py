
"""
XOR classification
===========================

A simple example for getting started with emlearn.

Will train a RandomForestClassifier model on a XOR dataset,
generate C code for this model using emlearn Python package,
load this model in C and make predictions using it.
"""

import subprocess
from sklearn.ensemble import RandomForestClassifier
import os.path
from pathlib import Path
import sklearn.metrics

import emlearn
import numpy
import pandas
import pandas as pd 
#kimport seaborn
#import matplotlib.pyplot as plt

try:
    # When executed as regular .py script
    here = os.path.dirname(__file__)
except NameError:
    # When executed as Jupyter notebook / Sphinx Gallery
    here = os.getcwd()

def make_noisy_xor(seed=42):
    #xx, yy = numpy.meshgrid(numpy.linspace(-3, 3, 500),
    #                     numpy.linspace(-3, 3, 500))

    rng = numpy.random.RandomState(seed)
    X = rng.randn(300, 2)
    y = numpy.logical_xor(X[:, 0] > 0, X[:, 1] > 0)

    # Add some noise
    flip = rng.randint(300, size=15)
    y[flip] = ~y[flip]

    #print(X.shape)
    df = pandas.DataFrame((X * 255).astype(numpy.int16))
    df['label'] = y
    #print(df.head())
    df['x'] = df[0]
    df['y'] = df[1]
    #df = pd.DataFrame({'x' : (X[:,0]*255).astype(numpy.int16),
    #                   'y' : (X[:,1]*255).astype(numpy.int16),
    #                   'label' : y,
    #                   })
    #print(df.head())
    return df

def dataset_split_random(data, val_size=0.25, test_size=0.25, random_state=3, column='split'):
    """
    Split DataFrame into 3 non-overlapping parts: train,val,test with specified proportions

    Returns a new DataFrame with the rows marked by the assigned split in @column
    """
    train_size = (1.0 - val_size - test_size)
    from sklearn.model_selection import train_test_split
    
    train_val_idx, test_idx = train_test_split(data.index, test_size=test_size, random_state=random_state)
    val_ratio = (val_size / (val_size+train_size))
    train_idx, val_idx = train_test_split(train_val_idx, test_size=val_ratio, random_state=random_state)


    train = data.loc[train_idx]
    val = data.loc[val_idx]
    test = data.loc[test_idx]

    #data = data.copy()
    #data.loc[train_idx, column] = 'train'
    #data.loc[val_idx, column] = 'val'
    #data.loc[test_idx, column] = 'test'

    return train, val, test

def train_model(dataset, seed=42):
    X_train = dataset.loc['train', [0, 1]]
    Y_train = dataset.loc['train', 'label']

    model = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=seed)
    model.fit(X_train, Y_train)

    return model



# %%
# Convert model to C using emlearn
# ---------------------------------
def convert_model(model):

    model_filename = os.path.join(here, 'xor_model.h')
    cmodel = emlearn.convert(model)
    code = cmodel.save(file=model_filename, name='xor')

    assert os.path.exists(model_filename)
    print(f"Generated {model_filename}")

def predict(bin_path, X, verbose=1):

    def predict_one(x):
        args = [ bin_path, str(x[0]), str(x[1]) ]
        out = subprocess.check_output(args)
        cls = int(out)
        #if verbose > 0:
        #    print(f"run xor in1={x[0]:+.2f} in2={x[1]:+.2f} out={cls} ")
        return cls

    y = [ predict_one(x) for x in numpy.array(X) ]
    return numpy.array(y)

def compile_model(out_dir: Path, inp: Path)->Path:
    """
    Compile the C model 
    """

    # Compile the xor.c example program
    include_dirs = [ emlearn.includedir ]

    bin_path = emlearn.common.compile_executable(str(inp.absolute()), str(out_dir.absolute()), include_dirs=include_dirs)

    return Path(bin_path)

def evaluate_model(bin_path:Path, test):

    # Make predictions on dataset
    X_test = test[['x','y']]
    Y_test = test[['label']]

    y_pred_c = predict(str(bin_path), X_test)

    f1_score_c = sklearn.metrics.f1_score(Y_test, y_pred_c)
    return f1_score_c

def experiment(inp_model:Path):
    """
    See if the inp fails to run, or if it's accuracy drops
    """
    expected_acc = 0.9677

    compiled_model_path = compile_model(Path('examples'), Path('xor.c'))
    acc = evaluate_model(compiled_model_path, dataset)

    print(f"{expected_acc-acc}")

    return

if __name__ == "__main__":

    data_path = Path('dataset.csv')
    if not data_path.exists():
        df = make_noisy_xor()
        df.to_csv(data_path, index=False)
    else:
        df= pd.read_csv(data_path)

    train, val, test = dataset_split_random(df, test_size=0.10)
    compiled_model_path = Path('xor_bin.bin').absolute()

    acc = evaluate_model(compiled_model_path, test)
    print(f"F1: {acc}")


