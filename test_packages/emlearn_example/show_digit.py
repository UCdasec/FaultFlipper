from sklearn.datasets import load_digits
import matplotlib.pyplot as plt
digits = load_digits()
print(digits.data.shape)
plt.gray()
plt.matshow(digits.images[1795])
plt.show()
