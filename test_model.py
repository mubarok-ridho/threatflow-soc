# test_model.py — taruh di root project
import numpy as np
import joblib
from tensorflow import keras

save_dir = 'models/'
scaler  = joblib.load(save_dir + 'scaler.pkl')
cnn     = keras.models.load_model(save_dir + 'cnn_model.keras')
resnet  = keras.models.load_model(save_dir + 'resnet_best.keras')

# Test dengan data dummy — semua nilai 0.5 (tengah-tengah)
arr = np.full((1, 36), 0.5)  # sudah scaled manual
print(f"Input: {arr}")

cnn_out    = cnn.predict(arr.reshape(1, 36, 1), verbose=0)
resnet_out = resnet.predict(arr, verbose=0)

print(f"CNN output    : {cnn_out}")
print(f"ResNet output : {resnet_out}")

# Test dengan data semua 0
arr_zero = np.zeros((1, 36))
cnn_zero    = cnn.predict(arr_zero.reshape(1, 36, 1), verbose=0)
resnet_zero = resnet.predict(arr_zero, verbose=0)
print(f"\nAll zeros:")
print(f"CNN output    : {cnn_zero}")
print(f"ResNet output : {resnet_zero}")

# Test dengan data semua 1
arr_one = np.ones((1, 36))
cnn_one    = cnn.predict(arr_one.reshape(1, 36, 1), verbose=0)
resnet_one = resnet.predict(arr_one, verbose=0)
print(f"\nAll ones:")
print(f"CNN output    : {cnn_one}")
print(f"ResNet output : {resnet_one}")