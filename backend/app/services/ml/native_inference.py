import numpy as np
import h5py

def relu(x):
    return np.maximum(0, x)

def sigmoid(x):
    # Clip to prevent overflow
    x = np.clip(x, -500, 500)
    return 1 / (1 + np.exp(-x))

class NativeAutoencoder:
    def __init__(self, h5_path):
        self.weights = []
        with h5py.File(h5_path, 'r') as f:
            mw = f['model_weights']
            layer_names = [k for k in mw.keys() if 'dense' in k]
            layer_names.sort(key=lambda x: int(x.split('_')[-1]) if '_' in x else 0)
            
            for name in layer_names:
                g = mw[name][name]
                w = g['kernel'][()]
                b = g['bias'][()]
                self.weights.append((w, b))
                
    def predict(self, X):
        out = X
        for w, b in self.weights[:-1]:
            out = relu(np.dot(out, w) + b)
        w, b = self.weights[-1]
        out = sigmoid(np.dot(out, w) + b)
        return out

class NativeLSTM:
    def __init__(self, h5_path):
        self.layers = []
        with h5py.File(h5_path, 'r') as f:
            mw = f['model_weights']
            
            lg = mw['lstm']['sequential']['lstm']['lstm_cell']
            self.lstm1 = (lg['kernel'][()], lg['recurrent_kernel'][()], lg['bias'][()])
            
            lg2 = mw['lstm_1']['sequential']['lstm_1']['lstm_cell']
            self.lstm2 = (lg2['kernel'][()], lg2['recurrent_kernel'][()], lg2['bias'][()])
            
            dg = mw['dense']['sequential']['dense']
            self.dense1 = (dg['kernel'][()], dg['bias'][()])
            
            dg2 = mw['dense_1']['sequential']['dense_1']
            self.dense2 = (dg2['kernel'][()], dg2['bias'][()])

    def _lstm_step(self, x, h, c, w, rw, b, units):
        z = np.dot(x, w) + np.dot(h, rw) + b
        i = sigmoid(z[:, :units])
        f = sigmoid(z[:, units:2*units])
        c_hat = relu(z[:, 2*units:3*units])
        o = sigmoid(z[:, 3*units:])
        
        c = f * c + i * c_hat
        h = o * relu(c)
        return h, c
        
    def predict(self, X):
        x = X[:, 0, :]
        units1 = 128
        h1, c1 = np.zeros((x.shape[0], units1)), np.zeros((x.shape[0], units1))
        h1, c1 = self._lstm_step(x, h1, c1, self.lstm1[0], self.lstm1[1], self.lstm1[2], units1)
        
        units2 = 64
        h2, c2 = np.zeros((x.shape[0], units2)), np.zeros((x.shape[0], units2))
        h2, c2 = self._lstm_step(h1, h2, c2, self.lstm2[0], self.lstm2[1], self.lstm2[2], units2)
        
        d1 = relu(np.dot(h2, self.dense1[0]) + self.dense1[1])
        out = sigmoid(np.dot(d1, self.dense2[0]) + self.dense2[1])
        return out
