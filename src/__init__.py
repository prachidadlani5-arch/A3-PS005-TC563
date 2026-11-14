# Antigravity BGP Anomaly Monitor package
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import numpy as np
if not hasattr(np, "long"):
    np.long = np.int_
if not hasattr(np, "ulong"):
    np.ulong = np.uint
