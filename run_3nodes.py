# -*- coding: utf-8 -*-
"""
Created on Thu Jul 25 11:43:22 2024

@author: toran
"""

import os
import platform


if platform.system() == 'Windows':
    for i in range(3):  # Open 3 separate terminal windows
        os.system(f"start cmd /k D:\COMP9337\Assignment\DIMY1.0.py 127.0.0.1 55000 {i}")

else:    
    for i in range(3):  # Open 3 separate terminal windows
        os.system(f'gnome-terminal -- python DIMY1.0.py 127.0.0.1 55000 {i} 12345')
