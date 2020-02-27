"""
FTPServer
"""

import sys
import os
PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, PATH)

if __name__ == '__main__':
    from core import main
    main.main()
