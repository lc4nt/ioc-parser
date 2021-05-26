import os
import re
from pathlib import Path

class WhiteList(dict):
    def __init__(self, basedir):
        base = basedir
        if basedir == "":
            base = Path(__file__) / "res" / "whitelists"

        for fpath in base.iterdir():
            t = os.path.splitext(str(fpath))[0].split('_',1)[1]
            patterns = [line.strip() for line in open(fpath)]
            self[t]  = [re.compile(p) for p in patterns]
