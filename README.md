# ioc-parser-3
*This tool was forked from https://github.com/PaloAltoNetworks/ioc-parser and adapted to run with python3. No one should manually copy and paste IoCs from PDFs for the rest of their life.* 


IOC Parser is a tool to extract indicators of compromise from security reports in PDF format. A good collection of APT related reports with many IOCs can be found here: [APTNotes](https://github.com/kbandla/APTnotes).

## Installation
It is recommended to create a virtualenv, since the versions of the libraries are fixed within the `requirements.txt` file.  
```
python -m venv myvenv
source ./myvenv/bin/activate
```

Once you created the virtual environment, cd in the source of this project and install it with pip:
```
cd ./ioc-parser
pip install .
```
Note: untested on Windows.


## Usage
**iocparser [-h] [-p INI] [-i FORMAT] [-o FORMAT] [-d] [-l LIB] [-w DIR]  FILE**
* *FILE* File/directory path to report(s)
* *-p INI* (optional) Pattern file
* *-i FORMAT* (optional) Input format (pdf/txt/html)
* *-o FORMAT* (optional) Output format (csv/json/yara/autofocus)
* *-d* (optional) Deduplicate matches  
* *-l LIB* (optional) Parsing library (pypdf2/pdfminer)  
* *-w DIR* (optional) Directory containing the excluded patterns, in their respective .ini files


## Requirements
See `requirements.txt`