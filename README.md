# ioc-parser-3
*This tool was forked from https://github.com/PaloAltoNetworks/ioc-parser and adapted to run with python3.* 


IOC Parser is a tool to extract indicators of compromise from security reports in PDF format. A good collection of APT related reports with many IOCs can be found here: [APTNotes](https://github.com/kbandla/APTnotes).

## Usage
**ioc-parser.py [-h] [-p INI] [-i FORMAT] [-o FORMAT] [-d] [-l LIB] FILE**
* *FILE* File/directory path to report(s)
* *-p INI* Pattern file
* *-i FORMAT* Input format (pdf/txt/html)
* *-o FORMAT* Output format (csv/json/yara/autofocus)
* *-d* Deduplicate matches
* *-l LIB* Parsing library

## Requirements
See `requirements.txt`