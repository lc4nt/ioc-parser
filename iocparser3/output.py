import os
import sys
import csv
import json

OUTPUT_FORMATS = ('csv', 'json', 'yara', 'autofocus')

def getHandler(output_format):
    output_format = output_format.lower()
    if output_format not in OUTPUT_FORMATS:
        print("[WARNING] Invalid output format specified.. using CSV")
        output_format = 'csv'

    handler_format = "OutputHandler_" + output_format
    handler_class = getattr(sys.modules[__name__], handler_format)

    return handler_class()

class OutputHandler(object):
    def print_match(self, fpath, page, name, match, last = False):
        pass

    def print_header(self, fpath):
        pass

    def print_footer(self, fpath):
        pass

    def print_error(self, fpath, exception):
        print("[ERROR] %s" % (exception))

class OutputHandler_csv(OutputHandler):
    def __init__(self):
        self.csv_writer = csv.writer(sys.stdout, delimiter = '\t')

    def print_match(self, fpath, page, name, match):
        self.csv_writer.writerow((fpath, page, name, match))

    def print_error(self, fpath, exception):
        self.csv_writer.writerow((fpath, '0', 'error', exception))

class OutputHandler_json(OutputHandler):
    def print_match(self, fpath, page, name, match):
        data = {
            'path' : fpath,
            'file' : os.path.basename(fpath),
            'page' : page,
            'type' : name,
            'match': match
        }

        print(json.dumps(data))

    def print_error(self, fpath, exception):
        data = {
            'path'      : fpath,
            'file'      : os.path.basename(fpath),
            'type'      : 'error',
            'exception' : exception
        }

        print(json.dumps(data))

class OutputHandler_yara(OutputHandler):
    def __init__(self):
        self.rule_enc = ''.join(chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

    def print_match(self, fpath, page, name, match):
        if name in self.cnt:
            self.cnt[name] += 1
        else:
            self.cnt[name] = 1
        
        string_id = "$%s%d" % (name, self.cnt[name])
        self.sids.append(string_id)
        string_value = match.replace('\\', '\\\\')
        print("\t\t%s = \"%s\"" % (string_id, string_value))

    def print_header(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)

        print("rule %s" % (rule_name))
        print("{")
        print("\tstrings:")

        self.cnt = {}
        self.sids = []

    def print_footer(self, fpath):
        cond = ' or '.join(self.sids)

        print("\tcondition:")
        print("\t\t" + cond)
        print("}")

class OutputHandler_autofocus(OutputHandler):
    def __init__(self):
        self.rule_enc = ''.join(chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

    def print_match(self, fpath, page, name, match):
        string_value = match.replace('hxxp', 'http').replace('\\', '\\\\')

        if name == "MD5":
            auto_focus_query = '{"field":"sample.md5","operator":"is","value":\"%s\"},' % (string_value)
        elif name == "SHA1":
            auto_focus_query = '{"field":"sample.sha1","operator":"is","value":\"%s\"},' % (string_value)
        elif name == "SHA256":
            auto_focus_query = '{"field":"sample.sha256","operator":"is","value":\"%s\"},' % (string_value)
        elif name == "URL":
            auto_focus_query = '{"field":"sample.tasks.connection","operator":"contains","value":\"%s\"},' % (string_value)
        elif name == "Host":
            auto_focus_query = '{"field":"sample.tasks.dns","operator":"contains","value":\"%s\"},' % (string_value)
        elif name == "Registry":
            #auto_focus_query = '{"field":"sample.tasks.registry","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Filepath":
            #auto_focus_query = '{"field":"sample.tasks.file","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Filename":
            #auto_focus_query = '{"field":"alias.filename","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Email":
            #auto_focus_query = '{"field":"alias.email","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "IP":
            auto_focus_query = '{"field":"sample.tasks.connection","operator":"contains","value":\"%s\"},' % (string_value)
        elif name == "CVE":
            return
        print(auto_focus_query) 

    def print_header(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)

        print("AutoFocus Search for: %s" % (rule_name))
        print('{"operator":"Any","children":[')


    def print_footer(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)
        print('{"field":"sample.tag","operator":"is in the list","value":[\"%s\"]}]}' % (rule_name))



