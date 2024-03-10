#!/usr/bin/env python
"""
# SQLGO License - Version 1.1

Copyright (C) 2023-2024 Heisenberg

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.


"""
import os
import sys
import re
import random
import string
import glob
import os
import re
sys.path.append(os.getcwd())
from sqlmap.lib.core.common import setColor
from src.data import arg,config
from src.core.enums.enums import DBMS
import json



class _IOFileReader(object):
    def __init__(self, to_write, to_read):
        self.__os = os
        self.__sys = sys
        self._payload_dir = os.path.join(self.__os.getcwd(), "data", "payloads", "%s.txt"%to_read)
        self.__paylods_dir = os.path.join(self.__os.getcwd(), "data", "payloads", "%s.txt"%to_write)
        self.__regex = re
        self.__numeric_pattern = re.compile(r'\[RANDNUM\]|\[RANDNUM1\]|\[INFERENCE\]|\[RANDNUM2\]|\[SLEEPTIME\]')
        self.__string_pattern = re.compile(r'\[RANDSTR\]|\[RANDSTR1\]|\[GENERIC_SQL_COMMENT\]|\[ORIGVALUE\]|\[DELIMITER_START\]|\[QUERY\]')
        self.__string = string
        self.__files = [
            "error_boolean.txt"
        ]

    def __enter__(self):
        with open(self._payload_dir, "r") as file:
            content = file.read()
            if re.search(self.__numeric_pattern, content) or re.search(self.__string_pattern, content):
                content = re.sub(self.__numeric_pattern, lambda x: str(random.randint(0, 100)), content)
                content = re.sub(self.__string_pattern,
                                 lambda x: ''.join(random.choice(self.__string.ascii_letters + str(self.__string.digits)) for _ in range(len(x.group(0)))), content)
                return content
            else:
                return content

    def __exit__(self, exc_type, exc_value, exc_traceback):
        pass

    def replace(self):
        with open(self._payload_dir, "r") as file:
            content = file.read()
            if re.search(self.__numeric_pattern, content) or re.search(self.__string_pattern, content):
                for file_name in self.__files:
                    replaced_content = re.sub(self.__numeric_pattern, lambda x: str(random.randint(0, 100)), content)
                    replaced_content = re.sub(self.__string_pattern,
                                               lambda x: ''.join(
                                                   random.choice(self.__string.ascii_letters + str(self.__string.digits)) for _ in range(len(x.group(0)))), replaced_content)
                    with open(self.__paylods_dir, "w") as out_file:  # Open outside loop
                        lines = replaced_content.split(";")
                        out_file.write("\n".join(lines))
            return content



class IOFileReader(object):
    
    @classmethod
    def payload(cls,_file):   
        with open(os.getcwd()+"/data/payloads/"+_file, "r") as file: 
            payload = file.read() 
            rows = payload.split("\n") 
            sorted_rows = sorted(rows) 
            sorted_payload = "\n".join(sorted_rows) 
            return sorted_payload
    @classmethod
    def generic(cls,path):
        with open(os.getcwd()+path, "r") as file: 
            payload = file.read() 
            rows = payload.split("\n") 
            sorted_rows = sorted(rows) 
            sorted_payload = "\n".join(sorted_rows) 
            return sorted_payload



def _listTamperingFunctions():
    """
    Lists available tamper functions
    """

    infoMsg = "listing available tamper scripts\n"
    print(infoMsg)

    for script in sorted(glob.glob(os.path.join(os.getcwd(), "tampers", "*.py"))):
        with open(script, "r") as file:
            content = file.read()
            match = re.search(r'(?s).+"""(.+)"""', content)
            if match:
                comment = match.group(1).strip()
                print("* %s - %s\n" % (setColor(os.path.basename(script), "yellow"), re.sub(r" *\n *", " ", comment.split("\n\n")[0].strip())))

def read_input(msg, default=None, boolean=False,options=[]):
    """
    A function to read input from the stream.
    *Note:first option of the list the the default value 
    """
    if not options:
        options = ["y", "n"]
    retVal = None
    if arg.batch:
        retVal = default
        return True

    if default is not None:
        msg += " [%s/%s]" % (default[0].upper()+default[1:] or options[0],options[1])

    while retVal is None:
        retVal = input(msg).strip().lower()

        if retVal == '' and default is not None:
            retVal = default
        elif retVal == '0' and boolean:
            retVal = False
        elif retVal == '1' and boolean:
            retVal = True
        elif retVal == options[0] or retVal == default:
            retVal = True
        elif retVal == options[1]:
            retVal = False

        try:
            if boolean:
                retVal = bool(int(retVal))
            else:
                retVal = int(retVal)

        except ValueError:
            pass

    return retVal

def whatDbms(response):
    try:
        dbmsVars = vars(DBMS)
        for dbmsVar in dbmsVars.values():
            if re.search(dbmsVar, response, re.IGNORECASE):
                return dbmsVar
    
    except TypeError:
        return
        


def exportCsv(**kwargs):
    keys = list(kwargs.keys())
    values = list(kwargs.values())
    result = [keys]  
    result.append(values)  
    return result
x = exportCsv(a=1, b=2, c=3)
print(x)