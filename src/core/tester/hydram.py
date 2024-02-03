from sqlmap.lib.core.data import conf,kb
from src.core.parser.cmdline import dbms
from src.logger.log import logger
from src.core.Exceptions.exceptions import SQLGOFilePathException
from src.core.parser.cmdline import url
from src.core.parser.cmdline import user_file
from src.core.parser.cmdline import pass_file
from src.core.parser.cmdline import hydra
from urllib.parse import urlparse
from utilis.readfile import ReadFile
import os
import sys
import platform
import subprocess


__tool__ = "hydra"

class Hydra(object):
    def __init__(self):
        try:
            self.userfile = user_file
            self.passfile = pass_file
            self.host = urlparse(url).hostname
            self.dbms = conf.dbms or dbms or "mysql"
            self.mysql_scheme = "mysql://"
            self.hydra_command = f"hydra -l {self.userfile} -p {self.passfile} {self.mysql_scheme}{self.host}"

        
        except AttributeError:
            self.userfile = user_file
            self.passfile = pass_file
            self.host = urlparse(url).hostname
            self.dbms = dbms
            self.mysql_scheme = "mysql://"
            self.hydra_command = f"hydra -l {self.userfile} -p {self.passfile} {self.mysql_scheme}{self.host}"
    
    def _check_hydra(self):
        try:
            command = os.system(__tool__)
            if "Hydra" in str(command):
                logger.info("hydra installed on your system!")
                return True
        except Exception as ex:
            logger.error("Error occurred: %s"%ex)
        
    
    def _check_file_paths(self):
        if not os.path.exists(self.userfile) or not os.path.exists(self.passfile):
            errMsg = "the provided file paths '%s' and '%s' do not exist" % (self.userfile, self.passfile)
            logger.error(errMsg)
            raise SQLGOFilePathException(errMsg)
        else:
            return True
    
    def run_hydra(self):
        if self._check_file_paths():
            os.system(self.hydra_command)
    

    






            
hydra_handler = Hydra()