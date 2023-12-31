import argparse
import os
import sys
sys.path.append(os.getcwd())
import extra.version

class Cmdline(argparse.ArgumentParser):
    def __init__(self):
        super().__init__(description="sqlgo")

        self.add_argument("-o", "--output", help="Get output file as result",required=False)
        self.add_argument("--verbose", action="store", help="Enable verbose mode and set the range of(default is 1)",type=int,required=False,default=1)
        self.add_argument("--version",action="version",version="SQLgo version: "+extra.version.VERSION)
        self.add_argument("--url","-u",help="Give the program url of the target",required=False)
        self.add_argument("--port","-p",help="Specify the port for the injection",required=False,type=int)
        self.add_argument("--inspect","-insp",help="Inspect the target response",required=False)
        self.add_argument("--column","-C",help="Specify the database possible column",required=False)
        self.add_argument("--table","-T",help="Specify the database possible table",required=False)
        self.add_argument("--dbms",help="Specify the DBMS of the server",required=False,type=str)
        self.add_argument("--db","-d",help="Specify the database name",required=False,action="store_true")
        self.add_argument("-dbs",help="Enumerate the DBMS databases",required=False,action="store_true")
        self.add_argument("-tables",help="Enumerate the DBMS tables",required=False,action="store_true")
        self.add_argument("--columns",help="Enumerate the DBMS columns",required=False,action="store_true")
        self.add_argument("--random-agent",help="Use random user agents",required=False,action="store_true")
        self.add_argument("--user-agent",help="Specify the user agent",required=False)
        self.add_argument("--dump",help="Dump the databases and show user",required=False,action="store_true")
        self.add_argument("--dump-table",help="Dump the tables and show user",required=False,action="store_true")
        self.add_argument("--dump-column",help="Dump the columns and show user",required=False,action="store_true")
        self.add_argument("--dump-user",help="Dump the users",required=False,action="store_true")
        self.add_argument("--dump-password",help="Dump the passwords",required=False,action="store_true")
        self.add_argument("--time-out",help="Set timeout amount",type=int,required=False)
        self.add_argument("--attack",help="Specify the attack type",default="normal",type=str,required=False)
        self.add_argument("--install-dependent",help="install the required modules for sqlgo to be executed",action="store_true",required=False)
        self.add_argument("--disable-warning",help="disable the ssl warning",action="store_true",required=False)
        self.add_argument("--payload",help="send you own payload",required=False,action="store_true")
        self.add_argument("--proxy-server",help="specify the proxyserver",type=str,required=False)
        self.add_argument("--proxy-port",help="specify proxy port ",action="store",type=int,required=False)
        self.add_argument("--proxy",help="use proxy servers",required=False,action="store_true")
        self.add_argument("--level",help="increase the level of performing tests(from range 1-5 default is 1 )",type=int,default=1,required=False)
        self.add_argument("--tamper",help="use tampers for specifying the payloads specific changes,eg: --tamper space2plus",required=False,type=str)
        self.add_argument("--time-based-t",help="specify the treshold of the time base injection (only for the time based injection,default = 0.5)",type=float,required=False)
        self.add_argument("--crawl",help="add crawling tests",action="store_true",required=False)
        



    



def extract():
    obj = Cmdline()
    args = obj.parse_args()
    output = args.output
    verbose = args.verbose
    url = args.url
    port = args.port
    inspect = args.inspect
    column = args.column
    table = args.table
    dbms = args.dbms
    db = args.db
    dbs = args.dbs
    tables = args.tables
    columns = args.columns
    random_agent = args.random_agent
    user_agent = args.user_agent
    dump = args.dump
    dump_table = args.dump_table
    dump_column = args.dump_column
    dump_user = args.dump_user
    dump_password = args.dump_password
    time_out = args.time_out
    attack = args.attack
    install = args.install_dependent
    warning_dis = args.disable_warning
    payload = args.payload
    Proxy_server = args.proxy_server
    Proxy_port = args.proxy_port
    user_proxy = args.proxy
    level = args.level
    tamper = args.tamper
    time_based_treshold = args.time_based_t
    crawl = args.crawl
    return (
        output,
        verbose,
        url,
        port,
        inspect,
        column,
        table,
        dbms,
        db,
        dbs,
        tables,
        columns,
        random_agent,
        user_agent,
        dump,
        dump_table,
        dump_column,
        dump_user,
        dump_password,
        time_out,
        attack,
        install,
        warning_dis,
        payload,
        Proxy_server,
        Proxy_port,
        user_proxy,
        level,
        tamper,
        time_based_treshold,
        crawl
    )

result = extract()
output = result[0]
verbose = result[1]
url = result[2]
port = result[3]
inspect = result[4]
column = result[5]
table = result[6]
dbms = result[7]
db = result[8]
dbs = result[9]
tables = result[10]
columns = result[11]
random_agent = result[12]
user_agent = result[13]
dump = result[14]
dump_table = result[15]
dump_column = result[16]
dump_user = result[17]
dump_password = result[18]
time_out = result[19]
attack = result[20]
install_dep = result[21]
warning_disable = result[22]
payload = result[23]
proxy_server = result[24]
proxy_port = result[25]
user_proxy = result[26]
level = result[27]
tamper = result[28]
time_based_tres = result[29]
crawl = result[30]




