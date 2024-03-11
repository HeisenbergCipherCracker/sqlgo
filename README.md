# sqlgo

# What is sqlgo project?
sqlgo is a tool which designed for SQL injection test for the educational targets,not illegal.remember: FOR ETHICAL USE ONLY!!!

# how to install sqlgo?
```
git clone --depth 1 https://github.com/HeisenbergCipherCracker/sqlgo.git
```
copy the above command to the terminal and navigate to the sqlgo directory
make sure you have git installed on your system.

# dependencies
- use the following commands to install the sqlgo dependencies using pip 
```
pip install -r requirements.txt
```
```
pip3 install -r requirements.txt
```
**for window OS**
```
python -m pip install -r requirements.txt
```
python3 -m pip install-r requirements.txt
**for unix based systems**







**Show the help menu**
```
python3 sqlgo.py --help
```

**Update the program**

```
python3 sqlgo.py --update
```

**Launch attack**
```
python3 sqlgo.py -u http://www.target-url?id=1 --level <level> --verbose <verbose> --tamper <tamper> --dbms<DBMS> --dump
```
# Features of sqlgo
1) Supports SQL Injection attacks against MySQL
2) Support of sending the different payloads including stack query , time delay and union all payload and other strong payloads.
3) provides lot of tamper scripts to tamper the payloads to  bypass WAF or Intrusion detection systems (IDS).
4) Provides various encoding techniques to encode
5) Automatic sql injection vulnerability detection and scanner 


# How do i report the bugs?
bugs will be accepted if they exists and you can report it from the github page of sqlgo. you can go to the issues tab in the github and report the bug in the clear sentence.

**Persain Translation : https://github.com/HeisenbergCipherCracker/sqlgo/blob/main/doc/translations/farsi.md**

**French translation : https://github.com/HeisenbergCipherCracker/sqlgo/blob/main/doc/translations/french.md**
