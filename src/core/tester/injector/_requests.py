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
try:
    import urllib.request
except:
    import urllib2 as urllib
try:
    from urllib.parse import urljoin
except:
    from urlparse import urljoin

import time
try:
    import requests
except:
    import third.requester as requests
import urllib3
try:
    import urllib.parse
except:
    import urlparse
try:
    from urllib.parse import urlparse
except:
    from urlparse import urlparse

from src.core.payloads.errorb import error_based
from src.core.setting.setting import REQUESTS
import src.core.setting.setting as settings
from src.core.payloads.makesetsqlpayload import make_set_sql_payload
from src.core.payloads.timebased import time_based_payload
from src.core.payloads.unionpayload import union_payload
from src.logger.log import logger
from src.core.tester.XSSfuns import getFormDetails
from src.core.tester.detector import sqlInjectionBasicDetection 
import traceback
from src.core.tester.XSSfuns import getAllForms
from src.core.tester.XSSfuns import getFormDetails,submitForm
from extras.bs4funs import getFormFromResponse
from src.core.request.parameters import get_url_part
from src.core.request.agent import header
from src.core.request.proxy.proxy import use_proxy,set_proxy
from src.core.parser.cmdline import proxy_port
from src.core.parser.cmdline import proxy_server
from src.core.enums.payloads import Payload
from src.core.parser.cmdline import user_proxy
from src.core.payloads.blindbased import BlindBased
from tampers.maintamper import applyTamper
from src.core.parser.cmdline import tamper
from src.core.tester.injector.checks import newline_fixation
from src.core.tester.injector.parameters import get_url_part
from extras.averagetime import average_response
from src.core.parser.cmdline import verbose
from src.datastruc.tree import root
from src.datastruc.tree import Tree
from src.core.parser.cmdline import beep
from src.core.enums.devstatus import DevStatus
from src.core.enums.priority import PRIORITY
from src.datastruc.injectdict import injeciondict
from src.core.common.urlreplace import update_url
from src.core.enums.enums import PAYLOAD_SENDING
from src.core.parser.cmdline import delay_time
from src.core.tester.injector.checks import extract_some_keyword
from sqlmap.lib.core.data import conf
from src.core.common.common import IOFileReader
from extras.error import errors
from src.core.tester.prompts import parameter
from src.data import arg,config
from src.core.enums.enums import DBMS
from src.core.common.common import whatDbms
import re

__status__ = DevStatus.READY_FOR_PRODUCTION_AND_USE
__priority__ = PRIORITY.VERY_HIGH
_responses = []

def host_injection(url,vuln_parameter="", payload="" ):

    payload = urlparse(url).netloc + payload

    def inject_host(url, vuln_parameter, payload):

        http = urllib3.PoolManager()  
        logger.debug(settings.SESSION_HANDLER_CREATED%url)

        url = url.partition('?')[0]
        headers = {'Host': payload}

        try:
            response = http.request('GET', url, headers=headers)
            logger.debug(settings.RESPONSE_RECIEVED_FROM_HOST%url%response)
            return response.data.decode('utf-8')  
        except Exception as err_msg:
            return str(err_msg)

    try:
        response = inject_host(url, vuln_parameter, payload)
        logger.debug(settings.RESPONSE_SENT_TO_BE_INSPECTED_FOR_SQL_VULN%url)
    except Exception as err_msg:
        response = str(err_msg)

    return response

def error_based_injection(url,param=None,payload=True,isauto=True,addheader=True):
    try:
        _error_based = Tree("error_based")
        _content = None
        if isauto:
            if payload:
                for _payload in error_based().split("\n"):
                    request = urllib.request.Request(url,data=_payload.encode(),method=REQUESTS.POST)
                    response = urllib.request.urlopen(request)
                    logger.debug(settings.CONNECTION_ESTABLISHED_WITH_TARGET%url)
                    injeciondict.place = settings.ERROR_BASED_INJ_RESPONSE
                    injeciondict.parameter = str(response) if not isinstance(response,str) else response
                    if addheader:
                        try:
                            request.add_header(settings.CUSTOM_HEADER_NAME, settings.CUSTOM_HEADER_VALUE.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload))
                            logger.debug(settings.HEADERS_ADDED_TO_THE_REQUEST)
                            response = urllib.request.urlopen(request,timeout=settings.DEFAULT_TIME_OUT)
                            _content = response.read()
                            _error_based.add_child(Tree(_content),Tree(response))
                        
                        except:
                            pass
                    
                    if user_proxy:
                        url_proxy = set_proxy(proxy_server,proxy_port)
                        result_use_general_proxy = use_proxy(request, proxy=url_proxy)
                        _content = result_use_general_proxy.read()
                        logger.debug(settings.USING_PRXOY%url_proxy)
                        _error_based.add_child(Tree(_content))


                    
                    else:
                        _content = response.read()
                        _error_based.add_child(str(Tree(_content if not isinstance(_content,bytes) else str(bytes.decode()))))
    
    except Exception as e:
        logger.debug(str(e))
        

def time_based_inejction(url,payload=True,isauto=True):
    _ = 0
    _retval = None
    _time_based = Tree("time_based")

    try:
        forms = getAllForms(url)

        for form in forms:
            form_data = {}
            for input_field in form.find_all('input'):
                form_data[input_field.get('name')] = input_field.get('value', '')
                logger.debug(settings.CTREATED_FROM_FOR_INJECTION%input_field)

            for _payload in time_based_payload().split("\n"):
                for line in settings.INJECTABLE_ARES_ON_THE_FORM:
                    _payload = applyTamper(_payload)
 

                    logger.debug(settings.TESTING_INJECTABLE_AREAS_ON_HTML_FORM%line)
                    form_data_copy = form_data.copy()
                    payload_field_name = line  
                    form_data_copy[payload_field_name] = _payload

                    # Make the POST request
                    request = urllib.request.Request(url, data=urllib.parse.urlencode(form_data_copy).encode(), method='POST')
                    response = urllib.request.urlopen(request)
                    logger.debug(settings.SENT_REQUEST_TO_TARGET%url)
                    injeciondict.place = settings.TIME_BASED_INJ_RESPONSE
                    injeciondict.parameter = str(response) if not isinstance(response,str) else response

                    response_content = response.read()
                    _time_based.add_child(Tree(response),Tree(response_content))


                    form_in_response = getFormFromResponse(response_content)
                    form_details = getFormDetails(form_in_response)
                    logger.debug(settings.READING_FORM_OF_HTML)

                    if is_sql_injection_vulnerable(response_content):
                        logger.warning("Potential sql injection detected!!!")
                        sqlInjectionBasicDetection(form_in_response, form_details)
                        logger.debug(settings.PERFORMING_SQL_INJECTION_DETECTION%url)
                    else:
                        if _ < 1:
                            logger.critical("No injectable areas found on the target")
                            sqlInjectionBasicDetection(form_in_response, form_details)
                            _ += 1



                    return form_in_response,_time_based

    except ValueError:
        pass

    except Exception as e:
        logger.debug(e)



def is_sql_injection_vulnerable(response):
    try:
        # Decode the response content to string
        response_text = response.decode('utf-8') if hasattr(response,"decode") else response
        logger.debug(settings.DECODING_RESPONSE)
        error_keywords = ["error", "exception", "syntax", "mysql", "sql", "warning","You have an error in your SQL syntax","check the manual that corresponds to you","warning: mysql_","supplied argument is not a valid mysql","to be resource, boolean given in","Warning: mysql_fetch_array()","Error Query", "Error performing query:","Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /hj/var/www/search.php on line 61","[SqlException]: Invalid column name","Incorrect syntax near the keyword "]
        error_keywords.extend(errors)
        return any(keyword in response_text.lower() for keyword in error_keywords)
    except Exception as e:
        print("Error decoding response: %s"%str(e))
        return False

def make_set_sql_injection(url,random_header=False):
    _retval = None
    _make_set = Tree("make_set")
    _ = 0
    try:
        url = get_url_part(url=url)
        forms = getAllForms(url)
        logger.debug(settings.CTREATED_FROM_FOR_INJECTION%forms)

        for form in forms:
            form_data = {}
            for input_field in form.find_all('input'):
                form_data[input_field.get('name')] = input_field.get('value', '')
                logger.debug(settings.GOT_INPUT_FIELD%input_field)

            for _payload in make_set_sql_payload().split("\n"):
                _payload = applyTamper(_payload)
                logger.info("testing : %s"%Payload.MAKE_SET.value)
                for line in settings.INJECTABLE_ARES_ON_THE_FORM:
                    form_data_copy = form_data.copy()
                    payload_field_name = line  
                    form_data_copy[payload_field_name] = _payload
                    logger.debug(settings.SUBMITED_PAYLOAD_ON_FORM%_payload)

                    request = urllib.request.Request(url, data=urllib.parse.urlencode(form_data_copy).encode(), method='POST')
                    if random_header is True:
                        if settings.CUSTOM_HEADER_INJECTION:
                            logger.debug(settings.PREAPARING_HEADERS)
                            custom_header_name = settings.CUSTOM_HEADER_NAME
                            custom_header_value = settings.CUSTOM_HEADER_VALUE

                            if custom_header_name and custom_header_value:
                                request.add_header(custom_header_name, custom_header_value)
                            else:
                                logger.info("Skipping invalid header name or value.")
                        else:
                            logger.warning("header injection disabled.")



                    response = urllib.request.urlopen(request)
                    logger.debug(settings.SENT_REQUEST_TO_TARGET%url)
                    injeciondict.place = settings.MAKE_SET_INJ_RESPONSE
                    injeciondict.parameter = str(response) if not isinstance(response,str) else response
                    response_content = response.read()
                    _make_set.add_child(Tree(response))

                    form_in_response = getFormFromResponse(response_content)
                    form_details = getFormDetails(form_in_response)
                    logger.debug(settings.READING_FORM_OF_HTML+settings.CRAFTING_FORM_IN_DETAILS)

                    if is_sql_injection_vulnerable(response_content):
                        logger.warning("Potential SQL injection detected!!!")
                        sqlInjectionBasicDetection(form_in_response, form_details)
                        logger.debug(settings.PERFORMING_SQL_INJECTION_DETECTION+"sql injection vulnerability already exists in the url %s"%url)
                    else:
                        if _ < 1:
                            logger.critical("No SQL injection detected on the target")
                            logger.debug("using payload:%s"%_payload)
                            _ += 1

                return form_in_response,_make_set
                    
    
    except Exception as e:
        logger.error("Error: %s"%str(e))
        return
        # Handle the exception as needed


def union_based_injection(url):
    _ = 0
    _tamreq = None
    _tresponse = None
    _retval = None
    _union_based = Tree("union_based")
    for __ in union_payload().split("\n"):
        try:
            forms = getAllForms(url)
            logger.debug(settings.CTREATED_FROM_FOR_INJECTION%""+"testing : possible parameters on the received form.")
            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                for _payload in union_payload().split("\n"):

                    for line in settings.INJECTABLE_ARES_ON_THE_FORM:
                        _payload = applyTamper(_payload)

                        logger.info("testing : %s"%Payload.UNION_ALL_SELECT.value)
                        form_data_copy = form_data.copy()
                        payload_field_name = line  
                        form_data_copy[payload_field_name] = _payload
                        logger.debug(settings.TESTING_INJECTABLE_AREAS_ON_HTML_FORM%_payload)

                        # Make the POST request
                        request = urllib.request.Request(url, data=urllib.parse.urlencode(form_data_copy).encode(), method='POST')
                        response = urllib.request.urlopen(request)

                        logger.debug(settings.SENT_REQUEST_TO_TARGET%url)
                        injeciondict.place = settings.UNION_BASED_INJ_RESPONSE
                        injeciondict.parameter = str(response) if not isinstance(response,str) else response
                        logger.debug(settings.CRAFTED_REQUEST_TO_BE_SENT%url)

                        response_content = response.read()
                        _union_based.add_child(Tree(response_content),Tree(response))

                        form_in_response = getFormFromResponse(response_content)
                        form_details = getFormDetails(form_in_response)
                        sqlInjectionBasicDetection(form_in_response, form_details)

                        if is_sql_injection_vulnerable(response_content):
                            if beep:
                                __import__("extra.beep.beep")
                            logger.warning("Potential sql injection detected!!!")
                            # Call sqlInjectionBasicDetection with both parameters
                            sqlInjectionBasicDetection(form_in_response, form_details)
                        else:
                            logger.debug("No injectable areas found on the target via payload%s"%_payload)
                            sqlInjectionBasicDetection(form_in_response, form_details)
                    
                    return _union_based
                
        except ValueError:
            continue

        except Exception as e:
            logger.error(e)
            return


def mysql_blind_based_injection(url):
    _ = 0
    _retval = None
    _blind_based = Tree("blind_based")
    for __ in BlindBased.mysql_version_query().split("\n"):
        try:
            forms = getAllForms(url)
            logger.debug(settings.CRAFTING_FORM_IN_DETAILS+"created form of html from target %s"%url)
            for form in forms:
                logger.debug(settings.INCLUDING_FORMS%form)
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                for _payload in BlindBased.mysql_version_query().split("\n"):
                    for line in settings.INJECTABLE_ARES_ON_THE_FORM:
                        logger.info("testing : %s"%Payload.MYSQL_BLIND_BASED.value)
                        form_data_copy = form_data.copy()
                        logger.debug("copied the data form %s"%form_data_copy)
                        payload_field_name = line 
                        form_data_copy[payload_field_name] = _payload
                        logger.debug(settings.TESTING_INJECTABLE_AREAS_ON_HTML_FORM%line)

                        # Make the POST request
                        request = urllib.request.Request(url, data=urllib.parse.urlencode(form_data_copy).encode(), method='POST')
                        response = urllib.request.urlopen(request)

                        logger.debug(settings.SENT_REQUEST_TO_TARGET%url)
                        injeciondict.place = settings.BLIND_BASED_INJ_RESPONSE
                        injeciondict.parameter = str(response) if not isinstance(response,str) else response

                        response_content = response.read()
                        _blind_based.add_child(Tree(response_content))


                        form_in_response = getFormFromResponse(response_content)
                        form_details = getFormDetails(form_in_response)
                        sqlInjectionBasicDetection(form_in_response, form_details)

                        if is_sql_injection_vulnerable(response_content):
                            if beep:
                                __import__("extra.beep.beep")
                            logger.debug(settings.PERFORMING_SQL_INJECTION_DETECTION%url)
                            logger.warning("Potential sql injection detected!!!")
                            sqlInjectionBasicDetection(form_in_response, form_details)
                        else:
                            logger.debug("No injectable areas found on the target via payload%s"%_payload)
                            sqlInjectionBasicDetection(form_in_response, form_details)
                    
                    return _blind_based

                # return form_in_response

        except ValueError:
            continue

        except Exception as e:
            logger.debug(e)

def postgre_sql_blind_injection(url):
    _ = 0
    _retval = None
    _postgre = Tree("postgre")
    for __ in BlindBased.postgre_sql_payload_version_query().split("\n"):
        try:
            forms = getAllForms(url)

            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                for _payload in BlindBased.postgre_sql_payload_version_query().split("\n"):
                    for line in settings.INJECTABLE_ARES_ON_THE_FORM:
                        _payload = applyTamper(_payload)

                        logger.info("testing : %s"%Payload.POSTGRE_SQL_VERSION_QUERY_BLIND_BASED.value)
                        form_data_copy = form_data.copy()
                        payload_field_name = line  # Replace with the actual name
                        form_data_copy[payload_field_name] = _payload
                        logger.debug(settings.TESTING_INJECTABLE_AREAS_ON_HTML_FORM%_payload)

                        # Make the POST request
                        request = urllib.request.Request(url, data=urllib.parse.urlencode(form_data_copy).encode(), method='POST')
                        response = urllib.request.urlopen(request)

                        logger.debug(settings.SENT_REQUEST_TO_TARGET%url)
                        injeciondict.place = settings.POSTGRE_RESPONSE_IN_INJ_DICT
                        injeciondict.parameter = str(response) if not isinstance(response,str) else response

                        response_content = response.read()
                        _postgre.add_child(Tree(response_content))
                        logger.debug(settings.SENT_POST_REQUEST%url)

                        form_in_response = getFormFromResponse(response_content)
                        form_details = getFormDetails(form_in_response)
                        sqlInjectionBasicDetection(form_in_response, form_details)
                        logger.debug("inspecting injection on %s"%form_details)
                        if is_sql_injection_vulnerable(response_content):
                            if beep:
                                __import__("extra.beep.beep")
                            logger.warning("Potential sql injection detected!!!")
                            # Call sqlInjectionBasicDetection with both parameters
                            sqlInjectionBasicDetection(form_in_response, form_details)
                        else:
                            logger.debug("No injectable areas found on the target via payload%s"%_payload)
                            sqlInjectionBasicDetection(form_in_response, form_details)
                    
                    return _postgre
                




                # return form_in_response

        except ValueError:
            continue

        except Exception as e:
            logger.error(e)
            return

def user_agent_injection(url, vuln_parameter, payload):
    _responses = []
    def inject_user_agent(url, vuln_parameter, payload):
        global _responses
        logger.info(settings.TESTING_IF_CRAWLING_PARAMETER_IS_INJECTABLE%"User-agent")

        request = urllib.request.Request(url)
        url = get_url_part(url)
        request = urllib.request.Request(url)
        payload = newline_fixation(payload)
        request.add_header('User-Agent', payload)
        try:
            response = urllib.request.urlopen(request, timeout=settings.TIMEOUT)
            logger.debug(settings.CRAWLING_TEST_RESPONSE%str(response))
        except ValueError:
            pass

    if settings.TIME_RELATIVE_ATTACK or True:
        start = 0
        end = 0
        start = time.monotonic()

    try:
        response = inject_user_agent(url, vuln_parameter, payload)
    except Exception as err_msg:
        response = str(err_msg)
        logger.debug(response)

    if settings.TIME_RELATIVE_ATTACK:
        end = time.monotonic()
        how_long = float(end - start)
        _responses.append(how_long)
        _avres = average_response(_responses)
        return how_long,_avres

    else:
        return response
    




def referer_injection(url, vuln_parameter, payload):
    if settings.REFERER_INJECTION is not None:
        logger.info(settings.REFERER_INJECTION)
    _responses = []
    def inject(url, vuln_parameter, payload):
        global _responses
        logger.info(settings.TESTING_IF_CRAWLING_PARAMETER_IS_INJECTABLE%"Referer")

        request = urllib.request.Request(url)
        url = get_url_part(url)
        request = urllib.request.Request(url)
        payload = newline_fixation(payload)
        request.add_header("Referer", payload)
        try:
            response = urllib.request.urlopen(request, timeout=settings.TIMEOUT)
            logger.debug(settings.CRAWLING_TEST_RESPONSE%str(response))
        except ValueError:
            pass

    if settings.TIME_RELATIVE_ATTACK or True:
        start = 0
        end = 0
        start = time.monotonic()

    try:
        response = inject(url, vuln_parameter, payload)
    except Exception as err_msg:
        response = str(err_msg)
        logger.info(response if response is not None else "")

    if settings.TIME_RELATIVE_ATTACK:
        end = time.monotonic()
        how_long = float(end - start)
        _responses.append(how_long)
        _avres = average_response(_responses)
        return how_long,_avres

    else:
        return response
    



def error_based_url_replace(url):

    for payload in error_based().split("\n"):
        try:
            print(PAYLOAD_SENDING.SENDING%payload if verbose >= 3 else "")

            _ = update_url(url,payload)
            __url = _
            if verbose > 3:
                logger.debug(__url)
            _payload = applyTamper(payload)
            _ = update_url(url,_payload)
            __url = _
            if "http" not in __url:
                _url = re.sub(r'^(?!http)(.+)', r'http://\1', url)
    
            if "https" not  in _url:
                _url = re.sub(r'^(?!https)(.+)', r'https://\1',url)
            response = requests.get(__url)
            if verbose > 5:
                logger.debug("status code %d"%response.status_code)
            logger.debug(response.text if verbose >= 5 else "")
            logger.info("testing :%s"%Payload.ERROR_BASED.value+"\033[1mReplacing the url\033[0m")

            forms = getAllForms(url)
            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                    form_data_copy = form_data.copy()
                    payload_field_name = payload 
                    form_data_copy[payload_field_name] = _payload
                    if input_field.get("name") == payload:
                        input_field["value"] = _payload
                        __url = update_url(url)
                        break
                if response.status_code == 500:
                    logger.warning("The server has encountered status code error 500.this might be a sql injection vulnerability on %s,this can also occur due to the server erros.if you believe that this is a WAF/IPS protection, you can use advacned tools or use proxy chains."%url)

                response_content = response.text
                form_in_response = getFormFromResponse(response_content)
                form_details = getFormDetails(form_in_response)

                sqlInjectionBasicDetection(form_in_response, form_details)
                config.possibleDbms = whatDbms(response_content)
                if config.possibleDbms is not None:
                    dbmsMsg = "it looks like the back-end DBMS is %s"
                    time.sleep(delay_time)
                    logger.info(dbmsMsg%config.possibleDbms)
                if is_sql_injection_vulnerable(response_content):
                    if arg.beep:
                        __import__("extras.beep.beep")
                    logger.info("%s (GET) parameter is %s injectable"%(parameter,"Error based SQl query"))
                    logger.warning("tamper : %s"%arg.tamper if arg.tamper is not None else "Nlo tamper usage")
                    logger.warning("Potential sql injection detected!!!")
                    logger.warning("found potential sql injection on %s"%url)
                    logger.warning("payload:%s"%payload)
                    logger.warning("url: %s"%__url)
                    logger.debug("response : %s"%response_content)
                    conf.keyword = extract_some_keyword(__url)
                    conf.vuln = True


                    logger.warning("program will be resume the injection after %d seconds."%delay_time)
                    time.sleep(delay_time)
                    # Call sqlInjectionBasicDetection with both parameters
                    sqlInjectionBasicDetection(form_in_response, form_details)
        except Exception as e:
            count = 0
            if any(["HTTPConnectionPool" in str(e)]):
                count += 1
            
            if count > 0 and "HTTPConnectionPool" in str(e):
                logger.error(e)


def time_based_url_replace(url):

    for payload in time_based_payload().split("\n"):
        try:
            print(PAYLOAD_SENDING.SENDING%payload if verbose >= 3 else "")



            _payload = applyTamper(payload)
            _ = update_url(url,_payload)

            __url = _
            response = requests.get(__url)
            if verbose > 3:
                logger.debug(__url)
            if verbose > 5:
                logger.debug("status code %d"%response.status_code)
            logger.info("testing :%s"%Payload.TIME_BASED.value+"\033[1mReplacing the url\033[0m")

            logger.debug(response.text if verbose >= 5 else "")
            forms = getAllForms(url)
            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                    form_data_copy = form_data.copy()
                    payload_field_name = payload 
                    form_data_copy[payload_field_name] = _payload
                    if input_field.get("name") == payload:
                        input_field["value"] = _payload
                        __url = update_url(url)
                        break
                if response.status_code == 500:
                    logger.warning("The server has encountered status code error 500.this might be a sql injection vulnerability on %s,this can also occur due to the server erros.if you believe that this is a WAF/IPS protection, you can use advacned tools or use proxy chains."%url)

                response_content = response.text
                form_in_response = getFormFromResponse(response_content)
                form_details = getFormDetails(form_in_response)

                sqlInjectionBasicDetection(form_in_response, form_details)
                if is_sql_injection_vulnerable(response_content):
                    if arg.beep:
                        __import__("extras.beep.beep")

                    logger.warning("Potential sql injection detected!!!")
                    # Call sqlInjectionBasicDetection with both parameters
                    sqlInjectionBasicDetection(form_in_response, form_details)
                    config.possibleDbms = whatDbms(response_content)
                    if config.possibleDbms is not None:
                        dbmsMsg = "it looks like the back-end DBMS is %s"
                        logger.info(dbmsMsg%config.possibleDbms)
                        time.sleep(delay_time)
                    if arg.beep:
                        __import__("extras.beep.beep")
                    logger.info("%s (GET) parameter is %s injectable"%(parameter,"time based Sql query"))
                    logger.warning("tamper : %s"%arg.tamper if arg.tamper is not None else "Nlo tamper usage")
                    logger.warning("found potential sql injection on %s"%url)
                    logger.warning("payload:%s"%payload)
                    logger.warning("url: %s"%__url)
                    logger.debug("response : %s"%response_content)
                    logger.warning("program will be resume the injection after %d seconds."%delay_time)
                    conf.keyword = extract_some_keyword(__url)
                    conf.vuln = True


                    time.sleep(delay_time)
        except Exception as e:
            count = 0
            if any(["HTTPConnectionPool" in str(e)]):
                count += 1
            
            if count > 0 and "HTTPConnectionPool" in str(e):
                logger.error(e)
    
def make_set_url_replace(url):

    for payload in make_set_sql_payload().split("\n"):
        try:

            _ = update_url(url,payload)
            __url = _
            if verbose > 3:
                logger.debug(__url)
            _payload = applyTamper(payload)
            print(PAYLOAD_SENDING.SENDING.format(_payload if verbose >= 3 else ""))
            response = requests.get(__url)

            if verbose > 5:
                logger.debug("status code:%d"%response.status_code if verbose >= 5 else "")
            logger.info("testing :%s"%Payload.MAKE_SET.value+"\033[1mReplacing the url\033[0m")

            logger.debug(response.text)
            forms = getAllForms(url)
            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                    form_data_copy = form_data.copy()
                    payload_field_name = payload 
                    form_data_copy[payload_field_name] = _payload
                    if input_field.get("name") == payload:
                        input_field["value"] = _payload
                        __url = update_url(url)
                        break
                if response.status_code == 500:
                    logger.warning("The server has encountered status code error 500.this might be a sql injection vulnerability on %s,this can also occur due to the server erros.if you believe that this is a WAF/IPS protection, you can use advacned tools or use proxy chains."%url)

                response_content = response.text
                form_in_response = getFormFromResponse(response_content)
                form_details = getFormDetails(form_in_response)
                config.possibleDbms = whatDbms(response_content)
                if config.possibleDbms is not None:
                    dbmsMsg = "it looks like the back-end DBMS is %s"
                    logger.info(dbmsMsg%config.possibleDbms)
                    time.sleep(delay_time)
                try:
                    sqlInjectionBasicDetection(form_in_response, form_details)
                except requests.exceptions.MissingSchema as exc:
                    logger.debug("missing schema %s"%exc)
                if is_sql_injection_vulnerable(response_content):
                    if arg.beep:
                        __import__("extras.beep.beep")
                    logger.info("%s (GET) parameter is %s injectable"%(parameter,"Make set mysql query"))
                    logger.warning("tamper : %s"%"No tamper used" if arg.tamper is not None else arg.tamper)
                    logger.warning("Potential sql injection detected!!!")
                    logger.warning("found potential sql injection on %s"%url)
                    logger.warning("payload:%s"%_payload)
                    logger.warning("url: %s"%__url)
                    logger.warning("program will be resume the injection after %d seconds."%delay_time)
                    sqlInjectionBasicDetection(form_in_response, form_details)
                    if arg.beep:
                        __import__("extras.beep.beep")
                    conf.keyword = extract_some_keyword(__url)
                    conf.vuln = True


                    time.sleep(delay_time)

        except Exception as e:
            traceback.print_exc()
            logger.error(e)

def union_based_url_replace(url):

    for payload in union_payload().split("\n"):
        try:


            _payload = applyTamper(payload )
            print(PAYLOAD_SENDING.SENDING%_payload if verbose >= 3 else "")

            _ = update_url(url,_payload)
            __url = _
            if verbose > 3:
                logger.debug(__url)
            response = requests.get(__url)
            if verbose > 5:
                logger.debug("status code %d"%response.status_code)
            logger.info("testing :%s"%Payload.UNION_ALL_SELECT.value+"\033[1mReplacing the url\033[0m")
            logger.debug(response.text if verbose >= 5 else "")
            forms = getAllForms(url)
            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                    form_data_copy = form_data.copy()
                    payload_field_name = payload 
                    form_data_copy[payload_field_name] = _payload
                    if input_field.get("name") == payload:
                        input_field["value"] = _payload
                        __url = update_url(url)
                        break

                response_content = response.text
                form_in_response = getFormFromResponse(response_content)
                form_details = getFormDetails(form_in_response)

                sqlInjectionBasicDetection(form_in_response, form_details)

                config.possibleDbms = whatDbms(response_content)
                if config.possibleDbms is not None:
                    dbmsMsg = "it looks like the back-end DBMS is %s"
                    logger.info(dbmsMsg%config.possibleDbms)
                    time.sleep(delay_time)
                sqlInjectionBasicDetection(form_in_response, form_details)
                if is_sql_injection_vulnerable(response_content):
                    logger.warning("Potential sql injection detected!!!")
                    if arg.beep:
                        __import__("extras.beep.beep")
                    logger.info("%s (GET) parameter is %s injectable"%(parameter,"Union based(ALL SELECT) query"))
                    logger.warning("tamper : %s"%arg.tamper if arg.tamper is not None else "no tamper used")
                    logger.warning("found potential sql injection on %s"%url)
                    logger.warning("payload:%s"%payload)
                    logger.warning("url: %s"%__url)
                    logger.warning("program will be resume the injection after %d seconds"%delay_time)
                    logger.debug("response: %s"%response_content)
                    conf.keyword = extract_some_keyword(__url)
                    conf.vuln = True
                    time.sleep(delay_time)

                    # Call sqlInjectionBasicDetection with both parameters
                    sqlInjectionBasicDetection(form_in_response, form_details)
                    if arg.beep:
                        __import__("extras.beep.beep")
                

        except Exception as e:
            count = 0
            if any(["HTTPConnectionPool" in str(e)]):
                count += 1
            
            if count > 0 and "HTTPConnectionPool" in str(e):
                logger.error(e)


def stack_query(url):

    for payload in IOFileReader.payload("stack_q.txt").split("\n"):
        try:
            _payload = applyTamper(payload)
            print(PAYLOAD_SENDING.SENDING%_payload if verbose >= 3 else "")

            _ = update_url(url,_payload)
            __url = _
            if verbose > 3:
                logger.debug(__url)
            response = requests.get(__url)
            if verbose > 5:
                logger.debug("status code %d"%response.status_code)
            logger.info("testing :%s"%Payload.STACK_Q.value+"\033[1mReplacing the url\033[0m")
            logger.debug(response.text if verbose >= 5 else "")
            forms = getAllForms(url)
            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                    form_data_copy = form_data.copy()
                    payload_field_name = payload 
                    form_data_copy[payload_field_name] = _payload
                    if input_field.get("name") == payload:
                        input_field["value"] = _payload
                        __url = update_url(url)
                        break
                
                if response.status_code == 500:
                    logger.warning("The server has encountered status code error 500.this might be a sql injection vulnerability on %s,this can also occur due to the server erros.if you believe that this is a WAF/IPS protection, you can use advacned tools or use proxy chains."%url)
                response_content = response.text
                form_in_response = getFormFromResponse(response_content)
                form_details = getFormDetails(form_in_response)

                sqlInjectionBasicDetection(form_in_response, form_details)
                config.possibleDbms = whatDbms(response_content)
                if config.possibleDbms is not None:
                    dbmsMsg = "it looks like the back-end DBMS is %s"
                    logger.info(dbmsMsg%config.possibleDbms)
                    time.sleep(delay_time)
                if is_sql_injection_vulnerable(response_content):
                    logger.warning("Potential sql injection detected!!!")
                    if arg.beep:
                        __import__("extras.beep.beep")
                    logger.info("%s (GET) parameter is %s injectable"%(parameter,"SQl"+stack_query.__name__))
                    logger.warning("tamper : %s"%arg.tamper if arg.tamper is not None else "No tamper was used")
                    logger.warning("found potential sql injection on %s"%url)
                    logger.warning("payload:%s"%payload)
                    logger.warning("url: %s"%__url)
                    logger.warning("program will be resume the injection after %d seconds"%delay_time)
                    logger.debug("response: %s"%response_content)
                    conf.keyword = extract_some_keyword(__url)
                    conf.vuln = True
                    time.sleep(delay_time)

                    # Call sqlInjectionBasicDetection with both parameters
                    sqlInjectionBasicDetection(form_in_response, form_details)
                    __import__("extras.beep.beep")
                

        except Exception as e:
            count = 0
            if any(["HTTPConnectionPool" in str(e)]):
                count += 1
            
            if count > 0 and "HTTPConnectionPool" in str(e):
                logger.error(e)


def error_boolean(url):

    for payload in IOFileReader.payload("error_boolean.txt").split("\n"):
        try:

            _payload = applyTamper(payload)
            _ = update_url(url,_payload)
            __url = _
            print(PAYLOAD_SENDING.SENDING%payload if verbose >= 3 else "")

            response = requests.get(__url)
            if verbose > 3:
                logger.debug(__url)
            if verbose > 5:
                logger.debug("status code %d"%response.status_code)
            logger.info("testing :%s"%Payload.ERROR_BOOL.value+"\033[1mReplacing the url\033[0m")
            logger.debug(response.text if verbose >= 5 else "")
            forms = getAllForms(url)
            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                    form_data_copy = form_data.copy()
                    payload_field_name = payload 
                    form_data_copy[payload_field_name] = _payload
                    if input_field.get("name") == payload:
                        input_field["value"] = _payload
                        __url = update_url(url)
                        break
                if response.status_code == 500:
                    logger.warning("The server has encountered status code error 500.this might be a sql injection vulnerability on %s,this can also occur due to the server erros.if you believe that this is a WAF/IPS protection, you can use advacned tools or use proxy chains."%url)

                response_content = response.text
                form_in_response = getFormFromResponse(response_content)
                form_details = getFormDetails(form_in_response)
                config.possibleDbms = whatDbms(response_content)
                sqlInjectionBasicDetection(form_in_response, form_details)
                if config.possibleDbms is not None:
                    dbmsMsg = "it looks like the back-end DBMS is %s"
                    logger.info(dbmsMsg%config.possibleDbms)
                    time.sleep(delay_time)
                if is_sql_injection_vulnerable(response_content):
                    logger.warning("Potential sql injection detected!!!")
                    __import__("extras.beep.beep")
                    logger.info("%s (GET) parameter is %s injectable"%(parameter,error_boolean.__name__+"SQl query"))
                    logger.warning("tamper : %s"%"No tamper used" if arg.tamper is not None else arg.tamper)
                    logger.warning("found potential sql injection on %s"%url)
                    logger.warning("payload:%s"%payload)
                    logger.warning("url: %s"%__url)
                    logger.warning("program will be resume the injection after %d seconds"%delay_time)
                    logger.debug("response: %s"%response_content)
                    conf.keyword = extract_some_keyword(__url)
                    conf.vuln = True
                    time.sleep(delay_time)

                    # Call sqlInjectionBasicDetection with both parameters
                    sqlInjectionBasicDetection(form_in_response, form_details)
                    if arg.beep:
                        __import__("extras.beep.beep")
                

        except Exception as e:
            count = 0
            if any(["HTTPConnectionPool" in str(e)]):
                count += 1
            
            if count > 0 and "HTTPConnectionPool" in str(e):
                logger.error(e)


def inline(url):

    for payload in IOFileReader.payload("inline.txt").split("\n"):
        try:
            _payload = applyTamper(payload)
            _ = update_url(url,_payload)
            __url = _
            print(PAYLOAD_SENDING.SENDING%payload if verbose >= 3 else "")

            if verbose > 3:
                logger.debug(__url)
            response = requests.get(__url)
            if verbose > 5:
                logger.debug("status code %d"%response.status_code)
            logger.info("testing :%s"%Payload.INLINE_Q.value+"\033[1mReplacing the url\033[0m")
            logger.debug(response.text if verbose >= 5 else "")
            forms = getAllForms(url)
            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                    form_data_copy = form_data.copy()
                    payload_field_name = payload 
                    form_data_copy[payload_field_name] = _payload
                    if input_field.get("name") == payload:
                        input_field["value"] = _payload
                        __url = update_url(url)
                        break
                if response.status_code == 500:
                    logger.warning("The server has encountered status code error 500.this might be a sql injection vulnerability on %s,this can also occur due to the server erros.if you believe that this is a WAF/IPS protection, you can use advacned tools or use proxy chains."%url)

                response_content = response.text
                form_in_response = getFormFromResponse(response_content)
                form_details = getFormDetails(form_in_response)

                sqlInjectionBasicDetection(form_in_response, form_details)
                config.possibleDbms = whatDbms(response_content)
                if config.possibleDbms is not None:
                    dbmsMsg = "it looks like the back-end DBMS is %s"
                    logger.info(dbmsMsg%config.possibleDbms)
                    time.sleep(delay_time)
                if is_sql_injection_vulnerable(response_content):
                    logger.warning("Potential sql injection detected!!!")
                    if arg.beep:
                        __import__("extras.beep.beep")
                    logger.info("%s parameter is %s injectable"%(parameter,inline.__name__+"Sql query"))
                    logger.warning("tamper : %s"%arg.tamper if arg.tamper is not None else "No tamper used")
                    logger.warning("found potential sql injection on %s"%url)
                    logger.warning("payload:%s"%payload)
                    logger.warning("url: %s"%__url)
                    logger.warning("program will be resume the injection after %d seconds"%delay_time)
                    logger.debug("response: %s"%response_content)
                    conf.keyword = extract_some_keyword(__url)
                    conf.vuln = True
                    time.sleep(delay_time)

                    # Call sqlInjectionBasicDetection with both parameters
                    sqlInjectionBasicDetection(form_in_response, form_details)
                    if arg.beep:
                        __import__("extras.beep.beep")
                

        except Exception as e:
            count = 0
            if any(["HTTPConnectionPool" in str(e)]):
                count += 1
            
            if count > 0 and "HTTPConnectionPool" in str(e):
                logger.error(e)

def time_based_heavy_q(url):

    for payload in IOFileReader.payload("time_based.txt").split("\n"):
        try:

            _ = update_url(url,payload)
            __url = _
            if verbose > 3:
                logger.debug(__url)
            _payload = applyTamper(payload)
            _ = update_url(url,_payload)
            print(PAYLOAD_SENDING.SENDING%payload if verbose >= 3 else "")

            __url = _
            response = requests.get(__url)
            if verbose > 5:
                logger.debug("status code %d"%response.status_code)
            logger.info("testing :%s"%Payload.TIME_BASED_HEAVY_Q.value+"\033[1m\033[0m")
            logger.debug(response.text if verbose >= 5 else "")
            forms = getAllForms(url)
            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                    form_data_copy = form_data.copy()
                    payload_field_name = payload 
                    form_data_copy[payload_field_name] = _payload
                    if input_field.get("name") == payload:
                        input_field["value"] = _payload
                        __url = update_url(url)
                        break
                if response.status_code == 500:
                    logger.warning("The server has encountered status code error 500.this might be a sql injection vulnerability on %s,this can also occur due to the server erros.if you believe that this is a WAF/IPS protection, you can use advacned tools or use proxy chains."%url)

                response_content = response.text
                form_in_response = getFormFromResponse(response_content)
                form_details = getFormDetails(form_in_response)

                sqlInjectionBasicDetection(form_in_response, form_details)
                config.possibleDbms = whatDbms(response_content)
                if config.possibleDbms is not None:
                    dbmsMsg = "it looks like the back-end DBMS is %s"
                    logger.info(dbmsMsg%config.possibleDbms)
                    time.sleep(delay_time)
                if is_sql_injection_vulnerable(response_content):
                    logger.warning("Potential sql injection detected!!!")
                    if arg.beep:
                        __import__("extras.beep.beep")
                    logger.info("%s parameter is %s injectable"%(parameter,time_based_heavy_q.__name__+"eury"))
                    logger.warning("tamper : %s"%arg.tamper if arg.tamper is not None else "No tamper used")
                    logger.warning("found potential sql injection on %s"%url)
                    logger.warning("payload:%s"%payload)
                    logger.warning("url: %s"%__url)
                    logger.warning("program will be resume the injection after %d seconds"%delay_time)
                    logger.debug("response: %s"%response_content)
                    conf.keyword = extract_some_keyword(__url)
                    conf.vuln = True
                    time.sleep(delay_time)

                    # Call sqlInjectionBasicDetection with both parameters
                    sqlInjectionBasicDetection(form_in_response, form_details)
                    if arg.beep:
                        __import__("extras.beep.beep")
                

        except Exception as e:
            count = 0
            if any(["HTTPConnectionPool" in str(e)]):
                count += 1
            
            if count > 0 and "HTTPConnectionPool" in str(e):
                logger.error(e)


def sqlQuery(sql=arg.sqlQuery,url=arg.url):
        try:

            _ = update_url(url,sql)
            __url = _
            if verbose > 3:
                logger.debug(__url)
            _payload = applyTamper(sql)
            _ = update_url(url,_payload)
            print(PAYLOAD_SENDING.SENDING.format(sql if verbose >= 3 else ""))

            __url = _
            response = requests.get(__url)
            print(response.status_code)
            if verbose > 5:
                logger.debug("status code %d"%response.status_code)
            logger.info("testing :%s"%Payload.TIME_BASED_HEAVY_Q.value+"\033[1m\033[0m")
            logger.debug(response.text if verbose >= 5 else "")
            forms = getAllForms(url)
            for form in forms:
                form_data = {}
                for input_field in form.find_all('input'):
                    form_data[input_field.get('name')] = input_field.get('value', '')
                    form_data_copy = form_data.copy()
                    payload_field_name = sql 
                    form_data_copy[payload_field_name] = _payload
                    if input_field.get("name") == sql:
                        input_field["value"] = _payload
                        __url = update_url(url)
                        break
                if response.status_code == 500:
                    logger.warning("The server has encountered status code error 500.this might be a sql injection vulnerability on %s,this can also occur due to the server erros.if you believe that this is a WAF/IPS protection, you can use advacned tools or use proxy chains."%url)

                response_content = response.text
                form_in_response = getFormFromResponse(response_content)
                form_details = getFormDetails(form_in_response)

                sqlInjectionBasicDetection(form_in_response, form_details)
                config.possibleDbms = whatDbms(response_content)
                if config.possibleDbms is not None:
                    dbmsMsg = "it looks like the back-end DBMS is %s"
                    logger.info(dbmsMsg%config.possibleDbms)
                    time.sleep(delay_time)
                if is_sql_injection_vulnerable(response_content):
                    logger.warning("Potential sql injection detected!!!")
                    if arg.beep:
                        __import__("extras.beep.beep")
                    logger.info("%s parameter is %s injectable"%(parameter,time_based_heavy_q.__name__+"eury"))
                    logger.warning("found potential sql injection on %s"%url)
                    logger.warning("payload:%s"%sql)
                    logger.warning("url: %s"%__url)
                    logger.warning("program will be resume the injection after %d seconds"%delay_time)
                    logger.debug("response: %s"%response_content)
                    conf.keyword = extract_some_keyword(__url)
                    conf.vuln = True
                    time.sleep(delay_time)
                

                    # Call sqlInjectionBasicDetection with both parameters
                    sqlInjectionBasicDetection(form_in_response, form_details)
                    if arg.beep:
                        __import__("extras.beep.beep")
                

        except Exception as e:
            logger.error(e)
            traceback.print_exc()
            count = 0
            if any(["HTTPConnectionPool" in str(e)]):
                count += 1
            
            if count > 0 and "HTTPConnectionPool" in str(e):
                logger.error(e)

