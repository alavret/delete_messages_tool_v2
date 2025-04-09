import argparse
from dotenv import load_dotenv
import requests
import logging
import logging.handlers as handlers
import os.path
import sys
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from os import environ
import re
import csv
import json
from dataclasses import dataclass
from textwrap import dedent
from http import HTTPStatus
from asyncio import run, wait_for
from collections import namedtuple
from email.message import Message
from email.parser import BytesHeaderParser, BytesParser
from email.header import decode_header
from typing import Collection
import email
import asyncio
import concurrent.futures
import aioimaplib
from typing import Optional


DEFAULT_IMAP_SERVER = "imap.yandex.ru"
DEFAULT_IMAP_PORT = 993
DEFAULT_360_API_URL = "https://api360.yandex.net"
DEFAULT_OAUTH_API_URL = "https://oauth.yandex.ru/token"
LOG_FILE = "get_audit.log"
DEFAULT_DAYS_AGO = 45
FILTERED_EVENTS = ["message_receive"]
FILTERED_MAILBOXES = ["alavret@yandry.ru"]


ID_HEADER_SET = {'Content-Type', 'From', 'To', 'Cc', 'Bcc', 'Date', 'Subject',
                                   'Message-ID', 'In-Reply-To', 'References', 'X-Yandex-Fwd', 'Return-Path', 'X-Yandex-Spam', "X-Mailer"}
FETCH_MESSAGE_DATA_UID = re.compile(rb'.*UID (?P<uid>\d+).*')
FETCH_MESSAGE_DATA_SEQNUM = re.compile(rb'(?P<seqnum>\d+) FETCH.*')
FETCH_MESSAGE_DATA_FLAGS  = re.compile(rb'.*FLAGS \((?P<flags>.*?)\).*')
MessageAttributes = namedtuple('MessageAttributes', 'uid flags sequence_number')

EXIT_CODE = 1

logger = logging.getLogger("get_audit_log")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
#file_handler = handlers.TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30, encoding='utf-8')
file_handler = handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024,  backupCount=5, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)
logger.addHandler(file_handler)

def arg_parser():
    parser = argparse.ArgumentParser(
        description=dedent(
            """
            Script for downloading audit log records from Yandex 360.

            Define Environment variables or use .env file to set values of those variables:
            OAUTH_TOKEN_ARG - OAuth Token,
            ORGANIZATION_ID_ARG - Organization ID,
            APPLICATION_CLIENT_ID_ARG - WEB Application ClientID,
            APPLICATION_CLIENT_SECRET_ARG - WEB Application secret

            For example:
            OAUTH_TOKEN_ARG = "AgAAgfAAAAD4beAkEsWrefhNeyN1TVYjGT1k",
            ORGANIZATION_ID_ARG =1 23
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    def argument_range(value: str) -> int:
        try:
            if int(value) < 0 or int(value) > 90:
                raise argparse.ArgumentTypeError(
                    f"{value} is invalid. Valid values in range: [0, 90]"
                )
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{value}' is not int value")
        return int(value)

    parser.add_argument(
        "--rfc-message-id", help="Message subject", type=str, required=False
    )
        
    parser.add_argument(
        "--days-ago",
        help="Number of days ago to search and download audit log records [0, 90]",
        type=argument_range,
        required=False,
    )
    return parser

def get_initials_config():
    parsr = arg_parser()
    try:
        args = parsr.parse_args()
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    try:
        settings = get_settings()
    except ValueError:
        logger.error(f"The value of ORGANIZATION_ID_ARG must be an integer.")
        sys.exit(EXIT_CODE)
    except KeyError as key:
        logger.error(f"Required environment vars not provided: {key}")
        #parsr.print_usage()
        sys.exit(EXIT_CODE)

    input_params = {}
    if args.days_ago is None: 
        logger.warning("Command line argument 'days_ago' is not set. Using default value - {DEFAULT_DAYS_AGO} days ago  }.")
        args.date_ago = DEFAULT_DAYS_AGO
    input_params["days_ago"] = args.date_ago

    if args.rfc_message_id is None: 
        input_params["message_ids"] = []
    else:
        l = []
        l.append(args.rfc_message_id)
        input_params["message_ids"] = l

    input_params["events"] = FILTERED_EVENTS
    input_params["mailboxes"] = FILTERED_MAILBOXES
    input_params["days_interval"] = args.date_ago
    settings.search_param = input_params

    return settings

    days_ago = args.days_ago
    imap_messages = {}
    records = fetch_audit_logs(settings, days_ago=days_ago)
    records = FilterEvents(records)
    target_records = []
    #print(records)
    for user in FILTERED_MAILBOXES:
        token = get_user_token(user, settings)
        if token:
            asyncio.run(get_imap_messages(user, token, days_ago, imap_messages))
            #print(imap_messages)
        for record in records:
            if record["userLogin"] == user and record["msgId"]:
                d = {}
                d["date"] = record["date"][0:-4]
                imap_data = imap_messages.get(record["msgId"],'')
                if imap_data:
                    d["from"] = imap_data['from']
                    if imap_data['folder'] == "Trash":
                        d["deleted"] = "Удалено"
                    else:
                        d["deleted"] = "Не удалено"
                else:
                    d["from"] = record["from"]
                    
                    d["deleted"] = "Удалено"

                d["subject"] = record["subject"]
                d["msgId"] = record["msgId"]
                target_records.append(d)

    last_day_of_prev_month = datetime.now().replace(day=1) - timedelta(days=1)
    check_value = last_day_of_prev_month.strftime("%Y-%m")
    last_month_records = []
    for record in target_records:
        if record["date"][:7] == check_value:
            last_month_records.append(record)

    #print(last_month_records)
    
    if last_month_records:

        file_name = f'{settings.output_file.split(".")[0]}_{datetime.now().strftime("%y-%m-%d_%H-%M-%S")}.csv'
        write_to_ifarma_file(last_month_records, file_name)

        logger.info(f"{len(records)} audit records written to {settings.output_file}")


    logger.info("Sript finished.")

def FilterEvents(events: list) -> list:
    filtered_events = []
    for event in events:
        if event["eventType"] in FILTERED_EVENTS and event["userLogin"] in FILTERED_MAILBOXES:
            filtered_events.append(event)
    return filtered_events

@dataclass
class SettingParams:
    oauth_token: str
    organization_id: int
    message_id_file_name: str
    mailboxes_to_search_file_name: str
    application_client_id: str
    application_client_secret: str
    search_param : dict

def get_settings():
    settings = SettingParams (
        oauth_token = os.environ.get("OAUTH_TOKEN_ARG"),
        organization_id = int(os.environ.get("ORGANIZATION_ID_ARG")),
        application_client_id = os.environ.get("APPLICATION_CLIENT_ID_ARG"),
        application_client_secret = os.environ.get("APPLICATION_CLIENT_SECRET_ARG"),
        message_id_file_name = os.environ.get("MESSAGE_ID_FILE_NAME"),
        mailboxes_to_search_file_name = os.environ.get("MAILBOXES_TO_SEARCH_FILE_NAME"),
        search_param = {}
    )
    return settings

def fetch_audit_logs(settings: "SettingParams", days_ago: int):
    day_last_check = (datetime.now().replace(hour=0, minute=0, second=0) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    log_records = []

    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.organization_id}/audit_log/mail"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}

    params = {
        "pageSize": 100,
        "afterDate": day_last_check,
    }
    
    while True:           
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request: {response.status_code}")
                return
            temp_list = response.json()["events"]

            logger.debug(f'Received {len(temp_list)} records, from {temp_list[-1]["date"]} to {temp_list[0]["date"]}')
            for entry in temp_list:
                log_records.append(parse_to_dict(entry))
            #log_records.extend(temp_list)
            if response.json()["nextPageToken"] == "":
                break
            else:
                params["pageToken"] = response.json()["nextPageToken"]
        except requests.exceptions.RequestException as err:
            logger.error(f"Error during GET request: {err}")
            return
        
    return log_records

def WriteToFile(data, filename):
    with open(filename, 'w', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=data[0].keys(), delimiter=';')

        writer.writeheader()
        writer.writerows(data)

def write_to_ifarma_file(data, filename):
    field_names = ["Дата-время", "От кого", "Тема", "Идентификатор", "Удалено да/нет"]
    prepared_data = []
    for entry in data:
        prepared_data.append({
            "Дата-время": entry["date"],
            "От кого": entry["from"],
            "Тема": entry["subject"],
            "Идентификатор": entry["msgId"],
            "Удалено да/нет": entry["deleted"]
        })
    with open(filename, 'w', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=field_names, delimiter=';')

        writer.writeheader()
        writer.writerows(prepared_data)

def parse_to_dict(data: dict):
    #obj = json.dumps(data)
    d = {}
    d["eventType"] = data.get("eventType",'')
    d["date"] = data.get("date").replace('T', ' ').replace('Z', '')
    d["userLogin"] = data.get("userLogin",'')
    d["userName"] = data.get("userName",'')
    d["from"] = data.get("from",'')
    d["to"] = data.get("to",'')
    d["subject"] = data.get("subject",'')
    d["folderName"] = data.get("folderName",'')
    d["folderType"] = data.get("folderType",'')
    d["labels"] = data.get("labels",[])
    d["orgId"] = data.get("orgId")
    d["requestId"] = data.get("requestId",'')
    d["clientIp"] = data.get("clientIp",'')
    d["userUid"] = data.get("userUid",'')
    d["msgId"] = data.get("msgId",'')
    d["uniqId"] = data.get("uniqId",'')
    d["source"] = data.get("source",'')
    d["mid"] = data.get("mid",'')
    d["cc"] = data.get("cc",'')
    d["bcc"] = data.get("bcc",'')
    d["destMid"] = data.get("destMid",'')
    d["actorUid"] = data.get("actorUid",'')
    return d
    


def log_error(info="Error"):
    logger.error(info)

def log_info(info="Info"):
    logger.info(info)

def log_debug(info="Debug"):
    logger.debug(info)

def get_user_token(user_mail: str, settings: "SettingParams"):
    logger.debug(f"Getting user token for {user_mail}")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": settings.application_client_id,
        "client_secret": settings.application_client_secret,
        "subject_token": user_mail,
        "subject_token_type": "urn:yandex:params:oauth:token-type:email",
    }
    response = requests.post(url=DEFAULT_OAUTH_API_URL, headers=headers, data=data)
    logger.debug(f"User token for {user_mail} received")
    return response.json()["access_token"]
    if response.status_code != HTTPStatus.OK.value:
        logger.exception(f"Error during GET request: {response.status_code}")
    return ''

async def get_imap_messages(user_mail: str, token: str, days_ago: int, imap_messages: dict):
    message_dict = {}
    loop = asyncio.get_running_loop()
    today = datetime.now() 
    date_days_ago = today - timedelta(days=days_ago)
    search_criteria = f'(SINCE {date_days_ago.strftime("%d-%b-%Y")})'
    with concurrent.futures.ThreadPoolExecutor() as pool:
        logger.debug(f"Connect to IMAP server for {user_mail}")
        await loop.run_in_executor(pool, log_debug, f"Connect to IMAP server for {user_mail}")
    try:
        imap_connector = aioimaplib.IMAP4_SSL(host=DEFAULT_IMAP_SERVER, port=DEFAULT_IMAP_PORT)
        imap_connector = aioimaplib.IMAP4_SSL(host=DEFAULT_IMAP_SERVER, port=DEFAULT_IMAP_PORT)
        await imap_connector.wait_hello_from_server()
        await imap_connector.xoauth2(user=user_mail, token=token)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            await loop.run_in_executor(pool, log_debug, f"Connect to IMAP server for {user_mail} successful")
        status, folders = await imap_connector.list('""', "*")
        folders = [map_folder(folder) for folder in folders if map_folder(folder)]
        for folder in folders:
            with concurrent.futures.ThreadPoolExecutor() as pool:
                await loop.run_in_executor(pool, log_debug, f"Get messages from {folder}")
            await imap_connector.select(folder)
  
            response = await imap_connector.search(search_criteria)
            if response.result == 'OK':
                if len(response.lines[0]) > 0:
                    for num in response.lines[0].split():
                        message_dict = {}
                        response = await imap_connector.fetch(int(num), '(UID FLAGS BODY.PEEK[HEADER.FIELDS (%s)])' % ' '.join(ID_HEADER_SET))
                        if response.result == 'OK':
                            for i in range(0, len(response.lines) - 1, 3):
                                fetch_command_without_literal = b'%s %s' % (response.lines[i], response.lines[i + 2])

                                uid = int(FETCH_MESSAGE_DATA_UID.match(fetch_command_without_literal).group('uid'))
                                flags = FETCH_MESSAGE_DATA_FLAGS.match(fetch_command_without_literal).group('flags')
                                seqnum = FETCH_MESSAGE_DATA_SEQNUM.match(fetch_command_without_literal).group('seqnum')
                                # these attributes could be used for local state management
                                message_attrs = MessageAttributes(uid, flags, seqnum)
                                message_dict["uid"] = uid
                                message_dict["flags"] = flags.decode("ascii")
                                message_dict["seqnum"] = int(seqnum.decode("ascii"))
                                message_dict["folder"] = folder
                                print(message_attrs)

                                # uid fetch always includes the UID of the last message in the mailbox
                                # cf https://tools.ietf.org/html/rfc3501#page-61
                                message_headers = BytesHeaderParser().parsebytes(response.lines[i + 1])
                                for header in message_headers.keys():
                                    decoded_to_intermediate = decode_header(message_headers[header])
                                    header_value = []
                                    for s in decoded_to_intermediate:
                                        if s[1] is not None:
                                            header_value.append(s[0].decode(s[1]))
                                        else:
                                            if isinstance(s[0], (bytes, bytearray)):
                                                header_value.append(s[0].decode("ascii").strip())
                                            else:
                                                header_value.append(s[0])
                                    with concurrent.futures.ThreadPoolExecutor() as pool:
                                        await loop.run_in_executor(pool, log_debug, f'{header}: {" ".join(header_value) if len(header_value) > 1 else header_value[0]}')
                                    #print(f'{header}: {" ".join(header_value.split()) if len(header_value) > 1 else header_value[0]}')
                                    message_dict[header.lower()] = f'{" ".join(header_value) if len(header_value) > 1 else header_value[0]}'
                        imap_messages[message_dict["message-id"]] = message_dict
            else:
                continue

    except Exception as e:
        with concurrent.futures.ThreadPoolExecutor() as pool:
            await loop.run_in_executor(pool, log_debug, f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        #logger.exception(exp)       
    return imap_messages

def map_folder(folder: Optional[bytes]) -> Optional[str]:
    if not folder or folder == b"LIST Completed.":
        return None
    valid = folder.decode("ascii").split('"|"')[-1].strip().strip('""')
    return f'"{valid}"'

def main_menu(settings: SettingParams):

    while True:
        print("\n")
        print("---------------------- Config params ----------------------")
        for key, value in settings.search_param.items():
            print(f"{key}: {value}")
        print("------------------------------------------------------------")
        #print("\n")
        print("Select option:")
        print("1. Set messate id.")
        print("2. Set days ago.")
        print("3. Enter count of days for search.")
        print("4. Enter mailboxes to search nemu.")
        print("5. Search and delete menu.")
        # print("3. Delete all contacts.")
        # print("4. Output bad records to file")
        print("0. Exit")

        choice = input("Enter your choice (0-5): ")

        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            set_message_id_menu(settings)
        elif choice == "2":
            set_days_ago(settings)
        elif choice == "3":
            set_count_of_days(settings)
        elif choice == "4":
            set_mailboxes_menu(settings)
        else:
            print("Invalid choice. Please try again.")
    return settings

def set_days_ago(settings: SettingParams):
    print("\n")
    print("----------------- Set days ago ----------------------")
    print(f"Current days ago: {settings.search_param['days_ago']}")
    print("-----------------------------------------------------")
    print("\n")
    answer = input("Enter number of days ago to search from (empty string to cancel): ")
    if answer:
        if answer.isdigit():
            if int(answer) > 0 and int(answer) < 90:
                settings.search_param['days_ago'] = int(answer)
                settings.search_param['days_interval'] = int(answer)
            else:
                print("Invalid number of days ago (max 90 days). Please try again.")
    return settings

def set_count_of_days(settings: SettingParams):
    print("\n")
    print("----------------- Set number of days to search ----------------------")
    print(f"Current days ago: {settings.search_param['days_interval']}")
    print("---------------------------------------------------------------------")
    print("\n")
    answer = input("Enter number of days to search to (empty string to cancel): ")
    if answer:
        if answer.isdigit():
            if int(answer) > 0 and int(answer) < settings.search_param['days_ago']:
                settings.search_param['days_interval'] = int(answer)
            else:
                print(f"Invalid number of days ago (max {settings.search_param['days_ago']} days). Please try again.")
    return settings


def set_mailboxes_menu(settings: SettingParams):
    while True:
        print("\n")
        print("----------------- Set mailboxes to search menu ----------------------")
        print(f"Current mailboxes list: {settings.search_param['mailboxes']}")
        print("---------------------------------------------------------------------")
        #print("\n")
        print("Select option:")
        print("1. Enter mailboxes to search manually.")
        print(f"2. Load mailboxes to search from file ({settings.mailboxes_to_search_file_name}).")
        print("3. Clear mailboxes to search.")

        print("0. Exit to main menu.")

        choice = input("Enter your choice (0-2): ")

        if choice == "0":
            #print("Goodbye!")
            break
        elif choice == "1":
            print('\n')
            set_message_id_manually(settings)
        elif choice == "2":
            print('\n')
            set_message_id_from_file()
        elif choice == "3":
            print('\n')
            clear_message_id(settings)

        else:
            print("Invalid choice. Please try again.")
    return settings

def clear_message_id(settings: SettingParams):
    answer = input("Clear mailboxes list? (Y/n): ")
    if answer.upper() not in ["Y", "YES"]:
        return settings
    settings.search_param["mailboxes"] = []
    return settings

def set_message_id_manually(settings: SettingParams):
    answer = input("Enter several emails, sparated by comma or semicolon: ")
    if answer:
        manually_list = answer.replace(",", ";").split(";")
        for manual in manually_list:
            settings.search_param["mailboxes"].append(manual.strip())
        return settings
    return settings
    
def set_message_id_from_file(settings: SettingParams):
    file_name = settings.mailboxes_to_search_file_name
    if not os.path.exists(file_name):
        full_path = os.path.join(os.path.dirname(__file__), file_name)
        if not os.path.exists(full_path):
            logger.error(f'ERROR! Input file {file_name} not exist!')
            return settings
        else:
            file_name = full_path            
    
    ## Another way to read file with needed transfromations
    headers = []
    data = []
    try:
        logger.info("-" *100)
        logger.info(f'Reading file {file_name}')
        logger.info("-" *100)
        with open(file_name, 'r', encoding='utf-8') as csvfile:
            headers = csvfile.readline().replace('"', '').replace(",",";").split(";")
            logger.debug(f'Headers: {[h.strip() for h in headers]}')
            for line in csvfile:
                logger.debug(f'Reading from file line - {line}')
                fields = line.replace('"', '').replace(",",";").split(";")
                entry = {}
                for i,value in enumerate(fields):
                    entry[headers[i].strip()] = value.strip()
                data.append(entry["mailbox"])
        logger.info(f'End reading file {file_name}')
        logger.info("\n")
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return settings

    if data:
        logger.info("-" *100)
        logger.info(f'Mailboxes, that will be added from file {file_name}')
        logger.info("-" *100)
        for line in data:
            logger.info(line)

        answer = input("Mailboxes will be replaced. Continue? (Y/n): ")
        if answer.upper() in ["Y", "YES"]:
            settings.search_param["mailboxes"] = []
            settings.search_param["mailboxes"].extend(data)
    else:
        logger.info("-" *100)
        logger.info(f'No lines in {file_name}')
        logger.info("-" *100)
    
    return settings

def set_message_id_menu(settings: SettingParams):
    while True:
        print("\n")
        print("----------------- Set message id menu ----------------------")
        print(f"Current message IDs: {settings.search_param['message_ids']}")
        print("------------------------------------------------------------")
        #print("\n")
        print("Select option:")
        print("1. Enter messate id manually.")
        print(f"2. Load message id from file ({settings.message_id_file_name}).")
        print("3. Clear message id.")

        print("0. Exit to main menu.")

        choice = input("Enter your choice (0-2): ")

        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            print('\n')
            set_message_id_manually(settings)
        elif choice == "2":
            print('\n')
            set_message_id_from_file(settings)
        elif choice == "3":
            print('\n')
            clear_message_id(settings)

        else:
            print("Invalid choice. Please try again.")
    return settings

def clear_message_id(settings: SettingParams):
    answer = input("Clear message-ids list? (Y/n): ")
    if answer.upper() not in ["Y", "YES"]:
        return settings
    settings.search_param["message_ids"] = []
    return settings

def set_message_id_manually(settings: SettingParams):
    answer = input("Enter several message id, sparated by comma or semicolon: ")
    if answer:
        manually_list = answer.replace(",", ";").split(";")
        for manual in manually_list:
            settings.search_param["message_ids"].append(manual.strip())
        return settings
    
def set_message_id_from_file(settings: SettingParams):
    file_name = settings.message_id_file_name
    if not os.path.exists(file_name):
        full_path = os.path.join(os.path.dirname(__file__), file_name)
        if not os.path.exists(full_path):
            logger.error(f'ERROR! Input file {file_name} not exist!')
            return settings
        else:
            file_name = full_path
    
    ## Another way to read file with needed transfromations
    headers = []
    data = []
    try:
        logger.info("-" *100)
        logger.info(f'Reading file {file_name}')
        logger.info("-" *100)
        with open(file_name, 'r', encoding='utf-8') as csvfile:
            headers = csvfile.readline().replace('"', '').replace(",",";").split(";")
            logger.debug(f'Headers: {[h.strip() for h in headers]}')
            for line in csvfile:
                logger.debug(f'Reading from file line - {line}')
                fields = line.replace('"', '').replace(",",";").split(";")
                entry = {}
                for i,value in enumerate(fields):
                    entry[headers[i].strip()] = value.strip()
                data.append(entry["message-id"])
        logger.info(f'End reading file {file_name}')
        logger.info("\n")
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return settings

    if data:
        logger.info("-" *100)
        logger.info(f'Message IDs, that will be added from file {file_name}')
        logger.info("-" *100)
        for line in data:
            logger.info(line)

        answer = input("Message IDs will be replaced. Continue? (Y/n): ")
        if answer.upper() in ["Y", "YES"]:
            #settings.search_param["message_ids"].clear()
            settings.search_param["message_ids"] = data
    else:
        logger.info("-" *100)
        logger.info(f'No lines in {file_name}')
        logger.info("-" *100)
    
    return settings

if __name__ == "__main__":

    denv_path = os.path.join(os.path.dirname(__file__), '.env')

    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path,verbose=True, override=True)

    settings = get_initials_config()
    try:
        main_menu(settings)
    except Exception as exp:
        logging.exception(exp)
        sys.exit(EXIT_CODE)