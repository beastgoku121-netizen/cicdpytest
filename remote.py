import sys
from dotenv import load_dotenv
load_dotenv('.env')

import json
import requests,jwt
from cryptography.fernet import Fernet
from log_handler.nmr_logger import NMRLogger
import os, time
from datetime import datetime
import subprocess

def secrets(key):
    return os.environ.get(key)

CURRENT_HASH_FILE_PATH = secrets('CURRENT_HASH_FILE_PATH')
DA_MASTER_IP = secrets('DA_MASTER_IP')
input_path = secrets('input_path')
output_path = secrets('output_path')
log_path = secrets('log_path')
analysis_script_path = secrets('analysis_script_path')
ram_dump_path = secrets('ram_dump_path')
behaviorResultsFilename = secrets('behaviorResultsFilename')
networkResultsFilename = secrets('networkResultsFilename')
memoryResultsFilename = secrets('memoryResultsFilename')

#encryption, decryption and jwt token keys
DA_MASTER_TO_DA_WORKER = secrets('DA_MASTER_TO_DA_WORKER').encode()
DA_WORKER_TO_DA_MASTER = secrets('DA_WORKER_TO_DA_MASTER').encode()
JWT_SECRET_KEY = secrets('JWT_SECRET_KEY')

#api endpoints
downloadAPI = secrets('downloadAPI')
uploadAPI = secrets('uploadAPI')
worker_ping_api = secrets('worker_ping_api')
logs_upload_api = secrets('logs_upload_api')
memory_upload_api = secrets('memory_upload_api')
get_task_url = secrets('get_task_url')

if not os.path.exists(input_path):
    os.makedirs(input_path)

if not os.path.exists(output_path):
    os.makedirs(output_path)

oldPids, newPids = [], []

logger = NMRLogger(platform="linux", module="DA-Behavioural-Engine", subModule="remote", path=log_path)
logger.info(message=f"Initialized",event="DA Worker is up and running")

def encrypt_data(sample_fingerprint, data, key):
    try:
        FernetObject = Fernet(key)
        encryptedData = FernetObject.encrypt(data)
        return encryptedData
    except Exception as e:
        logger.error(sample_hash=sample_fingerprint, message=f"encrypt_data :: error occured  :: {e}")
        raise Exception(f"encrypt_data :: error occured :: {e}")

def decrypt_data(sample_fingerprint, data, key):
    try:
        FernetObject = Fernet(key)
        decryptedData = FernetObject.decrypt(data)
        return decryptedData
    except Exception as e:
        logger.error(sample_hash=sample_fingerprint, message=f"decrypt_data :: error occured  :: {e}")
        raise Exception(f"decrypt_data :: error occured :: {e}")

def create_jwt_token(sample_fingerprint, data, dict_key):
    try:
        jwtToken = jwt.encode({dict_key: data}, JWT_SECRET_KEY)
        return jwtToken
    except Exception as e:
        logger.error(sample_hash=sample_fingerprint, message=f"create_jwt_token :: error occured  :: {e}")
        raise Exception(f"create_jwt_token :: error occured :: {e}")

def decode_jwt_token(sample_fingerprint, token):
    try:
        data = jwt.decode(token, JWT_SECRET_KEY, algorithms="HS256")
        return data
    except Exception as e:
        logger.error(sample_hash=sample_fingerprint, message=f"decode_jwt_token :: error occured  :: {e}")
        raise Exception(f"decode_jwt_token :: error occured :: {e}")

def decode_and_decrypt(sample_fingerprint, token, key):
    token_data = decode_jwt_token(sample_fingerprint, token=token)
    logger.debug(sample_hash=sample_fingerprint, message=f"decode_and_decrypt :: token decoded")
    data = decrypt_data(sample_fingerprint=sample_fingerprint, data=token_data["data"].encode(), key=key)
    logger.debug(sample_hash=sample_fingerprint, message=f"decode_and_decrypt :: data decrypted")
    return data

def encrypt_and_create_token(sample_fingerprint, data, key, dict_key):
    encrypted_data = encrypt_data(sample_fingerprint=sample_fingerprint, data=data, key=key)
    logger.debug(sample_hash=sample_fingerprint, message=f"encrypt_and_create_token :: data encrypted")
    token = create_jwt_token(sample_fingerprint, encrypted_data.decode(), dict_key=dict_key)
    logger.debug(sample_hash=sample_fingerprint, message=f"encrypt_and_create_token :: token created")
    return token

def get_vm_name():
    try:
        logger.debug(message=f"get_vm_name function called")
        try:
            ip = subprocess.check_output(['hostname','--all-ip-addresses']).decode().split(' ')[0].replace('.','_')
        except Exception as E:
            logger.debug(message=f"Error occurred in get_static_ip function. Defaulting to 0.0.0.0")
            ip = "0_0_0_0"
        logger.debug(message = f"ip of machine = {ip}")
        vmName = f"DA_ANDROID_ENGINE_{ip}"
        logger.debug(message = f"vmName is ||| {vmName}")
        return vmName
    except Exception as E:
        logger.error(message=f"get_vm_name function Error occurred || {E}")
        raise Exception(f"get_vm_name function Error occurred || {E}")

def getAllPids():
    pid_list = []
    ret = subprocess.check_output(["ps","-ef"]).decode().split('\n')
    ret.pop(0)
    ret.pop(-1)
    for lines in ret:
        pid_list.append(lines.split()[1])
    return pid_list

def send_worker_details_to_da_master(environment,filetype,hash_value):
    try:
        logger.debug(sample_hash=hash_value,message=f"send_worker_details_to_da_master function called")
        vmName = get_vm_name()
        url = f"http://{DA_MASTER_IP}/{worker_ping_api}/{environment}/{filetype}/{hash_value}/{vmName}"
        resp = requests.get(url)
        if resp.text == 'success':
            logger.debug(sample_hash=hash_value,message=f"Worker details sent to DA master")
            return "success"
        else:
            logger.debug(sample_hash=hash_value,message=f"Worker details upload to DA master FAILED")
            return "failed"
    except Exception as E:
        logger.error(sample_hash=hash_value,message=f"send_worker_details_to_da_master function Error occurred || {E}")
        return "failed"

def download_sample_from_master(hash_value):
    try:
        logger.debug(sample_hash=hash_value,message=f"download_sample_from_master function called")
        download_url = f"http://{DA_MASTER_IP}/{downloadAPI}/{hash_value}"
        response = requests.get(download_url)
        logger.debug(sample_hash=hash_value,message=f"Response received from da master")
        jwtToken = response.content
        plainData = decode_and_decrypt(sample_fingerprint=hash_value, token=jwtToken, key=DA_MASTER_TO_DA_WORKER)
        with open(os.path.join(input_path,hash_value),'wb') as fp:
            fp.write(plainData)
        logger.debug(sample_hash=hash_value,message=f"Sample file written to disk. download_sample_from_master function complete")
        return "success"
    except Exception as E:
        logger.error(sample_hash=hash_value,message=f"download_sample_from_master function Error occurred || {E}")
        return "failed"

def upload_hash_secific_logs_to_da_master(hash_value):
    try:
        logger.debug(sample_hash=hash_value,message=f"Analysis and upload complete. Reading logs")
        logfilepath = f"{log_path}/android_worker.{hash_value}.log"
        with open(logfilepath, 'rb') as fp:
            log_content = fp.read()
        token = encrypt_and_create_token(sample_fingerprint=hash_value, data=log_content, key=DA_WORKER_TO_DA_MASTER, dict_key='log_content')
        URL = f"http://{DA_MASTER_IP}/{logs_upload_api}/{hash_value}/{get_vm_name()}"
        response = requests.post(URL, data=token)
        if response.text == "success":
            os.system(f"rm {logfilepath}")
        logger.debug(sample_hash=hash_value,message=f"Log upload complete to DA Master.")
        return "success"
    except Exception as E:
        logger.error(sample_hash=hash_value,message=f"upload_dynamic_results_to_da_master function Error occurred || {E}")
        return "failed"

def check_unable_partial_error_files(hash_value):
    try:
        logger.debug(sample_hash=hash_value,message=f"check_unable_partial_error_files function called.")
        hashdirectory = f'{output_path}/{hash_value}'
        important_files = ['unable.txt', 'partial.txt', 'completed.txt']
        for filename in os.listdir(hashdirectory):
            if filename.lower() in important_files:
                logger.info(sample_hash=hash_value, message=f"{filename.lower()} found in results therefore not generating any error files")
                filepath = f'{hashdirectory}/{filename}'
                ret5 = os.system(f"python3 ./android_results_compressor.py {input_path} {output_path} {hash_value}")
                p1 = subprocess.Popen(["/usr/bin/7z","a",f"{hash_value}_Dynamic_Analysis_Results.7z",filepath],cwd=f"{hashdirectory}/")
                p1.wait()
                return
        logger.info(sample_hash=hash_value, message=f"no txt file found therefore generating error.txt")
        filepath = f"{hashdirectory}/{hash_value}_Dynamic_Error.txt"
        error = "Error occurred in dynamic analysis. No results were available."
        plainData = error.encode()
        with open(filepath, "wb") as fp:
            fp.write(plainData)
        p1 = subprocess.Popen(["/usr/bin/7z","a",f"{hash_value}_Dynamic_Analysis_Results.7z",filepath],cwd=f"{hashdirectory}/")
        p1.wait()
    except Exception as E:
        logger.error(sample_hash=hash_value, message=f"Error occurred in check_unable_partial_error_files :: {E}")

def createDummyResults(hash_value, module, error="Error Occcurred. No results available for analysis"):
    try:
        logger.debug(sample_hash=hash_value,message=f"createDummyResults function called for {module}")
        hashdirectory = f'{output_path}/{hash_value}'
        if not os.path.exists(hashdirectory):
            os.makedirs(hashdirectory)
        da_unable_flag = os.path.join(hashdirectory, "unable.txt")
        if module=='Dynamic':
            # we are not handling dynamic error here as it is now handled while uploading dynamic results.
            return
        elif os.path.exists(da_unable_flag):
            logger.debug(sample_hash=hash_value, message=f"DA created unable file therefore memory analysis is not possible. creating unable.txt for it.")
            filepath = f"{hashdirectory}/{hash_value}_{module}_Unable.txt"
        else:
            filepath = f"{hashdirectory}/{hash_value}_{module}_Error.txt"
        plainData = error.encode()
        with open(filepath, "wb") as fp:
            fp.write(plainData)
        p1 = subprocess.Popen(["/usr/bin/7z","a",f"{hash_value}_{module}_Analysis_Results.7z",filepath],cwd=f"{output_path}/{hash_value}/")
        p1.wait()
    except Exception as E:
        logger.error(sample_hash=hash_value,message=f"Error occurred in createDummyResults ||| {E}")
        return "failed"

def error_handling(environment, filetype, hash_value,  error="Error Occcurred. No results available for analysis"):
    try:
        logger.debug(sample_hash=hash_value,message=f"error_handling function called")
        # createDummyResults(hash_value, module='Dynamic', error=error)
        createDummyResults(hash_value, module='Memory', error=error)
        upload_dynamic_results_to_da_master(environment, filetype, hash_value)
    except Exception as E:
        logger.error(sample_hash=hash_value,message=f"error_handling function Error occurred || {E}")

def kill_all_hanging_process(environment, filetype, hash_value):
    try:
        newPids = getAllPids()
        pidsToKill = list()
        for pid in newPids:
            if pid not in oldPids:
                try:
                    pidsToKill.append(pid)
                    os.system(f"sudo kill -9 {pid}")
                except Exception as E:
                    logger.debug(sample_hash=hash_value, message = f" Error in killing process {pid}. Pid must be closed already")
        logger.debug(sample_hash = hash_value,message = f" PIDS killed ||| {pidsToKill} ") 
        # createDummyResults(hash_value, module='Dynamic', error="Exception occurred in android_dynamic_analysis")
        createDummyResults(hash_value, module='Memory', error="Exception occurred in android_dynamic_analysis")
        ret = upload_dynamic_results_to_da_master(environment, filetype, hash_value) 
        logger.debug(sample_hash=hash_value, message = f"Hanging processes killed. Task reverted to normal state")
    except Exception as E:
        logger.error(sample_hash=hash_value, message=f"Error occurred in kill_all_hanging_process ::: {E}")

def upload_memory_results_to_da_master(hash_value, filetype, environment):
    try:
        logger.debug(sample_hash=hash_value,message = f"Reading memory analysis results")
        memoryFile = f"{output_path}/{hash_value}/{hash_value}_{memoryResultsFilename}"
        with open(memoryFile,'rb') as fp:
            memoryContent = fp.read()
        jwtToken = encrypt_and_create_token(sample_fingerprint=hash_value, data=memoryContent, key=DA_WORKER_TO_DA_MASTER, dict_key='memoryData')
        URL = f"http://{DA_MASTER_IP}/{memory_upload_api}/{environment}/{filetype}/{hash_value}"
        vm = get_vm_name()
        response = requests.post(URL, data=jwtToken, headers = {"vmName":vm})
        add_in_current_hash_log([('memory_sent',response.text)])
        if response.text == "success":
            logger.debug(sample_hash=hash_value,message=f"upload_memory_results_to_da_master complete")
            return "success"
        else:
            logger.debug(sample_hash=hash_value,message=f"upload_memory_results_to_da_master failed")
            return "failed"
    except Exception as E:
            logger.debug(message = f"Error occurred in  upload_memory_results_to_da_master:: {E}")
            return "failed"

def upload_dynamic_results_to_da_master(environment, filetype, hash_value):
    try:
        logger.debug(sample_hash=hash_value,message=f"upload_dynamic_results_to_da_master function called")
        check_unable_partial_error_files(hash_value)
        behaviorFile = f"{output_path}/{hash_value}/{hash_value}_{behaviorResultsFilename}"
        with open(behaviorFile,'rb') as fp:
            behaviorContent = fp.read()
        jwtToken = encrypt_and_create_token(sample_fingerprint=hash_value, data=behaviorContent, key=DA_WORKER_TO_DA_MASTER, dict_key='behaviorData')
        URL = f"http://{DA_MASTER_IP}/{uploadAPI}/{environment}/{filetype}/{hash_value}"
        vm = get_vm_name()
        response = requests.post(URL, data=jwtToken, headers = {"vmName":vm})
        add_in_current_hash_log([('dynamic_sent',response.text)])
        if response.text == "success":
            logger.debug(sample_hash=hash_value,message=f"upload_dynamic_results_to_da_master complete")
            return "success"
        else:
            logger.debug(sample_hash=hash_value,message=f"upload_dynamic_results_to_da_master failed")
            return "failed"
    except Exception as E:
        logger.error(sample_hash=hash_value,message=f"upload_dynamic_results_to_da_master function Error occurred || {E}")
        return "failed"

def add_in_current_hash_log(kvTupleList):
    if not os.path.exists(CURRENT_HASH_FILE_PATH):
        os.system(f'touch {CURRENT_HASH_FILE_PATH}')
    data={}
    with open(CURRENT_HASH_FILE_PATH,'r+') as csh:
        try:
            data = json.load(csh)
            print(f'data:{data}')
        except json.decoder.JSONDecodeError as e:
            print(f'-----------error caught------------ {e}')
        for k,v in kvTupleList:
            data[k] = v
        csh.seek(0)
        json.dump(data, csh,indent=4)
        csh.truncate()

def android_dynamic_analysis(environment, filetype, hash_value):
    global logger
    logger = NMRLogger(platform="dynamic_android_analysis", module="android_worker", subModule=hash_value, path=log_path)
    logger.debug(sample_hash=hash_value,message=f"android_dynamic_analysis function called || {environment} {filetype}")
    
    if environment.lower() != 'android':
        logger.error(sample_hash=hash_value,message=f"Error. Environment is not Android. Analysis Aborted")
        error_handling(environment, filetype, hash_value,error=f"Analysis is not feasible as wrong environment is passed ::: {environment}.")
        return "failed, environment is not android"
    
    ret = download_sample_from_master(hash_value)
    if ret != "success":
        logger.error(f"failed, {ret} for {hash_value} in download")
        error_handling(environment, filetype, hash_value, error=f"Error occurred in sample downloading.")
        return "failed"
    
    send_worker_details_to_da_master(environment,filetype,hash_value)
    
    try:
        logger.debug(sample_hash=hash_value,message="Entering android Analysis environment")
        global oldPids
        oldPids = getAllPids()
        
        logger.debug(sample_hash=hash_value, message= "Calling First Analysis command for android dyanmic analyzer")
        ret1 = os.system(f"/home/ubuntu/Desktop/BehaviouralEngine/nmr_dynamicanalysis_android/advenv/bin/python3 {analysis_script_path} {input_path} {output_path} {hash_value}")

        logger.debug(sample_hash=hash_value, message = f"Dynamic analyzer command completed ||| return_code :: {ret1}")

        fileCheckLocation = f"{output_path}/{hash_value}/Dynamic_Analysis_Results"
        os.system(f"sudo chown -R ubuntu:ubuntu {output_path}/{hash_value}")
        logger.debug(sample_hash=hash_value,message = f"Checking for existance of network pcap and memory ram_dump.lime file at location {fileCheckLocation}")
        memoryAnalysisFlag = os.path.exists(f"{fileCheckLocation}/ram_dump.lime")
        networkAnalysisFlag = os.path.exists(f"{fileCheckLocation}/network.pcap")
        logger.debug(sample_hash=hash_value,message=f"Memory Ram_Dump.lime File created : {memoryAnalysisFlag}")
        logger.debug(sample_hash=hash_value, message=f"Network PCAP file created: {networkAnalysisFlag}")

        if networkAnalysisFlag:
            if not os.path.exists(f"{output_path}/{hash_value}/PCAP"):
                os.makedirs(f"Sample_Output/{hash_value}/PCAP")
            net_copy = os.system(f"mv {output_path}/{hash_value}/Dynamic_Analysis_Results/network.pcap {output_path}/{hash_value}/PCAP/out.pcap")
            logger.debug(sample_hash=hash_value,message = f"copy of network pcap file complete || cp command result:  {net_copy}")
            subprocess.call(["7z", "a", f"{hash_value}_{behaviorResultsFilename}", "PCAP"], cwd=f"{output_path}/{hash_value}")

        if memoryAnalysisFlag:
            mem_copy = os.system(f"cp {output_path}/{hash_value}/Dynamic_Analysis_Results/ram_dump.lime {ram_dump_path}/{hash_value}_ram_dump.lime")
            logger.debug(sample_hash=hash_value,message = f"copy of ram dump lime file complete || cp command result:  {mem_copy}")
        else:
            logger.debug(sample_hash=hash_value,message=f"No Ram_Dump file available. Analysis can not be triggered.")
            # not calling dummy results generation as it is handled later.
            
        logger.info(sample_hash=hash_value, message=f"memory and network input files copied to desired location.")

        # ret5 = os.system(f"python3 ./android_results_compressor.py {input_path} {output_path} {hash_value}")
        # logger.debug(sample_hash = hash_value, message = f"Android results compressor called. {ret5}")

        if not os.path.exists(f"{fileCheckLocation}/Android_Dynamic_Analysis_API_Monitor_Result.json"):
            logger.debug(sample_hash=hash_value,message=f"API monitor result does not exist.")
            # createDummyResults(hash_value, module='Dynamic', error="Results file was not present.")
        upload_dynamic_results_to_da_master(environment, filetype, hash_value)

        if os.path.exists(f"{ram_dump_path}/{hash_value}_ram_dump.lime"):
            logger.debug(sample_hash = hash_value, message = f"Now initiating memory analysis.")
            memoryAnalysis = subprocess.Popen(["NMR_MemoryDataCollection_Android/memory_venv/bin/python","NMR_MemoryDataCollection_Android/new_automate.py",hash_value,f"{ram_dump_path}/{hash_value}_ram_dump.lime","report.7z"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            memoryAnalysis.communicate()
            logger.debug(sample_hash=hash_value, message = "Memory analysis complete")
            ret4 = os.system(f"mv report.7z {output_path}/{hash_value}/{hash_value}_Memory_Analysis_Results.7z")
            logger.debug(sample_hash=hash_value, message = f"Memory report file moved to output directory ::: {ret4}")
        else:
            logger.debug(sample_hash=hash_value,message=f"No Ram_Dump file copied. Analysis can not be triggered creating memory dummy results now.")
            createDummyResults(hash_value, module='Memory', error="copying of Ram_Dump file failed. Analysis can not be triggered")
    except Exception as E:
        logger.error(sample_hash=hash_value,message=f"Exception Occurred in dynamic android analysis. Killing al hanging processes.||| {E}")
        kill_all_hanging_process(environment, filetype, hash_value)

def get_task_from_master():
    try:
        url = f"http://{DA_MASTER_IP}/{get_task_url}"
        ret = requests.get(url=url)
        print(f'get_android_task: {ret.text}')
        if ret.text == "success":
            hash_value = ret.headers['hash_value']
            filetype = ret.headers['filetype']
            environment = ret.headers['environment']
            logger.info(message=f"get_task_from_master received task |||  {environment} {filetype} {hash_value}")
            add_in_current_hash_log([('hash',hash_value),('file_type',filetype),('environment',environment)])
            android_dynamic_analysis(hash_value=hash_value, environment=environment, filetype=filetype)
            while True:
                if not os.path.exists(f"{output_path}/{hash_value}/{hash_value}_{memoryResultsFilename}"):
                    print("waiting for memory analysis results.")
                    time.sleep(10)
                else:
                    upload_memory_results_to_da_master(hash_value, filetype, environment)
                    break
            upload_hash_secific_logs_to_da_master(hash_value)
            os.system(f'rm {CURRENT_HASH_FILE_PATH}')
    except Exception as E:
        logger.debug(message = f"Error occurred in  get_task_from_master:: {E}")

if __name__ == '__main__':
        while True:
            try:
                get_task_from_master()
                time.sleep(10)
            except:
                sys.exit(1)
