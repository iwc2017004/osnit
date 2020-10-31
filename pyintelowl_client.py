import hashlib
import os
import requests
import time

from pyintelowl.pyintelowl import (
    IntelOwl,
    IntelOwlClientException
)
from pyintelowl.token_auth import (
    IntelOwlInvalidAPITokenException
)

def get_reports_from_intelowl_server(file_path,api_token_file,url):
    md5 = None
    results = []
    elapsed_time = None
    try:
        filename = None
        binary = None
        if not os.path.exists(file_path):
            raise IntelOwlClientException("{} does not exists".format(file_path))
        with open(file_path, "rb") as f:
            binary = f.read()
            filename = os.path.basename(f.name)
        md5 = hashlib.md5(binary).hexdigest()

        pyintelowl_client = IntelOwl(api_token_file,False,url,False)

        analysis_available = False
        job_id_to_get = None
        print("Info: about to request ask_analysis_availability for md5: {}, analyzers: {}"
                    "".format(md5, None))
        api_request_result = pyintelowl_client.ask_analysis_availability(md5,None,True,False)
        errors = api_request_result.get('errors', [])
        if errors:
            raise IntelOwlClientException("API ask_analysis_availability failed. Errors: {}"
                                          "".format(errors))
        answer = api_request_result.get('answer', {})
        status = answer.get('status', '')
        if not status:
            raise IntelOwlClientException("API ask_analysis_availability gave result without status!?!?"
                                          "answer:{}".format(answer))
        print(status)
        if status != 'not_available':
            analysis_available = True
            job_id_to_get = answer.get('job_id', '')
            if job_id_to_get:
                print("Info: found already existing job with id {} and status {} for md5 {} and analyzers {}"
                            "".format(job_id_to_get, status, md5, 'all'))
            else:
                raise IntelOwlClientException(
                    "API ask_analysis_availability gave result without job_id!?!? answer:{}"
                    "".format(answer))

        if not analysis_available:
            print('Info: Result not available')
            api_request_result = pyintelowl_client.send_observable_analysis_request(md5, None,
                                                                                    md5, False,
                                                                                    False,
                                                                                    True)
            errors = api_request_result.get('errors', [])
            if errors:
                raise IntelOwlClientException("API send_analysis_request failed. Errors: {}"
                                              "".format(errors))
            answer = api_request_result.get('answer', {})
            print("Info: md5 {} received response from intel_owl: {}".format(md5, answer))
            status = answer.get('status', '')
            if not status:
                raise IntelOwlClientException(
                    "API send_analysis_request gave result without status!?!? answer:{}"
                    "".format(answer))
            if status != "accepted":
                raise IntelOwlClientException("API send_analysis_request gave unexpected result status:{}"
                                              "".format(status))
            job_id_to_get = answer.get('job_id', '')
            analyzers_running = answer.get('analyzers_running', '')
            warnings = answer.get('warnings', [])
            if job_id_to_get:
                print("Info: started job with id {} and status {} for md5 {} and analyzers {}. Warnings:{}"
                            "".format(job_id_to_get, status, md5, analyzers_running, warnings))
            else:
                raise IntelOwlClientException("API send_analysis_request gave result without job_id!?!?"
                                              "answer:{}".format(answer))

        # third step: at this moment we must have a job_id to check for results
        polling_max_tries = 60 * 20
        polling_interval = 1
        print("Info: started polling")
        for chance in range(polling_max_tries):
            time.sleep(polling_interval)
            api_request_result = pyintelowl_client.ask_analysis_result(job_id_to_get)
            errors = api_request_result.get('errors', [])
            if errors:
                raise IntelOwlClientException("API ask_analysis_result failed. Errors: {}"
                                              "".format(errors))
            answer = api_request_result.get('answer', {})
            status = answer.get('status', '')
            if not status:
                raise IntelOwlClientException(
                    "API ask_analysis_result gave result without status!?!? job_id:{} answer:{}"
                    "".format(job_id_to_get, answer))
            if status in ['invalid_id', 'not_available']:
                raise IntelOwlClientException("API send_analysis_request gave status {}".format(status))
            if status == 'running':
                continue
            if status == 'pending':
                print("Warning: API ask_analysis_result check job in status 'pending'. Maybe it is stuck"
                               "job_id:{} md5:{} analyzer_list:{}".format(job_id_to_get, md5, None))
            elif status in ['reported_without_fails', 'reported_with_fails', 'failed']:
                print("Warning: job_id {} Analysis finished. Status: {} "
                            "md5:{} analyzer_list:{}".format(job_id_to_get, status, md5, None))
                results = answer.get('results', [])
                elapsed_time = answer.get('elapsed_time_in_seconds', [])
                break
        if not results:
            raise IntelOwlClientException("reached polling timeout without results. Job_id {}"
                                          "".format(job_id_to_get))
    except IntelOwlClientException as e:
        print("Error:{} md5:{}".format(e, md5))
    except requests.exceptions.HTTPError as e:
        print('Error: ',e)
    except IntelOwlInvalidAPITokenException as e:
        print('Error: ',e)
        exit(-1)
    except Exception as e:
        print('Error: ',e)

    print("Info: elapsed time: {}".format(elapsed_time))
    return(results)



if __name__ == "__main__":
    get_reports_from_intelowl_server(r'C:\Users\Roopesh\Workspace\NMR_Android\Apps\VT_APK\vt.apk',r'C:\Users\Roopesh\Workspace\nmr_osint_analysis\api_token.txt','http://10.10.106.101')
