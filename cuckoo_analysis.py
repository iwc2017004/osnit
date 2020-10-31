import requests
import time
import json

def post_file_for_cuckoo_analysis(file):
    URL = "http://10.10.106.102:8090/tasks/create/file"
    Headers ={"Authorization":"Bearer p5SVnPunJLAzA-evCv9Hlg"}

    try:
        with open(file,"rb") as sample_file:
            files = {
                "file" : ("temp_name",sample_file),
            }
            response = requests.post(URL,headers=Headers, files=files)
        print('Info: Status Code:',response.status_code)
        if(response.status_code==200):
            task_id = response.json()["task_id"]
            print('Task ID:',task_id)
            report = get_report_for_task_id(str(task_id))
            return report
        else:
            print('Submitting sample to cuckoo server failed')
            return {}
    except Exception as e:
        print(e)

def get_report_for_task_id(task_id):
    status_url = "http://10.10.106.102:8090/tasks/view/"+task_id
    URL = "http://10.10.106.102:8090/tasks/report/"+task_id
    Headers = {"Authorization": "Bearer p5SVnPunJLAzA-evCv9Hlg"}

    while(1):
        response = requests.get(status_url, headers=Headers)
        if(response.status_code==200):
            response_json = response.json()
            task_status = response_json['task']['status']
            print('Info: Status = ', task_status)
            if task_status=='reported':
                break
            time.sleep(5)
        else:
            print('Error: Response Code ', response.status_code)
            return {}


    response = requests.get(URL, headers=Headers)
    if(response.status_code==200):
        print('Info: Getting Report from cuckoo Success')
        return response.json()
    else:
        print('Error: Getting report from cuckoo failed')
        return {}


if __name__=="__main__":
    post_file_for_cuckoo_analysis(r'C:\Users\Roopesh\Desktop\reports\apus-browser.pdf')
    #get_report_for_task_id('35')

