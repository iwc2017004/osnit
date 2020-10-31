'''
The following packages need to be installed for this module 
pip3 install intezer_sdk

'''
import sys
from pprint import pprint
from intezer_sdk import api
from intezer_sdk.analysis import Analysis
import requests
import json
from maltiverse import Maltiverse
import time
import io
class Osint:
    INTEZER_API_key = 'e80939fe-e5dc-4c90-b6f9-bce9b25fbaad'
    METADEFENDER_API_key = '571c7a78531894c4aa54c30e07a8e388'
    MALTIVER_USER = 'workrelatedcircle@gmail.com'
    MALTIVER_PASS = 'Hilbertdevid54321'
    def __init__(self, hash=None, delay=20, file=None):
        
        self.hash = hash
        self.json = dict()
        self.file=file
        self.check_input = True
    
    def get_intezer_analysis_by_hash_without_wait(self):  # type: (str) -> None
        INTEZER_API_key = self.INTEZER_API_key
        report = dict()
        details = dict()
        try:
            api.set_global_api(INTEZER_API_key)
            analysis = Analysis(file_hash=self.hash)
            analysis.send()
            analysis.wait_for_completion()
            result = analysis.result()
            print(result)
            details['url']=result['analysis_url']
            details['status']=result['verdict']
            details['analysis_time']=result['analysis_time']
            report[self.hash] = {'intezer':details}
            self.json['intezer']= details
        except Exception as ex:
            print("Intezer api request error",ex)
        

    def get_metadefender_ReportByHash(self):
        url = 'https://api.metadefender.com/v2/hash/'
        
        urlres = url + self.hash
        headers = {
            'apikey': self.METADEFENDER_API_key
        }
        try:
            response = requests.request("GET", urlres, headers=headers)
            if(response.status_code == 200):
                print(response)
                result = response.json()
                output = dict()
                print(result.keys())
                print(self.hash)
                if( self.hash.upper() in result.keys()):
                    print("check")
                    output['status']='Not found'
                    output['url']=url
                else:
                    output['url']=url
                    output['status'] = result['threat_name']
                    output['detected'] = result['scan_results']['total_detected_avs']
                    output['total_avs'] = result['scan_results']['total_avs']
            else:
                output['status'] = "reqeust error"
            self.json['metadefender']= output
        except Exception as ex:
            print("Metadefender api request error",ex)

    def getMaltiverseReportByHash(self):
        description = dict()
        try:
            api = Maltiverse()
            api.login(email=self.MALTIVER_USER,password=self.MALTIVER_PASS)
            #print(api.auth_token)
        #    print(api.session.headers)
        #    print(api.team_name)
            result = api.sample_get_by_md5(self.hash)
            print(result)
            if('status' in result):
                print("Cannot get result, Check your api limit")
                return -1
            elif len(result['hits']['hits']) > 0:
                description['status'] = result['hits']['hits'][0]['_source']['classification']
                description['score'] = result['hits']['hits'][0]['_source']['av_ratio']
                description['url'] = 'None'
            else:
                description['status'] = 'Not Found'
                description['score'] = 0
                description['url'] = 'None'
    #        report[hashValue] = {"maltiverse":description}
            self.json['Maltiverse']= description
        except Exception as ex:
            print("Maltiverse api request error",ex)
#        return report


    def tasks(self):
        self.get_metadefender_ReportByHash()
        self.get_intezer_analysis_by_hash_without_wait()
        self.getMaltiverseReportByHash()

    def main(self):
        if self.check_input:
            ouput = dict()
            if self.hash is not None:
                self.tasks()   
                ouput[self.hash]=self.json             
            else:                
                with open(self.file, "r") as fle:
                    for hash in fle:
                        self.hash=hash.strip()
                        self.json={}
                        self.tasks()
                        ouput[self.hash]=self.json
            with open('result.json', 'w') as ofle:
                json.dump(ouput, ofle)
                print("Data has been saved to a file successfully!!")  
                
        return self.json

if __name__=="__main__":
    start = time.time()
    hash="707fedfeadbfa4248cfc6711b5a0b98e1684cd37a6e0544e9b7bde4b86096963"
    osint=Osint(hash=hash)    
    results = osint.main()
    pprint(results)
    print(time.time()-start)
