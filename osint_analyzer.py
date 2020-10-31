from cuckoo_analysis import (post_file_for_cuckoo_analysis,get_report_for_task_id)
from get_reports import Malware
from osintscan import Osint
import os
import json
import hashlib
from pyintelowl_client import get_reports_from_intelowl_server
import io

class OSINT_Analyzer:
    def __init__(self,file_path,output_path,api_token_file,intelowl_url):
        self.file_path = file_path
        self.file_hash = self.hash_gen(self.file_path)
        self.output_path = output_path
        #self.malware_reports = Malware(file=self.file_path)
        self.osint_reports = Osint(hash=self.file_hash,file=self.file_path)
        self.api_token_file = api_token_file
        self.intelowl_url = intelowl_url

    def nmr_osint_get_report_from_cuckoo(self):
        self.cuckoo_report = post_file_for_cuckoo_analysis(self.file_path)

    def nmr_osint_save_cuckoo_results_to_json(self):
        with open(os.path.join(self.output_path,'cuckoo_analysis.json'),'w') as file:
            json.dump(self.cuckoo_report,file)

    def nmr_osint_get_malware_api_reports(self):
        self.malware_reports_analysis_result = self.malware_reports.main()
        self.malware_reports.driver.quit()
        print('Info: Collecting reports successful')

    def nmr_osint_save_malware_api_reports_to_json(self):
        with open(os.path.join(self.output_path,'osint_api_reports.json'),'w') as file:
            json.dump(self.malware_reports_analysis_result,file)

    def nmr_osint_get_malware_sandbox_reports(self):
        self.osint_reports_analysis_result = self.osint_reports.main()
        print('Info: Collecting reports successful')

    def nmr_osint_save_malware_sandbox_reports(self):
        with open(os.path.join(self.output_path,'sandbox_api_reports.json'),'w') as file:
            json.dump(self.osint_reports_analysis_result,file)


    def nmr_osint_save_malware_api_reports_to_json(self):
        with open(os.path.join(self.output_path,'osint_api_reports.json'),'w') as file:
            json.dump(self.malware_reports_analysis_result,file)

    def nmr_osint_get_pyintelowl_report(self):
        self.pyintelowl_result = get_reports_from_intelowl_server(self.file_path,self.api_token_file,self.intelowl_url)

    def nmr_osint_save_pyintelowl_report_to_json(self):
        with open(os.path.join(self.output_path, 'intel_owl_reports.json'), 'w') as file:
            json.dump(self.pyintelowl_result, file)



    def hash_gen(self,file_path):
        """Generate and return sha1 and sha256 as a tuple."""
        try:
            print('Generating Hashes')
            md5 = hashlib.md5()
            block_size = 65536
            with io.open(file_path, mode='rb') as afile:
                buf = afile.read(block_size)
                while buf:
                    md5.update(buf)
                    buf = afile.read(block_size)
            md5 = md5.hexdigest()
            return md5
        except Exception as ex:
            print('Error:Generating Hashes',ex)



    def run(self):
        #self.nmr_osint_get_report_from_cuckoo()
        #self.nmr_osint_save_cuckoo_results_to_json()
#        self.nmr_osint_get_malware_api_reports()
#        self.nmr_osint_save_malware_api_reports_to_json()
        self.nmr_osint_get_malware_sandbox_reports()
        self.nmr_osint_save_malware_sandbox_reports()
#        self.nmr_osint_get_pyintelowl_report()
#        self.nmr_osint_save_pyintelowl_report_to_json()


if __name__=='__main__':
    osint_analyzer = OSINT_Analyzer(r'/home/mal/Desktop/samples/unpacked_lbop20_PEtite.exe',r'output',
                                    r'C:\Users\Roopesh\Workspace\nmr_osint_analysis\api_token.txt','http://10.10.106.101')
    osint_analyzer.run()
