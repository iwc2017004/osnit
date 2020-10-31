import json
import sys
import time
import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import os
import hashlib
import io

class Malware:
    def hash_gen(self,file_path):
        """Generate and return sha1 and sha256 as a tuple."""
        try:
            print('Generating Hashes')
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            block_size = 65536
            with io.open(file_path, mode='rb') as afile:
                buf = afile.read(block_size)
                while buf:
                    sha1.update(buf)
                    sha256.update(buf)
                    buf = afile.read(block_size)
            sha1val = sha1.hexdigest()
            sha256val = sha256.hexdigest()
            return (sha1val, sha256val)
        except Exception:
            print('Error:Generating Hashes')


    def __init__(self, hash=None, delay=20, file=None):
        if file:
            self.sha1,self.sha256=self.hash_gen(file_path=file)
        elif hash:
            self.sha256=hash
            self.sha1=hash
        self.delay = delay
        self.json = dict()
        self.file = file
        self.driver = webdriver.Chrome()
        self.check_input = True
        self._check_io()



    def _check_io(self):
        if self.sha1 is None and self.file is None and self.sha256 is None:
            print("Please provide hash or file as input")
            self.check_input = False

    def _get_delay(self, delay):
        # private function of the class
        if delay is None:
            return self.delay
        return delay

    def extract_cape(self, res):
        soup = bs(res.text, 'lxml')
        score = status = ''

        ele = soup.find(class_="col-lg-1")
        if ele:
            tags = ele.text.split('\n')
            if len(tags):
                tags.remove('MalScore')
                result = [s for s in tags if len(s)]
                score, status = result

        yara = set()
        fle = soup.find(id="file")
        if fle:
            th = fle.find_all('th')
            td = fle.find_all('td')
            for t, d in zip(yara):
                if 'Yara' in t.text:
                    yara.add(d.text.strip())
            yara = list(yara)

        description = set()
        signature = soup.find(id="signatures")
        if signature:
            divs = signature.find_all('div')
            for div in divs:
                div = div.text.strip()
                if 'Yara' in div:
                    description.add(div)
            description = list(description)

        result = dict()

        if any([len(score), len(status), len(description), len(yara)]):
            result['website'] = res.url
            result['score'] = score
            result['status'] = status
            result['description'] = description
            result['yara'] = yara
            return result
        return {}

    # Works with request module
    def cape(self, delay=None):
        print("Info: cape - Analysing {} funtion at {}".format(self.sha256, sys._getframe().f_code.co_name))
        delay = self._get_delay(delay)
        output = dict()
        count = 0
        self.json['cape'] = dict()
        try:
            url = "https://cape.contextis.com/api/tasks/search/" + 'sha256' + "/" + self.sha256
            response = requests.get(url)
            if response.status_code == 200:
                try:
                    data = response.json()['data']
                    ids = [str(record['id']) for record in data]
                    for _id in ids:
                        res = requests.get("https://cape.contextis.com/analysis/" + _id)
                        if res.status_code == 200:
                            report = self.extract_cape(res)
                            if len(report):
                                count += 1
                                output["report_" + str(count)] = report
                except:
                    return
        except Exception as e:
            print(e)
        self.json['cape'] = output
        return

        # Works with request module

    def malshare(self, delay=None):
        print("Info: malshare - Analysing {} funtion at {}".format(self.sha256, sys._getframe().f_code.co_name))
        output = dict()
        self.json['malshare'] = dict()
        api = "bd032c3e94c5ddc3d9c802748015c303298fabbab007d1da3501138bc06005eb"
        url = "https://malshare.com/api.php?api_key=" + api + "&action=search&query=" + self.sha256
        res = requests.get(url)
        if res.status_code == 200:
            try:
                data = res.json()
                url = "https://malshare.com/sample.php?action=detail&hash=" + self.sha256
                output['website'] = url
                output['yara'] = data['yarahits']['yara']
                output['description'] = data['score'] = data['status'] = None
                self.json['malshare'] = {"report_1": output}
            except Exception as e:
                print('Error: ',e)
        return

    def valkyrie(self, delay=None):
        print("Info: valkyrie - Analysing {} funtion at {}".format(self.sha1, sys._getframe().f_code.co_name))
        output = dict()
        self.json['valkyrie'] = dict()
        delay = self._get_delay(delay)
        url = 'https://valkyrie.comodo.com/get_info?sha1=' + self.sha1
        # driver = webdriver.Firefox()
        self.driver.get(url)
        url = self.driver.current_url
        try:
            WebDriverWait(self.driver, delay).until(
                EC.presence_of_element_located((By.ID, "fi_tab")))
            status_id = self.driver.find_element_by_id('final-score')
            status = status_id.text.strip().split('\n')[0].capitalize()
            output['status'] = status
            output['website'] = url
            output['yara'] = output['description'] = output["score"] = None

        except TimeoutException as err:
            print("Error:", err)

        if len(output):
            self.json['valkyrie'] = {"report_1": output}
        return

    def vicheck(self, delay=None):
        print("Info: vicheck - Analysing {} funtion at {}".format(self.sha256, sys._getframe().f_code.co_name))
        output = dict()
        self.json['vicheck'] = dict()
        delay = self._get_delay(delay)
        url = "https://vicheck.ca/hashquery.php"
        self.driver.get(url)
        url = self.driver.current_url
        try:
            WebDriverWait(self.driver, delay).until(
                EC.presence_of_element_located((By.ID, "submit")))

            self.driver.find_element_by_name("hash").send_keys(self.sha256)
            self.driver.find_element_by_id("submit").click()

            WebDriverWait(self.driver, delay).until(
                EC.presence_of_element_located((By.CLASS_NAME, "panel-group")))
            eles = self.driver.find_element_by_class_name("panel-footer")
            ele = eles.text.split('\n')[-2:]
            for e in ele:
                e = [s.strip() for s in e.split(':')]
                output[e[0].lower()] = e[1]

            output['website'] = url
            output['yara'] = output['description'] = None
        except TimeoutException as err:
            print("Error: ",err)

        if len(output):
            self.json['vicheck'] = {"report_1": output}
        return

    def hybrid(self, delay=None):
        print("Info: Hybrid - Analysing {} funtion at {}".format(self.sha256, sys._getframe().f_code.co_name))
        output = dict()
        self.json['hybrid'] = dict()
        delay = self._get_delay(delay)
        url = "https://www.hybrid-analysis.com/sample/" + self.sha256
        self.driver.get(url)
        url = self.driver.current_url
        try:
            WebDriverWait(self.driver, delay).until(
                EC.presence_of_element_located((By.ID, "basic-malware-detection-info")))
            time.sleep(2)
            ele = self.driver.find_element_by_id("basic-malware-detection-info")
            ele_list = ele.text.split('\n')
            status = ele_list[0]
            threat_score = (ele_list[1].split())
            av_detection = ele_list[2].split()
            label = ele_list[3].split()
            output = {'URL': url, 'status': status, 'Threat Score': threat_score[2], 'AV Detection':av_detection[2],'Label':label[2]}

        except TimeoutException as err:
            print("Error: ",err)
            self.json['hybrid'] = {}

        if len(output):
            self.json['hybrid'] = {"report_1": output}
        return

    def iris(self, delay=None):
        print("Info: Iris - Analysing {} funtion at {}".format(self.sha256, sys._getframe().f_code.co_name))
        output = dict()
        yara_eles = list()
        self.json['iris'] = dict()
        delay = self._get_delay(delay)
        url = "https://iris-h.services/pages/report/" + self.sha256
        self.driver.get(url)
        url = self.driver.current_url
        try:
            WebDriverWait(self.driver, delay).until(
                EC.presence_of_element_located((By.CLASS_NAME, "risk-info-block")))
            time.sleep(2)
            ele = self.driver.find_element_by_class_name("risk-info-block")
            score = ' '.join(ele.text.split('\n'))

            yara_eles = self.driver.find_elements_by_class_name('findings-card-body')

        except TimeoutException as err:
            print("Error: ",err)

        if len(yara_eles) > 2:
            yara_ele = yara_eles[2].text.split('\n')
            yara = [x.split(':')[1].strip() for x in yara_ele if x.startswith('Name') or x.startswith('Description')]
            output["website"] = url
            output["score"] = None
            output["status"] = score
            output['yara'], output['description'] = yara

        if len(output):
            self.json['iris'] = {"report_1": output}
        return

    def tasks(self):
        self.cape()
        self.malshare()
        self.vicheck()
        self.valkyrie()
        self.iris()
        self.hybrid()

    def main(self):
        if self.check_input:
            self.tasks()

        return self.json


if __name__=='__main__':
    start = time.time()
    malware = Malware(file=os.path.abspath('..\\Apps\\Diva_App\\diva-beta.apk'))
    #malware = Malware(hash='707fedfeadbfa4248cfc6711b5a0b98e1684cd37a6e0544e9b7bde4b86096963')
    results = malware.main()
    malware.driver.quit()
    print(results)
    print(time.time() - start)
