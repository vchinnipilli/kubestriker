import requests

class BatchV1Api(object):

    def __init__(self, service_url, token=''):
        self.service_url = service_url
        self.token = token
        self.api_end_point = 'apis/batch/v1'
        self.url = self.service_url + "/" + str(self.api_end_point)
        self.session = requests.Session()
        self.session.verify = False

    def execute(self, url):
        '''
        checks for the server response
        '''  
        try:
            response = self.session.get(url, timeout=5)
            return response
        except requests.exceptions.SSLError:
            return False
        except Exception:
            return False

    def list_job_for_all_namespaces(self):
        '''
        captures jobs data
        '''  
        context = 'jobs'
        url = self.url + "/" + context
        result = self.execute(url)
        if result:
            if result.status_code == 200:
                return result.json()
            else:
                return {}

    def list_cronjob_for_all_namespaces(self):
        '''
        captures cron jobs data
        '''  
        context = 'cronjobs'
        url = self.url + "/" + context
        result = self.execute(url)
        if result:
            if result.status_code == 200:
                return result.json()
            else:
                return {}
