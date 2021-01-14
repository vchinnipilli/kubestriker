import requests
from kubestriker.bars import prefix, sub_prefix, service_open


class Kubelet_RO(object):
    def __init__(self, service_url,file_obj):
        self.result = {}
        self.url = service_url
        self.session = requests.Session()
        self.session.verify = False
        self.file_obj=file_obj

    def execute(self, url):
        try:
            response = self.session.get(url, timeout=5)
            return response
        except requests.exceptions.SSLError:
            return False
        except Exception:
            return False

    def gather_response_data(self, json_data):
        names_list = []
        items_data = json_data.get('items')
        if items_data:
            for items in items_data:
                name = items.get('metadata', {}).get('name')
                if name:
                    names_list.append(name)
        return names_list

    

    def kubelet_ro(self):
        kubelet_rw_res = {}
        context_list = ['metrics', 'metrics/cadvisor', 'metrics/resource', 'metrics/probes', 'spec',
                        'stats', 'pods']
        for context in context_list:
            url = self.url + "/" + context
            result = self.execute(url)
            if result is not False:
                status_code = result.status_code
                if status_code == 200:
                    service_open(context,self.file_obj)
                    #metadata_list = self.gather_response_data(result.json())
                    #kubelet_rw_res.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                elif status_code == 403:
                    kubelet_rw_res.update({context: {'status': status_code}})
            else:
                kubelet_rw_res.update({context: {'status': False}})
        self.result.update({'kubelet_ro': kubelet_rw_res})

