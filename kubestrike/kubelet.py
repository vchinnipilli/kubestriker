import requests


class Kubelet(object):
    def __init__(self, result, namespace=None, token=''):
        if namespace is None:
            namespace = []
        self.result = {}
        if result is not None:
            self.result = result
        self.namespaces = namespace
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = {'Authorization': 'Bearer {}'.format(token)}

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

    def read_namespaced_data(self, end_point, context, kublet_con):
        for namespace in self.namespaces:
            url = end_point + "/namespaces/" + namespace + "/" + context
            result = self.execute(url)
            namespace_result = self.result.get(namespace)
            nm_result = {}
            if result is not False:
                status_code = result.status_code
                if status_code == 200:
                    metadata_list = self.gather_response_data(result.json())
                    nm_result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                else:
                    nm_result.update({context: {'status': status_code}})
            else:
                nm_result.update({context: {'status': False}})
            if not namespace_result:
                self.result.update({namespace: {kublet_con: nm_result}})
            else:
                namespace_result.update({kublet_con: nm_result})

    def kubelet_rw(self, end_point):
        kubelet_rw_res = {}
        protocol = "https"
        context_list = ['configz', 'runningpods', 'pods', 'metrics', 'metrics/cadvisor', 'metrics/resource/v1alpha1',
                        'metrics/probes', 'logs']
        for context in context_list:
            url = protocol + "://" + str(end_point) + "/" + context
            print(url)
            result = self.execute(url)
            if result is not False:
                status_code = result.status_code
                if status_code == 200:
                    metadata_list = self.gather_response_data(result.json())
                    kubelet_rw_res.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                elif status_code == 403:
                    kubelet_rw_res.update({context: {'status': status_code}})
                    self.read_namespaced_data(end_point, context, 'kubelet_rw')
            else:
                kubelet_rw_res.update({context: {'status': False}})
        self.result.update({'kubelet_rw': kubelet_rw_res})

    def kubelet_ro(self, end_point):
        protocol = "http"
        context_list = ['metrics', 'metrics/cadvisor', 'metrics/resource', 'metrics/probes', 'spec',
                        'stats', 'pods']
        kubelet_ro_res = {}
        for context in context_list:
            url = protocol + "://" + str(end_point) + "/" + context
            result = self.execute(url)
            if result is not False:
                status_code = result.status_code
                if status_code == 200:
                    metadata_list = self.gather_response_data(result.json())
                    kubelet_ro_res.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                elif status_code == 403:
                    kubelet_ro_res.update({context: {'status': status_code}})
                    self.read_namespaced_data(end_point, context, 'kubelet_ro')
            else:
                kubelet_ro_res.update({context: {'status': False}})
        self.result.update({'kubelet_ro': kubelet_ro_res})
