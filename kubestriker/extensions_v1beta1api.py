import requests

class ExtensionsV1beta1Api(object):

    def __init__(self, service_url, result, namespace=None, token=''):
        if namespace is None:
            namespace = []
        self.result = {}
        if result is not None:
            self.result = result
        self.service_url = service_url
        self.namespaces = namespace
        self.api_end_point = 'apis/networking.k8s.io/v1'
        self.url = self.service_url + "/" + str(self.api_end_point)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = {'Authorization': 'Bearer {}'.format(token)}

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

    def gather_response_data(self, json_data):
        '''
        captures names of various resources
        '''  
        names_list = []
        items_data = json_data.get('items')
        if items_data:
            for items in items_data:
                name = items.get('metadata', {}).get('name')
                if name:
                    names_list.append(name)
        return names_list

    def read_namespaced_data(self, context):
        '''
        captures data of resources for respective namespaces
        '''  
        json_result = {}
        for namespace in self.namespaces:
            url = self.url + "/namespaces/" + namespace + "/" + context
            result = self.execute(url)
            namespace_result = self.result.get(namespace)
            nm_result = {}
            if result is not False:
                status_code = result.status_code
                if status_code == 200:
                    metadata_list = self.gather_response_data(result.json())
                    nm_result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                    json_result.update({namespace:result.json()})
                else:
                    nm_result.update({context: {'status': status_code}})
            else:
                nm_result.update({context: {'status': False}})
            if not namespace_result:
                self.result.update({namespace: nm_result})
            else:
                namespace_result.update(nm_result)
        return json_result

    def list_ingress_for_all_namespaces(self):
        '''
        captures Ingress data for all namespaces
        '''  
        context = 'ingresses'
        url = self.url + "/" + context
        result = self.execute(url)
        if result:
            if result.status_code == 200:
                return result.json()
            else:
                return {}

    def list_ingress_status_for_all_namespaces(self):
        '''
        captures Ingress status for all namespaces
        '''  
        context = 'ingresses/status'
        url = self.url + "/" + context
        result = self.execute(url)
        if result:
            if result.status_code == 200:
                return result.json()
            else:
                return {}

    def list_network_policy_for_all_namespaces(self):
        '''
        captures network policies for all namespaces
        '''  
        context = 'networkpolicies'
        url = self.url + "/" + context
        result = self.execute(url)
        networkpolicies_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                networkpolicies_data.update({"network": result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                networkpolicies_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return networkpolicies_data

    def list_replica_set_for_all_namespaces(self):
        '''
        captures RS for all namespaces
        '''  
        context = 'replicasets'
        url = self.url + "/" + context
        result = self.execute(url)
        if result:
            if result.status_code == 200:
                return result.json()
            else:
                return {}

