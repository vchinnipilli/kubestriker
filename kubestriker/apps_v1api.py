import requests

class AppsV1Api(object):

    def __init__(self, service_url, result, namespace=None, token=''):
        if namespace is None:
            namespace = []
        self.result = {}
        if result is not None:
            self.result = result
        self.service_url = service_url
        self.namespaces = namespace
        self.api_end_point = 'apis/apps/v1'
        self.url = self.service_url + "/" + str(self.api_end_point)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = {'Authorization': 'Bearer {}'.format(token)}
        self.deployments_data = self.list_deployment_for_all_namespaces()
        self.daemonsets_data = self.list_daemon_set_for_all_namespaces()
        self.replicasets_data = self.list_replica_set_for_all_namespaces()
        self.statefulsets_data = self.list_stateful_set_for_all_namespaces()

    def execute(self, url):
        '''
        This function checks for server response
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
        This functions captures the names of various resources in kuberentes
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
        This function calls namespaced resources
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

    def list_deployment_for_all_namespaces(self):
        '''
        This function lists various deployments
        '''
        context = 'deployments'
        url = self.url + "/" + context
        result = self.execute(url)
        deployments_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                deployments_data.update({"apps": result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                deployments_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return deployments_data

    def list_daemon_set_for_all_namespaces(self):
        '''
        This function grabs DS data
        '''
        context = 'daemonsets'
        url = self.url + "/" + context
        result = self.execute(url)
        daemonsets_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                daemonsets_data.update({"apps": result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                daemonsets_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return daemonsets_data

    def list_replica_set_for_all_namespaces(self):
        '''
        This function grabs RS data
        '''
        context = 'replicasets'
        url = self.url + "/" + context
        result = self.execute(url)
        replicasets_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                replicasets_data.update({"apps": result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                replicasets_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return replicasets_data

    def list_stateful_set_for_all_namespaces(self):
        '''
        This function grabs Stateful sets data
        '''
        context = 'statefulsets'
        url = self.url + "/" + context
        result = self.execute(url)
        statefulsets_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                statefulsets_data.update({"apps": result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                statefulsets_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return statefulsets_data
