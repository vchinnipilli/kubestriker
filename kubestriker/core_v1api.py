import requests

class CoreV1Api(object):

    def __init__(self, service_url, result, namespace=None, token=''):
        if namespace is None:
            namespace = []
        self.result = {}
        if result is not None:
            self.result = result
        self.service_url = service_url
        self.namespaces = namespace
        self.api_end_point = 'api/v1'
        self.url = self.service_url + "/" + str(self.api_end_point)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = {'Authorization': 'Bearer {}'.format(token)}
        self.pods_data = self.pods_all_namespaces()
        self.namespaces_data = self.list_namespaces()
        self.nodes_data = self.list_nodes()
        self.endpoints_data = self.list_endpoints_for_all_namespaces()
        self.services_data = self.list_service_for_all_namespaces()
        self.configmaps_data = self.list_config_map_for_all_namespaces()
        self.secrets_data = self.list_secret_for_all_namespaces()


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

    def read_namespaced_data(self, context):
        '''
        checks for namespaced data
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

    def pods_all_namespaces(self):
        '''
        captures data of pods for all namespaces
        '''  
        context = 'pods'
        url = self.url + "/" + context
        result = self.execute(url)
        pods_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                pods_data.update({"core":result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                pods_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return pods_data

    def list_namespaces(self):
        '''
        captures namespaces
        '''  
        context = 'namespaces'
        url = self.url + "/" + context
        result = self.execute(url)
        namespaces_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                namespaces_data.update({"core":result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                namespaces_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return namespaces_data

    def list_nodes(self):
        '''
        captures nodes data
        '''
        context = 'nodes'
        url = self.url + "/" + context
        result = self.execute(url)
        nodes_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                nodes_data.update({"core":result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                nodes_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return nodes_data

    def list_endpoints_for_all_namespaces(self):
        '''
        captures end points data for all namespaces
        '''
        context = 'endpoints'
        url = self.url + "/" + context
        result = self.execute(url)
        endpoints_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                endpoints_data.update({"core":result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                endpoints_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return endpoints_data

    def list_service_for_all_namespaces(self):
        '''
        captures services data for all namespaces
        '''
        context = 'services'
        url = self.url + "/" + context
        result = self.execute(url)
        services_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                services_data.update({"core":result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                services_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return services_data

    def list_config_map_for_all_namespaces(self):
        '''
        captures configmaps data for all namespaces
        '''
        context = 'configmaps'
        url = self.url + "/" + context
        result = self.execute(url)
        configmaps_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                configmaps_data.update({"core":result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                configmaps_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return configmaps_data

    def list_secret_for_all_namespaces(self):
        '''
        captures secrets data for all namespaces
        '''
        context = 'secrets'
        url = self.url + "/" + context
        result = self.execute(url)
        secrets_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                secrets_data.update({"core":result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                secrets_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return secrets_data

    def gather_response_data(self, json_data):
        '''
        Gathers names for various resources in the cluster
        '''
        names_list = []
        items_data = json_data.get('items')
        if items_data:
            for items in items_data:
                name = items.get('metadata', {}).get('name')
                if name:
                    names_list.append(name)
        return names_list

    def result_parse(self, result, context):
        '''
        Generates a boolean dictionary for the services active
        '''
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                return result.json(), status_code
            else:
                self.result.update({context: {'status': status_code}})
                return {}, status_code
        else:
            self.result.update({context: {'status': False}})
            return {}, None
    def result_namespces_parse(self, result, context, namespace):
        '''
        Generates a boolean dictionary for the services active in various namespaces
        '''
        json_data = {}
        status_code = None
        namespace_result = self.result.get(namespace)
        nm_result = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                nm_result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                json_data = result.json()
            else:
                nm_result.update({context: {'status': status_code}})
        else:
            nm_result.update({context: {'status': False}})
        if not namespace_result:
            self.result.update({namespace: nm_result})
        else:
            namespace_result.update(nm_result)
        return json_data, status_code
