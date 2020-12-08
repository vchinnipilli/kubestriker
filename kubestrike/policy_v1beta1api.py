import requests

class PolicyV1beta1Api(object):

    def __init__(self, service_url, result, namespace=None, token=''):
        if namespace is None:
            namespace = []
        self.result = {}
        if result is not None:
            self.result = result
        self.service_url = service_url
        self.namespaces = namespace
        self.api_end_point = 'apis/policy/v1beta1'
        self.url = self.service_url + "/" + str(self.api_end_point)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = {'Authorization': 'Bearer {}'.format(token)}
        self.podsecuritypolicies_data = self.list_pod_security_policy()

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

    def read_namespaced_data(self, context):
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

    def list_pod_security_policy(self):
        context = 'podsecuritypolicies'
        url = self.url + "/" + context
        result = self.execute(url)
        podsecuritypolicies_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                podsecuritypolicies_data.update({"policy": result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                podsecuritypolicies_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return podsecuritypolicies_data
