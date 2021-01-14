import requests
import warnings

warnings.filterwarnings("ignore")


class RbacAuthorizationV1Api(object):

    def __init__(self, service_url, result, namespace=None, token=''):
        if namespace is None:
            namespace = []
        self.result = {}
        if result is not None:
            self.result = result
        self.service_url = service_url
        self.namespaces = namespace
        self.api_end_point = 'apis/rbac.authorization.k8s.io/v1'
        self.url = self.service_url + "/" + str(self.api_end_point)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = {'Authorization': 'Bearer {}'.format(token)}
        self.roles_data = self.roles()
        self.roles_bindings_data = self.rolebindings()
        self.clusterroles_data = self.clusterroles()
        self.clusterrolebindings_data = self.clusterrolebindings()

    def execute(self, url):
        try:
            response = self.session.get(url, timeout=5)
            return response
        except requests.exceptions.SSLError:
            return False
        except Exception:
            return False

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

    def roles(self):
        context = 'roles'
        url = self.url + "/" + context
        result = self.execute(url)
        roles_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                roles_data.update({'rbac':result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                roles_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return roles_data

    def rolebindings(self):
        context = 'rolebindings'
        url = self.url + "/" + context
        result = self.execute(url)
        rolebindings_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                rolebindings_data.update({'rbac':result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                rolebindings_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return rolebindings_data

    def clusterroles(self):
        context = 'clusterroles'
        url = self.url + "/" + context
        result = self.execute(url)
        clusterroles_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                clusterroles_data.update({'rbac':result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                clusterroles_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return clusterroles_data

    def clusterrolebindings(self):
        context = 'clusterrolebindings'
        url = self.url + "/" + context
        result = self.execute(url)
        clusterrolebindings_data = {}
        if result is not False:
            status_code = result.status_code
            if status_code == 200:
                metadata_list = self.gather_response_data(result.json())
                self.result.update({context: {'status': status_code, 'metadata_names': metadata_list}})
                clusterrolebindings_data.update({'rbac':result.json()})
            elif status_code == 403:
                self.result.update({context: {'status': status_code}})
                clusterrolebindings_data.update(self.read_namespaced_data(context))
        else:
            self.result.update({context: {'status': False}})
        return clusterrolebindings_data


    def gather_response_data(self, json_data):
        names_list = []
        items_data = json_data.get('items')
        if items_data:
            for items in items_data:
                name = items.get('metadata', {}).get('name')
                if name:
                    names_list.append(name)
        return names_list

    def result_parse(self, result, context):
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

    def result_namespces_parse(self, result, context, url,namespace):
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

