import warnings
from colored import stylize
import yaml
from colored import fg
from kubestrike.rbac_authorization_v1api import RbacAuthorizationV1Api
from kubestrike.validate_roles import Validate_Roles
from kubestrike.core_v1api import CoreV1Api
from kubestrike.apps_v1api import AppsV1Api
from kubestrike.policy_v1beta1api import PolicyV1beta1Api
from kubestrike.pvl_containers import PvlContainers
from kubestrike.psp_role import PspRole
from kubestrike.extensions_v1beta1api import ExtensionsV1beta1Api
from kubestrike.jwt_token_converter import decode_jwt_token_data
from kubestrike.bars import prefix, scan_status, service_open, resource_available, print_msg_box
from kubestrike.kubelet_ro import Kubelet_RO
from kubestrike.kubelet_rw import Kubelet_RW

warnings.filterwarnings("ignore")


class ServiceHunt(object):
    def __init__(self, file_obj):
        self.result = {}
        self.file_obj = file_obj

    @prefix('[+] Gearing up for Api Server Secure Scan......................................')
    def apiserver_secure(self, data, token=None, choice=None, user_name=None):
        namespacelist = []
        if token:
            try:
                token = token.strip()
                decoded_data = yaml.safe_load(decode_jwt_token_data(token))
                # print(decoded_data)
                namespace = decoded_data.get('kubernetes.io/serviceaccount/namespace')
                # print(namespace)
                namespacelist = ['default', 'kube-node-lease', 'kube-public', 'kube-system']
                namespacelist.append(namespace)
            except Exception:
                pass
        else:
            token = ''
        result_data = {}
        print("\nGearing up for Api Server Secure Scan................................", file=self.file_obj)
        end_point = data.get('apiserver_secure').get('end_point')
        end_point_url = "https://" + end_point

        # appsv1 = AppsV1Api(end_point_url, result_data, namespacelist, token)
        # deployments_data = appsv1.deployments_data
        policyv1 = PolicyV1beta1Api(end_point_url, result_data, namespacelist, token)
        psp_data = policyv1.podsecuritypolicies_data
        if choice == 'Scan IAM misconfigurations':
            rbackv1 = RbacAuthorizationV1Api(end_point_url, result_data, namespacelist, token)
            roles_data = rbackv1.roles_data
            roles_bindings_data = rbackv1.roles_bindings_data
            clusterroles_data = rbackv1.clusterroles_data
            clusterrolebindings_data = rbackv1.clusterrolebindings_data
            self.misconfigurations(roles_data, roles_bindings_data, clusterroles_data, clusterrolebindings_data,
                                   namespacelist, user_name)
        elif choice == 'Scan misconfigured containers':
            corev1 = CoreV1Api(end_point_url, result_data, namespacelist, token)
            pods_data = corev1.pods_data
            nodes_data = corev1.nodes_data
            self.result.update(pods_data)
            self.misconfigured_containers(pods_data, namespacelist)
            self.grab_nodes_data(nodes_data, namespacelist)
        elif choice == 'Scan misconfigured podsecuritypolicies':
            if psp_data:
                rbackv1 = RbacAuthorizationV1Api(end_point_url, result_data, namespacelist, token)
                roles_data = rbackv1.roles_data
                roles_bindings_data = rbackv1.roles_bindings_data
                clusterroles_data = rbackv1.clusterroles_data
                clusterrolebindings_data = rbackv1.clusterrolebindings_data
                self.pod_security_polocies(psp_data, roles_data, roles_bindings_data, clusterroles_data,
                                           clusterrolebindings_data, namespacelist)
        elif choice == 'Scan misconfigured network policies':
            networking = ExtensionsV1beta1Api(end_point_url, result_data, namespacelist, token)
            network_policies_data = networking.list_network_policy_for_all_namespaces()
            ingress_list, egress_list = self.network_policies_data_parsing(network_policies_data, namespacelist)
            if ingress_list:
                resource_available("Wide Open Ingress policies")
                print_msg_box('######## Wide Open Ingress Policies ########', file_obj=self.file_obj)
                for ingrs_container in list(set(ingress_list)):
                    print(ingrs_container, file=self.file_obj)
            if egress_list:
                resource_available("Wide Open Egress policies")
                print_msg_box('######## Wide Open Egress Policies ########', file_obj=self.file_obj)
                for egrs_container in list(set(egress_list)):
                    print(egrs_container, file=self.file_obj)
        else:
            rbackv1 = RbacAuthorizationV1Api(end_point_url, result_data, namespacelist, token)
            roles_data = rbackv1.roles_data
            roles_bindings_data = rbackv1.roles_bindings_data
            clusterroles_data = rbackv1.clusterroles_data
            clusterrolebindings_data = rbackv1.clusterrolebindings_data
            corev1 = CoreV1Api(end_point_url, result_data, namespacelist, token)
            pods_data = corev1.pods_data
            nodes_data = corev1.nodes_data
            self.result.update(pods_data)
            self.misconfigurations(roles_data, roles_bindings_data, clusterroles_data, clusterrolebindings_data,
                                   namespacelist)
            self.misconfigured_containers(pods_data, namespacelist)
            self.grab_nodes_data(nodes_data, namespacelist)
            if psp_data:
                self.pod_security_polocies(psp_data, roles_data, roles_bindings_data, clusterroles_data,
                                           clusterrolebindings_data, namespacelist)
            networking = ExtensionsV1beta1Api(end_point_url, result_data, namespacelist, token)
            network_policies_data = networking.list_network_policy_for_all_namespaces()
            ingress_list, egress_list = self.network_policies_data_parsing(network_policies_data, namespacelist)
            if ingress_list:
                resource_available("Wide Open Ingress policies")
                print_msg_box('######## Wide Open Ingress Policies ########', file_obj=self.file_obj)
                for ingrs_container in list(set(ingress_list)):
                    print(ingrs_container, file=self.file_obj)
            if egress_list:
                resource_available("Wide Open Egress policies")
                print_msg_box('######## Wide Open Egress Policies ########', file_obj=self.file_obj)
                for egrs_container in list(set(egress_list)):
                    print(egrs_container, file=self.file_obj)

    @prefix('[+] Gearing up for Api Server Insecure Scan....................................')
    def apiserver_insecure(self, data):
        print("\nGearing up for Api Server Insecure Scan....................................", file=self.file_obj)
        namespacelist = []
        token = ''
        result_data = {}
        end_point = data.get('apiserver_insecure').get('end_point')
        end_point_url = "http://" + end_point
        rbackv1 = RbacAuthorizationV1Api(end_point_url, result_data, namespacelist, token)
        roles_data = rbackv1.roles_data
        roles_bindings_data = rbackv1.roles_bindings_data
        clusterroles_data = rbackv1.clusterroles_data
        clusterrolebindings_data = rbackv1.clusterrolebindings_data
        corev1 = CoreV1Api(end_point_url, result_data, namespacelist, token)
        pods_data = corev1.pods_data
        nodes_data = corev1.nodes_data
        self.result.update(pods_data)
        appsv1 = AppsV1Api(end_point_url, result_data, namespacelist, token)
        # deployments_data = appsv1.deployments_data
        policyv1 = PolicyV1beta1Api(end_point_url, result_data, namespacelist, token)
        psp_data = policyv1.podsecuritypolicies_data
        self.misconfigurations(roles_data, roles_bindings_data, clusterroles_data, clusterrolebindings_data,
                               namespacelist)
        self.misconfigured_containers(pods_data, namespacelist)
        self.grab_nodes_data(nodes_data, namespacelist)
        if psp_data:
            self.pod_security_polocies(psp_data, roles_data, roles_bindings_data, clusterroles_data,
                                       clusterrolebindings_data, namespacelist)
        networking = ExtensionsV1beta1Api(end_point_url, result_data, namespacelist, token)
        network_policies_data = networking.list_network_policy_for_all_namespaces()
        ingress_list, egress_list = self.network_policies_data_parsing(network_policies_data, namespacelist)
        if ingress_list:
            resource_available("Wide Open Ingress policies")
            print_msg_box('######## Wide Open Ingress Policies ########', file_obj=self.file_obj)
            for ingrs_container in list(set(ingress_list)):
                print(ingrs_container, file=self.file_obj)
        if egress_list:
            resource_available("Wide open Egress policies")
            print_msg_box('######## Wide Open Eggress Policies ########', file_obj=self.file_obj)
            for egrs_container in list(set(egress_list)):
                print(egrs_container, file=self.file_obj)

    @prefix('[+] Gearing up for Kubelet Read/Write Scan.....................................')
    def kubelet_rw(self, data):
        print('[+] Gearing up for Kubelet Read/Write Scan.....................................', file=self.file_obj)
        end_point = data.get('kubelet_rw').get('end_point')
        end_point_url = "https://" + end_point
        print('\n', file=self.file_obj)
        print("Kubelet Read/Write url: " + end_point_url, file=self.file_obj)
        kube_rw = Kubelet_RW(end_point_url, self.file_obj)
        kube_rw.kubelet_rw()

    @prefix('[+] Gearing up for Kubelet Read Only Scan......................................')
    def kubelet_ro(self, data):
        print('[+] Gearing up for Kubelet Read Only Scan......................................', file=self.file_obj)
        end_point = data.get('kubelet_ro').get('end_point')
        end_point_url = "http://" + end_point
        print('\n', file=self.file_obj)
        print("Kubelet Read Only url: " + end_point_url, file=self.file_obj)
        kube_ro = Kubelet_RO(end_point_url, self.file_obj)
        kube_ro.kubelet_ro()

    @prefix('[+] Scanning Network policies ................................................')
    def network_policies_data_parsing(self, network_policies_total_data, namespacelist=None):
        print('Scanning Network policies ................................................', file=self.file_obj)
        ingress_list = []
        egress_list = []
        if len(network_policies_total_data) == 0:
            return ingress_list, egress_list
        network_policies_data = network_policies_total_data.get('network')
        if network_policies_data is not None:
            items = network_policies_data.get('items')
            if items:
                for network_data in items:
                    spec = network_data.get('spec')
                    if spec:
                        ingress = spec.get('ingress')
                        if ingress is not None and len(ingress) == 1 and not ingress[0]:
                            ingress_list.append(network_data.get('metadata').get('name'))
                        egress = spec.get('egress')
                        if egress is not None and len(egress) == 1 and not egress[0]:
                            egress_list.append(network_data.get('metadata').get('name'))
        else:
            if namespacelist:
                for namespace in namespacelist:
                    network_policies_data = network_policies_total_data.get(namespace)
                    if network_policies_data is not None:
                        items = network_policies_data.get('items')
                        if items:
                            for network_data in items:
                                spec = network_data.get('spec')
                                if spec:
                                    ingress = spec.get('ingress')
                                    if ingress is not None and len(ingress) == 0:
                                        ingress_list.append(network_data.get('metadata').get('name'))
                                    egress = spec.get('egress')
                                    if egress is not None and len(egress) == 0:
                                        egress_list.append(network_data.get('metadata').get('name'))
        return ingress_list, egress_list

    def misconfigurations(self, roles_data, roles_bindings_data, clusterroles_data, clusterrolebindings_data,
                          namespacelist, user_name=None):
        print(stylize("\n[+] Scanning for IAM Misconfigurations ........................................\n",
                      fg("green_1")))
        print('Scanning for IAM Misconfigurations ........................................', file=self.file_obj)
        if (roles_data and roles_bindings_data and clusterroles_data and clusterrolebindings_data) is not None:
            if (roles_data.get('rbac') and roles_bindings_data.get('rbac') and clusterroles_data.get(
                    'rbac') and clusterrolebindings_data.get('rbac')) is not None:
                Validate_Roles(self.file_obj).validate_roles(roles_data['rbac'], roles_bindings_data['rbac'],
                                                             clusterroles_data['rbac'],
                                                             clusterrolebindings_data['rbac'], user_name)
            else:
                for namespace in namespacelist:
                    print("\nValidating namespace roles" + namespace, file=self.file_obj)
                    if namespace in (
                            roles_data and roles_bindings_data and clusterroles_data and clusterrolebindings_data):
                        Validate_Roles(self.file_obj).validate_roles(roles_data[namespace],
                                                                     roles_bindings_data[namespace],
                                                                     clusterroles_data[namespace],
                                                                     clusterrolebindings_data[namespace], user_name)
        else:
            print("IAM Misconfigurations data not available", file=self.file_obj)

    def misconfigured_containers(self, pods_data, namespacelist):
        print(stylize("\n[+] Scanning for Misonfigured containers ......................................\n",
                      fg("green_1")))
        print("\nScanning for Misonfigured containers ......................................", file=self.file_obj)
        pod_deploy_data_list = [pods_data]  # , deployments_data]
        for pvl_validate_data in pod_deploy_data_list:
            if pvl_validate_data:
                pvl_containers = []
                cpu = []
                memory = []
                livenessprobe = []
                readnessprobe = []
                priorityclassname_in = []
                service_account_in = []
                mounted_in = []
                docker_sock_containers = []
                if pvl_validate_data.get('core') is not None:
                    pvl_validate_data = pvl_validate_data['core']
                elif pvl_validate_data.get('apps') is not None:
                    pvl_validate_data = pvl_validate_data['apps']
                else:
                    pvl_validate_data = {}
                if len(pvl_validate_data) != 0:
                    for pod_data in pvl_validate_data['items']:
                        containers_list, match_signs = PvlContainers().containers_check(pod_data)
                        pvl_containers.append({'match_signs': match_signs, 'pvl_container': containers_list})
                        # print('privileged containers', str(containers_list))
                        PvlContainers().container_metrics(pod_data, cpu, memory, livenessprobe, readnessprobe,
                                                          priorityclassname_in, service_account_in, mounted_in,
                                                          docker_sock_containers)
                else:
                    for namespace in namespacelist:
                        if namespace in pods_data:
                            pods_data = pods_data[namespace]
                            for pod_data in pods_data['items']:
                                containers_list, match_signs = PvlContainers().containers_check(pod_data)
                                pvl_containers.append({'match_signs': match_signs, 'pvl_container': containers_list})
                                # print('privileged containers', str(containers_list))
                                PvlContainers().container_metrics(pod_data, cpu, memory, livenessprobe, readnessprobe,
                                                                  priorityclassname_in, service_account_in, mounted_in,
                                                                  docker_sock_containers)
                scan_status("       [+] Scanning for Privileged Containers .................................")
                scan_status("       [+] Scanning for livenessProbe .........................................")
                scan_status("       [+] Scanning for readinessProbe ........................................")
                scan_status("       [+] Scanning for CPU Limit .............................................")
                scan_status("       [+] Scanning for Memory Limit ..........................................")
                scan_status("       [+] Scanning for Priorityclassname .....................................")
                scan_status("       [+] Scanning for ServiceAccount Mount ..................................")
                scan_status("       [+] Scanning for Secrets Mounted .......................................")
                scan_status("       [+] Scanning for docker Socket Mount ...................................")
                print("       [+] Scanning for Privileged Containers .................................",
                      file=self.file_obj)
                print("       [+] Scanning for livenessProbe .........................................",
                      file=self.file_obj)
                print("       [+] Scanning for readinessProbe ........................................",
                      file=self.file_obj)
                print("       [+] Scanning for CPU Limit .............................................",
                      file=self.file_obj)
                print("       [+] Scanning for Memory Limit ..........................................",
                      file=self.file_obj)
                print("       [+] Scanning for Priorityclassname .....................................",
                      file=self.file_obj)
                print("       [+] Scanning for ServiceAccount Mount ..................................",
                      file=self.file_obj)
                print("       [+] Scanning for Secrets Mounted .......................................",
                      file=self.file_obj)
                print("       [+] Scanning for docker Socket Mount .................................\n",
                      file=self.file_obj)

                print_msg_box('######## Privileged containers ########', file_obj=self.file_obj)
                pvlc_list = []
                for pvlc_data in pvl_containers:
                    pvl_container = pvlc_data.get('pvl_container')
                    if pvl_container:
                        match_sighns = pvlc_data.get('match_signs')
                        for pvlc in pvl_container:
                            if not pvlc in pvlc_list:
                                print("{pvlc} is configured with {match_sighns}".format(pvlc=pvlc,
                                                                                        match_sighns=str(match_sighns)),
                                      file=self.file_obj)
                                pvlc_list.append(pvlc)

                print_msg_box('######## livenessprobe not set in below containers ########', file_obj=self.file_obj)
                for liveness_container in list(set(livenessprobe)):
                    print(liveness_container, file=self.file_obj)

                print_msg_box('######## readinessprobe not set in below containers ########', file_obj=self.file_obj)
                for readiness_container in list(set(readnessprobe)):
                    print(readiness_container, file=self.file_obj)

                print_msg_box('######## CPU Limit not set below containers ########', file_obj=self.file_obj)
                for cpu_container in list(set(cpu)):
                    print(cpu_container, file=self.file_obj)

                print_msg_box('######## Memory Limit not set in below containers ########', file_obj=self.file_obj)
                for memory_container in list(set(memory)):
                    print(memory_container, file=self.file_obj)

                print_msg_box('######## Priorityclassname not set in below containers ########', file_obj=self.file_obj)
                for pcl_container in list(set(priorityclassname_in)):
                    print(pcl_container, file=self.file_obj)

                print_msg_box('######## Service account mounted in below containers ########', file_obj=self.file_obj)
                for sac_container in list(set(service_account_in)):
                    print(sac_container, file=self.file_obj)

                print_msg_box('######## Secret mounted in below containers ########', file_obj=self.file_obj)
                for mounted in list(set(mounted_in)):
                    print(mounted, file=self.file_obj)

                print_msg_box('######## Docker Socket mounted in below containers ########', file_obj=self.file_obj)
                for docker_socket in list(set(docker_sock_containers)):
                    print(docker_socket, file=self.file_obj)

                print(stylize("\n[+] Identified Misonfigured containers ........................................\n",
                              fg("green_1")))
                print("[+] Identified Misonfigured containers ........................................",
                      file=self.file_obj)
                if pvl_containers:
                    resource_available("Containers with High Privileges", self.file_obj)
                if livenessprobe:
                    resource_available("Containers with missing liveness Probe", self.file_obj)
                if readnessprobe:
                    resource_available("Containers with missing readiness Probe", self.file_obj)
                if cpu:
                    resource_available("Containers with missing CPU Limit", self.file_obj)
                if memory:
                    resource_available("Containers with missing Memory Limit", self.file_obj)
                if priorityclassname_in:
                    resource_available("Containers with missing Priorityclassname", self.file_obj)
                if service_account_in:
                    resource_available("Containers with ServiceAccount Mounted", self.file_obj)
                if mounted_in:
                    resource_available("Conatiners with Secrets Mounted", self.file_obj)
                if docker_sock_containers:
                    resource_available("Containers with Docker socket Mount", self.file_obj)
            else:
                print("\nPod or deployment data not available", file=self.file_obj)

    def pod_security_polocies(self, psp_data, roles_data, roles_bindings_data, clusterroles_data,
                              clusterrolebindings_data, namespacelist):
        psp_privilized = None
        print("\n[+] Validating Pod Security Policies..................................", file=self.file_obj)
        psp = PspRole()
        if psp_data.get('policy') is not None:
            psp_privilized, psp_restricted = psp.validate_psp_rule(psp_data.get('policy'))
            if (roles_data.get('rbac') and roles_bindings_data.get('rbac') and clusterroles_data.get(
                    'rbac') and clusterrolebindings_data.get('rbac')) is not None:
                psp_roles_data = psp.validate_psp_role(roles_data['rbac'], roles_bindings_data['rbac'],
                                                       clusterroles_data['rbac'],
                                                       clusterrolebindings_data['rbac'])
                psp.psp_update_data(psp_privilized, psp_restricted, psp_roles_data)
            print(stylize("\n[+] Identified Misconfigured Pod Security Policies ...........................\n",
                          fg("green_1")))
            if psp_privilized:
                resource_available("Privilized Pod Security Policies", self.file_obj)
            if psp_restricted:
                resource_available("Restricted Pod Security Policies", self.file_obj)
        else:
            for namespace in namespacelist:
                psp_privilized, psp_restricted = psp.validate_psp_rule(psp_data.get(namespace))
                if (roles_data.get(namespace) and roles_bindings_data.get(namespace) and clusterroles_data.get(
                        namespace) and clusterrolebindings_data.get(namespace)) is not None:
                    psp_roles_data = psp.validate_psp_role(roles_data[namespace], roles_bindings_data[namespace],
                                                           clusterroles_data[namespace],
                                                           clusterrolebindings_data[namespace])
                    psp.psp_update_data(psp_privilized, psp_restricted, psp_roles_data)
                print(
                    stylize("\n[+] Identified Misconfigured Pod Security Policies ...........................\n",
                            fg("green_1")))
                print("\n[+] Identified Misconfigured Pod Security Policies ...........................\n",
                      file=self.file_obj)
                if psp_privilized:
                    resource_available(namespace + " Privilized Pod Security Policies", self.file_obj)
                if psp_restricted:
                    resource_available(namespace + " Restricted Pod Security Policies", self.file_obj)
        print_msg_box('######## Privilized PSPs ########', file_obj=self.file_obj)
        if psp_privilized:
            psp_container_list = []
            for psp_container, psp_data in psp_privilized.items():
                match_signs = psp_data.get('matched_signs')
                ser_acn_details = psp_data.get('service_acount')
                if ser_acn_details is None:
                    if not psp_container in psp_container_list:
                        print("{psp_container} has privilized rules {match_signs}".format(psp_container=psp_container,
                                                                                         match_signs=str(match_signs)),
                              file=self.file_obj)
                        psp_container_list.append(psp_container)
            print(file=self.file_obj)
            psp_container_list = []
            for psp_container, psp_data in psp_privilized.items():
                match_signs = psp_data.get('matched_signs')
                ser_acn_details = psp_data.get('service_acount')
                if ser_acn_details:
                    kind = ser_acn_details.get('kind')
                    name = ser_acn_details.get('name')

                    if not psp_container in psp_container_list:
                        print(
                            "{psp_container} lets {kind} {name} use {match_signs}".format(psp_container=psp_container,
                                                                                         kind=kind, name=name,
                                                                                         match_signs=str(match_signs)),
                            file=self.file_obj)
                        psp_container_list.append(psp_container)

    def grab_nodes_data(self, nodes_total_data, namespacelist):
        nodes_list = []
        if nodes_total_data:
            nodes_data = nodes_total_data.get('core')
            if nodes_data:
                items_data = nodes_data.get('items')
                for items in items_data:
                    name = items.get('metadata', {}).get('name')
                    if name and name not in nodes_list:
                        nodes_list.append(name)
            else:
                for namespace in namespacelist:
                    nodes_data = nodes_total_data.get(namespace)
                    if nodes_data:
                        items_data = nodes_data.get('items')
                        for items in items_data:
                            name = items.get('metadata', {}).get('name')
                            if name and name not in nodes_list:
                                nodes_list.append(name)
        if nodes_list:
            print_msg_box('######## below are the nodes ########', file_obj=self.file_obj)
            for node in list(set(nodes_list)):
                print(node, file=self.file_obj)
