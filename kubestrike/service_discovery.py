import socket
import warnings
from kubestrike.bars import prefix, sub_prefix, service_open, print_msg_box

warnings.filterwarnings("ignore")

class ServiceDiscovery(object):
    def __init__(self,file_object):
        self.result = {}
        self.service_discovery_status = []
        self.file_obj = file_object

    def port_scan(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            return True
        else:
            return False

    @prefix('[+] Performing Service Discovery.................................................')
    def service_result(self, ip, port=None):
        print("Performing Service Discovery on host {host}..........".format(host=str(ip)),file=self.file_obj)
        self.apiserver_secure(ip, port)
        self.apiserver_insecure(ip)
        self.kubelet_rw(ip)
        self.kubelet_ro(ip)
        self.kubecontroller(ip)
        self.etcd_client(ip)
        self.etcd_server(ip)
        self.kubeproxy_healthcheck(ip)
        self.scheduler(ip)
        self.kubeproxy(ip)
        self.important_ports(ip)
        self.dashboard(ip)
        self.service_discovery_results_status()
    
    @prefix('[+] KubeServer Secure Identified Services ........................................')
    def service_discovery_results_status(self):
        print('\n', file=self.file_obj)
        print("KubeServer Secure Identified Services ........................................",file=self.file_obj)
        service_discovery_status = self.service_discovery_status
        for status in service_discovery_status:
            service_open(status,self.file_obj)
        print('\n',file=self.file_obj)
        print_msg_box('######## Below mentioned are the valid urls of the identified Endpoints ########', file_obj=self.file_obj)
        for service, status in self.result.items():
            if status.get('active') == True:
                end_point = status.get('end_point')
                print("     --> {service} identified {end_point}".format(service=service,end_point=end_point),file=self.file_obj)

    @sub_prefix('       [+] Scanning for KubeServer Secure Service................................')
    def apiserver_secure(self, host, port=None):
        print("       [+] Scanning for KubeServer Secure Service................................",file=self.file_obj)
        ports = [443, 6443, 8443]
        apiserver_secure = False
        end_point = None
        if port:
            ports.append(int(port))
        for port in ports:
            p_res = self.port_scan(host, port)
            if p_res:
                apiserver_secure = True
                end_point = host + ':' + str(port)
                self.service_discovery_status.append('KubeServer Secure')
                break
        self.result.update({'apiserver_secure': {'active': apiserver_secure, 'end_point': end_point}})

    @sub_prefix('       [+] Scanning for KubeServer Insecure Service..............................')
    def apiserver_insecure(self, host):
        print("       [+] Scanning for KubeServer Insecure Service..............................", file=self.file_obj)
        apiserver_insecure = False
        end_point = None
        port = 8080
        p_res = self.port_scan(host, port)
        if p_res:
            apiserver_insecure = True
            end_point = host + ':' + str(port)
            self.service_discovery_status.append('KubeServer Insecure Service')
        self.result.update({'apiserver_insecure': {'active': apiserver_insecure, 'end_point': end_point}})

    @sub_prefix('       [+] Scanning for Kubelet ReadWrite Service................................')
    def kubelet_rw(self, host):
        print("       [+] Scanning for Kubelet ReadWrite Service................................", file=self.file_obj)
        kubelet_rw = False
        end_point = None
        port = 10250
        p_res = self.port_scan(host, port)
        if p_res:
            kubelet_rw = True
            end_point = host + ':' + str(port)
            self.service_discovery_status.append('Kubelet ReadWrite Service')
        self.result.update({'kubelet_rw': {'active': kubelet_rw, 'end_point': end_point}})
               
    @sub_prefix('       [+] Scanning for kubecontroller Service...................................')
    def kubecontroller(self, host):
        print("       [+] Scanning for kubecontroller Service................................", file=self.file_obj)
        kubecontroller = False
        end_point = None
        port = 10257
        p_res = self.port_scan(host, port)
        if p_res:
            kubecontroller = True
            end_point = host + ':' + str(port)
            self.service_discovery_status.append('Kubecontroller Service')
        self.result.update({'kubecontroller': {'active': kubecontroller, 'end_point': end_point}})
                
    @sub_prefix('       [+] Scanning for Kubelet Readonly Service.................................')
    def kubelet_ro(self, host):
        print("       [+] Scanning for Kubelet Readonly Service.................................", file=self.file_obj)
        kubelet_ro = False
        end_point = None
        port = 10255
        p_res = self.port_scan(host, port)
        if p_res:
            kubelet_ro = True
            end_point = host + ':' + str(port)
            self.service_discovery_status.append('Kubelet Readonly Service')
        self.result.update({'kubelet_ro': {'active': kubelet_ro, 'end_point': end_point}})
                
    @sub_prefix('       [+] Scanning for ETCD Client..............................................')
    def etcd_client(self, host):
        print("       [+] Scanning for ETCD Client..............................................", file=self.file_obj)
        etcd_client = False
        end_point = None
        port = 2379
        p_res = self.port_scan(host, port)
        if p_res:
            etcd_client = True
            end_point = host + ':' + str(port)
            self.service_discovery_status.append('ETCD Client')
        self.result.update({'etcd_client': {'active': etcd_client, 'end_point': end_point}})
                
    @sub_prefix('       [+] Scanning for ETCD Server..............................................')
    def etcd_server(self, host):
        print("       [+] Scanning for ETCD Server..............................................", file=self.file_obj)
        etcd_server = False
        end_point = None
        port = 2380
        p_res = self.port_scan(host, port)
        if p_res:
            etcd_server = True
            end_point = host + ':' + str(port)
            self.service_discovery_status.append('ETCD Server')
        self.result.update({'etcd_server': {'active': etcd_server, 'end_point': end_point}})
                
    @sub_prefix('       [+] Scanning for Kube proxy Healthcheck...................................')
    def kubeproxy_healthcheck(self, host):
        print("       [+] Scanning for Kube proxy Healthcheck...................................", file=self.file_obj)
        kubeproxy_healthcheck = False
        end_point = None
        ports = [10256, 10257, 10249]
        for port in ports:
            p_res = self.port_scan(host, port)
            if p_res:
                kubeproxy_healthcheck = True
                end_point = host + ':' + str(port)
                self.service_discovery_status.append('Kube proxy Healthcheck')
                break
        self.result.update({'kubeproxy_healthcheck': {'active': kubeproxy_healthcheck, 'end_point': end_point}})
                
    @sub_prefix('       [+] Scanning for Kube Scheduler Service...................................')
    def scheduler(self, host):
        print("       [+] Scanning for Kube Scheduler Service...................................", file=self.file_obj)
        scheduler = False
        end_point = None
        ports = [10251, 10259]
        for port in ports:
            p_res = self.port_scan(host, port)
            if p_res:
                scheduler = True
                end_point = host + ':' + str(port)
                self.service_discovery_status.append('Kube Scheduler Service')
                break
        self.result.update({'scheduler': {'active': scheduler, 'end_point': end_point}})
                
    @sub_prefix('       [+] Scanning for Kube proxy ..............................................')
    def kubeproxy(self, host):
        print("       [+] Scanning for Kube proxy ..............................................", file=self.file_obj)
        kubeproxy = False
        end_point = None
        port = 8001
        p_res = self.port_scan(host, port)
        if p_res:
            kubeproxy = True
            end_point = host + ':' + str(port)
            self.service_discovery_status.append('Kube proxy')
        self.result.update({'kubeproxy': {'active': kubeproxy, 'end_point': end_point}})

    @sub_prefix('       [+] Scanning for known Open Ports.........................................')
    def important_ports(self, host):
        print("       [+] Scanning for known Open Ports.........................................", file=self.file_obj)
        important_ports = False
        end_point = None
        port = 22
        p_res = self.port_scan(host, port)
        if p_res:
            important_ports = True
            end_point = host + ':' + str(port)
            self.service_discovery_status.append('Open Port 22')
        self.result.update({'important_ports': {'active': important_ports, 'end_point': end_point}})

    @sub_prefix('       [+] Scanning for Kubernetes Dashboard.....................................')
    def dashboard(self, host):
        print("       [+] Scanning for Kubernetes Dashboard.....................................", file=self.file_obj)
        dashboard = False
        end_point = None
        port = 3000
        p_res = self.port_scan(host, port)
        if p_res:
            dashboard = True
            end_point = host + ':' + str(port)
            self.service_discovery_status.append('Kubernetes Dashboard')
        self.result.update({'dashboard': {'active': dashboard, 'end_point': end_point}})
