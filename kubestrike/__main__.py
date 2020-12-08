import sys
import getpass
import requests
import yaml
from pyfiglet import Figlet
from colored import fg, bg, attr, fore, style, stylize
from selectmenu import SelectMenu
from kubestrike.validate_input import ValidateInput
from kubestrike.service_discovery import ServiceDiscovery
from kubestrike.service_hunt import ServiceHunt
from kubestrike.cmd_exec import cmd_exec
from kubestrike.bars import cowsay
from kubestrike.jwt_token_converter import decode_jwt_token_data
menu = SelectMenu()


def main():
    """
    This function executes all services on host
    :return:
    """
    process = True
    while process:
        menu.add_choices(["url or ip", "configfile", "iprange or cidr"])
        option = menu.select("Choose one of the below options:")
        if option == 'url or ip':
            input_host = input("Enter the target K8s Endpoint : ")
            host, port = ValidateInput().input_to_host(input_host)
            if not host:
                cowsay("Target is neither reachable nor valid")
                return
            file_name = str(host) + ".txt"
            file_obj = open(file_name, 'w')
            kube_services_process(option, file_obj, host, port)
        elif option == 'iprange or cidr':
            print(fore.MAGENTA_1 + "Example ip range input : 192.168.99.1-9" + style.RESET)
            print(fore.MAGENTA_1 + "Example of cidr range : 192.168.99.1/28 " + style.RESET)
            input_range = input("Enter the ip or cidr range : ")
            host_list = ValidateInput().iprange_to_iplist(input_range)
            if host_list:
                for host in host_list:
                    file_name = str(host) + ".txt"
                    file_obj = open(file_name, 'w')
                    kube_services_process(option, file_obj, host)
            else:
                cowsay("Please enter a valid IP range")
        elif option == 'configfile':
            menu.add_choices(["default", "Kube config custom path"])
            print("")
            result = menu.select("Choose one the below options:")
            if result == 'Kube config custom path':
                input_file = input("Enter the full path of custom config file: ")
            else:
                input_file = 'default'
            host_url_list = ValidateInput().config_file_to_host_list(input_file)
            menu.add_choices(host_url_list)
            print("")
            result = menu.select("Choose one of the below url:")
            host, port = ValidateInput().input_to_host(result)
            if not host:
                cowsay("Input is not valid")
                return
            file_name = str(host) + ".txt"
            file_obj = open(file_name, 'w')
            kube_services_process(option, file_obj, host)
        else:
            cowsay("No option is selected")
        menu.add_choices(["continue", "exit"])
        process_status = menu.select("Choose process continue or exit :")
        if process_status == 'exit':
            process = False

def kube_services_process(option, file_obj, host, port=None):
    """
    This function executes api server secure and insecure, kubelet RW and RO
    :param option:
    :param file_obj:
    :param host:
    :param port:
    :return:
    """
    token = ''
    end_point = ''
    service_discovery = ServiceDiscovery(file_obj)
    service_discovery.service_result(host, port)
    service_discovery_result = service_discovery.result
    apiserver_insecure = service_discovery_result.get('apiserver_insecure').get('active')
    kubelet_rw = service_discovery_result.get('kubelet_rw').get('active')
    kubelet_ro = service_discovery_result.get('kubelet_ro').get('active')
    ser_hunt = ServiceHunt(file_obj)
    if apiserver_insecure:
        end_point = service_discovery_result.get('apiserver_insecure').get('end_point')
        get_git_version(end_point)
        ser_hunt.apiserver_insecure(service_discovery_result)
    else:
        apiserver_secure = service_discovery_result.get('apiserver_secure').get('active')
        if apiserver_secure:
            end_point = service_discovery_result.get('apiserver_secure').get('end_point')
            get_git_version(end_point)
            menu.add_choices(['authenticated scan', 'unauthenticated scan'])
            print("")
            option = menu.select("Choose one of the below option:")
            if option == 'authenticated scan':
                print(fore.CYAN_1 + "Grab the Token:" + style.RESET)
                print(fore.MAGENTA_1 + "     aws eks get-token --cluster-name cluster-name --region ap-southeast-2" + style.RESET)
                print(fore.MAGENTA_1 + "     az aks get-credentials --resource-group myResourceGroup --name myAKSCluster" + style.RESET)
                print(fore.MAGENTA_1 + "     gcloud container clusters get-credentials CLUSTER_NAME --zone=COMPUTE_ZONE" + style.RESET)
                print("")
                count = 0
                while count <= 3:
                    token = getpass.getpass("Provide token : ")
                    token = token.strip()
                    end_point_url = "https://" + end_point
                    end_point_url1 = "https://" + end_point + '/api'
                    response_status = check_service(end_point_url, token)
                    response_status1 = check_service(end_point_url1, token)
                    if response_status == False or response_status1 == False:
                        cowsay("Could not autheticate with the provided token")
                        count = count + 1
                        if count == 3:
                            cowsay('Maximum retries reached!!')
                            return
                    else:
                        cowsay('Authentication Successful!!')
                        break
                check_choice = None
                user_name = None
                menu.add_choices(["Perform All Checks", "Perform individual Checks"])
                print("")
                checks_status = menu.select("Choose checks option")
                if checks_status == 'Perform individual Checks':
                    menu.add_choices(["Scan IAM misconfigurations", "Scan misconfigured containers", "Scan misconfigured podsecuritypolicies","Scan misconfigured network policies"])
                    check_choice = menu.select("select choice to scan")
                    if check_choice == 'Scan IAM misconfigurations':
                        menu.add_choices(["total check","user check"])
                        check_user_choice = menu.select("select choice to scan")
                        if check_user_choice == 'user check':
                            user_name = input("Give username: ")
                ser_hunt.apiserver_secure(service_discovery_result, token,check_choice,user_name)
            else:
                ser_hunt.apiserver_secure(service_discovery_result)
    if kubelet_rw:
        ser_hunt.kubelet_rw(service_discovery_result)
    if kubelet_ro:
        ser_hunt.kubelet_ro(service_discovery_result)
    file_obj.close()
    pods_data = ser_hunt.result
    if pods_data:
        if option == 'iprange or cidr':
            print(fore.MAGENTA_1 + "This host {end_point} has pods data, if you want to execute commands scan this host alone" + style.RESET)
            return
        menu.add_choices(["excute command on containers", "exit"])
        result_cmd_exec = menu.select("Chose one the below options:")
        if result_cmd_exec == 'excute command on containers':
            command_execute(pods_data, end_point, token)
    cowsay("Scan completed and Results generated with the target file name")


def command_execute(pods_data, end_point, token):
    """
    This function is used to form the command excution url and call the another function to execute
    :param pods_data:
    :param end_point:
    :param token:
    :return:
    """
    pod_name_list = []
    pod_containers_data = {}
    pod_namespace_data = {}
    for pods_key, pods_value in pods_data.items():
        for pod_data in pods_value['items']:
            pod_name = pod_data.get('metadata').get('name')
            namespace = pod_data.get('metadata').get('namespace')
            pod_namespace_data.update({pod_name: namespace})
            spec_data = pod_data.get('spec')
            if not spec_data:
                print("spec data is not available in input json")
                return
            containers_data = spec_data.get('containers', [])
            initcontainers_data = spec_data.get('initContainers', [])
            con_list = []
            for cn in containers_data:
                name = cn.get('name')
                if name not in con_list:
                    con_list.append(name)
            for cn in initcontainers_data:
                name = cn.get('name')
                if name not in con_list:
                    con_list.append(name)
            con_str = ",".join(con_list)
            pod_name_list.append(pod_name)
            pod_containers_data.update({pod_name: con_str})
    if not pod_name_list:
        cowsay("No access to get pods data")
        return
    print(fore.MAGENTA_1 + "\nBelow listed are the pods available in the cluster\n" + style.RESET)
    print(pod_name_list)
    process_continue = True
    inp_pod_name = None
    while process_continue:
        if inp_pod_name:
            print( fore.CYAN_1 + "This is the previous pod" + style.RESET, inp_pod_name)
            menu.add_choices(["Continue with the existing pod", "Select a new pod"])
            result_pod = menu.select("Choose option:")
            if result_pod == 'Select a new pod':
                inp_pod_name = input("Enter the any one of pod name  : ")
        else:
            inp_pod_name = input("\n Choose a pod for the above list  : ")
        print( fore.MAGENTA_1 + "\nBelow listed are the containers in this pod - " + style.RESET + str(inp_pod_name) + '\n')
        print(pod_containers_data.get(inp_pod_name) + '\n')
        pod_namespace = pod_namespace_data.get(inp_pod_name)
        inp_container = input("Enter the container name to execute commands: ")
        print(inp_container)
        inp_command = input("\nEnter the command to be executed: ")
        cmd_url = ""
        for command in inp_command.split():
            cmd_url = cmd_url + "command=" + str(command) + "&"
        end_point_url = "wss://" + end_point
        pod_url = '/api/v1/namespaces/{namespace}/pods/{pod_name}/exec?'.format(namespace=pod_namespace,
                                                                                pod_name=inp_pod_name)
        container_context = 'container={container}&stdin=true&stdout=true&tty=true'.format(container=inp_container)
        url_context = pod_url+cmd_url+container_context
        url = end_point_url + url_context
        try:
            result = cmd_exec(url, token)
            print(f'\n{result}')
        except Exception as e:
            cowsay("Command execution failed - " + str(e))
        menu.add_choices(["continue", "exit"])
        result_process = menu.select("Chose one the below options:")
        if result_process == 'exit':
            process_continue = False

def check_service(url, token):
    '''
    This function checks for various services running
    '''
    session = requests.Session()
    session.verify = False
    session.headers = {'Authorization': 'Bearer {}'.format(token)}
    try:
        response = session.get(url, timeout=5)
        if response.status_code ==200:
            return True
        else:
            decoded_data = yaml.safe_load(decode_jwt_token_data(token))
            namespace = decoded_data.get('kubernetes.io/serviceaccount/namespace')
            namespace_url = url+"/api/v1/namespaces/"+namespace
            namespace_response = session.get(namespace_url, timeout=5)
            if namespace_response.status_code == 200:
                return True
            else:
                return False
    except requests.exceptions.SSLError:
        return False
    except Exception:
        return False

def get_git_version(end_point):
    '''
    This function discovers the kuberentes version
    '''
    session = requests.Session()
    session.verify = False
    url = 'https://'+end_point+"/version"
    try:
        response = session.get(url, timeout=5)
        if response.status_code == 200:
            content = response.json()
            git_version = content.get('gitVersion')
            print("\nThe version of Kuberentes is: {git_version}".format(git_version=git_version))
    except Exception as e:
        pass


if __name__ == '__main__':
    x = (stylize((Figlet(font='slant', justify='center').renderText('>>>-kube-strike->')), fg("orange_1")))
    print(stylize('\n  ###########################################################################',
                  fg("light_sky_blue_1")))
    print(x)
    t = (stylize('  ###########################################################################',
                 fg("light_sky_blue_1")))
    print(t + fore.LIGHT_RED + '   v1.0.0\n' + style.RESET)
    print(stylize('[+] Gearing up Kube-Strike......................................................\n', fg("green_1")))
    try:
        main()
    except KeyboardInterrupt:
        cowsay("KeyboardInterrupted process")
        sys.exit(1)
    except Exception as e:
        cowsay("Process failed due to - " + str(e))
