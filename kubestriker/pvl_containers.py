# Read data from files
import json
from kubestriker.bars import prefix

dangerous_caps = [
    "*", "DAC_READ_SEARCH", "LINUX_IMMUTABLE", "NET_BROADCAST", "NET_ADMIN", "IPC_LOCK", "IPC_OWNER",
    "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "SYS_BOOT", "SYS_PACCT", "SYS_ADMIN", "SYS_NICE", "SYS_RESOURCE",
    "SYS_TIME", "SYS_TTY_CONFIG", "LEASE", "AUDIT_CONTROL", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM",
    "BLOCK_SUSPEND"
]


class PvlContainers(object):
    def __init__(self):
        pass

    def validate_spec_data(self, spec_sign, spec_data):
        spec_match = {}
        if spec_data:
            for key, value in spec_sign.items():
                if key == 'securityContext':
                    sc_data = {}
                    spec_sec_data = spec_data.get(key, {})
                    for sc_key, sc_value in value.items():
                        if sc_key == 'capabilities':
                            cap_list = spec_sec_data.get(sc_key, {}).get('add')
                            if cap_list:
                                matched_capabilities = [sign for sign in cap_list if sign in dangerous_caps]
                                if matched_capabilities:
                                    sc_data.update({sc_key: matched_capabilities})
                        elif spec_sec_data.get(sc_key) == sc_value:
                            sc_data.update({sc_key: sc_value})
                    if sc_data:
                        spec_match.update({key: sc_data})
                elif spec_data.get(key) == value:
                    spec_match.update({key: value})
        return spec_match

    def validate_containers_data(self, spec_container_sign, containers_data, volumes, containers_list):
        container_match = {}
        for container_data in containers_data:
            spec_match = self.validate_spec_data(spec_container_sign, container_data)
            if spec_match:
                if not container_data.get('name') in containers_list:
                    containers_list.append(container_data.get('name'))
                    container_match.update(spec_match)
            elif "hostport" in container_data:
                if not container_data.get('name') in containers_list:
                    containers_list.append(container_data.get('name'))
                    container_match.update({'hostport': container_data.get('hostport')})
            elif container_data.get('securityContext', {}).get('runAsGroup') == 0:
                if not container_data.get('name') in containers_list:
                    containers_list.append(container_data.get('name'))
                    container_match.update({'securityContext': 'runAsGroup=0'})
            elif volumes:
                volume_mounts = container_data.get('volumeMounts')
                for volume in volumes:
                    if volume.get('hostPath') and volume_mounts:
                        for volume_mount in volume_mounts:
                            if volume.get('name') == volume_mount.get('name'):
                                if not container_data.get('name') in containers_list:
                                    containers_list.append(container_data.get('name'))
                                    container_match.update({'volume': volume.get('name')})
                                    break
            else:
                pass

        return container_match

    def containers_check(self, containers_json):
        match_signs = {}
        containers_list = []
        spec_sign = {'securityContext': {'runAsUser': 0, 'privileged': True, 'allowPrivilegeEscalation': True,
                                         'capabilities': {'add': dangerous_caps}}, 'hostIPC': True, 'hostPID': True,
                     'hostNetwork': True}
        spec_data = containers_json.get('spec')
        if not spec_data:
            print("spec data is not available in input json")
            return containers_list
        containers_data = spec_data.get('containers', [])
        initcontainers_data = spec_data.get('initContainers', [])
        spec_match = self.validate_spec_data(spec_sign, spec_data)
        if spec_match:
            # print("matching signs", spec_match)
            match_signs.update(spec_match)
            for cn in containers_data:
                name = cn.get('name')
                if not name in containers_list:
                    containers_list.append(name)
            for cn in initcontainers_data:
                name = cn.get('name')
                if not name in containers_list:
                    containers_list.append(name)
        else:
            spec_container_sign = {
                'securityContext': {'runAsUser': 0, 'privileged': True, 'allowPrivilegeEscalation': True,
                                    "runAsNonRoot": False, "runAsGroup": True,
                                    'capabilities': {'add': dangerous_caps}}, 'hostPort': "*"}
            volumes = spec_data.get('volumes')
            container_match = {}
            init_container_match = {}
            if containers_data:
                container_match = self.validate_containers_data(spec_container_sign, containers_data, volumes,
                                                                containers_list)
            if initcontainers_data:
                init_container_match = self.validate_containers_data(spec_container_sign, initcontainers_data, volumes,
                                                                     containers_list)
            match_signs.update(container_match)
            match_signs.update(init_container_match)
            # print("matching signs", container_match, init_container_match)
        return containers_list, match_signs

    def container_metrics(self, containers_json, cpu=None, memory=None, livenessprobe=None, readnessprobe=None,
                          priorityclassname_in=None, service_account_in=None, mounted_in=None,docker_sock_containers=None):
        if priorityclassname_in is None:
            priorityclassname_in = []
        if service_account_in is None:
            service_account_in = []
        if readnessprobe is None:
            readnessprobe = []
        if livenessprobe is None:
            livenessprobe = []
        if memory is None:
            memory = []
        if cpu is None:
            cpu = []
        if mounted_in is None:
            mounted_in = []
        if docker_sock_containers is None:
            docker_sock_containers = []
        spec_data = containers_json.get('spec')
        if not spec_data:
            print("spec data is not available in input json")
            return
        normalcontainers_data = spec_data.get('containers')
        initcontainers_data = spec_data.get('initContainers')
        limits = ['cpu', 'memory']
        probes_list = ['livenessProbe', 'readinessProbe']
        volumes = spec_data.get('volumes')
        for containers_data in [normalcontainers_data, initcontainers_data]:
            if not containers_data:
                continue
            for container in containers_data:
                resources_limits = container.get('resources', {}).get('limits', {})
                for limit in limits:
                    if not resources_limits.get(limit):
                        # print(limit + " not set in this container " + container.get('name'))
                        if limit == 'cpu':
                            cpu.append(container.get('name'))
                        else:
                            memory.append(container.get('name'))
                for probe in probes_list:
                    if not container.get(probe):
                        # print(probe + " not set in this container " + container.get('name'))
                        if probe == 'livenessProbe':
                            livenessprobe.append(container.get('name'))
                        else:
                            readnessprobe.append(container.get('name'))
                if 'priorityClassName' not in spec_data.keys():
                    # print('priorityClassName is not in ' + container.get('name'))
                    priorityclassname_in.append(container.get('name'))
                if 'serviceAccount' in spec_data.keys():
                    # print('serviceAccount is in ' + container.get('name'))
                    service_account_in.append(container.get('name'))
                volume_mounts = container.get('volumeMounts', [])
                for volume_mount in volume_mounts:
                    if isinstance(volume_mount, dict):
                        if volume_mount.get('mountPath') == '/var/run/secrets/kubernetes.io/serviceaccount':
                            mounted_in.append(container.get('name'))
                self.get_docker_sock_containers(volumes,container,docker_sock_containers)

    def get_docker_sock_containers(self,volumes,container_data,docker_sock_containers):
        docker_matched_key_list = []
        if volumes:
            env_data = container_data.get('env', [])
            for env in env_data:
                if isinstance(env, dict) and len(env) != 0:
                    for key, value in env.items():
                        if value == '/var/run/docker.sock' or value == 'unix:///host/var/run/docker.sock':
                            if key not in docker_matched_key_list:
                                docker_matched_key_list.append(key)
            for volume in volumes:
                path = volume.get('hostPath', {}).get('path')
                if path in docker_matched_key_list or path == '/var/run/docker.sock' or path == 'unix:///host/var/run/docker.sock':
                    if not container_data.get('name') in docker_sock_containers:
                        docker_sock_containers.append(container_data.get('name'))
                elif docker_matched_key_list:
                    if not container_data.get('name') in docker_sock_containers:
                        docker_sock_containers.append(container_data.get('name'))
