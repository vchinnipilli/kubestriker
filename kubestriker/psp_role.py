from kubestriker.bars import prefix

class PspRole(object):
    def __init__(self):
        pass

    @prefix('[+] Scanning Pod Security Policies............................................')
    def validate_psp_rule(self, psp_main_json):
        '''
        Avoid repetition
        Insert Gap
        '''
        psp_privilized = {}
        psp_restcrited = {}
        dangerous_caps = [
            "*", "DAC_READ_SEARCH", "LINUX_IMMUTABLE", "NET_BROADCAST", "NET_ADMIN", "IPC_LOCK", "IPC_OWNER",
            "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "SYS_BOOT", "SYS_PACCT", "SYS_ADMIN", "SYS_NICE", "SYS_RESOURCE",
            "SYS_TIME", "SYS_TTY_CONFIG", "LEASE", "AUDIT_CONTROL", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM",
            "BLOCK_SUSPEND"
        ]
        spec_sign = {'privileged': True, 'allowPrivilegeEscalation': True, 'DefaultAllowPrivilegeEscalation': True,
                     'runAsUser': {'rule': 'RunAsAny'}, 'runAsGroup': {'rule': 'RunAsAny'},
                     'allowedCapabilities': dangerous_caps,
                     'hostPID': True, 'volumes': ['*']}
        role_kind = psp_main_json.get('kind')
        for roles_data in psp_main_json['items']:
            spec_update = {}
            #role_kind = roles_data.get('kind')
            role_name = roles_data.get('metadata').get('name')
            if role_kind.lower() == 'podsecuritypolicylist':
                spec_data = roles_data.get('spec')
                if not spec_data:
                    continue
                for psp_key, psp_value in spec_sign.items():
                    if psp_key == 'allowedCapabilities':
                        if spec_data.get(psp_key) and any([sign for sign in psp_value if sign in spec_data.get(psp_key)]):
                            spec_update.update({psp_key: [sign for sign in psp_value if sign in spec_data.get(psp_key)]})
                    elif spec_data.get(psp_key) == psp_value:
                        spec_update.update({psp_key: psp_value})

                if spec_update:
                    psp_privilized.update({role_name: {"matched_signs":spec_update}})
                    #print(role_name + " is a privileged psp with flags ",spec_update)
                else:
                    psp_restcrited.update({role_name: {}})
                    #print(role_name + " is a restricted psp")
                #print()
        return psp_privilized, psp_restcrited

    def validate_psp_role(self, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json):
        '''
        Insert Gap as discsussed
        '''
        role_users = []
        roles_check_json = [roles_json, clusterroles_json]
        verbs_sign = ["use"]
        resource_sign = ['podsecuritypolicies']
        psp_data = {}
        for roles_json in roles_check_json:
            role_kind = roles_json.get('kind')
            for roles_data in roles_json['items']:
                if not roles_data.get('rules'):
                    continue
                #role_kind = roles_data.get('kind')
                for rule in roles_data['rules']:
                    if not rule.get('verbs', None):
                        continue
                    if not rule.get('resources', None):
                        continue
                    if verbs_sign == rule['verbs'] and resource_sign == rule['resources']:
                        role_name = roles_data['metadata']['name']
                        if role_name in role_users:
                            continue
                        if role_kind.lower() == 'rolelist':
                            binding_json = roles_bindings_json
                        if role_kind.lower() == 'clusterrolelist':
                            binding_json = cluster_bindings_json
                        role_users.append(role_name)
                        for entity in binding_json['items']:
                            if entity['roleRef']['name'] == role_name:
                                subjects = entity.get('subjects', [])
                                if subjects:
                                    for subject in subjects:
                                        kind = subject.get('kind')
                                        name = subject.get('name')
                                        psp_data.update({role_name: {'kind': kind, 'name': name}})
        return psp_data

    def psp_update_data(self, psp_privilized, psp_restricted, psp_roles_data):

        for key, value in psp_roles_data.items():
            if psp_privilized.get(key):
                psp_privilized.get(key).update({'service_acount':value})
        for key, value in psp_roles_data.items():
            if psp_restricted.get(key):
                psp_privilized.get(key).update(value)
        #print({'privilized': psp_privilized})
        #print({'restricted': psp_restricted})
