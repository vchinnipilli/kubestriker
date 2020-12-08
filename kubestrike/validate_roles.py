import json
from kubestrike.bars import prefix, sub_prefix,service_open, resource_available, print_msg_box

class Validate_Roles(object):
    def __init__(self,file_obj=None):
        self.result = {}
        self.file_obj = file_obj
        self.validation_status = []

    @prefix('[+] Identified IAM Misconfigurations ..........................................')
    def service_discovery_results_status(self):
        print('[+] Identified IAM Misconfigurations ..........................................',file=self.file_obj)
        service_discovery_status = self.validation_status
        for status in service_discovery_status:
            resource_available(status,self.file_obj)

    def binds_search(self, role_name, binding_json):
        role_ref = {}
        subjects_data = []
        for entity in binding_json['items']:
            try:
                if entity['roleRef']['name'] == role_name:
                    role_ref = entity.get('roleRef', {})
                    subjects = entity.get('subjects', [])
                    [subjects_data.append(x) for x in subjects if x not in subjects_data]
                    # if subjects not in subjects_data:
                    #     subjects_data.extend(subjects)
            except Exception as e:
                print(e)
                return role_ref, subjects_data
        return role_ref, subjects_data

    # Validate the roles
    def validate_roles(self,roles_json,roles_bindings_json,clusterroles_json,cluster_bindings_json,user_name=None):
        if user_name:
            self.access_search(user_name, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json)
        else:
            self.validate_admin_role(roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json, user_name)
            self.validate_read_admin_role(roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,
                                          user_name)
            self.validate_destructive_role(roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json, user_name)
            self.validate_secrets_role(roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,user_name)
            self.validate_impersonate_role(roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,user_name)
            self.validate_psp_role(roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json, user_name)
            self.validate_privileged_role(roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,user_name)
            self.service_discovery_results_status()
        # self.access_search(user_name, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json)

    # Scanning for admin role:
    @sub_prefix('       [+] Scanning for Admin Roles............................................')
    def validate_admin_role(self, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,
                            user_name=None):
        '''
        avoid repetition
        Insert  gap after each role
        '''
        print_msg_box("######## Admin roles ######## ",file_obj=self.file_obj)
        admin_role = False
        role_users = []
        roles_check_json = [roles_json, clusterroles_json]
        for roles_json in roles_check_json:
            role_kind = roles_json.get('kind')
            for roles_data in roles_json['items']:
                #role_kind = roles_data.get('kind')
                if not roles_data.get('rules'):
                    continue
                for rule in roles_data['rules']:
                    if not rule.get('verbs', None):
                        continue
                    if not rule.get('resources', None):
                        continue
                    if '*' in rule['resources'] and '*' in rule['verbs']:
                        role_name = roles_data['metadata']['name']
                        if user_name:
                            if user_name == role_name:
                                admin_role = True
                                self.result.update({'admin_role': admin_role})
                                return
                            else:
                                self.result.update({'admin_role': admin_role})
                                continue
                        if role_name in role_users:
                            continue
                        if role_kind.lower() == 'rolelist':
                            print(role_name + " is an admin role",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, roles_bindings_json)
                        if role_kind.lower() == 'clusterrolelist':
                            print(role_name + " is a cluster admin role",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, cluster_bindings_json)
                        role_users.append(role_name)
                        if role_ref:
                            for subject in subjects:
                                kind = subject.get('kind')
                                name = subject.get('name')
                                namespace = subject.get('namespace')
                                if namespace:
                                    print("{kind} {name} has Admin Privileges in namespace {namespace}".format(
                                        kind=kind,
                                        name=name,
                                        namespace=namespace),file=self.file_obj)
                                else:
                                    print("{kind} {name} has Admin Privileges in Cluster".format(kind=kind,
                                                                                                 name=name),file=self.file_obj)
                        print(file=self.file_obj)
            if role_users:
                self.validation_status.append('Admin Roles')
    # Validate read admin role
    @sub_prefix('       [+] Scanning for Read only Admin Roles..................................')
    def validate_read_admin_role(self, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,
                                 user_name=None):
        '''
        '''
        #print("######## Read only admin roles ######## ",file=self.file_obj)
        print_msg_box('######## Read only admin roles ########', file_obj=self.file_obj)
        read_admin_role = False
        role_users = []
        roles_check_json = [roles_json, clusterroles_json]
        verbs_sign = ['get', 'list']
        resource_sign = ['*']
        for roles_json in roles_check_json:
            role_kind = roles_json.get('kind')
            for roles_data in roles_json['items']:
                #role_kind = roles_data.get('kind')
                if not roles_data.get('rules'):
                    continue
                for rule in roles_data['rules']:
                    if not rule.get('verbs', None):
                        continue
                    if not rule.get('resources', None):
                        continue
                    if any(
                            [sign for sign in resource_sign if sign in rule['resources']]) and any(
                        [sign for sign in verbs_sign if sign in rule['verbs']]):
                        role_name = roles_data['metadata']['name']
                        if user_name:
                            if user_name == role_name:
                                read_admin_role = True
                                self.result.update({'read_admin_role': read_admin_role})
                                return
                            else:
                                self.result.update({'read_admin_role': read_admin_role})
                                continue
                        if role_name in role_users:
                            continue
                        if role_kind.lower() == 'rolelist':
                            print(role_name + " is an admin read role",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, roles_bindings_json)
                        if role_kind.lower() == 'clusterrolelist':
                            print(role_name + " is a clusteradmin read role",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, cluster_bindings_json)
                        role_users.append(role_name)
                        if role_ref:
                            for subject in subjects:
                                kind = subject.get('kind')
                                name = subject.get('name')
                                namespace = subject.get('namespace')
                                if namespace:
                                    print(
                                        "{kind} {name} has Read Admin Privileges in namespace {namespace}".format(
                                            kind=kind, name=name, namespace=namespace),file=self.file_obj)
                                else:
                                    print(
                                        "{kind} {name} has Read Admin Privileges in Cluster".format(kind=kind,
                                                                                                    name=name),file=self.file_obj)
                        print(file=self.file_obj)
            if role_users:
                self.validation_status.append('Read Only Admin roles')
    # Scanning for destructive role:
    @sub_prefix('       [+] Scanning for Destructive Roles......................................')
    def validate_destructive_role(self, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,
                                  user_name=None):
        '''
        '''
        print_msg_box('######## Destructive roles ########', file_obj=self.file_obj)
        destructive_role = False
        role_users = []
        roles_check_json = [roles_json, clusterroles_json]
        verbs_sign = ['delete', 'deletecollection']
        resource_sign = ['secrets',
                         'pods',
                         'deployments',
                         'daemonsets',
                         'statefulsets',
                         'replicationcontrollers',
                         'replicasets',
                         'cronjobs',
                         'jobs',
                         'roles',
                         'clusterroles',
                         'rolebindings',
                         'clusterrolebindings',
                         'users',
                         'groups',
                         'nodes',
                         'pods/exec',
                         'pods/attach',
                         'pods/portforward',
                         'serviceaccounts'
                         ]
        for roles_json in roles_check_json:
            role_kind = roles_json.get('kind')
            for roles_data in roles_json['items']:
                #role_kind = roles_data.get('kind')
                if not roles_data.get('rules'):
                    continue
                for rule in roles_data['rules']:
                    if not rule.get('verbs', None):
                        continue
                    if not rule.get('resources', None):
                        continue
                    if any(
                            [sign for sign in resource_sign if sign in rule['resources']]) and any(
                        [sign for sign in verbs_sign if sign in rule['verbs']]):
                        role_name = roles_data['metadata']['name']
                        if user_name:
                            if user_name == role_name:
                                destructive_role = True
                                self.result.update({'destructive_role': destructive_role})
                                return
                            else:
                                self.result.update({'destructive_role': destructive_role})
                                continue
                        if role_name in role_users:
                            continue
                        if role_kind.lower() == 'rolelist':
                            print(role_name + " is an Destructive role",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, roles_bindings_json)
                        if role_kind.lower() == 'clusterrolelist':
                            print(role_name + " is a Destructive cluster role",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, cluster_bindings_json)
                        role_users.append(role_name)
                        if role_ref:
                            for subject in subjects:
                                kind = subject.get('kind')
                                name = subject.get('name')
                                namespace = subject.get('namespace')
                                for resource in rule['resources']:
                                    if namespace:
                                        print(
                                            "{kind} {name} has Destructive Privileges on {resources} in namespace {namespace}".format(
                                                kind=kind,
                                                name=name,
                                                resources=resource,
                                                namespace=namespace),file=self.file_obj)
                                    else:
                                        print(
                                            "{kind} {name} has Destructive Privileges on {resources} in Cluster".format(
                                                kind=kind,
                                                resources=resource,
                                                name=name),file=self.file_obj)
                        print(file=self.file_obj)
        if role_users:
            self.validation_status.append('Destructive roles')
    # Scanning for secret role:
    @sub_prefix('       [+] Scanning for Secrets Roles..........................................')
    def validate_secrets_role(self, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,
                              user_name=None):
        '''
        Insert Gap as Discussed
        '''
        print_msg_box('######## Secret Privileged roles ########', file_obj=self.file_obj)
        secrets_role = False
        role_users = []
        roles_check_json = [roles_json, clusterroles_json]
        verbs_sign = ['*', 'get', 'list', 'create', 'update']
        resource_sign = ['secrets']
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
                    if any(
                            [sign for sign in resource_sign if sign in rule['resources']]) and any(
                        [sign for sign in verbs_sign if sign in rule['verbs']]):
                        role_name = roles_data['metadata']['name']
                        if user_name:
                            if user_name == role_name:
                                secrets_role = True
                                self.result.update({'secrets_role': secrets_role})
                                return
                            else:
                                self.result.update({'secrets_role': secrets_role})
                                continue
                        if role_name in role_users:
                            continue
                        if role_kind.lower() == 'rolelist':
                            print(role_name + " role can Play with secrets",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, roles_bindings_json)
                        if role_kind.lower() == 'clusterrolelist':
                            print(role_name + " clusterrole can Play with secrets",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, cluster_bindings_json)
                        role_users.append(role_name)
                        if role_ref:
                            for subject in subjects:
                                kind = subject.get('kind')
                                name = subject.get('name')
                                namespace = subject.get('namespace')
                                for verb in rule['verbs']:
                                    if namespace:
                                        print(
                                            "{kind} {name} has Privileges to {verb} secrets in namespace {namespace}".format(
                                                kind=kind,
                                                name=name,
                                                verb=verb,
                                                namespace=namespace),file=self.file_obj)
                                    else:
                                        print(
                                            "{kind} {name} has Privileges to {verb} in Cluster".format(
                                                kind=kind,
                                                verb=verb,
                                                name=name),file=self.file_obj)
                        print(file=self.file_obj)
        if role_users:
            self.validation_status.append('Secrets roles')
    # Scanning for impersonate role:
    @sub_prefix('       [+] Scanning for Impersonate Roles......................................')
    def validate_impersonate_role(self, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,
                                  user_name=None):
        '''
        '''
        print_msg_box('######## Impersonate Privileged roles ########', file_obj=self.file_obj)
        impersonate_role = False
        role_users = []
        roles_check_json = [roles_json, clusterroles_json]
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
                    if 'impersonate' in rule['verbs']:
                        role_name = roles_data['metadata']['name']
                        if user_name:
                            if user_name == role_name:
                                impersonate_role = True
                                self.result.update({'impersonate_role': impersonate_role})
                                return
                            else:
                                self.result.update({'secrets_role': impersonate_role})
                                continue
                        if role_name in role_users:
                            continue
                        if role_kind.lower() == 'rolelist':
                            print(role_name + " is an impersonate role",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, roles_bindings_json)
                        if role_kind.lower() == 'clusterrolelist':
                            print(role_name + " is an impersonate cluster",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, cluster_bindings_json)
                        resourcenames = rule.get('resourceNames', [])
                        role_users.append(role_name)
                        if role_ref:
                            for subject in subjects:
                                kind = subject.get('kind')
                                name = subject.get('name')
                                namespace = subject.get('namespace')
                                for resource in rule['resources']:
                                    for resourcename in resourcenames:
                                        if namespace:
                                            print(
                                                "{kind} {name} has Privileges to impersonate {resources} in namespace {namespace} as {resourcenames}".format(
                                                    kind=kind,
                                                    name=name,
                                                    resources=resource,
                                                    namespace=namespace,
                                                    resourcenames=resourcename),file=self.file_obj)
                                        else:
                                            print(
                                                "{kind} {name} has Privileges to impersonate {resources} across Cluster as {resourcenames}".format(
                                                    kind=kind,
                                                    resources=resource,
                                                    name=name,
                                                    resourcenames=resourcename),file=self.file_obj)
                        print(file=self.file_obj)
        if role_users:
            self.validation_status.append('Impersonate roles')
    # Scanning for psp role:
    # Scanning for psp role:
    @sub_prefix('       [+] Scanning for PSP atached Roles......................................')
    def validate_psp_role(self, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,
                          user_name=None):
        '''
        Insert Gap as discsussed
        '''
        print_msg_box('######## PSP attached roles ########', file_obj=self.file_obj)
        psp_role = False
        role_users = []
        roles_check_json = [roles_json, clusterroles_json]
        verbs_sign = ["use"]
        resource_sign = ['podsecuritypolicies']
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
                        if user_name:
                            if user_name == role_name:
                                psp_role = True
                                self.result.update({'psp_role': psp_role})
                                return
                            else:
                                self.result.update({'psp_role': psp_role})
                                continue
                        if role_name in role_users:
                            continue
                        if role_kind.lower() == 'rolelist':
                            for resourceNames in rule['resourceNames']:  # added
                                print("Role " + role_name + " can {verb} podsecuritypolicy {resourceNames}".format(
                                    verb=rule['verbs'][0], resourceNames=resourceNames),file=self.file_obj)
                                binding_json = roles_bindings_json
                        if role_kind.lower() == 'clusterrolelist':
                            for resourceNames in rule['resourceNames']:  # added
                                print(
                                    "ClusterRole " + role_name + " can {verb} podsecuritypolicy {resourceNames}".format(
                                        verb=rule['verbs'][0], resourceNames=resourceNames),file=self.file_obj)
                                binding_json = cluster_bindings_json
                        role_users.append(role_name)
                        binding_metadata_name = ''
                        for entity in binding_json['items']:
                            if entity['roleRef']['name'] == role_name:
                                role_ref = entity.get('roleRef', [])
                                subjects = entity.get('subjects', [])
                                binding_metadata_name = entity.get('metadata', {}).get('name')
                        if role_ref:
                            for subject in subjects:
                                kind = subject.get('kind')
                                name = subject.get('name')
                                namespace = subject.get('namespace')
                                if namespace:  # changesdone
                                    print(
                                        "RoleBinding {role_name} attaches podSecurityPolicy {resourceNames} to {kind} {subject_name} in the namespace {namespace}".format(
                                            role_name=role_name, binding_metadata_name=binding_metadata_name,
                                            kind=kind, subject_name=name, namespace=namespace,
                                            resourceNames=rule['resourceNames'][0]
                                        ),file=self.file_obj)
                                else:
                                    print(
                                        "ClusterRoleBinding {role_name} attaches podSecurityPolicy {resourceNames} to {kind} {subject_name} across Cluster ".format(
                                            role_name=role_name, binding_metadata_name=binding_metadata_name,
                                            subject_name=name, resourceNames=rule['resourceNames'][0],
                                            kind=kind),file=self.file_obj)
                        print(file=self.file_obj)
        if role_users:
            self.validation_status.append('PSP attached roles')
    # Scanning for priviliged role:
    @sub_prefix('       [+] Scanning for Privileged Roles.......................................')
    def validate_privileged_role(self, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json,
                                 user_name=None):
        '''
        '''
        print_msg_box('######## Privileged roles ########', file_obj=self.file_obj)
        privileged_role = False
        role_users = []
        roles_check_json = [roles_json, clusterroles_json]
        verbs_sign = ['*', 'create', 'update', 'patch']
        resource_sign = ['secrets',
                         'pods',
                         'deployments',
                         'daemonsets',
                         'statefulsets',
                         'replicationcontrollers',
                         'replicasets',
                         'cronjobs',
                         'jobs',
                         'roles',
                         'clusterroles',
                         'rolebindings',
                         'clusterrolebindings',
                         'users',
                         'groups',
                         'nodes',
                         'pods/exec',
                         'pods/attach',
                         'pods/portforward',
                         'serviceaccounts'
                         ]
        for roles_json in roles_check_json:
            role_kind = roles_json.get('kind')
            for roles_data in roles_json['items']:
                #role_kind = roles_data.get('kind')
                if not roles_data.get('rules'):
                    continue
                for rule in roles_data['rules']:
                    if not rule.get('verbs', None):
                        continue
                    if not rule.get('resources', None):
                        continue
                    if any([sign for sign in resource_sign if sign in rule['resources']]) and any(
                            [sign for sign in verbs_sign if sign in rule['verbs']]):
                        role_name = roles_data['metadata']['name']
                        if user_name:
                            if user_name == role_name:
                                privileged_role = True
                                self.result.update({'privileged_role': privileged_role})
                                return
                            else:
                                self.result.update({'privileged_role': privileged_role})
                                continue
                        if role_name in role_users:
                            continue
                        if role_kind.lower() == 'rolelist':
                            print(role_name + " is a privileged role",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, roles_bindings_json)
                        if role_kind.lower() == 'clusterrolelist':
                            print(role_name + " is a privileged cluster role",file=self.file_obj)
                            role_ref, subjects = self.binds_search(role_name, cluster_bindings_json)
                        role_users.append(role_name)
                        if role_ref:
                            for subject in subjects:
                                kind = subject.get('kind')
                                name = subject.get('name')
                                namespace = subject.get('namespace')
                                if namespace:
                                    print("{role_name} is attached to {kind} {name}".format(role_name=role_name,
                                                                                            kind=kind, name=name),file=self.file_obj)
                                    print("{kind} {name} has High Privileges in namespace {namespace}".format(
                                        kind=kind, name=name, namespace=namespace),file=self.file_obj)
                                else:
                                    print("{role_name} is attached to {kind} {name}".format(role_name=role_name,
                                                                                            kind=kind, name=name),file=self.file_obj)
                                    print("{kind} {name} has High Privileges in cluster".format(
                                        kind=kind, name=name),file=self.file_obj)
                        print(file=self.file_obj)
        if role_users:
            self.validation_status.append('Privileged roles')
    # Access search :
    def access_search(self, role_name, roles_json, roles_bindings_json, clusterroles_json, cluster_bindings_json):
        '''
        '''
        metadata_name_list = []
        role_name_identified = False
        role_name = role_name.strip()
        roles_bindings_check_json = [roles_bindings_json, cluster_bindings_json]
        for bindings_json in roles_bindings_check_json:
            skind_rkind_rname_list = []
            rules_list = []
            verb_resource_list = []
            for entity in bindings_json['items']:
                subjects = entity.get('subjects', [])
                for subject in subjects:
                    subject_name = subject.get('name')
                    subject_kind = subject.get('kind')
                    if subject_name == role_name:
                        role_name_identified = True
                        role_ref = entity.get('roleRef', {})
                        role_ref_name = role_ref.get('name')
                        role_ref_kind = role_ref.get('kind')
                        skind_rkind_rname = subject_kind + "_" + role_ref_kind + "_" + role_ref_name
                        if skind_rkind_rname in skind_rkind_rname_list:
                            continue
                        skind_rkind_rname_list.append(skind_rkind_rname)
                        print(
                            "{subject_name} is a {subject_kind} and is bound to {role_ref_kind} {role_ref_name} ".format(
                                subject_name=subject_name, subject_kind=subject_kind, role_ref_name=role_ref_name,
                                role_ref_kind=role_ref_kind))
                        for roles_data_json in [roles_json, clusterroles_json]:
                            for role_data in roles_data_json['items']:
                                role_namespace = role_data.get('metadata', {}).get('namespace')
                                if role_ref_name == role_data['metadata']['name']:
                                    if not role_ref_name in metadata_name_list:
                                        metadata_name_list.append(role_ref_name)
                                    rules_data = role_data.get('rules', [])
                                    for rule in rules_data:
                                        if rule in rules_list:
                                            continue
                                        rules_list.append(rule)
                                        verbs = rule.get('verbs', [])
                                        resources = rule.get('resources', [])
                                        for verb in verbs:
                                            for resource in resources:
                                                verb_resource = verb + '_' + resource
                                                if verb_resource in verb_resource_list:
                                                    continue
                                                verb_resource_list.append(verb_resource)
                                                if role_namespace:
                                                    print(
                                                        "{subject_kind} {subject_name} has privileges to {verb} {resource} in the namespace {role_namespace}".format(
                                                            subject_name=subject_name, subject_kind=subject_kind,
                                                            verb=verb, resource=resource,
                                                            role_namespace=role_namespace))
                                                else:
                                                    print(
                                                        "{subject_kind} {subject_name} has privileges to {verb} {resource} in the cluster".format(
                                                            subject_name=subject_name, subject_kind=subject_kind,
                                                            verb=verb, resource=resource))
        if not role_name_identified:
            print("Subject does not exist for this " + str(role_name))
            #self.validation_status.append('access search')
        #print(metadata_name_list)
