"""
Parser Functions for VFP to EPMP Converter
Handles XML parsing of policies and application groups
"""

import logging

def parse_policies(root):
    """Parse VFP policies from XML"""
    policies = {}
    
    gpo_policies = root.find('.//GpoPolicies')
    if gpo_policies is not None:
        logging.info(f'Found GpoPolicies element')
        policy_elements = gpo_policies.findall('Policy')
        logging.info(f'Found {len(policy_elements)} Policy elements in GpoPolicies')
    else:
        logging.error('GpoPolicies element not found!')
        return policies
    
    # Debug: Internal type'ları say
    internal_type_counts = {}
    
    for policy in gpo_policies.findall('Policy'):
        gpid = policy.get('gpid', '').strip('{}')
        if not gpid:
            continue
        
        name = policy.get('name', '')
        action_str = policy.get('action', '1')
        internal_type = policy.get('internalType', '')
        
        # Debug: Internal type'ları say
        internal_type_counts[internal_type] = internal_type_counts.get(internal_type, 0) + 1
        
        # Debug: 281 policy'lerini logla
        if internal_type == '281':
            logging.info(f"🔍 Found 281 policy: '{name}' (gpid: {gpid})")
        
        try:
            action = int(action_str)
        except (ValueError, TypeError):
            action = 1
        
        policy_info = {
            'gpid': gpid,
            'name': name,
            'action': action,
            'description': policy.get('description', ''),
            'internal_type': internal_type,
            'target_app_groups': []
        }
        
        # Parse target application groups
        targets = policy.find('Targets')
        if targets is not None:
            for app_group in targets.findall('ApplicationGroup'):
                app_group_id = app_group.get('id', '').strip('{}')
                if app_group_id:
                    policy_info['target_app_groups'].append(app_group_id)
        
        if policy_info['name'] or policy_info['internal_type']:
            policies[gpid] = policy_info
        
    # Debug: Internal type counts
    logging.info(f"📊 Policy counts by internal type:")
    for itype, count in sorted(internal_type_counts.items()):
        logging.info(f"  {itype}: {count} policies")
        
    logging.info(f'Successfully parsed {len(policies)} policies')
    return policies

def parse_application_groups(root):
    """Parse VFP application groups from XML"""
    app_groups = {}
    
    app_groups_element = root.find('.//ApplicationGroups')
    if app_groups_element is not None:
        app_group_elements = app_groups_element.findall('ApplicationGroup')
        logging.info(f'Found {len(app_group_elements)} ApplicationGroup elements')
    else:
        logging.error('ApplicationGroups element not found!')
        return app_groups
    
    for app_group in app_groups_element.findall('ApplicationGroup'):
        group_id = app_group.get('id', '').strip('{}')
        if not group_id:
            continue
            
        group_info = {
            'id': group_id,
            'name': app_group.get('name', ''),
            'description': app_group.get('description', ''),
            'applications': []
        }
        
        # Parse applications in the group
        applications = []
        for executable in app_group.findall('.//Executable'):
            applications.append({'type': 'Executable', 'elements': [executable]})
        for msi in app_group.findall('.//MSI'):
            applications.append({'type': 'MSI', 'elements': [msi]})
        for script in app_group.findall('.//Script'):
            applications.append({'type': 'Script', 'elements': [script]})
        for dll in app_group.findall('.//Dll'):
            applications.append({'type': 'Dll', 'elements': [dll]})
        for com in app_group.findall('.//COM'):
            applications.append({'type': 'COM', 'elements': [com]})
        for activex in app_group.findall('.//ActiveXInstall'):
            applications.append({'type': 'ActiveXInstall', 'elements': [activex]})
        for msu in app_group.findall('.//MSU'):
            applications.append({'type': 'MSU', 'elements': [msu]})
            
        group_info['applications'] = applications
        app_groups[group_id] = group_info
        
    logging.info(f'Successfully parsed {len(app_groups)} application groups')
    return app_groups