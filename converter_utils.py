"""
Utility Functions for VFP to EPMP Converter
Helper functions and mappings - Installation Package Added
"""

import logging

def get_epmp_policy_type(internal_type):
    """VFP internalType'ından EPMP PolicyType'ını belirle - Installation Package eklendi"""
    type_mapping = {
        '280': 29,  # Publisher-based → Signature policy
        '281': None,  # Installed by Publisher → Skip (merge with 280)
        '220': 27,  # Location-based → Network policy
        '221': None,  # Installed from Location → Skip (used for network mapping only)
        '242': 24,  # Software Distribution → Software distribution policy
        '244': None,  # Installed by Software Distribution → Skip
        '230': 23,  # Installation Package → Installation Package policy (PolicyType 23)
        '231': None,  # Installed from Installation Package → Skip (used for installation package mapping)
        '285': 30,  # Product name → Product-based policy (PolicyType 30)
    }
    
    return type_mapping.get(internal_type, None)  # Unknown types return None

def get_epmp_action(vfp_action, policy_type):
    """VFP action'ından EPMP action'ına çevir"""
    return vfp_action  # Direct mapping

def analyze_source_application_types(app_group_info):
    """281 policy'sinin ApplicationGroup'undaki dosya tiplerini analiz et"""
    targeted_types = {
        'IsTargetedEXE': False,
        'IsTargetedDLL': False,
        'IsTargetedMSI': False,
        'IsTargetedMSU': False,
        'IsTargetedScript': False,
        'IsTargetedCOM': False,
        'IsTargetedActiveX': False
    }
    
    for app in app_group_info.get('applications', []):
        app_type = app.get('type', '')
        
        if app_type == 'Executable':
            targeted_types['IsTargetedEXE'] = True
        elif app_type == 'Dll':
            targeted_types['IsTargetedDLL'] = True
        elif app_type == 'MSI':
            targeted_types['IsTargetedMSI'] = True
        elif app_type == 'MSU':
            targeted_types['IsTargetedMSU'] = True
        elif app_type == 'Script':
            targeted_types['IsTargetedScript'] = True
        elif app_type == 'COM':
            targeted_types['IsTargetedCOM'] = True
        elif app_type == 'ActiveXInstall':
            targeted_types['IsTargetedActiveX'] = True
    
    found_types = [key for key, value in targeted_types.items() if value]
    if found_types:
        logging.info(f'Found application types: {", ".join(found_types)}')
    else:
        logging.warning('No application types found, defaulting to EXE')
        targeted_types['IsTargetedEXE'] = True
    
    return targeted_types

def get_publisher_policy_mapping(policies):
    """280 ve 281 policy'lerini eşleştir ve grupla"""
    publisher_mapping = {}
    
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] == '280':  # Ana Publisher policy
            publisher_name = policy_info['name']
            if publisher_name not in publisher_mapping:
                publisher_mapping[publisher_name] = {}
            publisher_mapping[publisher_name]['main'] = policy_info
            publisher_mapping[publisher_name]['main_gpid'] = gpid
            
        elif policy_info['internal_type'] == '281':  # Installed by Publisher
            policy_name = policy_info['name']
            if policy_name.startswith('Installed by: '):
                publisher_name = policy_name[13:]  # "Installed by: " prefix'ini kaldır
                if publisher_name not in publisher_mapping:
                    publisher_mapping[publisher_name] = {}
                publisher_mapping[publisher_name]['source_app'] = policy_info
                publisher_mapping[publisher_name]['source_app_gpid'] = gpid
            else:
                # Prefix olmayan durumlar için
                logging.warning(f'Unexpected Installed by Publisher policy format: {policy_name}')
    
    # Sadece main policy'si olan publisher'lar için uyarı ver
    orphaned_source_apps = 0
    orphaned_main_policies = 0
    
    for publisher_name, mapping in publisher_mapping.items():
        if 'main' not in mapping and 'source_app' in mapping:
            orphaned_source_apps += 1
            logging.warning(f'Orphaned source app policy for publisher: {publisher_name}')
        elif 'main' in mapping and 'source_app' not in mapping:
            orphaned_main_policies += 1
            logging.debug(f'Main publisher policy without source app: {publisher_name}')
    
    logging.info(f'Publisher mapping created: {len(publisher_mapping)} groups')
    if orphaned_source_apps > 0:
        logging.warning(f'Found {orphaned_source_apps} orphaned source app policies')
    if orphaned_main_policies > 0:
        logging.info(f'Found {orphaned_main_policies} main policies without source apps')
    
    return publisher_mapping

def get_installation_package_policy_mapping(policies):
    """230, 231 policy'lerini eşleştir ve grupla (Installation Package için)"""
    installation_package_mapping = {}
    
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] == '230':  # Ana Installation Package policy
            package_name = policy_info['name']
            if package_name not in installation_package_mapping:
                installation_package_mapping[package_name] = {}
            installation_package_mapping[package_name]['main'] = policy_info
            installation_package_mapping[package_name]['main_gpid'] = gpid
            
        elif policy_info['internal_type'] == '231':  # Installed from Installation Package
            policy_name = policy_info['name']
            if policy_name.startswith('Installed from: '):
                package_name = policy_name[15:]  # "Installed from: " prefix'ini kaldır
                if package_name not in installation_package_mapping:
                    installation_package_mapping[package_name] = {}
                installation_package_mapping[package_name]['source_app'] = policy_info
                installation_package_mapping[package_name]['source_app_gpid'] = gpid
    
    logging.info(f'Installation Package mapping created: {len(installation_package_mapping)} groups')
    return installation_package_mapping

def analyze_product_source_application_types(app_group_info):
    """285 policy'sinin ApplicationGroup'undaki dosya tiplerini analiz et (Product için)"""
    targeted_types = {
        'IsTargetedEXE': False,
        'IsTargetedDLL': False,
        'IsTargetedMSI': False
        # Product policy'lerde sadece EXE, DLL, MSI var
    }
    
    for app in app_group_info.get('applications', []):
        app_type = app.get('type', '')
        
        if app_type == 'Executable':
            targeted_types['IsTargetedEXE'] = True
        elif app_type == 'Dll':
            targeted_types['IsTargetedDLL'] = True
        elif app_type == 'MSI':
            targeted_types['IsTargetedMSI'] = True
    
    found_types = [key for key, value in targeted_types.items() if value]
    if found_types:
        logging.info(f'Found product application types: {", ".join(found_types)}')
    else:
        logging.warning('No product application types found, defaulting to EXE')
        targeted_types['IsTargetedEXE'] = True
    
    return targeted_types

def get_product_policy_mapping(policies):
    """285 policy'lerini işle (Product-based için - tek başına)"""
    product_mapping = {}
    
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] == '285':  # Product policy (tek başına)
            product_name = policy_info['name']
            if product_name not in product_mapping:
                product_mapping[product_name] = {}
            product_mapping[product_name]['main'] = policy_info
            product_mapping[product_name]['main_gpid'] = gpid
    
    logging.info(f'Product mapping created: {len(product_mapping)} groups')
    return product_mapping

def is_network_unc_path(path):
    """Network UNC path olup olmadığını kontrol et"""
    if not path:
        return False
    
    path = path.strip()
    
    # UNC path format: \\server\share
    if path.startswith('\\\\') and len(path) > 2:
        # At least one backslash after \\ (for server\share)
        if '\\' in path[2:]:
            return True
    
    return False

def normalize_network_path(path):
    """Network path'i normalize et"""
    if not path:
        return ""
    
    path = path.strip()
    
    # UNC path'i düzelt
    if path.startswith('\\\\'):
        # Ensure it ends with backslash if it's a share path
        if not path.endswith('\\') and '\\' in path[2:]:
            path += '\\'
    
    return path

def analyze_network_location_type(location):
    """Network location tipini analiz et"""
    if not location:
        return "UNKNOWN"
    
    location = location.lower().strip()
    
    # Generic patterns
    generic_patterns = ['*', '**', 'any', 'all', '\\\\*', '\\\\**']
    if location in generic_patterns:
        return "ANY_NETWORK"
    
    # Domain-based patterns
    if '\\\\*.' in location or location.startswith('\\\\*.'):
        return "DOMAIN_PATTERN"
    
    # Specific UNC path
    if location.startswith('\\\\') and '\\' in location[2:]:
        return "SPECIFIC_UNC"
    
    # Server name only
    if not location.startswith('\\\\') and '\\' not in location and '/' not in location:
        return "SERVER_NAME"
    
    # Local path (might be mistake)
    if '\\' in location or '/' in location:
        return "LOCAL_PATH"
    
    return "UNKNOWN"

def determine_apply_on_installed_for_network(has_installed_from_policy):
    """
    Network policy için ApplyPolicyOnInstalledApplications değerini belirle
    "Installed from" policy'si varsa True, yoksa False
    """
    return has_installed_from_policy

def get_location_type_description(location_type):
    """Location type için açıklama döndür"""
    descriptions = {
        'FIXED': 'Fixed drive (local hard disk)',
        'REMOVABLE': 'Removable drive (USB, CD, etc.)',
        'REMOTE': 'Remote/Network location',
        'NETWORK': 'Network drive',
        'CDROM': 'CD/DVD drive',
        'UNKNOWN': 'Unknown location type'
    }
    
    return descriptions.get(location_type.upper() if location_type else 'UNKNOWN', 
                          f'Custom location type: {location_type}')