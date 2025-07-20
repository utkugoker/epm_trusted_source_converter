"""
Policy Creation Functions for VFP to EPMP Converter - Installation Package Added
Creates specific policy types with their patterns and applications
"""

import logging
from uuid import uuid4
from converter_utils import get_epmp_action, analyze_source_application_types, analyze_product_source_application_types

def create_application_from_element(element, app_type):
    """XML element'ten application objesi oluştur"""
    app_id = str(uuid4())
    
    # Determine application type
    application_type_map = {
        'Executable': 3,
        'MSI': 5,
        'Script': 3,
        'Dll': 3,
        'COM': 3,
        'ActiveXInstall': 3,
        'MSU': 5
    }
    
    application_type = application_type_map.get(app_type, 3)
    
    patterns = {}
    display_name_parts = []
    
    # FileName pattern
    filename_elem = element.find('FileName')
    if filename_elem is not None and filename_elem.text:
        filename = filename_elem.text.strip()
        compare_as = 0  # exact by default
        case_sensitive = filename_elem.get('caseSensitive', 'false').lower() == 'true'
        file_size = 0
        hash_algorithm = filename_elem.get('hashAlgorithm', '')
        hash_value = filename_elem.get('hash', '')
        
        # compareAs attribute handling
        compare_as_attr = filename_elem.get('compareAs', 'exact')
        if compare_as_attr == 'exact':
            compare_as = 0
        elif compare_as_attr == 'startsWith':
            compare_as = 1
        elif compare_as_attr == 'endsWith':
            compare_as = 2
        elif compare_as_attr == 'contains':
            compare_as = 3
        
        file_name_pattern = {
            '@type': 'FileName',
            'compareAs': compare_as,
            'content': filename,
            'caseSensitive': case_sensitive,
            'fileSize': file_size,
            'isEmpty': False
        }
        
        # Only add hash fields if they have values
        if hash_algorithm and hash_value:
            file_name_pattern['hashAlgorithm'] = hash_algorithm
            file_name_pattern['hash'] = hash_value
            file_name_pattern['hashSHA256'] = ''  # Always empty for non-SHA256
        else:
            # Don't include hash fields if empty to avoid validation errors
            pass
        
        patterns['FILE_NAME'] = file_name_pattern
        display_name_parts.append(f"File Name: '{filename}'")
    
    # Publisher pattern
    publisher_elem = element.find('Publisher')
    if publisher_elem is not None and publisher_elem.text:
        publisher = publisher_elem.text.strip()
        compare_as = 0  # exact by default
        case_sensitive = publisher_elem.get('caseSensitive', 'true').lower() == 'true'
        
        # compareAs attribute handling
        compare_as_attr = publisher_elem.get('compareAs', 'exact')
        if compare_as_attr == 'exact':
            compare_as = 0
        elif compare_as_attr == 'startsWith':
            compare_as = 1
        elif compare_as_attr == 'endsWith':
            compare_as = 2
        elif compare_as_attr == 'contains':
            compare_as = 3
        
        patterns['PUBLISHER'] = {
            '@type': 'Publisher',
            'signatureLevel': 2,  # Normal signature validation for patterns
            'content': publisher,
            'compareAs': compare_as,
            'separator': ';',
            'caseSensitive': case_sensitive,
            'isEmpty': False
        }
        display_name_parts.append(f"Publisher: '{publisher}'")
    
    # Location pattern
    location_elem = element.find('Location')
    if location_elem is not None and location_elem.text:
        location = location_elem.text.strip()
        case_sensitive = location_elem.get('caseSensitive', 'false').lower() == 'true'
        with_subfolders = location_elem.get('withSubfolders', 'true').lower() == 'true'
        location_type = location_elem.get('locationType', 'FIXED')
        
        patterns['LOCATION'] = {
            '@type': 'Location',
            'content': location,
            'caseSensitive': case_sensitive,
            'withSubfolders': with_subfolders,
            'isEmpty': False
        }
        
        patterns['LOCATION_TYPE'] = {
            '@type': 'LocationType',
            'locationType': location_type,
            'isEmpty': False
        }
        display_name_parts.append(f"Location: '{location}'")
    
    # FileVerInfo patterns
    for file_info in element.findall('FileVerInfo'):
        info_name = file_info.get('name', '')
        info_value = file_info.text.strip() if file_info.text else ''
        case_sensitive = file_info.get('caseSensitive', 'true').lower() == 'true'
        
        if info_name and info_value:
            if info_name == 'ProductName':
                patterns['PRODUCT_NAME'] = {
                    '@type': 'FileInfo',
                    'compareAs': 0,
                    'content': info_value,
                    'caseSensitive': case_sensitive,
                    'elementName': 'FileVerInfo',
                    'attributeInfoName': 'ProductName',
                    'isEmpty': False
                }
                display_name_parts.append(f"Product: '{info_value}'")
            elif info_name == 'CompanyName':
                patterns['COMPANY_NAME'] = {
                    '@type': 'FileInfo',
                    'compareAs': 0,
                    'content': info_value,
                    'caseSensitive': case_sensitive,
                    'elementName': 'FileVerInfo',
                    'attributeInfoName': 'CompanyName',
                    'isEmpty': False
                }
                display_name_parts.append(f"Company: '{info_value}'")
            elif info_name == 'FileDescription':
                patterns['FILE_DESCRIPTION'] = {
                    '@type': 'FileInfo',
                    'compareAs': 0,
                    'content': info_value,
                    'caseSensitive': case_sensitive,
                    'elementName': 'FileVerInfo',
                    'attributeInfoName': 'FileDescription',
                    'isEmpty': False
                }
    
    # MSI Info patterns
    for msi_info in element.findall('FileMsiInfo'):
        info_name = msi_info.get('name', '')
        info_value = msi_info.text.strip() if msi_info.text else ''
        case_sensitive = msi_info.get('caseSensitive', 'true').lower() == 'true'
        
        if info_name and info_value:
            if info_name == 'ProductName':
                patterns['PRODUCT_NAME'] = {
                    '@type': 'FileInfo',
                    'compareAs': 0,
                    'content': info_value,
                    'caseSensitive': case_sensitive,
                    'elementName': 'FileMsiInfo',
                    'attributeInfoName': 'ProductName',
                    'isEmpty': False
                }
            elif info_name == 'Manufacturer':
                patterns['COMPANY_NAME'] = {
                    '@type': 'FileInfo',
                    'compareAs': 0,
                    'content': info_value,
                    'caseSensitive': case_sensitive,
                    'elementName': 'FileMsiInfo',
                    'attributeInfoName': 'Manufacturer',
                    'isEmpty': False
                }
    
    # Create display name
    if display_name_parts:
        display_name = ', '.join(display_name_parts)
    else:
        # Fallback display name generation
        if patterns.get('FILE_NAME'):
            display_name = f"File Name: '{patterns['FILE_NAME']['content']}'"
        elif patterns.get('PUBLISHER'):
            display_name = f"Publisher: '{patterns['PUBLISHER']['content']}'"
        elif patterns.get('PRODUCT_NAME'):
            display_name = f"Product: '{patterns['PRODUCT_NAME']['content']}'"
        else:
            display_name = f'{app_type} Application'
    
    application = {
        'id': app_id,
        'applicationType': application_type,
        'displayName': display_name,
        'description': '',
        'patterns': patterns,
        'restrictOpenSaveFileDialog': False,
        'protectInstalledFiles': False
    }
    
    # Add childProcess for Executable type
    if app_type == 'Executable':
        application['childProcess'] = False
    
    return application

def create_installation_package_policy(policy_info, app_group_info):
    """Installation Package Trusted Source Policy oluştur (PolicyType 23)"""
    action = get_epmp_action(policy_info['action'], 23)
    
    main_policy_id = str(uuid4())
    linked_policy_id = str(uuid4())
    
    # Application Group'tan dosya bilgilerini al ve Applications array'ine ekle
    applications = []
    
    for app in app_group_info.get('applications', []):
        for element in app.get('elements', []):
            app_info = create_application_from_element(element, app.get('type', 'Executable'))
            if app_info:
                # Installation Package için özel ayarlar
                app_info['restrictOpenSaveFileDialog'] = True  # Installation Package için true
                app_info['protectInstalledFiles'] = False
                applications.append(app_info)
                
                # Log the application being added
                display_name = app_info.get('displayName', 'Unknown Application')
                logging.info(f'Added application to Installation Package policy "{policy_info["name"]}": {display_name}')
    
    if not applications:
        logging.warning(f'No applications found for Installation Package policy: {policy_info["name"]}')
    
    policy = {
        'Id': main_policy_id,
        'Name': policy_info['name'],
        'PolicyType': 23,
        'Action': action,
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_id, 'InternalId': 0, 'PolicyType': 231}
        ],
        'Audit': False,
        'IsActive': True,
        'Applications': applications  # VFP'deki 230 ApplicationGroup'undaki uygulamalar
    }
    
    if action == 4:  # Elevate
        policy.update({
            'ReplaceUAC': True,
            'ReplaceUacAdmin': True,
            'ShellExtension': False
        })
    
    return policy

def create_product_policy(policy_info, app_group_info):
    """Product-based Trusted Source Policy oluştur (PolicyType 30)"""
    
    # Product name bilgisini al
    product_name = ""
    
    for app in app_group_info.get('applications', []):
        for element in app.get('elements', []):
            # FileVerInfo'dan ProductName al
            for file_info in element.findall('FileVerInfo'):
                if file_info.get('name') == 'ProductName' and file_info.text:
                    product_name = file_info.text.strip()
                    break
                
            if product_name:
                break
        if product_name:
            break
    
    if not product_name:
        product_name = policy_info['name']
        logging.warning(f'No ProductName found, using policy name: {product_name}')

    # Source Application Types'ı analiz et (Product için sadece EXE, DLL, MSI)
    targeted_types = analyze_product_source_application_types(app_group_info)

    action = get_epmp_action(policy_info['action'], 30)
    
    main_policy_id = str(uuid4())
    linked_policy_id = str(uuid4())
    
    # Fixed Publisher bilgisi - VFP dosyasında product policy'lerde publisher bilgisi yok
    fixed_publisher = {
        '@type': 'Publisher',
        'separator': ';',
        'signatureLevel': 0,
        'content': '',
        'compareAs': 0,
        'caseSensitive': True,
        'isEmpty': True  # Empty publisher for product policies
    }
    
    policy = {
        'Id': main_policy_id,
        'Name': policy_info['name'],
        'PolicyType': 30,
        'Action': action,
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_id, 'InternalId': 0, 'PolicyType': 285}  # VFP'deki 285 policy
        ],
        'Audit': False,
        'ProductName': product_name,
        'ProductCompareAs': 0,  # Exact match
        'Publisher': fixed_publisher,  # Fixed empty Publisher structure
        'IsActive': True
    }
    
    policy.update(targeted_types)
    
    if action == 4:  # Elevate
        policy.update({
            'ReplaceUAC': True,
            'ReplaceUacAdmin': True,
            'ShellExtension': False
        })
    
    logging.info(f'✅ Created Product policy with fixed empty Publisher: {policy["Name"]} (ProductName: {product_name})')
    
    return policy

def create_publisher_policy_with_source_types(main_policy_info, source_app_policy_info, main_app_group_info, source_app_group_info):
    """Publisher policy'sini Source Application Types analizi ile oluştur"""
    
    # Publisher bilgisini al (Ana policy'den)
    publisher_content = ""
    compare_as = 0
    case_sensitive = True
    
    for app in main_app_group_info.get('applications', []):
        for element in app.get('elements', []):
            publisher_elem = element.find('Publisher')
            if publisher_elem is not None and publisher_elem.text:
                publisher_content = publisher_elem.text.strip()
                
                compare_as_attr = publisher_elem.get('compareAs', 'exact')
                if compare_as_attr == 'exact':
                    compare_as = 0
                elif compare_as_attr == 'startsWith':
                    compare_as = 1
                elif compare_as_attr == 'endsWith':
                    compare_as = 2
                elif compare_as_attr == 'contains':
                    compare_as = 3
                
                case_sensitive_attr = publisher_elem.get('caseSensitive', 'True')
                case_sensitive = case_sensitive_attr.lower() == 'true'
                break
        if publisher_content:
            break

    if not publisher_content:
        publisher_content = main_policy_info['name']
        logging.warning(f'No publisher found, using policy name: {publisher_content}')

    # Source Application Types'ı analiz et
    if source_app_policy_info and source_app_group_info and source_app_group_info.get('applications'):
        # 281 policy'si varsa 281'deki ApplicationGroup'tan application tiplerini al
        targeted_types = analyze_source_application_types(source_app_group_info)
        logging.info(f'✅ Using Source Application Types from 281 policy for "{publisher_content}"')
    elif main_app_group_info and main_app_group_info.get('applications'):
        # 281 policy'si yoksa ana 280 policy'sindeki ApplicationGroup'tan application tiplerini al
        targeted_types = analyze_source_application_types(main_app_group_info)
        logging.info(f'✅ Using Application Types from main 280 policy for "{publisher_content}" (no 281 policy found)')
    else:
        # Son çare: sadece EXE'yi True yap
        targeted_types = {
            'IsTargetedEXE': True,
            'IsTargetedDLL': False,
            'IsTargetedMSI': False,
            'IsTargetedMSU': False,
            'IsTargetedScript': False,
            'IsTargetedCOM': False,
            'IsTargetedActiveX': False
        }
        logging.warning(f'⚠️ No application types found for "{publisher_content}", defaulting to EXE only')

    action = get_epmp_action(main_policy_info['action'], 29)
    
    main_policy_id = str(uuid4())
    linked_policy_1_id = str(uuid4())
    linked_policy_2_id = str(uuid4())
    
    policy = {
        'Id': main_policy_id,
        'Name': f"Signature '{publisher_content}'" if publisher_content else main_policy_info['name'],
        'PolicyType': 29,
        'Action': action,
        'Description': main_policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_1_id, 'InternalId': 0, 'PolicyType': 280},
            {'Id': linked_policy_2_id, 'InternalId': 0, 'PolicyType': 281}
        ],
        'Audit': False,
        'Publisher': {
            '@type': 'Publisher',
            'separator': ';',
            'signatureLevel': 2,
            'content': publisher_content,
            'compareAs': compare_as,
            'caseSensitive': case_sensitive,
            'isEmpty': not bool(publisher_content)
        },
        'ApplyPolicyOnInstalledApplications': True,
        'ApplyPolicyOnLocalHardDrivesOnly': False,
        'IsActive': True
    }
    
    policy.update(targeted_types)
    
    if action == 4:  # Elevate
        policy.update({
            'ReplaceUAC': True,
            'ReplaceUacAdmin': True,
            'ShellExtension': False
        })
    
    return policy

def create_network_policy(policy_info, app_group_info, has_installed_from_policy=False):
    """
    Network-based Trusted Source Policy oluştur - İyileştirilmiş versiyon
    
    Args:
        policy_info: Ana network policy bilgileri (type 220)
        app_group_info: Application group bilgileri
        has_installed_from_policy: Bu network policy'nin "Installed from" alt politikası (type 221) var mı?
    """
    network_location = ""
    location_type = "FIXED"
    with_subfolders = True
    case_sensitive = False
    
    # Application Group'tan network location bilgilerini al
    for app in app_group_info.get('applications', []):
        for element in app.get('elements', []):
            location_elem = element.find('Location')
            if location_elem is not None and location_elem.text:
                network_location = location_elem.text.strip()
                
                # VFP'den gelen location tipini al
                location_type = location_elem.get('locationType', 'FIXED')
                with_subfolders = location_elem.get('withSubfolders', 'true').lower() == 'true'
                case_sensitive = location_elem.get('caseSensitive', 'false').lower() == 'true'
                break
        if network_location:
            break

    # Eğer network location bulunamadıysa, policy name'den çıkarmaya çalış
    if not network_location:
        network_location = policy_info['name']
        logging.warning(f'No location found in ApplicationGroup, using policy name: {network_location}')

    action = get_epmp_action(policy_info['action'], 27)
    
    main_policy_id = str(uuid4())
    linked_policy_1_id = str(uuid4())
    linked_policy_2_id = str(uuid4())

    # Network share handling iyileştirmeleri
    is_any_network_share = False
    is_network_share_subfolders = with_subfolders
    
    # Gelişmiş network pattern analizi
    if network_location:
        # UNC path düzeltmeleri
        if network_location.startswith('\\\\') and not network_location.endswith('\\'):
            network_location += '\\'
        
        # Generic network share pattern kontrolü
        generic_patterns = ['*', '**', 'any', 'all', '\\\\*', '\\\\**']
        if network_location.lower() in [p.lower() for p in generic_patterns]:
            is_any_network_share = True
            network_location = "*"  # Standart format
            logging.info(f'Detected generic network share pattern: {policy_info["name"]}')
        
        # Domain-based patterns
        elif '\\\\*.' in network_location.lower() or network_location.lower().startswith('\\\\*.'):
            is_any_network_share = True
            logging.info(f'Detected domain-based network pattern: {network_location}')
        
        # Specific share validation
        elif network_location.startswith('\\\\') and '\\' in network_location[2:]:
            # Valid UNC path format: \\server\share
            logging.info(f'Detected specific network share: {network_location}')
        
        # Local path handling (convert to proper format if needed)
        elif network_location and not network_location.startswith('\\\\'):
            if '\\' in network_location or '/' in network_location:
                # This might be a local path mistakenly used as network
                logging.warning(f'Possible local path in network policy: {network_location}')
            else:
                # Single server name - convert to UNC format
                network_location = f'\\\\{network_location}\\'
                logging.info(f'Converted server name to UNC format: {network_location}')

    # KRITIK: "Installed from" policy'si (type 221) varsa ApplyPolicyOnInstalledApplications = true
    # Yoksa false (sadece runtime'da çalışan uygulamalar için)
    apply_on_installed = has_installed_from_policy
    
    # Policy oluştur
    policy = {
        'Id': main_policy_id,
        'Name': policy_info['name'],
        'PolicyType': 27,
        'Action': action,
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_1_id, 'InternalId': 0, 'PolicyType': 220},
            {'Id': linked_policy_2_id, 'InternalId': 0, 'PolicyType': 221}
        ],
        'Audit': False,
        'NetworkName': network_location,
        'ApplyPolicyOnInstalledApplications': apply_on_installed,
        'IsActive': True,
        'IsAnyNetworkShare': is_any_network_share,
        'IsNetworkShareSubfolders': is_network_share_subfolders,
        'CaseSensitive': case_sensitive,
        'LocationType': location_type
    }
    
    # Elevate action için ek ayarlar
    if action == 4:  # Elevate
        policy.update({
            'ReplaceUAC': True,
            'ReplaceUacAdmin': True,
            'ShellExtension': False
        })
    
    # Network share için özel validasyon ve loglama
    if is_any_network_share:
        logging.info(f'Created ANY network share policy: {policy["Name"]} (ApplyOnInstalled: {apply_on_installed})')
    else:
        logging.info(f'Created specific network share policy: {policy["Name"]} -> {network_location} (ApplyOnInstalled: {apply_on_installed})')
    
    # "Installed from" policy durumuna göre özel loglama
    if has_installed_from_policy:
        logging.info(f'  → Has "Installed from" policy (221) - ApplyPolicyOnInstalledApplications set to TRUE')
    else:
        logging.info(f'  → No "Installed from" policy - ApplyPolicyOnInstalledApplications set to FALSE (runtime only)')
    
    return policy

def create_software_distribution_policy(policy_info, app_group_info, child_policy=None):
    """Software Distribution Trusted Source Policy oluştur"""
    policy_name = policy_info['name']
    original_software_name = policy_info['name']
    
    predefined_mapping = {
        'sccm software distribution': 'SCCM Software Distribution',
        'system center configuration manager': 'SCCM Software Distribution',
        'microsoft sccm': 'SCCM Software Distribution',
        'sccm': 'SCCM Software Distribution',
        'configuration manager': 'SCCM Software Distribution',
        'system center': 'SCCM Software Distribution',
        'sms': 'SCCM Software Distribution',
        'epo product deployment': 'ePO Product Deployment',
        'mcafee epo': 'ePO Product Deployment',
        'epo': 'ePO Product Deployment',
        'mcafee epolicy orchestrator': 'ePO Product Deployment',
        'epolicy orchestrator': 'ePO Product Deployment',
        'microsoft intune': 'Microsoft Intune',
        'intune': 'Microsoft Intune',
        'microsoft endpoint manager': 'Microsoft Intune',
        'endpoint manager': 'Microsoft Intune'
    }
    
    software_name = original_software_name
    original_lower = original_software_name.lower()
    
    for key, predefined_value in predefined_mapping.items():
        if original_lower == key or original_lower.startswith(key):
            software_name = predefined_value
            logging.info(f'Mapped software distribution: "{original_software_name}" -> "{software_name}"')
            break
    
    action = 1  # Always Allow for software distribution trust
    
    if child_policy:
        child_action = get_epmp_action(child_policy['action'], 24)
    else:
        child_action = get_epmp_action(policy_info['action'], 24)
    
    apply_on_installed = child_action != 0
    
    main_policy_id = str(uuid4())
    linked_policy_1_id = str(uuid4())
    linked_policy_2_id = str(uuid4())
    
    policy = {
        'Id': main_policy_id,
        'Name': policy_name,
        'PolicyType': 24,
        'Action': action,
        'Description': policy_info.get('description', ''),
        'LinkedAgentPolicies': [
            {'Id': linked_policy_1_id, 'InternalId': 0, 'PolicyType': 242},
            {'Id': linked_policy_2_id, 'InternalId': 0, 'PolicyType': 244}
        ],
        'SoftwareName': software_name,
        'ApplyPolicyOnInstalledApplications': apply_on_installed,
        'IsActive': True,
        'IsPredefined': software_name in ['SCCM Software Distribution', 'ePO Product Deployment', 'Microsoft Intune'],
        'Applications': []
    }
    
    if child_action != 0:
        policy.update({
            'ChildAction': child_action,
            'ChildAudit': False,
            'ChildMonitorInstallationOfNewApplications': False
        })
        
        if child_action == 4:  # Elevate
            policy.update({
                'ChildReplaceUAC': True,
                'ChildReplaceUacAdmin': True,
                'ChildShellExtension': False
            })
    
    return policy

def find_network_policy_relationships(policies):
    """
    Network policy'leri (220) ve onların "Installed from" alt policy'lerini (221) eşleştir
    """
    network_mapping = {}
    
    # Debug: Önce tüm 220 ve 221 policy'leri listele
    network_220_policies = []
    network_221_policies = []
    
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] == '220':
            network_220_policies.append((gpid, policy_info['name']))
        elif policy_info['internal_type'] == '221':
            network_221_policies.append((gpid, policy_info['name']))
    
    logging.info(f"DEBUG: Found {len(network_220_policies)} type-220 network policies:")
    for gpid, name in network_220_policies:
        logging.info(f"  220: {name} ({gpid})")
    
    logging.info(f"DEBUG: Found {len(network_221_policies)} type-221 'Installed from' policies:")
    for gpid, name in network_221_policies:
        logging.info(f"  221: {name} ({gpid})")
    
    # Önce tüm 220 policy'leri bul
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] == '220':  # Network policy
            policy_name = policy_info['name']
            network_mapping[policy_name] = {
                'main': policy_info,
                'main_gpid': gpid,
                'installed_from': None,
                'installed_from_gpid': None
            }
            logging.debug(f"Added main network policy: {policy_name}")
    
    # Sonra 221 policy'leri bul ve eşleştir
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] == '221':  # Installed from Location
            policy_name = policy_info['name']
            
            logging.debug(f"Processing 221 policy: {policy_name}")
            
            # "Installed from: " prefix'ini kaldır
            if policy_name.startswith('Installed from: '):
                main_policy_name = policy_name[16:]  # "Installed from: " = 16 karakter
                
                logging.debug(f"  Extracted main policy name: {main_policy_name}")
                logging.debug(f"  Looking for match in network_mapping keys: {list(network_mapping.keys())}")
                
                if main_policy_name in network_mapping:
                    network_mapping[main_policy_name]['installed_from'] = policy_info
                    network_mapping[main_policy_name]['installed_from_gpid'] = gpid
                    logging.info(f"✅ MATCH FOUND! {main_policy_name} has installed_from policy")
                else:
                    logging.warning(f"❌ NO MATCH: Orphaned 'Installed from' policy: {policy_name}")
                    logging.warning(f"   Available network policy names: {list(network_mapping.keys())}")
            else:
                logging.warning(f'Unexpected "Installed from" policy format: {policy_name}')
    
    # İstatistikleri logla
    total_network_policies = len(network_mapping)
    with_installed_from = sum(1 for mapping in network_mapping.values() if mapping['installed_from'])
    without_installed_from = total_network_policies - with_installed_from
    
    logging.info(f'Network policy mapping created: {total_network_policies} network policies')
    logging.info(f'  - With "Installed from" policy: {with_installed_from}')
    logging.info(f'  - Without "Installed from" policy: {without_installed_from}')
    
    # Debug: Hangi policy'lerin eşleştiğini göster
    for name, mapping in network_mapping.items():
        if mapping['installed_from']:
            logging.info(f"  ✅ {name} HAS installed_from policy")
        else:
            logging.info(f"  ❌ {name} NO installed_from policy")
    
    return network_mapping

def should_skip_installed_from_policy(policy_info):
    """
    "Installed from:" politikalarının oluşturulup oluşturulmaması gerektiğini belirle
    
    ÖNEMLİ: Network policy'leri (221) ve Installation Package policy'leri (231) için 
    eşleştirme yapmak gerekiyor, bu yüzden onları tamamen skip etmeyin!
    """
    policy_name = policy_info.get('name', '')
    internal_type = policy_info.get('internal_type', '')
    
    # Network "Installed from" policy'lerini (221) ve Installation Package "Installed from" policy'lerini (231) KORUYUN
    if internal_type in ['221', '231']:
        return False  # Skip etme, sadece ignore et
    
    # "Installed from:", "Installed by:" başlangıçlı politikaları skip et
    skip_patterns = [
        'installed from:',
        'installed by:',
        'yüklenen:',  # Türkçe için
        'kurulmuş:'   # Türkçe için
    ]
    
    for pattern in skip_patterns:
        if policy_name.lower().startswith(pattern):
            # Network ve Installation Package policy'leri dışında skip et
            if internal_type not in ['221', '231', '281']:
                logging.info(f'Skipping "Installed from/by" policy: {policy_name}')
                return True
    
    # Belirli internal type'ları da skip et (221 ve 231 hariç!) - Installation Package eklendi
    skip_types = ['244']  # 231'i kaldırdık - Installation Package için gerekli
    if internal_type in skip_types:
        logging.info(f'Skipping policy with internal type {internal_type}: {policy_name}')
        return True
    
    return False