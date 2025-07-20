#!/usr/bin/env python3
"""
Enhanced VFP to EPMP Trusted Sources Converter - Main Module - Installation Package Added
Converts VFP (Viewfinity Policy) trusted source policies to EPMP format
Installation Package (230/231 → 23) desteği eklendi
281'li politikalar publisher politikaları işlendikten sonra filtrelenir
"""

import xml.etree.ElementTree as ET
import json
import os
import sys
import logging
from uuid import uuid4
from datetime import datetime

# Import helper modules (create these as separate files)
from converter_parsers import parse_policies, parse_application_groups
from converter_policies import (
    create_publisher_policy_with_source_types,
    create_network_policy,
    create_software_distribution_policy,
    create_installation_package_policy,
    create_product_policy,  # YENİ
    find_network_policy_relationships,
    should_skip_installed_from_policy
)
from converter_utils import (
    get_epmp_policy_type,
    get_publisher_policy_mapping,
    get_installation_package_policy_mapping,
    get_product_policy_mapping,  # YENİ
    analyze_source_application_types
)
from converter_validators import validate_epmp_data

def setup_logging():
    """Setup logging configuration"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_filename = f'logs/enhanced_trusted_sources_converter_{timestamp}.log'
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_filename

def convert_vfp_trusted_sources_to_epmp(vfp_content):
    """VFP Trusted Sources'ı EPMP formatına çevir - Installation Package eklendi"""
    root = ET.fromstring(vfp_content)
    logging.info('Successfully parsed VFP XML content')
    
    policies = parse_policies(root)
    app_groups = parse_application_groups(root)
    
    logging.info(f'Found {len(policies)} policies and {len(app_groups)} application groups')
    
    if len(policies) == 0:
        logging.error('NO POLICIES FOUND!')
        return None
        
    if len(app_groups) == 0:
        logging.error('NO APPLICATION GROUPS FOUND!')
        return None
    
    # DESTEKLENMEYEN POLICY TİPLERİNİ LOGLA VE ÇIKAR
    supported_types = ['280', '281', '220', '221', '242', '244', '230', '231', '285']  # Product-based eklendi
    unsupported_policies = []
    
    for gpid, policy_info in list(policies.items()):
        if policy_info['internal_type'] not in supported_types:
            unsupported_policies.append((policy_info['internal_type'], policy_info['name']))
            del policies[gpid]
    
    if unsupported_policies:
        logging.warning(f'Found {len(unsupported_policies)} unsupported policy types:')
        for policy_type, policy_name in unsupported_policies:
            logging.warning(f'  - Type {policy_type}: {policy_name}')
        logging.info('These policies will be skipped in this version.')
    
    # ÖN FİLTRELEME: "Installed from/by" politikalarını filtrele (221, 231 hariç - mapping için gerekli)
    filtered_policies = {}
    skipped_installed_policies = []
    
    for gpid, policy_info in policies.items():
        if should_skip_installed_from_policy(policy_info):
            skipped_installed_policies.append(policy_info['name'])
        else:
            filtered_policies[gpid] = policy_info
    
    if skipped_installed_policies:
        logging.info(f'Pre-filtered {len(skipped_installed_policies)} "Installed from/by" policies (221, 231 kept for mapping)')
        for skipped in skipped_installed_policies:
            logging.debug(f'  - Skipped: {skipped}')
    
    # Filtrelenmiş policies ile devam et
    policies = filtered_policies
    
    # Software Distribution policy'lerini gruplayalım
    software_dist_groups = {}
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] in ['242', '244']:
            name = policy_info['name']
            if policy_info['internal_type'] == '244' and name.startswith('Installed by: '):
                software_name = name[14:]
            elif policy_info['internal_type'] == '242':
                software_name = name
            else:
                software_name = name
            
            if software_name not in software_dist_groups:
                software_dist_groups[software_name] = {}
            
            software_dist_groups[software_name][policy_info['internal_type']] = policy_info
    
    # Mapping'leri al
    publisher_mapping = get_publisher_policy_mapping(policies)
    installation_package_mapping = get_installation_package_policy_mapping(policies)
    product_mapping = get_product_policy_mapping(policies)  # YENİ
    
    # Network policy'leri ve onların "Installed from" alt policy'lerini eşleştir
    network_mapping = find_network_policy_relationships(policies)
    
    epmp_policies = []
    processed_software_dist = set()
    processed_network = set()
    processed_publisher = set()
    processed_installation_package = set()
    processed_product = set()  # YENİ
    processed_281_policies = set()  # 281 policy'lerini takip et
    skipped_policies = []
    
    used_policy_ids = set()
    
    def add_policy_with_id_check(policy):
        policy_id = policy['Id']
        if policy_id in used_policy_ids:
            logging.error(f'DUPLICATE ID DETECTED: {policy_id}')
            new_id = str(uuid4())
            policy['Id'] = new_id
            policy_id = new_id
        
        used_policy_ids.add(policy_id)
        epmp_policies.append(policy)
        return True
    
    # Network policy'lerini işle
    logging.info('=== PROCESSING NETWORK POLICIES ===')
    processed_installed_from_policies = set()
    
    for network_name, mapping in network_mapping.items():
        main_policy = mapping['main']
        installed_from_policy = mapping['installed_from']
        
        if network_name not in processed_network:
            app_group_info = {'applications': []}
            for app_group_id in main_policy['target_app_groups']:
                if app_group_id in app_groups:
                    app_group_info = app_groups[app_group_id]
                    break
            
            try:
                has_installed_from = installed_from_policy is not None
                
                logging.info(f"Creating network policy for: {network_name}")
                logging.info(f"  Has installed_from policy: {has_installed_from}")
                
                epmp_policy = create_network_policy(main_policy, app_group_info, has_installed_from)
                add_policy_with_id_check(epmp_policy)
                processed_network.add(network_name)
                
                if installed_from_policy:
                    processed_installed_from_policies.add(installed_from_policy['name'])
                    logging.info(f"  → Marked as processed: {installed_from_policy['name']}")
                
                action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                vfp_action_name = action_names.get(main_policy['action'], f'Unknown({main_policy["action"]})')
                epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
                
                network_type = "ANY network share" if epmp_policy.get('IsAnyNetworkShare') else f"Specific: {epmp_policy.get('NetworkName', 'Unknown')}"
                
                if has_installed_from:
                    logging.info(f'✅ Created Network policy with "Installed from": {epmp_policy["Name"]} ({network_type}) (Action: {vfp_action_name} → {epmp_action_name})')
                else:
                    logging.info(f'✅ Created Network policy (runtime only): {epmp_policy["Name"]} ({network_type}) (Action: {vfp_action_name} → {epmp_action_name})')
                
            except Exception as e:
                logging.error(f'❌ Error creating network policy for "{network_name}": {str(e)}', exc_info=True)
    
    # Publisher policy'lerini işle
    logging.info('=== PROCESSING PUBLISHER POLICIES ===')
    for publisher_name, policy_data in publisher_mapping.items():
        if publisher_name not in processed_publisher:
            main_policy = policy_data.get('main')
            source_app_policy = policy_data.get('source_app')
            
            if main_policy:
                main_app_group_info = {'applications': []}
                for app_group_id in main_policy['target_app_groups']:
                    if app_group_id in app_groups:
                        main_app_group_info = app_groups[app_group_id]
                        break
                
                source_app_group_info = {'applications': []}
                if source_app_policy:
                    for app_group_id in source_app_policy['target_app_groups']:
                        if app_group_id in app_groups:
                            source_app_group_info = app_groups[app_group_id]
                            break
                            
                    # 281 policy'yi işlenmiş olarak işaretle
                    processed_281_policies.add(source_app_policy['name'])
                    logging.debug(f"281 policy marked as processed: {source_app_policy['name']}")
                            
                # DEBUG: 281 ApplicationGroup kontrolü
                if source_app_policy:
                    print(f"DEBUG: Found 281 policy for {main_policy['name']}")
                    print(f"DEBUG: 281 ApplicationGroup ID: {source_app_policy['target_app_groups']}")
                    print(f"DEBUG: 281 ApplicationGroup content: {source_app_group_info}")
    
                    # Application tiplerini manuel kontrol et
                    for app in source_app_group_info.get('applications', []):
                        print(f"DEBUG: App type: {app.get('type')}")            
                
                try:
                    epmp_policy = create_publisher_policy_with_source_types(
                        main_policy, source_app_policy, 
                        main_app_group_info, source_app_group_info
                    )
                    
                    add_policy_with_id_check(epmp_policy)
                    processed_publisher.add(publisher_name)
                    
                    action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                    vfp_action_name = action_names.get(main_policy['action'], f'Unknown({main_policy["action"]})')
                    epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
                    
                    if source_app_policy:
                        logging.info(f'✅ Created Publisher policy with Source App Types: {epmp_policy["Name"]} (Action: {vfp_action_name} → {epmp_action_name})')
                    else:
                        logging.info(f'✅ Created Publisher policy: {epmp_policy["Name"]} (Action: {vfp_action_name} → {epmp_action_name})')
                        
                except Exception as e:
                    logging.error(f'❌ Error creating publisher policy for "{publisher_name}": {str(e)}', exc_info=True)
            
            elif source_app_policy:
                logging.warning(f'Found orphaned Source App policy: {publisher_name}')
                processed_publisher.add(publisher_name)
                # Orphaned 281 policy'yi de işlenmiş olarak işaretle
                processed_281_policies.add(source_app_policy['name'])
    
    # Software Distribution policy'lerini işle
    logging.info('=== PROCESSING SOFTWARE DISTRIBUTION POLICIES ===')
    for software_name, policy_data in software_dist_groups.items():
        if software_name not in processed_software_dist:
            main_policy = policy_data.get('242')
            child_policy = policy_data.get('244')
            
            if main_policy:
                app_group_info = {'applications': []}
                for app_group_id in main_policy['target_app_groups']:
                    if app_group_id in app_groups:
                        app_group_info = app_groups[app_group_id]
                        break
                
                try:
                    epmp_policy = create_software_distribution_policy(main_policy, app_group_info, child_policy)
                    add_policy_with_id_check(epmp_policy)
                    processed_software_dist.add(software_name)
                    
                    action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                    child_action_name = action_names.get(epmp_policy.get('ChildAction', 1), 'Allow')
                    logging.info(f'✅ Created Software Distribution policy: {epmp_policy["Name"]} (Action: Allow, Installed Apps: {child_action_name})')
                    
                except Exception as e:
                    logging.error(f'❌ Error creating software distribution policy for "{software_name}": {str(e)}', exc_info=True)
    
    # Installation Package policy'lerini işle
    logging.info('=== PROCESSING INSTALLATION PACKAGE POLICIES ===')
    for package_name, policy_data in installation_package_mapping.items():
        if package_name not in processed_installation_package:
            main_policy = policy_data.get('main')
            source_app_policy = policy_data.get('source_app')
            
            if main_policy:
                main_app_group_info = {'applications': []}
                for app_group_id in main_policy['target_app_groups']:
                    if app_group_id in app_groups:
                        main_app_group_info = app_groups[app_group_id]
                        break
                
                try:
                    epmp_policy = create_installation_package_policy(main_policy, main_app_group_info)
                    
                    # Installation Package policies için özel validation
                    if 'Applications' in epmp_policy and epmp_policy['Applications']:
                        from converter_validators import validate_and_clean_applications
                        epmp_policy['Applications'] = validate_and_clean_applications(epmp_policy['Applications'])
                        
                    add_policy_with_id_check(epmp_policy)
                    processed_installation_package.add(package_name)
                    
                    action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                    vfp_action_name = action_names.get(main_policy['action'], f'Unknown({main_policy["action"]})')
                    epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
                    
                    app_count = len(epmp_policy.get('Applications', []))
                    if source_app_policy:
                        logging.info(f'✅ Created Installation Package policy with source app: {epmp_policy["Name"]} ({app_count} applications) (Action: {vfp_action_name} → {epmp_action_name})')
                    else:
                        logging.info(f'✅ Created Installation Package policy: {epmp_policy["Name"]} ({app_count} applications) (Action: {vfp_action_name} → {epmp_action_name})')
                        
                except Exception as e:
                    logging.error(f'❌ Error creating installation package policy for "{package_name}": {str(e)}', exc_info=True)
            
            elif source_app_policy:
                logging.warning(f'Found orphaned Installation Package Source App policy: {package_name}')
                processed_installation_package.add(package_name)
    
    # Product policy'lerini işle - YENİ
    logging.info('=== PROCESSING PRODUCT POLICIES ===')
    for product_name, policy_data in product_mapping.items():
        if product_name not in processed_product:
            main_policy = policy_data.get('main')
            
            if main_policy:
                main_app_group_info = {'applications': []}
                for app_group_id in main_policy['target_app_groups']:
                    if app_group_id in app_groups:
                        main_app_group_info = app_groups[app_group_id]
                        break
                
                try:
                    epmp_policy = create_product_policy(main_policy, main_app_group_info)
                    
                    add_policy_with_id_check(epmp_policy)
                    processed_product.add(product_name)
                    
                    action_names = {0: 'Off', 1: 'Allow', 2: 'Deny', 3: 'Require justification', 4: 'Elevate'}
                    vfp_action_name = action_names.get(main_policy['action'], f'Unknown({main_policy["action"]})')
                    epmp_action_name = action_names.get(epmp_policy['Action'], f'Unknown({epmp_policy["Action"]})')
                    
                    product_name_display = epmp_policy.get('ProductName', 'Unknown')
                    targeted_types = [key for key, value in epmp_policy.items() if key.startswith('IsTargeted') and value]
                    types_display = ', '.join([t.replace('IsTargeted', '') for t in targeted_types])
                    
                    logging.info(f'✅ Created Product policy: {epmp_policy["Name"]} (ProductName: {product_name_display}, Types: {types_display}) (Action: {vfp_action_name} → {epmp_action_name})')
                        
                except Exception as e:
                    logging.error(f'❌ Error creating product policy for "{product_name}": {str(e)}', exc_info=True)
    
    # SON FİLTRELEME: İşlenmiş 281 policy'lerini filtrele
    logging.info('=== FILTERING PROCESSED 281 POLICIES ===')
    filtered_281_policies = []
    
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] == '281':
            if policy_info['name'] not in processed_281_policies:
                filtered_281_policies.append(policy_info['name'])
                logging.warning(f'Unprocessed 281 policy found: {policy_info["name"]}')
            else:
                logging.debug(f'Filtering out processed 281 policy: {policy_info["name"]}')
    
    if filtered_281_policies:
        logging.info(f'Found {len(filtered_281_policies)} unprocessed 281 policies that will be skipped')
    
    # Diğer desteklenmeyen policy'leri logla (281'ler artık işlendikten sonra filtreleniyor)
    for gpid, policy_info in policies.items():
        if policy_info['internal_type'] not in ['244', '221', '231']:  # Skip edilenler
            # 281 policy'leri için özel kontrol
            if policy_info['internal_type'] == '281':
                if policy_info['name'] not in processed_281_policies:
                    if policy_info['name'] not in [p['name'] for p in skipped_policies]:
                        skipped_policies.append(policy_info)
                        logging.info(f'Skipping unprocessed 281 policy: {policy_info["name"]}')
            else:
                epmp_policy_type = get_epmp_policy_type(policy_info['internal_type'])
                if epmp_policy_type is None:
                    if policy_info['name'] not in [p['name'] for p in skipped_policies]:
                        skipped_policies.append(policy_info)
                        logging.warning(f'Skipping unsupported policy type {policy_info["internal_type"]}: {policy_info["name"]}')
    
    # Create EPMP structure
    epmp_data = {
        'Policies': epmp_policies,
        'AppGroups': [],
        'TrustSoftwareDistributors': [],
        'UserAccessTokens': [],
        'EndUserUIs': []
    }
    
    # İstatistikleri hesapla ve logla
    policy_type_counts = {}
    for policy in epmp_policies:
        policy_type = policy['PolicyType']
        policy_type_counts[policy_type] = policy_type_counts.get(policy_type, 0) + 1
    
    logging.info(f'Conversion completed! Total policies: {len(epmp_policies)}')
    for policy_type, count in policy_type_counts.items():
        type_name = {29: 'Publisher-based', 27: 'Network-based', 24: 'Software Distribution', 23: 'Installation Package', 30: 'Product-based'}.get(policy_type, f'Type {policy_type}')
        logging.info(f'  - {type_name}: {count}')
    
    if skipped_policies:
        logging.info(f'Skipped {len(skipped_policies)} policies (including processed 281 policies)')
    
    # Validate and clean EPMP data before returning
    logging.info('=== VALIDATING AND CLEANING EPMP DATA ===')
    if not validate_epmp_data(epmp_data):
        logging.error('EPMP data validation failed!')
        return None
    
    return epmp_data

def create_separate_source_files(epmp_data, base_output_file):
    """Source tipine göre ayrı EPMP dosyaları oluştur - Installation Package eklendi"""
    try:
        base_path = os.path.splitext(base_output_file)[0]
        
        policy_groups = {
            'publisher': [],
            'network': [],
            'software_dist': [],
            'installation_package': [],
            'product': []  # YENİ
        }
        
        for policy in epmp_data['Policies']:
            policy_type = policy.get('PolicyType')
            if policy_type == 29:
                policy_groups['publisher'].append(policy)
            elif policy_type == 27:
                policy_groups['network'].append(policy)
            elif policy_type == 24:
                policy_groups['software_dist'].append(policy)
            elif policy_type == 23:
                policy_groups['installation_package'].append(policy)
            elif policy_type == 30:  # YENİ
                policy_groups['product'].append(policy)
        
        type_names = {
            'publisher': 'Publisher-based',
            'network': 'Network-based',
            'software_dist': 'Software Distribution',
            'installation_package': 'Installation Package',
            'product': 'Product-based'  # YENİ
        }
        
        for group_key, policies in policy_groups.items():
            if policies:
                separate_data = {
                    'Policies': policies,
                    'AppGroups': [],
                    'TrustSoftwareDistributors': [],
                    'UserAccessTokens': [],
                    'EndUserUIs': []
                }
                
                output_filename = f"{base_path}_{group_key}.epmp"
                with open(output_filename, 'w', encoding='utf-8') as f:
                    json.dump(separate_data, f, indent=2, ensure_ascii=False)
                
                logging.info(f'Created {type_names[group_key]} file: {output_filename} ({len(policies)} policies)')
        
        logging.info('Successfully created separate source type files')
        
    except Exception as e:
        logging.error(f'Error creating separate source files: {str(e)}', exc_info=True)

def convert_file(input_file, output_file):
    """VFP dosyasını EPMP formatına çevir"""
    try:
        logging.info(f'Starting conversion from {input_file} to {output_file}')
        
        if not os.path.exists(input_file):
            logging.error(f'Input file not found: {input_file}')
            return False
        
        encodings_to_try = ['utf-16-le', 'utf-16-be', 'utf-16', 'utf-8']
        vfp_content = None
        
        for encoding in encodings_to_try:
            try:
                with open(input_file, 'r', encoding=encoding) as f:
                    vfp_content = f.read()
                    logging.info(f'Successfully read input file with encoding: {encoding}')
                    break
            except UnicodeDecodeError:
                continue
        
        if vfp_content is None:
            logging.error('Could not read file with any encoding')
            return False
        
        epmp_data = convert_vfp_trusted_sources_to_epmp(vfp_content)
        if epmp_data is None:
            return False
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(epmp_data, f, indent=2, ensure_ascii=False)
            logging.info(f'Successfully wrote main output file: {output_file}')
        
        create_separate_source_files(epmp_data, output_file)
        
        return True
    except Exception as e:
        logging.error(f'Error during conversion: {str(e)}', exc_info=True)
        return False

def main():
    """Main function"""
    print('Enhanced VFP to EPMP Trusted Sources Converter - COMPLETE VERSION')
    print('================================================================')
    print('Supports ALL policy types: Publisher, Network, Software Distribution, Installation Package, Product')
    print('All VFP trusted source policy types are now supported!')
    print('281 policies are filtered after publisher processing')
    
    log_file = setup_logging()
    
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = input('Enter VFP input file path: ').strip().strip('"')
    
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    else:
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        output_file = f'{base_name}_complete_trusted_sources.epmp'
    
    print(f'\n📁 Input file: {input_file}')
    print(f'📄 Output file: {output_file}')
    print(f'📋 Log file: {log_file}')
    
    if convert_file(input_file, output_file):
        print(f'\n✅ COMPLETE Trusted Sources conversion completed successfully!')
        print(f'📁 Log file: {log_file}')
        print(f'📄 Main output file: {output_file}')
        print(f'\n📊 Created separate files by source type:')
        
        base_path = os.path.splitext(output_file)[0]
        separate_files = []
        
        for suffix in ['_publisher', '_network', '_software_dist', '_installation_package', '_product']:
            separate_file = f"{base_path}{suffix}.epmp"
            if os.path.exists(separate_file):
                separate_files.append(separate_file)
        
        for separate_file in separate_files:
            file_size = os.path.getsize(separate_file)
            print(f'   📄 {os.path.basename(separate_file)} ({file_size:,} bytes)')
        
        print(f'\n🔧 ALL supported policy types:')
        print(f'  - Publisher-based policies (280/281 → 29)')
        print(f'  - Network-based policies (220/221 → 27)')
        print(f'  - Software Distribution policies (242/244 → 24)')
        print(f'  - Installation Package policies (230/231 → 23)')
        print(f'  - Product-based policies (285 → 30) ⭐ COMPLETE')
        print(f'\n🎉 All VFP trusted source policy types are now supported!')
        print(f'🔧 281 policies are properly filtered after publisher processing')
    else:
        print(f'\n❌ Conversion failed.')
        print(f'📁 Log file: {log_file}')

if __name__ == '__main__':
    main()