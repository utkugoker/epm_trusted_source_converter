"""
Validation Functions for VFP to EPMP Converter
Validates and cleans EPMP data before output
"""

import logging

def validate_and_clean_applications(applications):
    """Validate and clean application patterns to avoid EPMP validation errors"""
    cleaned_applications = []
    
    for app in applications:
        if not app or 'patterns' not in app:
            continue
            
        cleaned_app = app.copy()
        cleaned_patterns = {}
        
        for pattern_key, pattern_value in app['patterns'].items():
            if pattern_key == 'FILE_NAME':
                cleaned_pattern = clean_filename_pattern(pattern_value)
                if cleaned_pattern:
                    cleaned_patterns[pattern_key] = cleaned_pattern
            else:
                # For other patterns, just copy as-is
                cleaned_patterns[pattern_key] = pattern_value
        
        # Only include the application if it has at least one valid pattern
        if cleaned_patterns:
            cleaned_app['patterns'] = cleaned_patterns
            cleaned_applications.append(cleaned_app)
        else:
            logging.warning(f'Skipping application "{app.get("displayName", "Unknown")}" - no valid patterns')
    
    return cleaned_applications

def clean_filename_pattern(pattern):
    """Clean FileName pattern to avoid hash validation errors"""
    if not pattern or pattern.get('@type') != 'FileName':
        return pattern
    
    cleaned_pattern = pattern.copy()
    
    # Check hash and hashAlgorithm - STRICT validation
    hash_value = pattern.get('hash', '')
    hash_algorithm = pattern.get('hashAlgorithm', '')
    
    # Convert to string and strip whitespace
    if hash_value:
        hash_value = str(hash_value).strip()
    if hash_algorithm:
        hash_algorithm = str(hash_algorithm).strip()
    
    # CRITICAL: Remove hash fields if either is empty or None
    if not hash_value or not hash_algorithm or hash_value == '' or hash_algorithm == '':
        # Force remove ALL hash-related fields
        for hash_field in ['hash', 'hashAlgorithm', 'hashSHA256']:
            if hash_field in cleaned_pattern:
                del cleaned_pattern[hash_field]
        logging.debug(f'Removed empty/invalid hash fields from FileName pattern for: {pattern.get("content", "Unknown")}')
        return cleaned_pattern
    
    # Validate hash format if both values exist
    hash_algorithm_upper = hash_algorithm.upper()
    if hash_algorithm_upper in ['SHA1', 'MD5', 'SHA256']:
        expected_lengths = {
            'SHA1': 40,
            'MD5': 32,
            'SHA256': 64
        }
        expected_length = expected_lengths[hash_algorithm_upper]
        
        if len(hash_value) != expected_length:
            logging.warning(f'Invalid {hash_algorithm} hash length for {pattern.get("content", "Unknown")}: expected {expected_length}, got {len(hash_value)}')
            # Remove invalid hash fields
            for hash_field in ['hash', 'hashAlgorithm', 'hashSHA256']:
                if hash_field in cleaned_pattern:
                    del cleaned_pattern[hash_field]
        else:
            # Keep valid hash and ensure proper format
            cleaned_pattern['hash'] = hash_value.upper()
            cleaned_pattern['hashAlgorithm'] = hash_algorithm_upper
            # Only set hashSHA256 if this is actually SHA256
            if hash_algorithm_upper == 'SHA256':
                cleaned_pattern['hashSHA256'] = hash_value.upper()
            else:
                cleaned_pattern['hashSHA256'] = ''
    else:
        logging.warning(f'Unknown hash algorithm "{hash_algorithm}" for {pattern.get("content", "Unknown")}')
        # Remove unknown hash algorithm fields
        for hash_field in ['hash', 'hashAlgorithm', 'hashSHA256']:
            if hash_field in cleaned_pattern:
                del cleaned_pattern[hash_field]
    
    return cleaned_pattern

def validate_policy_structure(policy):
    """Validate basic policy structure"""
    required_fields = ['Id', 'Name', 'PolicyType', 'Action']
    
    for field in required_fields:
        if field not in policy:
            logging.error(f'Policy missing required field: {field}')
            return False
    
    # Validate PolicyType
    valid_policy_types = [23, 24, 27, 29, 30]
    if policy['PolicyType'] not in valid_policy_types:
        logging.warning(f'Unknown PolicyType: {policy["PolicyType"]}')
    
    # Validate Action
    valid_actions = [0, 1, 2, 3, 4]
    if policy['Action'] not in valid_actions:
        logging.warning(f'Unknown Action: {policy["Action"]}')
    
    # Clean Applications if present
    if 'Applications' in policy and policy['Applications']:
        policy['Applications'] = validate_and_clean_applications(policy['Applications'])
    
    return True

def validate_epmp_data(epmp_data):
    """Validate complete EPMP data structure"""
    if not epmp_data or 'Policies' not in epmp_data:
        logging.error('Invalid EPMP data structure')
        return False
    
    valid_policies = []
    
    for policy in epmp_data['Policies']:
        if validate_policy_structure(policy):
            valid_policies.append(policy)
        else:
            logging.error(f'Removing invalid policy: {policy.get("Name", "Unknown")}')
    
    epmp_data['Policies'] = valid_policies
    
    logging.info(f'Validation completed: {len(valid_policies)} valid policies')
    return len(valid_policies) > 0