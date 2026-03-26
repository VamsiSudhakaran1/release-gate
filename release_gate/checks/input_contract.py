"""INPUT_CONTRACT Check - Validates request schemas are defined"""
import json


class InputContractCheck:
    """Validates that input schemas are defined and tested"""
    
    def evaluate(self, config):
        """
        Evaluate INPUT_CONTRACT check
        
        Returns:
            dict: {status, evidence}
        """
        checks_config = config.get('checks', {})
        input_config = checks_config.get('input_contract', {})
        
        if not input_config.get('enabled', True):
            return {
                'status': 'PASS',
                'evidence': {'skipped': True}
            }
        
        # Check if schema is defined
        schema_defined = False
        required_fields = []
        
        if 'schema' in input_config:
            schema = input_config['schema']
            if isinstance(schema, dict):
                schema_defined = True
                required_fields = schema.get('required', [])
        
        # Check for sample payloads
        samples = input_config.get('samples', {})
        valid_samples = len(samples.get('valid', []))
        invalid_samples = len(samples.get('invalid', []))
        
        # Decision logic
        if not schema_defined:
            return {
                'status': 'FAIL',
                'evidence': {
                    'schema_defined': False,
                    'required_fields': 0,
                    'valid_samples_tested': valid_samples,
                    'invalid_samples_tested': invalid_samples,
                    'error': 'Schema not defined'
                }
            }
        
        if valid_samples == 0:
            return {
                'status': 'WARN',
                'evidence': {
                    'schema_defined': True,
                    'required_fields': len(required_fields),
                    'valid_samples_tested': valid_samples,
                    'invalid_samples_tested': invalid_samples,
                    'warning': 'No valid samples tested'
                }
            }
        
        return {
            'status': 'PASS',
            'evidence': {
                'schema_defined': True,
                'required_fields': len(required_fields),
                'valid_samples_tested': valid_samples,
                'invalid_samples_tested': invalid_samples
            }
        }
