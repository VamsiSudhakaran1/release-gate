"""IDENTITY_BOUNDARY Check - Enforces access control and rate limits"""


class IdentityBoundaryCheck:
    """Validates authentication, rate limits, and data isolation"""
    
    def evaluate(self, config):
        """
        Evaluate IDENTITY_BOUNDARY check
        
        Returns:
            dict: {status, evidence}
        """
        checks_config = config.get('checks', {})
        identity_config = checks_config.get('identity_boundary', {})
        
        if not identity_config.get('enabled', True):
            return {
                'status': 'PASS',
                'evidence': {'skipped': True}
            }
        
        # Check authentication
        auth_config = identity_config.get('authentication', {})
        auth_required = auth_config.get('required', False)
        auth_type = auth_config.get('type')
        
        # Check rate limiting
        rate_limit_config = identity_config.get('rate_limit', {})
        rate_limit = rate_limit_config.get('requests_per_minute', 0)
        
        # Check data isolation
        data_isolation = identity_config.get('data_isolation', [])
        has_isolation = len(data_isolation) > 0
        
        # Decision logic
        issues = []
        
        if not auth_required:
            issues.append('authentication_not_required')
        
        if rate_limit <= 0:
            issues.append('rate_limit_not_set')
        
        if not has_isolation:
            issues.append('data_isolation_not_configured')
        
        if issues:
            return {
                'status': 'FAIL',
                'evidence': {
                    'authentication_required': auth_required,
                    'rate_limit': rate_limit,
                    'data_isolation_configured': has_isolation,
                    'missing': issues
                }
            }
        
        return {
            'status': 'PASS',
            'evidence': {
                'authentication_required': True,
                'auth_type': auth_type,
                'rate_limit': rate_limit,
                'data_isolation_count': len(data_isolation)
            }
        }
