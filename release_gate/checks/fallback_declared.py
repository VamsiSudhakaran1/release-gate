"""FALLBACK_DECLARED Check - Ensures safety measures exist"""


class FallbackDeclaredCheck:
    """Validates that kill switches and fallback modes are declared"""
    
    def evaluate(self, config):
        """
        Evaluate FALLBACK_DECLARED check
        
        Returns:
            dict: {status, evidence}
        """
        checks_config = config.get('checks', {})
        fallback_config = checks_config.get('fallback_declared', {})
        
        if not fallback_config.get('enabled', True):
            return {
                'status': 'PASS',
                'evidence': {'skipped': True}
            }
        
        # Check for kill switch
        kill_switch = fallback_config.get('kill_switch')
        has_kill_switch = kill_switch is not None and kill_switch.get('type') is not None
        
        # Check for fallback mode
        fallback_mode = fallback_config.get('fallback_mode')
        has_fallback_mode = fallback_mode is not None and len(str(fallback_mode)) > 0
        
        # Check for team owner
        team_owner = fallback_config.get('team_owner')
        has_owner = team_owner is not None and len(str(team_owner)) > 0
        
        # Check for runbook
        runbook = fallback_config.get('runbook_url')
        has_runbook = runbook is not None and len(str(runbook)) > 0
        
        # Decision logic
        issues = []
        
        if not has_kill_switch:
            issues.append('kill_switch_missing')
        
        if not has_fallback_mode:
            issues.append('fallback_mode_missing')
        
        if not has_owner:
            issues.append('team_owner_missing')
        
        if not has_runbook:
            issues.append('runbook_missing')
        
        if issues:
            return {
                'status': 'FAIL',
                'evidence': {
                    'kill_switch_declared': has_kill_switch,
                    'fallback_mode_declared': has_fallback_mode,
                    'team_owner_declared': has_owner,
                    'runbook_declared': has_runbook,
                    'missing': issues
                }
            }
        
        return {
            'status': 'PASS',
            'evidence': {
                'kill_switch_declared': True,
                'fallback_mode': fallback_mode,
                'team_owner': team_owner,
                'runbook_url': runbook
            }
        }
