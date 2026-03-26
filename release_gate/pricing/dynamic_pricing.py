"""
Dynamic Pricing System for release-gate
File: release_gate/pricing/dynamic_pricing.py

Copy this file directly into your repository at:
release_gate/pricing/dynamic_pricing.py
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime
import json
from pathlib import Path
import re


class PricingSource(ABC):
    """Abstract pricing source"""
    
    @abstractmethod
    def get_model_price(self, model_name: str) -> Optional[Dict]:
        pass
    
    @abstractmethod
    def list_models(self) -> List[str]:
        pass
    
    @abstractmethod
    def get_source_name(self) -> str:
        pass
    
    @abstractmethod
    def get_last_updated(self) -> str:
        pass


class JsonPricingSource(PricingSource):
    """Read pricing from JSON file"""
    
    def __init__(self, json_file: str = "pricing.json"):
        self.json_file = Path(json_file)
        self.pricing_data = self._load_pricing()
    
    def _load_pricing(self) -> Dict:
        if not self.json_file.exists():
            return self._default_pricing()
        
        try:
            with open(self.json_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading pricing: {e}")
            return self._default_pricing()
    
    def _default_pricing(self) -> Dict:
        return {
            "models": {
                "gpt-4": {
                    "input": 0.00003,
                    "output": 0.0001,
                    "provider": "OpenAI",
                    "context_window": 8192,
                    "training_data_cutoff": "April 2024"
                },
                "gpt-4-turbo": {
                    "input": 0.00001,
                    "output": 0.00003,
                    "provider": "OpenAI",
                    "context_window": 128000,
                    "training_data_cutoff": "April 2024"
                },
                "gpt-4o": {
                    "input": 0.000005,
                    "output": 0.000015,
                    "provider": "OpenAI",
                    "context_window": 128000,
                    "training_data_cutoff": "August 2024"
                },
                "claude-3-opus": {
                    "input": 0.000015,
                    "output": 0.000075,
                    "provider": "Anthropic",
                    "context_window": 200000,
                    "training_data_cutoff": "August 2024"
                },
                "claude-3-sonnet": {
                    "input": 0.000003,
                    "output": 0.000015,
                    "provider": "Anthropic",
                    "context_window": 200000,
                    "training_data_cutoff": "August 2024"
                },
                "claude-3-5-sonnet": {
                    "input": 0.000003,
                    "output": 0.000015,
                    "provider": "Anthropic",
                    "context_window": 200000,
                    "training_data_cutoff": "October 2024"
                },
            },
            "last_updated": "2026-03-20",
            "metadata": {
                "source": "default",
                "note": "User can add custom models to pricing.json"
            }
        }
    
    def get_model_price(self, model_name: str) -> Optional[Dict]:
        models = self.pricing_data.get("models", {})
        
        if model_name in models:
            return models[model_name]
        
        for key, value in models.items():
            if model_name.lower() in key.lower() or key.lower() in model_name.lower():
                return value
        
        return None
    
    def list_models(self) -> List[str]:
        return list(self.pricing_data.get("models", {}).keys())
    
    def get_source_name(self) -> str:
        return "JSON File"
    
    def get_last_updated(self) -> str:
        return self.pricing_data.get("last_updated", "Unknown")
    
    def add_model(self, model_name: str, pricing: Dict):
        if "models" not in self.pricing_data:
            self.pricing_data["models"] = {}
        
        self.pricing_data["models"][model_name] = pricing
        self.pricing_data["last_updated"] = datetime.utcnow().isoformat()
        self._save_pricing()
    
    def _save_pricing(self):
        self.json_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.json_file, 'w') as f:
            json.dump(self.pricing_data, f, indent=2)


class CodeDetectionPricingSource(PricingSource):
    """Auto-detect models from code"""
    
    def __init__(self, json_source: JsonPricingSource):
        self.json_source = json_source
    
    def detect_models_from_code(self, code: str) -> List[str]:
        detected = []
        
        string_pattern = r'"([a-z0-9\-\.]+)"'
        for match in re.finditer(string_pattern, code):
            potential_model = match.group(1)
            if self.json_source.get_model_price(potential_model):
                detected.append(potential_model)
        
        model_param_pattern = r'model\s*=\s*["\']([a-z0-9\-\.]+)["\']'
        for match in re.finditer(model_param_pattern, code):
            potential_model = match.group(1)
            if self.json_source.get_model_price(potential_model):
                detected.append(potential_model)
        
        return list(set(detected))
    
    def detect_primary_model(self, code: str) -> Optional[str]:
        detected = self.detect_models_from_code(code)
        
        if not detected:
            return None
        
        model_counts = {}
        for model in detected:
            pattern = re.escape(model)
            count = len(re.findall(pattern, code))
            model_counts[model] = count
        
        if model_counts:
            return max(model_counts, key=model_counts.get)
        
        return None
    
    def get_model_price(self, model_name: str) -> Optional[Dict]:
        return self.json_source.get_model_price(model_name)
    
    def list_models(self) -> List[str]:
        return self.json_source.list_models()
    
    def get_source_name(self) -> str:
        return "Code Detection"
    
    def get_last_updated(self) -> str:
        return self.json_source.get_last_updated()


class DynamicPricingResolver:
    """Try multiple pricing sources in order"""
    
    def __init__(self, config: Dict = None):
        self.json_source = JsonPricingSource()
        self.code_detection = CodeDetectionPricingSource(self.json_source)
        
        self.sources: List[PricingSource] = [
            self.code_detection,
            self.json_source,
        ]
    
    def get_pricing(self, model_name: str) -> Optional[Dict]:
        """Get pricing for model, trying multiple sources"""
        
        for source in self.sources:
            try:
                pricing = source.get_model_price(model_name)
                
                if pricing:
                    pricing['_source'] = source.get_source_name()
                    return pricing
            
            except Exception as e:
                continue
        
        return None
    
    def detect_model_from_code(self, code: str) -> Optional[str]:
        """Auto-detect primary model from code"""
        return self.code_detection.detect_primary_model(code)
    
    def list_all_available_models(self) -> List[str]:
        """List all models across all sources"""
        all_models = set()
        
        for source in self.sources:
            try:
                models = source.list_models()
                all_models.update(models)
            except:
                continue
        
        return sorted(list(all_models))
    
    def add_custom_model(self, model_name: str, pricing: Dict):
        """Add custom model to JSON source"""
        self.json_source.add_model(model_name, pricing)
    
    def get_source_info(self) -> Dict:
        """Get info about pricing sources"""
        return {
            "sources": [
                {
                    "name": source.get_source_name(),
                    "last_updated": source.get_last_updated(),
                    "model_count": len(source.list_models())
                }
                for source in self.sources
            ]
        }
