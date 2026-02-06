import copy

import yaml

from nettacker.config import Config


class TemplateLoader:
    def __init__(self, name, inputs=None) -> None:
        self.name = name
        self.inputs = inputs or {}

    @staticmethod
    def _deep_merge(base, override):
        """
        Deep-merge two YAML-loaded structures.

        - dicts are merged recursively
        - all other types (including lists) are overridden
        """
        if isinstance(base, dict) and isinstance(override, dict):
            merged = copy.deepcopy(base)
            for key, value in override.items():
                if key in merged:
                    merged[key] = TemplateLoader._deep_merge(merged[key], value)
                else:
                    merged[key] = copy.deepcopy(value)
            return merged
        return copy.deepcopy(override)

    @staticmethod
    def parse(module_content, module_inputs):
        if isinstance(module_content, dict):
            for key in copy.deepcopy(module_content):
                if key in module_inputs:
                    if module_inputs[key]:
                        module_content[key] = module_inputs[key]
                elif isinstance(module_content[key], (dict, list)):
                    module_content[key] = TemplateLoader.parse(module_content[key], module_inputs)
        elif isinstance(module_content, list):
            array_index = 0
            for key in copy.deepcopy(module_content):
                module_content[array_index] = TemplateLoader.parse(key, module_inputs)
                array_index += 1

        return module_content

    def open(self):
        module_name_parts = self.name.split("_")
        action = module_name_parts[-1]
        library = "_".join(module_name_parts[:-1])

        with open(Config.path.modules_dir / action / f"{library}.yaml") as yaml_file:
            return yaml_file.read()

    def format(self):
        return self.open().format(**self.inputs)

    def load(self, _visited=None):
        """
        Load and parse a module YAML template.

        Supports lightweight module aliases via a root-level `include` key:
        - `include: other_module_name` will load/merge the included module, then apply overrides.
        """
        visited = _visited or set()
        if self.name in visited:
            raise ValueError(f"circular module include detected: {self.name}")
        visited.add(self.name)

        content = yaml.safe_load(self.format()) or {}
        include = content.pop("include", None)
        if include:
            included = TemplateLoader(include, self.inputs).load(_visited=visited)
            content = TemplateLoader._deep_merge(included, content)

        return self.parse(content, self.inputs)
