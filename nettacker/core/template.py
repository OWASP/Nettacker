import copy
import re

import yaml

from nettacker.config import Config
from nettacker.core.utils import common as common_utils


class TemplateLoader:
    def __init__(self, name, inputs=None) -> None:
        self.name = name
        self.inputs = inputs or {}

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

    def _apply_dynamic_placeholders(self, content: str) -> str:
        """
        Handle runtime placeholders like:
        - {rand_str(10)}
        """
        content = re.sub(
            r"\{rand_str\((\d+)\)\}",
            lambda m: common_utils.generate_random_token(int(m.group(1))),
            content,
        )
        return content

    def open(self):
        module_name_parts = self.name.split("_")
        action = module_name_parts[-1]
        library = "_".join(module_name_parts[:-1])

        with open(Config.path.modules_dir / action / f"{library}.yaml") as yaml_file:
            return yaml_file.read()

    def format(self):
        content = self.open()
        content = self._apply_dynamic_placeholders(content)
        return content.format(**self.inputs)

    def load(self):
        return self.parse(yaml.safe_load(self.format()), self.inputs)
