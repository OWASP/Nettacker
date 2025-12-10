import copy

import yaml

from nettacker.config import Config


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

    def open(self):
        """
        Return the contents of the YAML module file identified by this loader's name.

        The name is split on underscores to derive an action (last segment) and a
        library (remaining segments joined with underscores). The file at
        Config.path.modules_dir / action / f"{library}.yaml" is opened with UTF-8
        encoding and its full text is returned.

        Returns:
            str: The raw text of the YAML file.
        """
        module_name_parts = self.name.split("_")
        action = module_name_parts[-1]
        library = "_".join(module_name_parts[:-1])

        with open(
            Config.path.modules_dir / action / f"{library}.yaml", encoding="utf-8"
        ) as yaml_file:
            return yaml_file.read()

    def format(self):
        """
        Render the module's YAML template by applying the instance's inputs as
        format placeholders.

        Returns:
            str: The template string produced by calling `open()` and applying
                `str.format` with `self.inputs`.
        """
        return self.open().format(**self.inputs)

    def load(self):
        return self.parse(yaml.safe_load(self.format()), self.inputs)

