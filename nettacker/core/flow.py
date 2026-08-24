import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from nettacker.config import Config
from nettacker.core.messages import messages as _

INPUT_TOKEN_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

ON_FAILURE_VALUES = {"continue", "abort"}


class FlowError(Exception):
    """Raised for any malformed or invalid module-flow YAML definition."""


@dataclass
class FlowStep:
    id: str
    module: str
    depends_on: object
    params: dict = field(default_factory=dict)
    on_failure: str = None
    timeout: float = None
    retries: int = None


@dataclass
class Flow:
    name: str
    info: dict
    inputs: dict
    on_failure: str
    max_parallel: int
    steps: list
    timeout: float = None
    retries: int = None

    def step_ids(self):
        return [step.id for step in self.steps]


def referenced_step_ids(depends_on):
    """Flatten a (possibly nested) depends_on expression into the step ids it references."""
    ids = set()
    if depends_on is None:
        return ids
    if isinstance(depends_on, str):
        ids.add(depends_on)
    elif isinstance(depends_on, list):
        for item in depends_on:
            ids |= referenced_step_ids(item)
    elif isinstance(depends_on, dict):
        for key in ("any", "all"):
            for item in depends_on.get(key, []):
                ids |= referenced_step_ids(item)
    return ids


def is_valid_depends_on_shape(depends_on):
    """Check that a depends_on expression is a string, a list of valid expressions,
    or a mapping with exactly one 'any'/'all' key whose value is a list of valid
    expressions. Anything else (e.g. {"either": [...]}) or 1) can never be satisfied
    by evaluate_depends_on and must be rejected at load time instead of silently
    treated as an always-open dependency."""
    if depends_on is None:
        return True
    if isinstance(depends_on, str):
        return True
    if isinstance(depends_on, list):
        return all(is_valid_depends_on_shape(item) for item in depends_on)
    if isinstance(depends_on, dict):
        if set(depends_on.keys()) not in ({"any"}, {"all"}):
            return False
        (value,) = depends_on.values()
        return isinstance(value, list) and all(is_valid_depends_on_shape(item) for item in value)
    return False


def evaluate_depends_on(depends_on, completed, blocked):
    """
    Resolve a depends_on expression against a target's current per-step state.

    Returns "satisfied" (the step may run now), "blocked" (the expression can
    never become true, so the step must be blocked too), or "pending" (still
    waiting on steps that haven't resolved yet).
    """
    if not depends_on:
        return "satisfied"

    if isinstance(depends_on, str):
        if depends_on in completed:
            return "satisfied"
        if depends_on in blocked:
            return "blocked"
        return "pending"

    if isinstance(depends_on, list):
        return evaluate_depends_on({"all": depends_on}, completed, blocked)

    if isinstance(depends_on, dict):
        if "all" in depends_on:
            results = [evaluate_depends_on(item, completed, blocked) for item in depends_on["all"]]
            if any(result == "blocked" for result in results):
                return "blocked"
            if all(result == "satisfied" for result in results):
                return "satisfied"
            return "pending"
        if "any" in depends_on:
            results = [evaluate_depends_on(item, completed, blocked) for item in depends_on["any"]]
            if any(result == "satisfied" for result in results):
                return "satisfied"
            if all(result == "blocked" for result in results):
                return "blocked"
            return "pending"

    raise FlowError(_("flow_invalid_depends_on").format(depends_on))


def render_value(value, context):
    """Recursively substitute `{target}`-style tokens found in a step's params, the same
    placeholder convention module YAML files use for their own payload templating."""
    if isinstance(value, str):
        stripped = value.strip()
        full_match = INPUT_TOKEN_RE.fullmatch(stripped)
        if full_match:
            return context.get(full_match.group(1))

        def substitute(match):
            return str(context.get(match.group(1), match.group(0)))

        return INPUT_TOKEN_RE.sub(substitute, value)
    if isinstance(value, list):
        return [render_value(item, context) for item in value]
    if isinstance(value, dict):
        return {key: render_value(item, context) for key, item in value.items()}
    return value


def render_params(params, context):
    return render_value(params or {}, context)


class FlowLoader:
    @staticmethod
    def resolve_path(name_or_path):
        candidate = Path(name_or_path)
        if candidate.suffix in {".yaml", ".yml"} and candidate.is_file():
            return candidate

        flow_file = Config.path.flows_dir / f"{name_or_path}.yaml"
        if flow_file.is_file():
            return flow_file

        raise FlowError(_("flow_not_found").format(name_or_path))

    @staticmethod
    def load(name_or_path):
        path = FlowLoader.resolve_path(name_or_path)
        try:
            content = yaml.safe_load(path.read_text())
        except yaml.YAMLError as error:
            raise FlowError(_("flow_invalid_yaml").format(path, error)) from error

        return FlowLoader.build(content, path)

    @staticmethod
    def build(content, path="<in-memory>"):
        if not isinstance(content, dict) or not content.get("steps"):
            raise FlowError(_("flow_invalid_schema").format(path))
        if not isinstance(content["steps"], list):
            raise FlowError(_("flow_invalid_schema").format(path))

        info = content.get("info") or {}
        inputs = content.get("inputs") or {}
        defaults = content.get("defaults") or {}
        execution = content.get("execution") or {}
        for section in (info, inputs, defaults, execution):
            if not isinstance(section, dict):
                raise FlowError(_("flow_invalid_schema").format(path))
        max_parallel = execution.get("max_parallel", 4)

        steps = []
        seen_ids = set()
        for raw_step in content["steps"]:
            if not isinstance(raw_step, dict):
                raise FlowError(_("flow_invalid_schema").format(path))
            step_id = raw_step.get("id")
            module = raw_step.get("module")
            if not step_id or not module:
                raise FlowError(_("flow_step_missing_fields").format(path))
            if step_id in seen_ids:
                raise FlowError(_("flow_duplicate_step_id").format(step_id))
            seen_ids.add(step_id)

            steps.append(
                FlowStep(
                    id=step_id,
                    module=module,
                    depends_on=raw_step.get("depends_on") or [],
                    params=raw_step.get("params") or {},
                    on_failure=raw_step.get("on_failure"),
                    timeout=raw_step.get("timeout"),
                    retries=raw_step.get("retries"),
                )
            )

        flow = Flow(
            name=info.get("name", Path(path).stem),
            info=info,
            inputs=inputs,
            on_failure=defaults.get("on_failure", "continue"),
            timeout=defaults.get("timeout"),
            retries=defaults.get("retries"),
            max_parallel=max_parallel,
            steps=steps,
        )

        FlowLoader.validate(flow)
        return flow

    @staticmethod
    def validate(flow):
        if flow.on_failure not in ON_FAILURE_VALUES:
            raise FlowError(_("flow_invalid_on_failure").format(flow.on_failure))

        step_ids = set(flow.step_ids())
        for step in flow.steps:
            if step.on_failure and step.on_failure not in ON_FAILURE_VALUES:
                raise FlowError(_("flow_invalid_on_failure").format(step.on_failure))
            if not is_valid_depends_on_shape(step.depends_on):
                raise FlowError(_("flow_invalid_depends_on").format(step.depends_on))
            for referenced_id in referenced_step_ids(step.depends_on):
                if referenced_id not in step_ids:
                    raise FlowError(_("flow_unknown_dependency").format(step.id, referenced_id))

        FlowLoader._detect_cycles(flow)

    @staticmethod
    def _detect_cycles(flow):
        graph = {step.id: referenced_step_ids(step.depends_on) for step in flow.steps}
        visited = set()
        stack = set()

        def dfs(node):
            if node in stack:
                raise FlowError(_("flow_cycle_detected").format(node))
            if node in visited:
                return
            stack.add(node)
            for dependency in graph[node]:
                dfs(dependency)
            stack.remove(node)
            visited.add(node)

        for node in graph:
            dfs(node)

    @staticmethod
    def resolve_inputs(flow, options, explicitly_provided=frozenset()):
        """
        Resolve every declared flow input (except `target`, which is bound per-target
        at scan time) to a concrete value: an equivalently-named CLI option, but only
        if the user actually passed it on the command line (its dest is in
        `explicitly_provided`) - an untouched argparse default must not shadow the
        flow's own `default`. Falls back to the input's own `default` from the flow YAML.

        Must be called after all other CLI argument normalizers (ports, timeout, etc.)
        have run, so `options` already holds their fully-normalized values.
        """
        resolved = {}
        for name, spec in flow.inputs.items():
            if name == "target":
                continue
            spec = spec or {}
            if name in explicitly_provided:
                resolved[name] = getattr(options, name, None)
            elif "default" in spec:
                resolved[name] = spec["default"]
            elif spec.get("required"):
                raise FlowError(_("flow_missing_required_input").format(name))
            else:
                resolved[name] = getattr(options, name, None)
        return resolved
