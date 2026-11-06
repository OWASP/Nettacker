"""Engine for generating interactive D3 tree (v1) HTML graphs from scan events."""

import json

from nettacker.config import Config
from nettacker.core.messages import messages


def escape_for_html_js(json_str: str) -> str:
    """Escape HTML-sensitive characters in a JSON string for safe embedding in HTML/JS.

    Replaces ``<``, ``>``, and ``&`` with their Unicode escape sequences so that
    payloads containing HTML tags (e.g. XSS vectors in ``waf.yaml``) do not break
    the rendered graph.

    Args:
        json_str: The JSON string to sanitise.

    Returns:
        The escaped string safe for inline use in HTML and JavaScript.
    """
    return json_str.replace("<", "\\u003C").replace(">", "\\u003E").replace("&", "\\u0026")


def start(events):
    """
    generate the d3_tree_v1_graph with events

    Args:
        events: all events

    Returns:
        a graph in HTML
    """

    # define  a normalised_json
    normalisedjson = {"name": "Started attack", "children": {}}
    # get data for normalised_json
    for event in events:
        if event["target"] not in normalisedjson["children"]:
            normalisedjson["children"].update({event["target"]: {}})
            normalisedjson["children"][event["target"]].update({event["module_name"]: []})

        if event["module_name"] not in normalisedjson["children"][event["target"]]:
            normalisedjson["children"][event["target"]].update({event["module_name"]: []})
        normalisedjson["children"][event["target"]][event["module_name"]].append(
            f"target: {event['target']}, module_name: {event['module_name']}, port: "
            f"{event['port']}, event: {event['event']}"
        )
    # define a d3_structure_json
    d3_structure = {"name": "Starting attack", "children": []}
    # get data for normalised_json
    for target in list(normalisedjson["children"].keys()):
        for module_name in list(normalisedjson["children"][target].keys()):
            for description in normalisedjson["children"][target][module_name]:
                children_array = [{"name": module_name, "children": [{"name": description}]}]
                d3_structure["children"].append({"name": target, "children": children_array})

    with open(Config.path.web_static_dir / "report/d3_tree_v1.html") as f:
        template = f.read()
    data = (
        template.replace("__data_will_locate_here__", escape_for_html_js(json.dumps(d3_structure)))
        .replace("__title_to_replace__", messages("pentest_graphs"))
        .replace("__description_to_replace__", messages("graph_message"))
        .replace("__html_title_to_replace__", messages("nettacker_report"))
    )
    return data
