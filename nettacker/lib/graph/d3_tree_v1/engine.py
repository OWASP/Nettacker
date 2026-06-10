import json

from nettacker.config import Config
from nettacker.core.messages import messages


def escape_for_html_js(json_str: str) -> str:
    """
    This is necessary because some payloads have HTML tags for XSS
    as in waf.yaml, which break the HTML and output no graph. These are unicode escape
    characters for the same
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
        target = event.get("target", "unknown_target")
        module_name = event.get("module_name", "unknown_module")
        port = event.get("port", "unknown_port")
        event_name = event.get("event", "unknown_event")

        if target not in normalisedjson["children"]:
            normalisedjson["children"].update({target: {}})
            normalisedjson["children"][target].update({module_name: []})

        if module_name not in normalisedjson["children"][target]:
            normalisedjson["children"][target].update({module_name: []})
        normalisedjson["children"][target][module_name].append(
            f"target: {target}, module_name: {module_name}, port: {port}, event: {event_name}"
        )
    # define a d3_structure_json
    d3_structure = {"name": "Starting attack", "children": []}
    # get data for normalised_json
    for target in list(normalisedjson["children"].keys()):
        for module_name in list(normalisedjson["children"][target].keys()):
            for description in normalisedjson["children"][target][module_name]:
                children_array = [{"name": module_name, "children": [{"name": description}]}]
                d3_structure["children"].append({"name": target, "children": children_array})

    data = (
        open(Config.path.web_static_dir / "report/d3_tree_v1.html")
        .read()
        .replace("__data_will_locate_here__", escape_for_html_js(json.dumps(d3_structure)))
        .replace("__title_to_replace__", messages("pentest_graphs"))
        .replace("__description_to_replace__", messages("graph_message"))
        .replace("__html_title_to_replace__", messages("nettacker_report"))
    )
    return data
