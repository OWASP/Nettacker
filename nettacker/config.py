import inspect
from functools import lru_cache
from pathlib import Path

from nettacker import version
from nettacker.core.utils.common import now, generate_random_token

CWD = Path.cwd()
PACKAGE_PATH = Path(__file__).parent


@lru_cache(maxsize=128)
def version_info():
    """
    version information of the framework

    Returns:
        an array of version and code name
    """

    return version.__version__, version.__release_name__


class ConfigBase:
    @classmethod
    def as_dict(cls):
        return {attr_name: getattr(cls, attr_name) for attr_name in cls()}

    def __init__(self) -> None:
        self.attributes = sorted(
            (
                attribute[0]
                for attribute in inspect.getmembers(self)
                if not attribute[0].startswith("_") and not inspect.ismethod(attribute[1])
            )
        )
        self.idx = 0

    def __iter__(self):
        yield from self.attributes


class ApiConfig(ConfigBase):
    """OWASP Nettacker API Default Configuration"""

    api_access_log = str(CWD / ".data/nettacker.log")
    api_access_key = generate_random_token(32)
    api_client_whitelisted_ips = []  # disabled - to enable please put an array with list of ips/cidr/ranges
    # [
    #     "127.0.0.1",
    #     "10.0.0.0/24",
    #     "192.168.1.1-192.168.1.255"
    # ],
    api_debug_mode = False
    api_hostname = "0.0.0.0"
    api_port = 5000
    start_api_server = False


class DbConfig(ConfigBase):
    """
    Database Config (could be modified by user)
    For sqlite database:
        fill the name of the DB as sqlite,
        DATABASE as the name of the db user wants
        other details can be left empty
    For mysql users:
        fill the name of the DB as mysql
        DATABASE as the name of the database you want to create
        USERNAME, PASSWORD, HOST and the PORT of the MySQL server
        need to be filled respectively

    """

    engine = "sqlite"
    name = str(CWD / ".data/nettacker.db")
    host = ""
    port = ""
    username = ""
    password = ""


class PathConfig:
    """
    home path for the framework (could be modify by user)

    Returns:
        a JSON contain the working, tmp and results path
    """

    data_dir = CWD / ".data"
    database_file = CWD / ".data/nettacker.db"
    graph_dir = PACKAGE_PATH / "lib/graph"
    home_dir = CWD
    locale_dir = PACKAGE_PATH / "locale"
    logo_file = PACKAGE_PATH / "logo.txt"
    module_protocols_dir = PACKAGE_PATH / "core/lib"
    modules_dir = PACKAGE_PATH / "modules"
    payloads_dir = PACKAGE_PATH / "lib/payloads"
    release_name_file = PACKAGE_PATH / "release_name.txt"
    results_dir = CWD / ".data/results"
    tmp_dir = CWD / ".data/tmp"
    web_static_dir = PACKAGE_PATH / "web/static"
    user_agents_file = PACKAGE_PATH / "lib/payloads/User-Agents/web_browsers_user_agents.txt"


class DefaultSettings(ConfigBase):
    """OWASP Nettacker Default Configuration"""

    excluded_modules = None
    graph_name = "d3_tree_v2_graph"
    language = "en"
    modules_extra_args = None
    parallel_module_scan = 1
    passwords = None
    passwords_list = None
    ping_before_scan = False
    ports = None
    profiles = None
    report_path_filename = "{results_path}/results_{date_time}_{random_chars}.html".format(
        results_path=PathConfig.results_dir,
        date_time=now(format="%Y_%m_%d_%H_%M_%S"),
        random_chars=generate_random_token(10),
    )
    retries = 1
    scan_ip_range = False
    scan_subdomains = False
    selected_modules = None
    set_hardware_usage = "maximum"  # low, normal, high, maximum
    show_all_modules = False
    show_all_profiles = False
    show_help_menu = False
    show_version = False
    skip_service_discovery = False
    socks_proxy = None
    targets = None
    targets_list = None
    thread_per_host = 100
    time_sleep_between_requests = 0.0
    timeout = 3.0
    user_agent = "Nettacker {version_number} {version_code}".format(
        version_number=version_info()[0], version_code=version_info()[1]
    )
    usernames = None
    usernames_list = None
    verbose_event = False
    verbose_mode = False
    scan_compare_id = None
    compare_report_path_filename = ""


class Config:
    api = ApiConfig()
    db = DbConfig()
    path = PathConfig()
    settings = DefaultSettings()
