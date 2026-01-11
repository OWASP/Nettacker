import json
import time

try:
    import apsw
except ImportError:
    apsw = None

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from nettacker import logger
from nettacker.api.helpers import structure
from nettacker.config import Config
from nettacker.core.messages import messages
from nettacker.database.models import HostsLog, Report, TempEvents

config = Config()
logger = logger.get_logger()


def db_inputs(connection_type):
    """
    a function to determine the type of database the user wants to work with and
    selects the corresponding connection to the db

    Args:
        connection_type: type of db we are working with

    Returns:
        corresponding command to connect to the db
    """
    context = Config.db.as_dict()
    return {
        "postgres": "postgresql+psycopg2://{username}:{password}@{host}:{port}/{name}?sslmode={ssl_mode}".format(
            **context
        ),
        "mysql": "mysql+pymysql://{username}:{password}@{host}:{port}/{name}".format(**context),
        "sqlite": "sqlite:///{name}".format(**context),
    }[connection_type]


def create_connection():
    """
    a function to create connections to db with pessimistic approach

    For sqlite, it creates and returns a sqlite connection object
    for mysql and postgresql, it returns the connection or False if
    connection failed.
    """
    if Config.db.engine.startswith("sqlite") and Config.settings.use_apsw_for_sqlite:
        if apsw is None:
            raise ImportError("APSW is required for SQLite backend.")

        # In case of sqlite, the name parameter is the database path.
        try:
            DB_PATH = config.db.as_dict()["name"]
            connection = apsw.Connection(DB_PATH)
            connection.setbusytimeout(int(config.settings.timeout) * 100)
            cursor = connection.cursor()

            # Performance enhancing configurations. Put WAL cause that helps with concurrency.
            cursor.execute(f"PRAGMA journal_mode={Config.db.journal_mode}")
            cursor.execute(f"PRAGMA synchronous={Config.db.synchronous_mode}")

            return connection, cursor
        except Exception as e:
            logger.error(f"Failed to create APSW connection: {e}")
            raise

    else:
        connection_args = {}

        if Config.db.engine.startswith("sqlite"):
            connection_args["check_same_thread"] = False

        db_engine = create_engine(
            db_inputs(Config.db.engine),
            connect_args=connection_args,
            pool_size=50,
            pool_pre_ping=True,
        )

        return sessionmaker(bind=db_engine)()


def send_submit_query(session):
    """
    a function to send submit based queries to db
    (such as insert and update or delete), it retries 100 times if
    connection returned an error.

    Args:
        session: session to commit

    Returns:
        True if submitted success otherwise False
    """
    if isinstance(session, tuple):
        connection, _ = session
        try:
            for _ in range(1, Config.settings.max_submit_query_retry):
                try:
                    connection.execute("COMMIT")
                    return True
                except Exception:
                    connection.execute("ROLLBACK")
                    time.sleep(Config.settings.retry_delay)
        finally:
            connection.close()
        # If not already returned then connection failed
        logger.warn(messages("database_connect_fail"))
        return False
    else:
        try:
            for _ in range(1, Config.settings.max_submit_query_retry):
                try:
                    session.commit()
                    return True
                except Exception:
                    session.rollback()
                    time.sleep(Config.settings.retry_delay)
            logger.warn(messages("database_connect_fail"))
            return False
        except Exception:
            logger.warn(messages("database_connect_fail"))
            return False


def submit_report_to_db(event):
    """
    this function created to submit the generated reports into db, the
    files are not stored in db, just the path!

    Args:
        event: event log

    Returns:
        return True if submitted otherwise False
    """
    logger.verbose_info(messages("inserting_report_db"))
    session = create_connection()

    if isinstance(session, tuple):
        connection, cursor = session

        try:
            cursor.execute("BEGIN")
            cursor.execute(
                """
                INSERT INTO reports (date, scan_unique_id, report_path_filename, options)
                VALUES (?, ?, ?, ?)
                """,
                (
                    str(event["date"]),
                    event["scan_id"],
                    event["options"]["report_path_filename"],
                    json.dumps(event["options"]),
                ),
            )
            return send_submit_query(session)
        except Exception:
            cursor.execute("ROLLBACK")
            logger.warn("Could not insert report...")
            return False
    else:
        session.add(
            Report(
                date=event["date"],
                scan_unique_id=event["scan_id"],
                report_path_filename=event["options"]["report_path_filename"],
                options=json.dumps(event["options"]),
            )
        )
        return send_submit_query(session)


def remove_old_logs(options):
    """
    this function remove old events (and duplicated)
    from nettacker.database based on target, module, scan_id

    Args:
        options: identifiers

    Returns:
        True if success otherwise False
    """
    session = create_connection()
    if isinstance(session, tuple):
        connection, cursor = session

        try:
            cursor.execute("BEGIN")
            cursor.execute(
                """
                DELETE FROM scan_events
                    WHERE target = ?
                      AND module_name = ?
                      AND scan_unique_id != ?
                      AND scan_unique_id != ?
                """,
                (
                    options["target"],
                    options["module_name"],
                    options["scan_id"],
                    options["scan_compare_id"],
                ),
            )
            return send_submit_query(session)
        except Exception:
            cursor.execute("ROLLBACK")
            logger.warn("Could not remove old logs...")
            return False
        finally:
            cursor.close()
            connection.close()
    else:
        session.query(HostsLog).filter(
            HostsLog.target == options["target"],
            HostsLog.module_name == options["module_name"],
            HostsLog.scan_unique_id != options["scan_id"],
            HostsLog.scan_unique_id != options["scan_compare_id"],
            # Don't remove old logs if they are to be used for the scan reports
        ).delete(synchronize_session=False)
        return send_submit_query(session)


def submit_logs_to_db(log):
    """
    this function created to submit new events into database.
    This requires a little more robust handling in case of
    APSW in order to avoid database lock issues.

    Args:
        log: log event in JSON type

    Returns:
        True if success otherwise False
    """
    if isinstance(log, dict):
        session = create_connection()
        if isinstance(session, tuple):
            connection, cursor = session
            try:
                for _ in range(Config.settings.max_retries):
                    try:
                        if not connection.in_transaction:
                            connection.execute("BEGIN")
                        cursor.execute(
                            """
                            INSERT INTO scan_events (target, date, module_name, scan_unique_id, port, event, json_event)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                log["target"],
                                str(log["date"]),
                                log["module_name"],
                                log["scan_id"],
                                json.dumps(log["port"]),
                                json.dumps(log["event"]),
                                json.dumps(log["json_event"]),
                            ),
                        )
                        return send_submit_query(session)

                    except apsw.BusyError as e:
                        if "database is locked" in str(e).lower():
                            logger.warn(
                                f"[Retry {_ + 1}/{Config.settings.max_retries}] Database is locked. Retrying..."
                            )
                            if connection.in_transaction:
                                connection.execute("ROLLBACK")
                            time.sleep(Config.settings.retry_delay)
                            continue
                        else:
                            if connection.in_transaction:
                                connection.execute("ROLLBACK")
                            return False
                    except Exception:
                        try:
                            if connection.in_transaction:
                                connection.execute("ROLLBACK")
                        except Exception:
                            pass
                        return False
                # All retires exhausted but we want to continue operation
                logger.warn("All retries exhausted. Skipping this log.")
                return True
            finally:
                cursor.close()
                connection.close()

        else:
            session.add(
                HostsLog(
                    target=log["target"],
                    date=log["date"],
                    module_name=log["module_name"],
                    scan_unique_id=log["scan_id"],
                    port=json.dumps(log["port"]),
                    event=json.dumps(log["event"]),
                    json_event=json.dumps(log["json_event"]),
                )
            )
            return send_submit_query(session)
    else:
        logger.warn(messages("invalid_json_type_to_db").format(log))
        return False


def submit_temp_logs_to_db(log):
    """
    this function created to submit new events into database.
    This requires a little more robust handling in case of
    APSW in order to avoid database lock issues.

    Args:
        log: log event in JSON type

    Returns:
        True if success otherwise False
    """
    if isinstance(log, dict):
        session = create_connection()
        if isinstance(session, tuple):
            connection, cursor = session

            try:
                for _ in range(Config.settings.max_retries):
                    try:
                        if not connection.in_transaction:
                            cursor.execute("BEGIN")
                        cursor.execute(
                            """
                            INSERT INTO temp_events (target, date, module_name, scan_unique_id, event_name, port, event, data)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                log["target"],
                                str(log["date"]),
                                log["module_name"],
                                log["scan_id"],
                                log["event_name"],
                                json.dumps(log["port"]),
                                json.dumps(log["event"]),
                                json.dumps(log["data"]),
                            ),
                        )
                        return send_submit_query(session)
                    except apsw.BusyError as e:
                        if "database is locked" in str(e).lower():
                            logger.warn(
                                f"[Retry {_ + 1}/{Config.settings.max_retries}] Database is locked. Retrying..."
                            )
                            try:
                                if connection.in_transaction:
                                    connection.execute("ROLLBACK")
                            except Exception:
                                pass
                            time.sleep(Config.settings.retry_delay)
                            continue
                        else:
                            try:
                                if connection.in_transaction:
                                    connection.execute("ROLLBACK")
                            except Exception:
                                pass
                            return False
                    except Exception:
                        try:
                            if connection.in_transaction:
                                connection.execute("ROLLBACK")
                        except Exception:
                            pass
                        return False
                # All retires exhausted but we want to continue operation
                logger.warn("All retries exhausted. Skipping this log.")
                return True
            finally:
                cursor.close()
                connection.close()
        else:
            session.add(
                TempEvents(
                    target=log["target"],
                    date=log["date"],
                    module_name=log["module_name"],
                    scan_unique_id=log["scan_id"],
                    event_name=log["event_name"],
                    port=json.dumps(log["port"]),
                    event=json.dumps(log["event"]),
                    data=json.dumps(log["data"]),
                )
            )
            return send_submit_query(session)
    else:
        logger.warn(messages("invalid_json_type_to_db").format(log))
        return False


def find_temp_events(target, module_name, scan_id, event_name):
    """
    select all events by scan_unique id, target, module_name

    Args:
        target: target
        module_name: module name
        scan_id: unique scan identifier
        event_name: event_name

    Returns:
        an array with JSON events or an empty array
    """
    session = create_connection()
    if isinstance(session, tuple):
        connection, cursor = session
        try:
            cursor.execute(
                """
                SELECT event
                FROM temp_events
                WHERE target = ? AND module_name = ? AND scan_unique_id = ? AND event_name = ?
                LIMIT 1
            """,
                (target, module_name, scan_id, event_name),
            )

            row = cursor.fetchone()
            if row:
                return row[0]
            return []
        except Exception:
            logger.warn(messages("database_connect_fail"))
            return []
        finally:
            try:
                cursor.close()
                connection.close()
            except Exception:
                pass
    else:
        result = (
            session.query(TempEvents)
            .filter(
                TempEvents.target == target,
                TempEvents.module_name == module_name,
                TempEvents.scan_unique_id == scan_id,
                TempEvents.event_name == event_name,
            )
            .first()
        )

        return result.event if result else []


def find_events(target, module_name, scan_id):
    """
    select all events by scan_unique id, target, module_name

    Args:
        target: target
        module_name: module name
        scan_id: unique scan identifier

    Returns:
        an array with JSON events or an empty array
    """
    session = create_connection()
    if isinstance(session, tuple):
        connection, cursor = session

        try:
            cursor.execute(
                """
                SELECT json_event FROM scan_events
                WHERE target = ? AND module_name = ? and scan_unique_id = ?
                """,
                (target, module_name, scan_id),
            )

            rows = cursor.fetchall()
            if rows:
                return [json.dumps((json.loads(row[0]))) for row in rows]
            return []
        except Exception:
            logger.warn("Database query failed...")
            return []
        finally:
            try:
                cursor.close()
                connection.close()
            except Exception:
                pass
    else:
        return [
            row.json_event
            for row in session.query(HostsLog)
            .filter(
                HostsLog.target == target,
                HostsLog.module_name == module_name,
                HostsLog.scan_unique_id == scan_id,
            )
            .all()
        ]


def select_reports(page):
    """
    this function created to crawl into submitted results,
    it shows last 10 results submitted in the database.
    you may change the page (default 1) to go to next/previous page.

    Args:
        page: page number

    Returns:
        list of events in array and JSON type, otherwise an error in JSON type.
    """
    selected = []
    session = create_connection()
    if isinstance(session, tuple):
        connection, cursor = session
        offset = (page - 1) * 10

        try:
            cursor.execute(
                """
                SELECT id, date, scan_unique_id, report_path_filename, options
                FROM reports
                ORDER BY id DESC
                LIMIT 10 OFFSET ?
                """,
                (offset,),
            )

            rows = cursor.fetchall()

            for row in rows:
                tmp = {
                    "id": row[0],
                    "date": str(row[1]),
                    "scan_id": row[2],
                    "report_path_filename": row[3],
                    "options": json.loads(row[4]),
                }
                selected.append(tmp)
            return selected

        except Exception:
            logger.warn("Could not retrieve report...")
            return structure(status="error", msg="database error!")
        finally:
            cursor.close()
            connection.close()
    else:
        try:
            search_data = (
                session.query(Report).order_by(Report.id.desc()).offset((page * 10) - 10).limit(10)
            )
            for data in search_data:
                tmp = {
                    "id": data.id,
                    "date": data.date,
                    "scan_id": data.scan_unique_id,
                    "report_path_filename": data.report_path_filename,
                    "options": json.loads(data.options),
                }
                selected.append(tmp)
        except Exception:
            return structure(status="error", msg="database error!")
        return selected


def get_scan_result(id):
    """
    this function created to download results by the result ID.

    Args:
        id: scan id

    Returns:
        result file content (TEXT, HTML, JSON) if success otherwise and error in JSON type.
    """
    session = create_connection()
    if isinstance(session, tuple):
        connection, cursor = session
        try:
            cursor.execute(
                "SELECT report_path_filename from reports WHERE id = ?",
                (id,),
            )

            row = cursor.fetchone()
            if row:
                filename = row[0]
                try:
                    with open(str(filename), "rb") as fp:
                        contents = fp.read()
                    return filename, contents
                except IOError as e:
                    logger.error(f"Failed to read report file: {e}")
                    return None
            else:
                return structure(status="error", msg="database error!")
        finally:
            try:
                cursor.close()
                connection.close()
            except Exception:
                pass
    else:
        report = session.query(Report).filter_by(id=id).first()
        if not report:
            return None

        try:
            with open(str(report.report_path_filename), "rb") as fp:
                contents = fp.read()
            return report.report_path_filename, contents
        except IOError as e:
            logger.error(f"Failed to read report file: {e}")
            return None


def last_host_logs(page):
    """
    this function created to select the last 10 events from the database.
    you can goto next page by changing page value.

    Args:
        page: page number

    Returns:
        an array of events in JSON type if success otherwise an error in JSON type
    """
    session = create_connection()
    if isinstance(session, tuple):
        connection, cursor = session
        try:
            cursor.execute(
                """
                SELECT DISTINCT target 
                FROM scan_events
                ORDER BY id DESC 
                LIMIT 10 OFFSET ?
                """,
                [(page - 1) * 10],
            )
            targets = cursor.fetchall()

            if not targets:
                cursor.close()
                connection.close()
                return structure(status="finished", msg="No more search results")

            hosts = []

            for (target,) in targets:
                cursor.execute(
                    """
                    SELECT DISTINCT module_name 
                    FROM scan_events
                    WHERE target = ?
                    """,
                    [target],
                )
                module_names = [row[0] for row in cursor.fetchall()]

                cursor.execute(
                    """
                    SELECT date 
                    FROM scan_events
                    WHERE target = ? 
                    ORDER BY id DESC 
                    LIMIT 1
                    """,
                    [target],
                )
                latest_date = cursor.fetchone()
                latest_date = latest_date[0] if latest_date else None

                cursor.execute(
                    """
                    SELECT event 
                    FROM scan_events
                    WHERE target = ?
                    """,
                    [target],
                )
                events = [row[0] for row in cursor.fetchall()]

                hosts.append(
                    {
                        "target": target,
                        "info": {
                            "module_name": module_names,
                            "date": latest_date,
                            "events": events,
                        },
                    }
                )
            return hosts

        except Exception:
            logger.warn("Database query failed...")
            return structure(status="error", msg="Database error!")
        finally:
            try:
                cursor.close()
                connection.close()
            except Exception:
                pass
    else:
        hosts = [
            {
                "target": host.target,
                "info": {
                    "module_name": [
                        _.module_name
                        for _ in session.query(HostsLog)
                        .filter(HostsLog.target == host.target)
                        .group_by(HostsLog.module_name)
                        .all()
                    ],
                    "date": session.query(HostsLog)
                    .filter(HostsLog.target == host.target)
                    .order_by(HostsLog.id.desc())
                    .first()
                    .date,
                    "events": [
                        _.event
                        for _ in session.query(HostsLog)
                        .filter(HostsLog.target == host.target)
                        .all()
                    ],
                },
            }
            for host in session.query(HostsLog)
            .group_by(HostsLog.target)
            .order_by(HostsLog.id.desc())
            .offset((page * 10) - 10)
            .limit(10)
        ]
        if not hosts:
            return structure(status="finished", msg="No more search results")
        return hosts


def get_logs_by_scan_id(scan_id):
    """
    select all events by scan id hash

    Args:
        scan_id: scan id hash

    Returns:
        an array with JSON events or an empty array
    """
    session = create_connection()

    if isinstance(session, tuple):
        connection, cursor = session
        try:
            cursor.execute(
                "SELECT scan_unique_id, target, module_name, date, port, event, json_event from scan_events WHERE scan_unique_id = ?",
                (scan_id,),  # We have to put this as an indexed element
            )
            rows = cursor.fetchall()
            return [
                {
                    "scan_id": row[0],
                    "target": row[1],
                    "module_name": row[2],
                    "date": str(row[3]),
                    "port": json.loads(row[4]),
                    "event": json.loads(row[5]),
                    "json_event": json.loads(row[6]) if row[6] else {},
                }
                for row in rows
            ]
        finally:
            try:
                cursor.close()
                connection.close()
            except Exception:
                pass
    else:
        return [
            {
                "scan_id": scan_id,
                "target": log.target,
                "module_name": log.module_name,
                "date": str(log.date),
                "port": json.loads(log.port),
                "event": json.loads(log.event),
                "json_event": log.json_event,
            }
            for log in session.query(HostsLog).filter(HostsLog.scan_unique_id == scan_id).all()
        ]


def get_options_by_scan_id(scan_id):
    """
    select all stored options of the scan by scan id hash
    Args:
        scan_id: scan id hash
    Returns:
        an array with a dict with stored options or an empty array
    """
    session = create_connection()
    if isinstance(session, tuple):
        connection, cursor = session

        try:
            cursor.execute(
                "SELECT options from reports WHERE scan_unique_id = ?",
                (scan_id,),
            )
            rows = cursor.fetchall()
            if rows:
                return [{"options": row[0]} for row in rows]
            return []
        finally:
            try:
                cursor.close()
                connection.close()
            except Exception:
                pass

    else:
        return [
            {"options": log.options}
            for log in session.query(Report).filter(Report.scan_unique_id == scan_id).all()
        ]


def logs_to_report_json(target):
    """
    select all reports of a host

    Args:
        host: the host to search

    Returns:
        an array with JSON events or an empty array
    """
    try:
        session = create_connection()
        if isinstance(session, tuple):
            connection, cursor = session
            return_logs = []
            try:
                cursor.execute(
                    "SELECT scan_unique_id, target, port, event, json_event FROM scan_events WHERE target = ?",
                    (target,),
                )
                rows = cursor.fetchall()
                if rows:
                    for log in rows:
                        data = {
                            "scan_id": log[0],
                            "target": log[1],
                            "port": json.loads(log[2]),
                            "event": json.loads(log[3]),
                            "json_event": json.loads(log[4]),
                        }
                        return_logs.append(data)
                return return_logs
            finally:
                try:
                    cursor.close()
                    connection.close()
                except Exception:
                    pass
        else:
            return_logs = []
            logs = session.query(HostsLog).filter(HostsLog.target == target)
            for log in logs:
                data = {
                    "scan_id": log.scan_unique_id,
                    "target": log.target,
                    "port": json.loads(log.port),
                    "event": json.loads(log.event),
                    "json_event": json.loads(log.json_event),
                }
                return_logs.append(data)
            return return_logs

    except Exception:
        return []


def logs_to_report_html(target):
    """
    generate HTML report with d3_tree_v2_graph for a host

    Args:
        target: the target

    Returns:
        HTML report
    """
    from nettacker.core.graph import build_graph
    from nettacker.lib.html_log import log_data

    session = create_connection()
    if isinstance(session, tuple):
        connection, cursor = session
        try:
            cursor.execute(
                """
                SELECT date, target, module_name, scan_unique_id, port, event, json_event
                FROM scan_events
                WHERE target = ?
                """,
                (target,),
            )

            rows = cursor.fetchall()
            logs = [
                {
                    "date": log[0],
                    "target": log[1],
                    "module_name": log[2],
                    "scan_id": log[3],
                    "port": log[4],
                    "event": log[5],
                    "json_event": log[6],
                }
                for log in rows
            ]
        finally:
            try:
                cursor.close()
                connection.close()
            except Exception:
                pass

        html_graph = build_graph("d3_tree_v2_graph", logs)

        html_content = log_data.table_title.format(
            html_graph,
            log_data.css_1,
            "date",
            "target",
            "module_name",
            "scan_id",
            "port",
            "event",
            "json_event",
        )
        for event in logs:
            html_content += log_data.table_items.format(
                event["date"],
                event["target"],
                event["module_name"],
                event["scan_id"],
                event["port"],
                event["event"],
                event["json_event"],
            )
        html_content += (
            log_data.table_end + '<p class="footer">' + messages("nettacker_report") + "</p>"
        )
        return html_content
    else:
        logs = [
            {
                "date": log.date,
                "target": log.target,
                "module_name": log.module_name,
                "scan_id": log.scan_unique_id,
                "port": log.port,
                "event": log.event,
                "json_event": log.json_event,
            }
            for log in session.query(HostsLog).filter(HostsLog.target == target).all()
        ]
        html_graph = build_graph("d3_tree_v2_graph", logs)

        html_content = log_data.table_title.format(
            html_graph,
            log_data.css_1,
            "date",
            "target",
            "module_name",
            "scan_id",
            "port",
            "event",
            "json_event",
        )
        for event in logs:
            html_content += log_data.table_items.format(
                event["date"],
                event["target"],
                event["module_name"],
                event["scan_id"],
                event["port"],
                event["event"],
                event["json_event"],
            )
        html_content += (
            log_data.table_end + '<p class="footer">' + messages("nettacker_report") + "</p>"
        )
        return html_content


def search_logs(page, query):
    """
    search in events (host, date, port, module, category, description,
    username, password, scan_id, scan_cmd)

    Args:
        page: page number
        query: query to search

    Returns:
        an array with JSON structure of founded events or an empty array
    """
    selected = []
    session = create_connection()
    if isinstance(session, tuple):
        connection, cursor = session
        try:
            # Fetch targets matching the query
            cursor.execute(
                """
                SELECT DISTINCT target FROM scan_events
                WHERE target LIKE ? OR date LIKE ? OR module_name LIKE ?
                OR port LIKE ? OR event LIKE ? OR scan_unique_id LIKE ?
                ORDER BY id DESC
                LIMIT 10 OFFSET ?
                """,
                (
                    f"%{query}%",
                    f"%{query}%",
                    f"%{query}%",
                    f"%{query}%",
                    f"%{query}%",
                    f"%{query}%",
                    (page * 10) - 10,
                ),
            )
            targets = cursor.fetchall()
            for target_row in targets:
                target = target_row[0]
                # Fetch data for each target grouped by key fields
                cursor.execute(
                    """
                    SELECT date, module_name, port, event, json_event FROM scan_events
                    WHERE target = ?
                    GROUP BY module_name, port, scan_unique_id, event
                    ORDER BY id DESC
                    """,
                    (target,),
                )
                results = cursor.fetchall()

                tmp = {
                    "target": target,
                    "info": {
                        "module_name": [],
                        "port": [],
                        "date": [],
                        "event": [],
                        "json_event": [],
                    },
                }

                for data in results:
                    date, module_name, port, event, json_event = data
                    if module_name not in tmp["info"]["module_name"]:
                        tmp["info"]["module_name"].append(module_name)
                    if date not in tmp["info"]["date"]:
                        tmp["info"]["date"].append(date)
                    parsed_port = json.loads(port)
                    if parsed_port not in tmp["info"]["port"]:
                        tmp["info"]["port"].append(parsed_port)
                    parsed_event = json.loads(event)
                    if parsed_event not in tmp["info"]["event"]:
                        tmp["info"]["event"].append(parsed_event)
                    parsed_json_event = json.loads(json_event)
                    if parsed_json_event not in tmp["info"]["json_event"]:
                        tmp["info"]["json_event"].append(parsed_json_event)

                selected.append(tmp)

        except Exception:
            return structure(status="error", msg="database error!")
        finally:
            try:
                cursor.close()
                connection.close()
            except Exception:
                pass
        if not selected:
            return structure(status="finished", msg="No more search results")
        return selected
    else:
        try:
            for host in (
                session.query(HostsLog)
                .filter(
                    (HostsLog.target.like("%" + str(query) + "%"))
                    | (HostsLog.date.like("%" + str(query) + "%"))
                    | (HostsLog.module_name.like("%" + str(query) + "%"))
                    | (HostsLog.port.like("%" + str(query) + "%"))
                    | (HostsLog.event.like("%" + str(query) + "%"))
                    | (HostsLog.scan_unique_id.like("%" + str(query) + "%"))
                )
                .group_by(HostsLog.target)
                .order_by(HostsLog.id.desc())
                .offset((page * 10) - 10)
                .limit(10)
            ):
                for data in (
                    session.query(HostsLog)
                    .filter(HostsLog.target == str(host.target))
                    .group_by(
                        HostsLog.module_name,
                        HostsLog.port,
                        HostsLog.scan_unique_id,
                        HostsLog.event,
                    )
                    .order_by(HostsLog.id.desc())
                    .all()
                ):
                    n = 0
                    capture = None
                    for selected_data in selected:
                        if selected_data["target"] == host.target:
                            capture = n
                        n += 1
                    if capture is None:
                        tmp = {
                            "target": data.target,
                            "info": {
                                "module_name": [],
                                "port": [],
                                "date": [],
                                "event": [],
                                "json_event": [],
                            },
                        }
                        selected.append(tmp)
                        n = 0
                        for selected_data in selected:
                            if selected_data["target"] == host.target:
                                capture = n
                            n += 1
                    if data.target == selected[capture]["target"]:
                        if data.module_name not in selected[capture]["info"]["module_name"]:
                            selected[capture]["info"]["module_name"].append(data.module_name)
                        if data.date not in selected[capture]["info"]["date"]:
                            selected[capture]["info"]["date"].append(data.date)
                        if data.port not in selected[capture]["info"]["port"]:
                            selected[capture]["info"]["port"].append(json.loads(data.port))
                        if data.event not in selected[capture]["info"]["event"]:
                            selected[capture]["info"]["event"].append(json.loads(data.event))
                        if data.json_event not in selected[capture]["info"]["json_event"]:
                            selected[capture]["info"]["json_event"].append(
                                json.loads(data.json_event)
                            )
        except Exception:
            return structure(status="error", msg="database error!")
        if len(selected) == 0:
            return structure(status="finished", msg="No more search results")
        return selected
