import multiprocessing as mp
import os
import sys

from PyQt6.QtWidgets import QApplication

from netwatch_config import build_config
from netwatch_core import acquire_single_instance_mutex
from netwatch_log import setup_logging

if __name__ == '__main__':
    mp.freeze_support()

    BASE_DIR = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))

    # Config is data, not source: DEFAULTS <- netwatch.config.json <-
    # netwatch.<hostname>.json <- $NETWATCH_CONFIG. See netwatch_config.py.
    RESOURCE_DIR = getattr(sys, "_MEIPASS", BASE_DIR)
    CONFIG, config_notes = build_config(BASE_DIR, resource_dir=RESOURCE_DIR)
    boot_log = setup_logging("boot", CONFIG)
    for note in config_notes:
        (boot_log.warning if note.startswith("WARNING") else boot_log.info)("%s", note)

    instance_mutex = acquire_single_instance_mutex("Global\\NetWatch.SingleInstance")
    if instance_mutex is None:
        boot_log.info("NetWatch is already running; duplicate launch ignored")
        sys.exit(0)

    from netwatch_runtime import MonitoringRuntime
    from netwatch_service import service_lock
    from netwatch_ui import OperationsDashboard

    ledger_path = CONFIG["INCIDENT_DB"]
    with service_lock(ledger_path + ".service.lock"):
        runtime = MonitoringRuntime(CONFIG)
        try:
            runtime.start()
            q = runtime.queues
            app = QApplication(sys.argv)
            def shutdown_monitoring():
                runtime.stop()
                return runtime.shutdown_report
            window = OperationsDashboard(q["render"], q["alert"], q["db_status"], q["worker_status"],
                                         policy_queue=q["policy"], config=CONFIG,
                                         shutdown_event=runtime.shutdown_event, workers=tuple(runtime.workers),
                                         shutdown_callback=shutdown_monitoring)
            window.show()
            exit_code = app.exec()
        finally:
            runtime.stop()
    sys.exit(exit_code)
