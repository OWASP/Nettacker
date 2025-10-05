"""
Enhanced queue and dependency management system for Nettacker.
This module provides solutions for:
1. CPU-efficient dependency resolution using event-driven approach
2. Cross-subprocess thread sharing for better resource utilization
"""

import json
import multiprocessing
import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any

from nettacker.database.db import find_temp_events
from nettacker.logger import get_logger

log = get_logger()


@dataclass
class DependentTask:
    """Represents a task waiting for dependencies."""

    target: str
    module_name: str
    scan_id: str
    event_names: List[str]
    sub_step: Dict[str, Any]
    engine: Any
    run_args: tuple
    created_at: datetime
    max_wait_time: float = 30.0  # Maximum wait time in seconds


class DependencyResolver:
    """
    Event-driven dependency resolver that avoids busy-waiting.
    Instead of polling, tasks are queued and executed when dependencies become available.
    """

    def __init__(self):
        self._pending_tasks: Dict[str, List[DependentTask]] = {}
        self._dependency_cache: Dict[str, Any] = {}
        self._lock = threading.RLock()

    def _get_dependency_key(
        self, target: str, module_name: str, scan_id: str, event_name: str
    ) -> str:
        """Generate a unique key for dependency tracking."""
        return f"{target}:{module_name}:{scan_id}:{event_name}"

    def notify_dependency_available(
        self, target: str, module_name: str, scan_id: str, event_name: str, result: Any
    ):
        """
        Notify that a dependency is now available.
        This should be called when temp events are saved to the database.
        """
        dependency_key = self._get_dependency_key(target, module_name, scan_id, event_name)

        with self._lock:
            # Cache the result
            self._cache_dependency_result(dependency_key, result)

            # Check for pending tasks that can now be executed
            self._process_pending_tasks(dependency_key)

    def _cache_dependency_result(self, dependency_key: str, result: Any):
        """Cache dependency result for future use."""
        self._dependency_cache[dependency_key] = {"result": result, "timestamp": datetime.now()}

    def _process_pending_tasks(self, dependency_key: str):
        """Process tasks that were waiting for the given dependency."""
        if dependency_key not in self._pending_tasks:
            return

        ready_tasks = []
        remaining_tasks = []

        for task in self._pending_tasks[dependency_key]:
            if self._all_dependencies_available(task):
                ready_tasks.append(task)
            else:
                # Check if task has expired
                elapsed = (datetime.now() - task.created_at).total_seconds()
                if elapsed < task.max_wait_time:
                    remaining_tasks.append(task)
                else:
                    log.warn(
                        f"Task expired waiting for dependencies: {task.target} -> {task.module_name}"
                    )

        # Update pending tasks list
        if remaining_tasks:
            self._pending_tasks[dependency_key] = remaining_tasks
        else:
            del self._pending_tasks[dependency_key]

        # Execute ready tasks
        for task in ready_tasks:
            self._execute_task(task)

    def _all_dependencies_available(self, task: DependentTask) -> bool:
        """Check if all dependencies for a task are available."""
        for event_name in task.event_names:
            dependency_key = self._get_dependency_key(
                task.target, task.module_name, task.scan_id, event_name
            )
            if dependency_key not in self._dependency_cache:
                return False
        return True

    def _execute_task(self, task: DependentTask):
        """Execute a task that has all its dependencies available."""
        try:
            # Get dependency results
            dependency_results = []
            for event_name in task.event_names:
                dependency_key = self._get_dependency_key(
                    task.target, task.module_name, task.scan_id, event_name
                )
                dependency_results.append(self._dependency_cache[dependency_key]["result"])

            # Replace dependent values in sub_step
            updated_sub_step = task.engine.replace_dependent_values(
                task.sub_step, dependency_results
            )

            # Execute the task
            task.engine.run(updated_sub_step, *task.run_args[1:])

        except Exception as e:
            log.error(f"Error executing dependent task: {e}")

    def get_dependency_results_efficiently(
        self,
        target: str,
        module_name: str,
        scan_id: str,
        event_names: str,
        sub_step: Dict,
        engine: Any,
        run_args: tuple,
    ) -> Optional[List[Any]]:
        """
        Efficiently get dependency results without busy-waiting.
        Returns results immediately if available, otherwise queues the task.
        """
        event_name_list = event_names.split(",")

        # Check if all dependencies are already available
        all_available = True
        results = []

        with self._lock:
            for event_name in event_name_list:
                dependency_key = self._get_dependency_key(target, module_name, scan_id, event_name)

                if dependency_key in self._dependency_cache:
                    results.append(self._dependency_cache[dependency_key]["result"])
                else:
                    # Try to get from database once
                    event = find_temp_events(target, module_name, scan_id, event_name)
                    if event:
                        result = json.loads(event.event)["response"]["conditions_results"]
                        self._cache_dependency_result(dependency_key, result)
                        results.append(result)
                    else:
                        all_available = False
                        break

            if all_available:
                return results

            # Dependencies not available - queue the task
            task = DependentTask(
                target=target,
                module_name=module_name,
                scan_id=scan_id,
                event_names=event_name_list,
                sub_step=sub_step,
                engine=engine,
                run_args=run_args,
                created_at=datetime.now(),
            )

            # Add to pending tasks for each missing dependency
            for event_name in event_name_list:
                dependency_key = self._get_dependency_key(target, module_name, scan_id, event_name)
                if dependency_key not in self._dependency_cache:
                    if dependency_key not in self._pending_tasks:
                        self._pending_tasks[dependency_key] = []
                    self._pending_tasks[dependency_key].append(task)

            return None  # Task queued, will be executed later


class CrossProcessThreadPool:
    """
    Manages a shared thread pool across multiple processes.
    Allows processes to share work when they have idle threads.
    """

    def __init__(self, max_workers_per_process: Optional[int] = None):
        self.max_workers_per_process = max_workers_per_process or multiprocessing.cpu_count()
        self.task_queue = multiprocessing.Queue()
        self.workers = []
        self.is_running = multiprocessing.Value("i", 1)

    def start_workers(self, num_processes: int):
        """Start worker processes."""
        for i in range(num_processes):
            worker = multiprocessing.Process(
                target=self._worker_process,
                args=(i, self.task_queue, self.is_running),
            )
            worker.start()
            self.workers.append(worker)

    def submit_task(self, task_func, *args, **kwargs):
        """Submit a task to the shared pool."""
        task = {"func": task_func, "args": args, "kwargs": kwargs, "timestamp": time.time()}
        self.task_queue.put(task)

    def _worker_process(
        self,
        worker_id: int,
        task_queue: multiprocessing.Queue,
        is_running: multiprocessing.Value,
    ):
        """Worker process that executes tasks from the shared queue."""
        local_threads = []
        max_local_threads = self.max_workers_per_process

        log.info(f"Worker process {worker_id} started with {max_local_threads} threads")

        while is_running.value:
            try:
                # Clean up finished threads
                local_threads = [t for t in local_threads if t.is_alive()]

                # If we have capacity, get a new task
                if len(local_threads) < max_local_threads:
                    try:
                        task = task_queue.get(timeout=1.0)

                        # Create thread to execute task
                        thread = threading.Thread(
                            target=self._execute_task, args=(task, worker_id)
                        )
                        thread.start()
                        local_threads.append(thread)

                    except queue.Empty:
                        continue
                else:
                    # Wait a bit if at capacity
                    time.sleep(0.1)

            except Exception as e:
                log.exception(f"Worker process {worker_id} error: {e}")

        # Wait for remaining threads to finish
        for thread in local_threads:
            thread.join(timeout=5.0)

        log.info(f"Worker process {worker_id} finished")

    def _execute_task(self, task: Dict, worker_id: int):
        """Execute a single task."""
        try:
            func = task["func"]
            args = task["args"]
            kwargs = task["kwargs"]

            # Execute the task - engine.run() handles its own results/logging
            func(*args, **kwargs)

            log.debug(f"Worker {worker_id} completed task successfully")

        except Exception as e:
            log.exception(f"Worker {worker_id} task execution failed: {e}")

    def shutdown(self):
        """Shutdown the thread pool."""
        self.is_running.value = 0

        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=10.0)
            if worker.is_alive():
                worker.terminate()

        log.info("Thread pool shutdown complete")


# Global instances
dependency_resolver = DependencyResolver()
thread_pool = None


def initialize_thread_pool(num_processes: int, max_workers_per_process: int = None):
    """Initialize the global thread pool."""
    global thread_pool
    thread_pool = CrossProcessThreadPool(max_workers_per_process)
    thread_pool.start_workers(num_processes)
    return thread_pool


def shutdown_thread_pool():
    """Shutdown the global thread pool."""
    global thread_pool
    if thread_pool:
        thread_pool.shutdown()
        thread_pool = None
