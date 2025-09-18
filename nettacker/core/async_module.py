"""
Enhanced Async Module Engine for OWASP Nettacker
Provides async/await based execution for improved performance and resource utilization
"""

import asyncio
import copy
import importlib
import json
import time
from typing import Dict, List, Any, Optional

from nettacker import logger
from nettacker.config import Config
from nettacker.core.messages import messages as _
from nettacker.core.template import TemplateLoader
from nettacker.core.utils.common import expand_module_steps
from nettacker.core.utils.cross_platform import AsyncNetworkOptimizer
from nettacker.database.db import find_events

log = logger.get_logger()


class AsyncModule:
    """
    Enhanced async module execution engine
    Replaces threading with async/await for better performance and resource management
    """
    
    def __init__(
        self,
        module_name: str,
        options: Any,
        target: str,
        scan_id: str,
        process_number: int,
        thread_number: int,
        total_number_threads: int,
    ):
        self.module_name = module_name
        self.process_number = process_number
        self.module_thread_number = thread_number
        self.total_module_thread_number = total_number_threads
        
        self.module_inputs = options.__dict__
        self.module_inputs["target"] = target
        
        if options.modules_extra_args:
            for module_extra_args in self.module_inputs["modules_extra_args"]:
                self.module_inputs[module_extra_args] = self.module_inputs["modules_extra_args"][
                    module_extra_args
                ]
        
        self.target = target
        self.scan_id = scan_id
        self.skip_service_discovery = options.skip_service_discovery
        
        self.discovered_services = None
        self.ignored_core_modules = [
            "subdomain_scan",
            "icmp_scan", 
            "port_scan",
            "ssl_weak_version_vuln",
            "ssl_weak_cipher_vuln",
            "ssl_certificate_weak_signature_vuln",
            "ssl_self_signed_certificate_vuln",
            "ssl_expired_certificate_vuln",
            "ssl_expiring_certificate_scan",
        ]
        
        # Initialize async optimizer
        max_concurrent = min(self.module_inputs.get("thread_per_host", 100), 200)
        self.async_optimizer = AsyncNetworkOptimizer(max_concurrent_requests=max_concurrent)
        
        # Load service discovery signatures
        contents = TemplateLoader("port_scan", {"target": ""}).load()
        self.service_discovery_signatures = list(
            set(
                contents["payloads"][0]["steps"][0]["response"]["conditions"]
                .get("service", set(contents["payloads"][0]["steps"][0]["response"]["conditions"]))
                .keys()
            )
        )
        
        # Discover available libraries
        import os
        self.libraries = [
            module_protocol.split(".py")[0]
            for module_protocol in os.listdir(Config.path.module_protocols_dir)
            if module_protocol.endswith(".py")
            and module_protocol not in {"__init__.py", "base.py"}
        ]
    
    def load(self):
        """Load module content and perform service discovery"""
        self.module_content = TemplateLoader(self.module_name, self.module_inputs).load()
        
        if not self.skip_service_discovery and self.module_name not in self.ignored_core_modules:
            services = {}
            for service in find_events(self.target, "port_scan", self.scan_id):
                service_event = json.loads(service.json_event)
                port = service_event["port"]
                protocols = service_event["response"]["conditions_results"].keys()
                
                for protocol in protocols:
                    if protocol and protocol in self.libraries:
                        if protocol in services:
                            services[protocol].append(port)
                        else:
                            services[protocol] = [port]
            
            self.discovered_services = copy.deepcopy(services)
            
            # Filter payloads based on discovered services
            index_payload = 0
            for payload in copy.deepcopy(self.module_content["payloads"]):
                if (
                    payload["library"] not in self.discovered_services
                    and payload["library"] in self.service_discovery_signatures
                ):
                    del self.module_content["payloads"][index_payload]
                    index_payload -= 1
                else:
                    # Update steps with discovered ports
                    index_step = 0
                    for step in copy.deepcopy(
                        self.module_content["payloads"][index_payload]["steps"]
                    ):
                        step = TemplateLoader.parse(
                            step, {"port": self.discovered_services[payload["library"]]}
                        )
                        self.module_content["payloads"][index_payload]["steps"][index_step] = step
                        index_step += 1
                index_payload += 1
    
    def generate_loops(self):
        """Generate execution loops with port exclusion logic"""
        if self.module_inputs["excluded_ports"]:
            excluded_port_set = set(self.module_inputs["excluded_ports"])
            if self.module_content and "ports" in self.module_content["payloads"][0]["steps"][0]:
                all_ports = self.module_content["payloads"][0]["steps"][0]["ports"]
                all_ports[:] = [port for port in all_ports if port not in excluded_port_set]
        
        self.module_content["payloads"] = expand_module_steps(self.module_content["payloads"])
    
    def sort_loops(self):
        """Sort execution loops by dependency order"""
        steps = []
        for index in range(len(self.module_content["payloads"])):
            # First: Independent steps
            for step in copy.deepcopy(self.module_content["payloads"][index]["steps"]):
                if "dependent_on_temp_event" not in step[0]["response"]:
                    steps.append(step)
            
            # Second: Dependent steps that save only to temp events
            for step in copy.deepcopy(self.module_content["payloads"][index]["steps"]):
                if (
                    "dependent_on_temp_event" in step[0]["response"]
                    and "save_to_temp_events_only" in step[0]["response"]
                ):
                    steps.append(step)
            
            # Third: Dependent steps that save to permanent events
            for step in copy.deepcopy(self.module_content["payloads"][index]["steps"]):
                if (
                    "dependent_on_temp_event" in step[0]["response"]
                    and "save_to_temp_events_only" not in step[0]["response"]
                ):
                    steps.append(step)
            
            self.module_content["payloads"][index]["steps"] = steps
    
    async def _execute_step_async(
        self,
        engine: Any,
        sub_step: Dict,
        request_number: int,
        total_requests: int
    ) -> Optional[Any]:
        """
        Execute a single step asynchronously
        
        Args:
            engine: Protocol engine instance
            sub_step: Step configuration
            request_number: Current request number
            total_requests: Total number of requests
            
        Returns:
            Result of step execution
        """
        try:
            # Log the request
            log.verbose_event_info(
                _("sending_module_request").format(
                    self.process_number,
                    self.module_name,
                    self.target,
                    self.module_thread_number,
                    self.total_module_thread_number,
                    request_number,
                    total_requests,
                )
            )
            
            # Add delay between requests with jitter to prevent overwhelming targets
            if self.module_inputs["time_sleep_between_requests"] > 0:
                await self.async_optimizer.async_sleep_with_jitter(
                    self.module_inputs["time_sleep_between_requests"]
                )
            
            # Execute the step (would need async-compatible engine)
            # For now, we wrap the sync call in executor
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                engine.run,
                sub_step,
                self.module_name,
                self.target,
                self.scan_id,
                self.module_inputs,
                self.process_number,
                self.module_thread_number,
                self.total_module_thread_number,
                request_number,
                total_requests,
            )
            
            return result
            
        except Exception as e:
            log.error(f"Error executing step {request_number}: {e}")
            return None
    
    async def start_async(self) -> List[Any]:
        """
        Start async module execution
        
        Returns:
            List of execution results
        """
        # Count total requests
        total_number_of_requests = 0
        for payload in self.module_content["payloads"]:
            if payload["library"] not in self.libraries:
                log.warn(_("library_not_supported").format(payload["library"]))
                return []
            for step in payload["steps"]:
                total_number_of_requests += len(step)
        
        # Prepare coroutines for execution
        coroutines = []
        request_number_counter = 0
        
        for payload in self.module_content["payloads"]:
            library = payload["library"]
            
            try:
                engine = getattr(
                    importlib.import_module(f"nettacker.core.lib.{library.lower()}"),
                    f"{library.capitalize()}Engine",
                )()
            except (ImportError, AttributeError) as e:
                log.error(f"Failed to load engine for {library}: {e}")
                continue
            
            for step in payload["steps"]:
                for sub_step in step:
                    coro = self.async_optimizer.execute_with_semaphore(
                        self._execute_step_async(
                            engine,
                            sub_step,
                            request_number_counter,
                            total_number_of_requests
                        )
                    )
                    coroutines.append(coro)
                    request_number_counter += 1
        
        # Execute coroutines in optimized batches
        results = await self.async_optimizer.batch_execute(coroutines)
        
        # Filter out None results (errors)
        successful_results = [r for r in results if r is not None and not isinstance(r, Exception)]
        
        log.info(f"Completed {len(successful_results)}/{len(coroutines)} requests successfully")
        return successful_results
    
    def start(self) -> List[Any]:
        """
        Synchronous wrapper for async execution (backwards compatibility)
        
        Returns:
            List of execution results
        """
        try:
            # Try to use existing event loop
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If loop is already running, create a task
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, self.start_async())
                    return future.result()
            else:
                return loop.run_until_complete(self.start_async())
        except RuntimeError:
            # No event loop, create new one
            return asyncio.run(self.start_async())


class AsyncModuleManager:
    """
    Manager for async module execution with advanced performance monitoring
    """
    
    def __init__(self):
        self.execution_stats = {
            "total_modules": 0,
            "successful_modules": 0,
            "failed_modules": 0,
            "total_execution_time": 0.0,
            "average_execution_time": 0.0
        }
    
    async def execute_modules_batch(
        self,
        modules: List[AsyncModule],
        batch_size: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute multiple modules in optimized batches
        
        Args:
            modules: List of AsyncModule instances
            batch_size: Size of execution batches
            
        Returns:
            Dict containing execution results and statistics
        """
        start_time = time.time()
        
        if batch_size is None:
            batch_size = min(len(modules), 10)  # Default batch size
        
        results = {}
        successful_count = 0
        failed_count = 0
        
        for i in range(0, len(modules), batch_size):
            batch = modules[i:i + batch_size]
            batch_coroutines = []
            
            for module in batch:
                batch_coroutines.append(module.start_async())
            
            batch_results = await asyncio.gather(*batch_coroutines, return_exceptions=True)
            
            for j, result in enumerate(batch_results):
                module_name = batch[j].module_name
                if isinstance(result, Exception):
                    results[module_name] = {"error": str(result)}
                    failed_count += 1
                else:
                    results[module_name] = {"results": result}
                    successful_count += 1
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Update statistics
        self.execution_stats.update({
            "total_modules": len(modules),
            "successful_modules": successful_count,
            "failed_modules": failed_count,
            "total_execution_time": execution_time,
            "average_execution_time": execution_time / len(modules) if modules else 0.0
        })
        
        return {
            "results": results,
            "statistics": self.execution_stats.copy()
        }
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Get detailed performance report
        
        Returns:
            Dict containing performance metrics
        """
        return {
            "execution_statistics": self.execution_stats,
            "performance_metrics": {
                "success_rate": (
                    self.execution_stats["successful_modules"] / 
                    max(self.execution_stats["total_modules"], 1) * 100
                ),
                "failure_rate": (
                    self.execution_stats["failed_modules"] / 
                    max(self.execution_stats["total_modules"], 1) * 100
                ),
                "average_execution_time_per_module": self.execution_stats["average_execution_time"]
            }
        }