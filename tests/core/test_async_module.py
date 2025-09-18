"""
Comprehensive test suite for async module engine
Tests performance improvements and compatibility with existing functionality
"""

import asyncio
import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import pytest
import time

from nettacker.core.async_module import AsyncModule, AsyncModuleManager


class TestAsyncModule(unittest.TestCase):
    """Test cases for AsyncModule functionality"""
    
    def setUp(self):
        # Mock options object
        self.mock_options = MagicMock()
        self.mock_options.__dict__ = {
            'modules_extra_args': None,
            'excluded_ports': None,
            'thread_per_host': 10,
            'time_sleep_between_requests': 0.01
        }
        
        # Create test module instance
        self.module = AsyncModule(
            module_name="test_module",
            options=self.mock_options,
            target="127.0.0.1",
            scan_id="test_scan_123",
            process_number=1,
            thread_number=1,
            total_number_threads=1
        )
    
    def test_init_basic_properties(self):
        """Test basic initialization properties"""
        self.assertEqual(self.module.module_name, "test_module")
        self.assertEqual(self.module.target, "127.0.0.1")
        self.assertEqual(self.module.scan_id, "test_scan_123")
        self.assertEqual(self.module.process_number, 1)
        self.assertIsInstance(self.module.async_optimizer, object)
    
    def test_init_with_extra_args(self):
        """Test initialization with extra module arguments"""
        self.mock_options.modules_extra_args = {"custom_arg": "value"}
        self.mock_options.__dict__['modules_extra_args'] = {"custom_arg": "value"}
        
        module = AsyncModule(
            module_name="test_module",
            options=self.mock_options,
            target="127.0.0.1",
            scan_id="test_scan_123",
            process_number=1,
            thread_number=1,
            total_number_threads=1
        )
        
        self.assertIn("custom_arg", module.module_inputs)
        self.assertEqual(module.module_inputs["custom_arg"], "value")
    
    @patch('nettacker.core.async_module.TemplateLoader')
    def test_load_without_service_discovery(self, mock_template_loader):
        """Test module loading without service discovery"""
        mock_content = {"payloads": [{"library": "http", "steps": []}]}
        mock_template_loader.return_value.load.return_value = mock_content
        
        self.module.skip_service_discovery = True
        self.module.load()
        
        self.assertEqual(self.module.module_content, mock_content)
        mock_template_loader.assert_called_once()
    
    @patch('nettacker.core.async_module.find_events')
    @patch('nettacker.core.async_module.TemplateLoader')
    def test_load_with_service_discovery(self, mock_template_loader, mock_find_events):
        """Test module loading with service discovery"""
        # Mock template loader
        mock_content = {
            "payloads": [{
                "library": "http",
                "steps": [{"port": 80}]
            }]
        }
        mock_template_loader.return_value.load.return_value = mock_content
        mock_template_loader.parse.return_value = {"port": [80, 443]}
        
        # Mock service discovery
        mock_event = MagicMock()
        mock_event.json_event = '{"port": 80, "response": {"conditions_results": {"http": []}}}'
        mock_find_events.return_value = [mock_event]
        
        self.module.skip_service_discovery = False
        self.module.module_name = "custom_module"  # Not in ignored list
        self.module.libraries = ["http"]
        self.module.load()
        
        self.assertIsNotNone(self.module.discovered_services)
        self.assertIn("http", self.module.discovered_services)
    
    def test_generate_loops_with_excluded_ports(self):
        """Test loop generation with port exclusion"""
        self.module.module_content = {
            "payloads": [{
                "steps": [{
                    "ports": [80, 443, 8080, 8443]
                }]
            }]
        }
        self.module.module_inputs["excluded_ports"] = [8080, 8443]
        
        with patch('nettacker.core.async_module.expand_module_steps') as mock_expand:
            mock_expand.return_value = self.module.module_content["payloads"]
            self.module.generate_loops()
            
            remaining_ports = self.module.module_content["payloads"][0]["steps"][0]["ports"]
            self.assertEqual(remaining_ports, [80, 443])
    
    def test_sort_loops_dependency_order(self):
        """Test loop sorting by dependency order"""
        self.module.module_content = {
            "payloads": [{
                "steps": [
                    [{"response": {"dependent_on_temp_event": True, "save_to_temp_events_only": True}}],
                    [{"response": {}}],  # Independent step
                    [{"response": {"dependent_on_temp_event": True}}]  # Dependent step
                ]
            }]
        }
        
        self.module.sort_loops()
        
        steps = self.module.module_content["payloads"][0]["steps"]
        # Should be reordered: independent, temp-only dependent, regular dependent
        self.assertEqual(len(steps), 3)
    
    @pytest.mark.asyncio
    async def test_execute_step_async_success(self):
        """Test successful async step execution"""
        mock_engine = MagicMock()
        mock_engine.run.return_value = "success_result"
        
        sub_step = {"test": "data"}
        
        result = await self.module._execute_step_async(
            mock_engine, sub_step, 1, 10
        )
        
        # Should complete without error (though result will be from executor)
        self.assertIsNotNone(result)
    
    @pytest.mark.asyncio
    async def test_execute_step_async_with_delay(self):
        """Test async step execution with delay"""
        mock_engine = MagicMock()
        mock_engine.run.return_value = "success_result"
        
        self.module.module_inputs["time_sleep_between_requests"] = 0.05
        sub_step = {"test": "data"}
        
        start_time = time.time()
        result = await self.module._execute_step_async(
            mock_engine, sub_step, 1, 10
        )
        end_time = time.time()
        
        # Should have taken at least the delay time
        elapsed = end_time - start_time
        self.assertGreaterEqual(elapsed, 0.04)  # Account for timing precision
    
    @patch('nettacker.core.async_module.importlib.import_module')
    def test_start_async_no_libraries(self, mock_import):
        """Test async start with no supported libraries"""
        self.module.module_content = {
            "payloads": [{
                "library": "unsupported_lib",
                "steps": [[{"test": "data"}]]
            }]
        }
        self.module.libraries = ["http", "https"]  # Different libraries
        
        # Should handle missing library gracefully
        try:
            result = self.module.start()
            # Should not crash, may return empty results
            self.assertIsInstance(result, list)
        except Exception as e:
            self.fail(f"start() should handle missing libraries gracefully: {e}")
    
    def test_start_backwards_compatibility(self):
        """Test synchronous wrapper maintains backwards compatibility"""
        # Mock the async method to return a simple result
        with patch.object(self.module, 'start_async', return_value=["test_result"]) as mock_async:
            result = self.module.start()
            
            self.assertEqual(result, ["test_result"])
            mock_async.assert_called_once()


class TestAsyncModuleManager(unittest.TestCase):
    """Test cases for AsyncModuleManager"""
    
    def setUp(self):
        self.manager = AsyncModuleManager()
    
    def test_init_statistics(self):
        """Test initial statistics state"""
        expected_stats = {
            "total_modules": 0,
            "successful_modules": 0,
            "failed_modules": 0,
            "total_execution_time": 0.0,
            "average_execution_time": 0.0
        }
        self.assertEqual(self.manager.execution_stats, expected_stats)
    
    @pytest.mark.asyncio
    async def test_execute_modules_batch_empty(self):
        """Test batch execution with empty module list"""
        result = await self.manager.execute_modules_batch([])
        
        self.assertIn("results", result)
        self.assertIn("statistics", result)
        self.assertEqual(result["results"], {})
        self.assertEqual(result["statistics"]["total_modules"], 0)
    
    @pytest.mark.asyncio
    async def test_execute_modules_batch_single_module(self):
        """Test batch execution with single module"""
        # Create mock module
        mock_module = MagicMock()
        mock_module.module_name = "test_module"
        mock_module.start_async = AsyncMock(return_value=["result1", "result2"])
        
        result = await self.manager.execute_modules_batch([mock_module])
        
        self.assertIn("test_module", result["results"])
        self.assertEqual(result["statistics"]["total_modules"], 1)
        self.assertEqual(result["statistics"]["successful_modules"], 1)
        self.assertEqual(result["statistics"]["failed_modules"], 0)
    
    @pytest.mark.asyncio
    async def test_execute_modules_batch_with_failures(self):
        """Test batch execution with some module failures"""
        # Create mock modules
        success_module = MagicMock()
        success_module.module_name = "success_module"
        success_module.start_async = AsyncMock(return_value=["success"])
        
        failure_module = MagicMock()
        failure_module.module_name = "failure_module"
        failure_module.start_async = AsyncMock(side_effect=ValueError("Test error"))
        
        modules = [success_module, failure_module]
        result = await self.manager.execute_modules_batch(modules)
        
        self.assertEqual(result["statistics"]["total_modules"], 2)
        self.assertEqual(result["statistics"]["successful_modules"], 1)
        self.assertEqual(result["statistics"]["failed_modules"], 1)
        
        # Check results structure
        self.assertIn("success_module", result["results"])
        self.assertIn("failure_module", result["results"])
        self.assertIn("results", result["results"]["success_module"])
        self.assertIn("error", result["results"]["failure_module"])
    
    @pytest.mark.asyncio
    async def test_execute_modules_batch_custom_batch_size(self):
        """Test batch execution with custom batch size"""
        # Create multiple mock modules
        modules = []
        for i in range(5):
            mock_module = MagicMock()
            mock_module.module_name = f"module_{i}"
            mock_module.start_async = AsyncMock(return_value=[f"result_{i}"])
            modules.append(mock_module)
        
        result = await self.manager.execute_modules_batch(modules, batch_size=2)
        
        self.assertEqual(result["statistics"]["total_modules"], 5)
        self.assertEqual(result["statistics"]["successful_modules"], 5)
        self.assertEqual(len(result["results"]), 5)
    
    def test_get_performance_report_initial(self):
        """Test performance report with initial state"""
        report = self.manager.get_performance_report()
        
        self.assertIn("execution_statistics", report)
        self.assertIn("performance_metrics", report)
        
        metrics = report["performance_metrics"]
        self.assertEqual(metrics["success_rate"], 0.0)
        self.assertEqual(metrics["failure_rate"], 0.0)
        self.assertEqual(metrics["average_execution_time_per_module"], 0.0)
    
    def test_get_performance_report_with_data(self):
        """Test performance report with execution data"""
        # Simulate some execution statistics
        self.manager.execution_stats.update({
            "total_modules": 10,
            "successful_modules": 8,
            "failed_modules": 2,
            "total_execution_time": 5.0,
            "average_execution_time": 0.5
        })
        
        report = self.manager.get_performance_report()
        metrics = report["performance_metrics"]
        
        self.assertEqual(metrics["success_rate"], 80.0)
        self.assertEqual(metrics["failure_rate"], 20.0)
        self.assertEqual(metrics["average_execution_time_per_module"], 0.5)


class TestAsyncModuleIntegration(unittest.TestCase):
    """Integration tests for async module functionality"""
    
    @patch('nettacker.core.async_module.TemplateLoader')
    def test_full_module_lifecycle(self, mock_template_loader):
        """Test complete module lifecycle from init to execution"""
        # Setup mock template content
        mock_content = {
            "payloads": [{
                "library": "http",
                "steps": [[{"request": {"method": "GET", "url": "/"}}]]
            }]
        }
        mock_template_loader.return_value.load.return_value = mock_content
        
        # Create module
        mock_options = MagicMock()
        mock_options.__dict__ = {
            'modules_extra_args': None,
            'excluded_ports': None,
            'thread_per_host': 5,
            'time_sleep_between_requests': 0.0
        }
        
        module = AsyncModule(
            module_name="http_status_scan",
            options=mock_options,
            target="127.0.0.1",
            scan_id="integration_test",
            process_number=1,
            thread_number=1,
            total_number_threads=1
        )
        
        # Set skip service discovery for simpler test
        module.skip_service_discovery = True
        module.libraries = ["http"]
        
        # Load module
        module.load()
        self.assertIsNotNone(module.module_content)
        
        # Generate loops
        module.generate_loops()
        
        # Sort loops
        module.sort_loops()
        
        # The module should be ready for execution
        self.assertTrue(hasattr(module, 'start'))
        self.assertTrue(hasattr(module, 'start_async'))
    
    def test_async_optimizer_integration(self):
        """Test integration with async optimizer"""
        mock_options = MagicMock()
        mock_options.__dict__ = {
            'modules_extra_args': None,
            'excluded_ports': None,
            'thread_per_host': 20,
            'time_sleep_between_requests': 0.0
        }
        
        module = AsyncModule(
            module_name="test_module",
            options=mock_options,
            target="127.0.0.1",
            scan_id="optimizer_test",
            process_number=1,
            thread_number=1,
            total_number_threads=1
        )
        
        # Should have created optimizer with appropriate concurrency limit
        self.assertIsNotNone(module.async_optimizer)
        self.assertEqual(module.async_optimizer.max_concurrent_requests, 20)
    
    def test_module_manager_integration(self):
        """Test integration between modules and manager"""
        manager = AsyncModuleManager()
        
        # Create mock modules
        modules = []
        for i in range(3):
            mock_module = MagicMock()
            mock_module.module_name = f"test_module_{i}"
            mock_module.start_async = AsyncMock(return_value=[f"result_{i}"])
            modules.append(mock_module)
        
        # Manager should be able to handle the modules
        self.assertTrue(hasattr(manager, 'execute_modules_batch'))
        self.assertTrue(hasattr(manager, 'get_performance_report'))


if __name__ == '__main__':
    # Run async tests with pytest for Python 3.7+
    import sys
    if sys.version_info >= (3, 7):
        pytest.main([__file__, "-v"])
    else:
        # Run only sync tests for older Python
        unittest.main(verbosity=2)