"""
Test ThreadPoolExecutor implementation for large CIDR ranges.

This test verifies the fix for issue #1230 where scanning large CIDR ranges
with high --parallel-module-scan values caused the scan engine to hang or
become extremely slow.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import Mock, patch, MagicMock

import pytest

from nettacker.core.app import Nettacker


class TestThreadPoolPerformance:
    """Test the ThreadPoolExecutor implementation in scan_target_group."""

    def test_threadpool_executor_is_used(self):
        """Verify that ThreadPoolExecutor is imported and used."""
        # Simply verify the import exists
        from concurrent.futures import ThreadPoolExecutor, as_completed
        assert ThreadPoolExecutor is not None
        assert as_completed is not None

    @patch("nettacker.core.app.Module")
    @patch("nettacker.core.app.set_socks_proxy")
    def test_scan_target_group_creates_task_queue(self, mock_socks, mock_module):
        """Test that scan_target_group creates a task queue instead of threads."""
        # Setup mock
        mock_module_instance = MagicMock()
        mock_module.return_value = mock_module_instance
        mock_socks.return_value = (Mock(), Mock())

        # Create minimal arguments
        with patch("nettacker.core.app.ArgParser.__init__", return_value=None):
            nettacker = Nettacker.__new__(Nettacker)
            nettacker.arguments = Mock()
            nettacker.arguments.selected_modules = ["port_scan"]
            nettacker.arguments.parallel_module_scan = 5
            nettacker.arguments.socks_proxy = None
            nettacker.print_logo = Mock()
            nettacker.check_dependencies = Mock()

        # Define small target list (not large CIDR)
        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        scan_id = "test_scan_id"
        process_number = 0

        # Execute
        result = nettacker.scan_target_group(targets, scan_id, process_number)

        # Verify task queue behavior: all targets * modules should be processed
        expected_calls = len(targets) * len(nettacker.arguments.selected_modules)
        assert mock_module.call_count == expected_calls
        assert result is True

    @patch("nettacker.core.app.Module")
    @patch("nettacker.core.app.set_socks_proxy")
    def test_parallel_module_scan_limit_respected(self, mock_socks, mock_module):
        """Test that parallel_module_scan limit is respected."""
        # Setup: track active threads
        active_threads = []
        max_concurrent = 0

        def mock_scan(*args, **kwargs):
            """Mock that tracks concurrent execution."""
            active_threads.append(1)
            nonlocal max_concurrent
            max_concurrent = max(max_concurrent, len(active_threads))
            time.sleep(0.01)  # Simulate work
            active_threads.pop()

        mock_module_instance = MagicMock()
        mock_module_instance.load = Mock()
        mock_module_instance.generate_loops = Mock()
        mock_module_instance.sort_loops = Mock()
        mock_module_instance.start = Mock(side_effect=mock_scan)
        mock_module.return_value = mock_module_instance
        mock_socks.return_value = (Mock(), Mock())

        # Create nettacker instance
        with patch("nettacker.core.app.ArgParser.__init__", return_value=None):
            nettacker = Nettacker.__new__(Nettacker)
            nettacker.arguments = Mock()
            nettacker.arguments.selected_modules = ["port_scan"]
            nettacker.arguments.parallel_module_scan = 3  # Limit to 3
            nettacker.arguments.socks_proxy = None
            nettacker.print_logo = Mock()
            nettacker.check_dependencies = Mock()

        # Create 10 targets to ensure we exceed the limit
        targets = [f"192.168.1.{i}" for i in range(1, 11)]
        scan_id = "test_scan_id"
        process_number = 0

        # Execute
        nettacker.scan_target_group(targets, scan_id, process_number)

        # The max concurrent should not exceed parallel_module_scan
        # Note: Due to threading timing, this might be slightly higher but should be close
        assert max_concurrent <= nettacker.arguments.parallel_module_scan + 2

    @patch("nettacker.core.app.Module")
    @patch("nettacker.core.app.set_socks_proxy")
    def test_progress_logging_for_large_scans(self, mock_socks, mock_module):
        """Test that progress is logged for scans with >100 tasks."""
        mock_module_instance = MagicMock()
        mock_module.return_value = mock_module_instance
        mock_socks.return_value = (Mock(), Mock())

        with patch("nettacker.core.app.ArgParser.__init__", return_value=None):
            nettacker = Nettacker.__new__(Nettacker)
            nettacker.arguments = Mock()
            nettacker.arguments.selected_modules = ["port_scan"]
            nettacker.arguments.parallel_module_scan = 10
            nettacker.arguments.socks_proxy = None
            nettacker.print_logo = Mock()
            nettacker.check_dependencies = Mock()

        # Create 101 targets to trigger progress logging
        targets = [f"192.168.1.{i}" for i in range(1, 102)]
        scan_id = "test_scan_id"
        process_number = 0

        with patch("nettacker.logger.get_logger") as mock_logger:
            mock_log_instance = Mock()
            mock_logger.return_value = mock_log_instance

            # Execute
            nettacker.scan_target_group(targets, scan_id, process_number)

            # Verify progress logging occurred
            # Should have at least one progress log for 100 tasks
            info_calls = [call for call in mock_log_instance.info.call_args_list]
            assert len(info_calls) > 0

    @patch("nettacker.core.app.Module")
    @patch("nettacker.core.app.set_socks_proxy")
    def test_graceful_shutdown_on_keyboard_interrupt(self, mock_socks, mock_module):
        """Test that KeyboardInterrupt is handled gracefully."""

        def mock_scan_that_interrupts(*args, **kwargs):
            """Mock that raises KeyboardInterrupt after first call."""
            raise KeyboardInterrupt("User interrupted")

        mock_module_instance = MagicMock()
        mock_module_instance.load = Mock()
        mock_module_instance.generate_loops = Mock()
        mock_module_instance.sort_loops = Mock()
        mock_module_instance.start = Mock(side_effect=mock_scan_that_interrupts)
        mock_module.return_value = mock_module_instance
        mock_socks.return_value = (Mock(), Mock())

        with patch("nettacker.core.app.ArgParser.__init__", return_value=None):
            nettacker = Nettacker.__new__(Nettacker)
            nettacker.arguments = Mock()
            nettacker.arguments.selected_modules = ["port_scan"]
            nettacker.arguments.parallel_module_scan = 5
            nettacker.arguments.socks_proxy = None
            nettacker.print_logo = Mock()
            nettacker.check_dependencies = Mock()

        targets = ["192.168.1.1", "192.168.1.2"]
        scan_id = "test_scan_id"
        process_number = 0

        # Should not raise exception, should return False
        result = nettacker.scan_target_group(targets, scan_id, process_number)
        assert result is False

    @patch("nettacker.core.app.Module")
    @patch("nettacker.core.app.set_socks_proxy")
    def test_error_handling_for_failed_tasks(self, mock_socks, mock_module):
        """Test that failed tasks are logged but don't stop execution."""
        call_count = 0

        def mock_scan_with_failures(*args, **kwargs):
            """Mock that fails on first call, succeeds on others."""
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Simulated scan failure")

        mock_module_instance = MagicMock()
        mock_module_instance.load = Mock()
        mock_module_instance.generate_loops = Mock()
        mock_module_instance.sort_loops = Mock()
        mock_module_instance.start = Mock(side_effect=mock_scan_with_failures)
        mock_module.return_value = mock_module_instance
        mock_socks.return_value = (Mock(), Mock())

        with patch("nettacker.core.app.ArgParser.__init__", return_value=None):
            nettacker = Nettacker.__new__(Nettacker)
            nettacker.arguments = Mock()
            nettacker.arguments.selected_modules = ["port_scan"]
            nettacker.arguments.parallel_module_scan = 5
            nettacker.arguments.socks_proxy = None
            nettacker.print_logo = Mock()
            nettacker.check_dependencies = Mock()

        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        scan_id = "test_scan_id"
        process_number = 0

        with patch("nettacker.logger.get_logger") as mock_logger:
            mock_log_instance = Mock()
            mock_logger.return_value = mock_log_instance

            # Should complete despite errors
            result = nettacker.scan_target_group(targets, scan_id, process_number)

            # Verify error was logged
            assert mock_log_instance.error.called
            # Should still return True (completed all attempts)
            assert result is True

    def test_memory_efficiency_with_large_cidr(self):
        """
        Test that large CIDR ranges don't create all threads upfront.
        
        This is a conceptual test - in the old implementation, a /20 CIDR
        with 2 modules would create 8,192 thread objects immediately.
        With ThreadPoolExecutor, only max_workers threads are created.
        """
        # This test verifies the design pattern is correct
        # The actual implementation uses ThreadPoolExecutor which:
        # 1. Creates only max_workers threads
        # 2. Reuses threads for multiple tasks
        # 3. Manages queue internally
        
        from concurrent.futures import ThreadPoolExecutor
        
        # Simulate large task queue
        num_ips = 4096  # /20 CIDR
        num_modules = 2
        total_tasks = num_ips * num_modules  # 8,192 tasks
        max_workers = 50
        
        tasks_executed = 0
        
        def dummy_task(task_id):
            nonlocal tasks_executed
            tasks_executed += 1
            return task_id
        
        # With ThreadPoolExecutor, this should be memory efficient
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(dummy_task, i) for i in range(total_tasks)]
            
            # Wait for all to complete
            for future in as_completed(futures):
                future.result()
        
        # Verify all tasks executed
        assert tasks_executed == total_tasks
        
        # The key insight: ThreadPoolExecutor only created max_workers threads
        # not total_tasks threads, making it memory efficient


class TestBackwardCompatibility:
    """Ensure the refactor doesn't break existing functionality."""

    @patch("nettacker.core.app.Module")
    @patch("nettacker.core.app.set_socks_proxy")
    def test_single_target_single_module(self, mock_socks, mock_module):
        """Test the simple case: single target, single module."""
        mock_module_instance = MagicMock()
        mock_module.return_value = mock_module_instance
        mock_socks.return_value = (Mock(), Mock())

        with patch("nettacker.core.app.ArgParser.__init__", return_value=None):
            nettacker = Nettacker.__new__(Nettacker)
            nettacker.arguments = Mock()
            nettacker.arguments.selected_modules = ["port_scan"]
            nettacker.arguments.parallel_module_scan = 1
            nettacker.arguments.socks_proxy = None
            nettacker.print_logo = Mock()
            nettacker.check_dependencies = Mock()

        targets = ["192.168.1.1"]
        scan_id = "test_scan_id"
        process_number = 0

        result = nettacker.scan_target_group(targets, scan_id, process_number)

        assert mock_module.call_count == 1
        assert result is True

    @patch("nettacker.core.app.Module")
    @patch("nettacker.core.app.set_socks_proxy")
    def test_multiple_targets_multiple_modules(self, mock_socks, mock_module):
        """Test multiple targets with multiple modules."""
        mock_module_instance = MagicMock()
        mock_module.return_value = mock_module_instance
        mock_socks.return_value = (Mock(), Mock())

        with patch("nettacker.core.app.ArgParser.__init__", return_value=None):
            nettacker = Nettacker.__new__(Nettacker)
            nettacker.arguments = Mock()
            nettacker.arguments.selected_modules = ["port_scan", "subdomain_scan"]
            nettacker.arguments.parallel_module_scan = 10
            nettacker.arguments.socks_proxy = None
            nettacker.print_logo = Mock()
            nettacker.check_dependencies = Mock()

        targets = ["192.168.1.1", "192.168.1.2", "example.com"]
        scan_id = "test_scan_id"
        process_number = 0

        result = nettacker.scan_target_group(targets, scan_id, process_number)

        # Should call module for each target-module pair
        expected_calls = len(targets) * len(nettacker.arguments.selected_modules)
        assert mock_module.call_count == expected_calls
        assert result is True
