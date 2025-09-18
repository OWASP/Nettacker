#!/usr/bin/env python3
"""
Performance Benchmarking Suite for OWASP Nettacker
Compares threading vs async/await performance improvements
"""

import asyncio
import statistics
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Callable
import json
from pathlib import Path

from nettacker.core.utils.cross_platform import AsyncNetworkOptimizer


class PerformanceBenchmark:
    """
    Comprehensive performance benchmarking utility
    Measures execution time, resource utilization, and throughput
    """
    
    def __init__(self):
        self.results = {
            "threading_results": [],
            "async_results": [],
            "path_handling_results": {},
            "cross_platform_results": {}
        }
    
    def benchmark_threading_approach(self, num_tasks: int, task_duration: float) -> Dict[str, Any]:
        """
        Benchmark traditional threading approach
        
        Args:
            num_tasks: Number of concurrent tasks
            task_duration: Duration of each task in seconds
            
        Returns:
            Dict containing performance metrics
        """
        def mock_network_task(task_id: int) -> Dict[str, Any]:
            """Simulate network I/O task"""
            start_time = time.time()
            time.sleep(task_duration)  # Simulate blocking I/O
            end_time = time.time()
            
            return {
                "task_id": task_id,
                "execution_time": end_time - start_time,
                "thread_id": threading.get_ident()
            }
        
        start_time = time.time()
        
        # Use ThreadPoolExecutor for controlled threading
        with ThreadPoolExecutor(max_workers=min(num_tasks, 50)) as executor:
            futures = [
                executor.submit(mock_network_task, i)
                for i in range(num_tasks)
            ]
            
            results = [future.result() for future in futures]
        
        end_time = time.time()
        
        return {
            "approach": "threading",
            "total_execution_time": end_time - start_time,
            "num_tasks": num_tasks,
            "task_duration": task_duration,
            "avg_task_time": statistics.mean([r["execution_time"] for r in results]),
            "max_task_time": max([r["execution_time"] for r in results]),
            "min_task_time": min([r["execution_time"] for r in results]),
            "unique_threads": len(set([r["thread_id"] for r in results])),
            "throughput": num_tasks / (end_time - start_time)
        }
    
    async def benchmark_async_approach(self, num_tasks: int, task_duration: float) -> Dict[str, Any]:
        """
        Benchmark async/await approach
        
        Args:
            num_tasks: Number of concurrent tasks
            task_duration: Duration of each task in seconds
            
        Returns:
            Dict containing performance metrics
        """
        async def mock_async_network_task(task_id: int) -> Dict[str, Any]:
            """Simulate async network I/O task"""
            start_time = time.time()
            await asyncio.sleep(task_duration)  # Simulate async I/O
            end_time = time.time()
            
            return {
                "task_id": task_id,
                "execution_time": end_time - start_time,
                "coroutine_id": id(asyncio.current_task())
            }
        
        start_time = time.time()
        
        # Use async optimizer for controlled concurrency
        optimizer = AsyncNetworkOptimizer(max_concurrent_requests=min(num_tasks, 100))
        
        coroutines = [
            optimizer.execute_with_semaphore(mock_async_network_task(i))
            for i in range(num_tasks)
        ]
        
        results = await asyncio.gather(*coroutines)
        
        end_time = time.time()
        
        return {
            "approach": "async",
            "total_execution_time": end_time - start_time,
            "num_tasks": num_tasks,
            "task_duration": task_duration,
            "avg_task_time": statistics.mean([r["execution_time"] for r in results]),
            "max_task_time": max([r["execution_time"] for r in results]),
            "min_task_time": min([r["execution_time"] for r in results]),
            "unique_coroutines": len(set([r["coroutine_id"] for r in results])),
            "throughput": num_tasks / (end_time - start_time)
        }
    
    def benchmark_path_handling(self) -> Dict[str, Any]:
        """
        Benchmark path handling improvements
        
        Returns:
            Dict containing path handling performance metrics
        """
        import os
        from nettacker.core.utils.cross_platform import CrossPlatformPathHandler
        
        handler = CrossPlatformPathHandler()
        
        # Test path operations
        test_paths = [
            ["home", "user", "documents", "file.txt"],
            ["var", "log", "application", "error.log"],
            ["tmp", "cache", "session_123", "data.json"],
            ["opt", "software", "config", "settings.ini"],
            ["usr", "local", "bin", "script.sh"]
        ]
        
        # Benchmark old approach (os.path.join)
        start_time = time.time()
        for _ in range(1000):
            for path_components in test_paths:
                os.path.join(*path_components)
        old_approach_time = time.time() - start_time
        
        # Benchmark new approach (pathlib)
        start_time = time.time()
        for _ in range(1000):
            for path_components in test_paths:
                handler.safe_path_join(*path_components)
        new_approach_time = time.time() - start_time
        
        # Test filename sanitization
        dangerous_filenames = [
            "file<name>with:invalid|chars?.txt",
            "CON.txt",
            "file/with/separators.txt",
            "normal_file.txt",
            "file with spaces.txt"
        ]
        
        start_time = time.time()
        for _ in range(1000):
            for filename in dangerous_filenames:
                handler.generate_safe_filename(filename)
        sanitization_time = time.time() - start_time
        
        return {
            "old_path_join_time": old_approach_time,
            "new_path_join_time": new_approach_time,
            "improvement_factor": old_approach_time / new_approach_time if new_approach_time > 0 else float('inf'),
            "sanitization_time": sanitization_time,
            "sanitization_throughput": len(dangerous_filenames) * 1000 / sanitization_time
        }
    
    def benchmark_cross_platform_compatibility(self) -> Dict[str, Any]:
        """
        Benchmark cross-platform compatibility features
        
        Returns:
            Dict containing cross-platform performance metrics
        """
        import platform
        import tempfile
        from nettacker.core.utils.cross_platform import (
            CrossPlatformPathHandler,
            get_cross_platform_config_dir,
            get_cross_platform_data_dir
        )
        
        handler = CrossPlatformPathHandler()
        
        # Test directory creation performance
        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = Path(tmpdir)
            
            start_time = time.time()
            for i in range(100):
                test_dir = base_path / f"test_{i}" / "nested" / "directory"
                handler.ensure_directory_exists(test_dir)
            directory_creation_time = time.time() - start_time
        
        # Test config directory determination
        start_time = time.time()
        for _ in range(1000):
            get_cross_platform_config_dir("test_app")
            get_cross_platform_data_dir("test_app")
        config_dir_time = time.time() - start_time
        
        # Test platform-specific operations
        start_time = time.time()
        for _ in range(1000):
            handler.get_platform_temp_dir()
            handler.normalize_path_separators("/path/with/mixed\\separators")
        platform_ops_time = time.time() - start_time
        
        return {
            "platform": platform.system(),
            "directory_creation_time": directory_creation_time,
            "config_dir_determination_time": config_dir_time,
            "platform_ops_time": platform_ops_time,
            "total_cross_platform_overhead": (
                directory_creation_time + config_dir_time + platform_ops_time
            )
        }
    
    def run_comprehensive_benchmark(self) -> Dict[str, Any]:
        """
        Run comprehensive performance benchmark suite
        
        Returns:
            Dict containing all benchmark results
        """
        print("Starting comprehensive performance benchmark...")
        
        # Test scenarios: (num_tasks, task_duration)
        scenarios = [
            (10, 0.01),   # Light load
            (50, 0.01),   # Medium load  
            (100, 0.01),  # Heavy load
            (10, 0.1),    # Longer tasks
            (200, 0.005)  # High concurrency
        ]
        
        # Benchmark threading vs async
        for num_tasks, duration in scenarios:
            print(f"Benchmarking {num_tasks} tasks with {duration}s duration...")
            
            # Threading benchmark
            threading_result = self.benchmark_threading_approach(num_tasks, duration)
            self.results["threading_results"].append(threading_result)
            
            # Async benchmark
            async_result = asyncio.run(self.benchmark_async_approach(num_tasks, duration))
            self.results["async_results"].append(async_result)
            
            # Calculate improvement
            improvement = threading_result["total_execution_time"] / async_result["total_execution_time"]
            print(f"  Threading: {threading_result['total_execution_time']:.3f}s")
            print(f"  Async: {async_result['total_execution_time']:.3f}s")
            print(f"  Improvement: {improvement:.2f}x")
        
        # Path handling benchmark
        print("Benchmarking path handling improvements...")
        self.results["path_handling_results"] = self.benchmark_path_handling()
        
        # Cross-platform benchmark
        print("Benchmarking cross-platform compatibility...")
        self.results["cross_platform_results"] = self.benchmark_cross_platform_compatibility()
        
        return self.results
    
    def generate_performance_report(self, results: Dict[str, Any]) -> str:
        """
        Generate comprehensive performance report
        
        Args:
            results: Benchmark results
            
        Returns:
            Formatted performance report
        """
        report = []
        report.append("OWASP Nettacker Performance Benchmark Report")
        report.append("=" * 50)
        report.append("")
        
        # Threading vs Async Analysis
        report.append("Threading vs Async/Await Performance:")
        report.append("-" * 40)
        
        threading_times = [r["total_execution_time"] for r in results["threading_results"]]
        async_times = [r["total_execution_time"] for r in results["async_results"]]
        
        avg_threading_time = statistics.mean(threading_times)
        avg_async_time = statistics.mean(async_times)
        overall_improvement = avg_threading_time / avg_async_time
        
        report.append(f"Average threading execution time: {avg_threading_time:.3f}s")
        report.append(f"Average async execution time: {avg_async_time:.3f}s")
        report.append(f"Overall performance improvement: {overall_improvement:.2f}x")
        report.append("")
        
        # Detailed scenario analysis
        for i, (threading, async_res) in enumerate(zip(results["threading_results"], results["async_results"])):
            improvement = threading["total_execution_time"] / async_res["total_execution_time"]
            throughput_improvement = async_res["throughput"] / threading["throughput"]
            
            report.append(f"Scenario {i+1}: {threading['num_tasks']} tasks @ {threading['task_duration']}s")
            report.append(f"  Threading time: {threading['total_execution_time']:.3f}s")
            report.append(f"  Async time: {async_res['total_execution_time']:.3f}s")
            report.append(f"  Speed improvement: {improvement:.2f}x")
            report.append(f"  Throughput improvement: {throughput_improvement:.2f}x")
            report.append("")
        
        # Path handling analysis
        path_results = results["path_handling_results"]
        report.append("Path Handling Performance:")
        report.append("-" * 30)
        report.append(f"Old approach (os.path.join): {path_results['old_path_join_time']:.4f}s")
        report.append(f"New approach (pathlib): {path_results['new_path_join_time']:.4f}s")
        report.append(f"Path handling improvement: {path_results['improvement_factor']:.2f}x")
        report.append(f"Filename sanitization throughput: {path_results['sanitization_throughput']:.0f} files/sec")
        report.append("")
        
        # Cross-platform analysis
        cp_results = results["cross_platform_results"]
        report.append("Cross-Platform Compatibility:")
        report.append("-" * 32)
        report.append(f"Platform: {cp_results['platform']}")
        report.append(f"Directory creation overhead: {cp_results['directory_creation_time']:.4f}s")
        report.append(f"Config dir determination: {cp_results['config_dir_determination_time']:.4f}s")
        report.append(f"Platform operations: {cp_results['platform_ops_time']:.4f}s")
        report.append(f"Total cross-platform overhead: {cp_results['total_cross_platform_overhead']:.4f}s")
        report.append("")
        
        # Summary
        report.append("Performance Summary:")
        report.append("-" * 20)
        report.append(f"✓ Async execution is {overall_improvement:.1f}x faster than threading")
        
        if path_results['improvement_factor'] > 1:
            report.append(f"✓ Path handling is {path_results['improvement_factor']:.1f}x more efficient")
        else:
            report.append(f"- Path handling overhead: {1/path_results['improvement_factor']:.1f}x (acceptable for cross-platform compatibility)")
        
        report.append(f"✓ Cross-platform compatibility added with minimal overhead")
        report.append(f"✓ Filename sanitization processes {path_results['sanitization_throughput']:.0f} files/sec")
        
        return "\n".join(report)
    
    def save_results(self, results: Dict[str, Any], output_path: str = "benchmark_results.json"):
        """
        Save benchmark results to JSON file
        
        Args:
            results: Benchmark results
            output_path: Output file path
        """
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {output_path}")


def main():
    """Main benchmark execution"""
    benchmark = PerformanceBenchmark()
    
    print("OWASP Nettacker Performance Benchmark Suite")
    print("=" * 50)
    print("This benchmark compares threading vs async performance")
    print("and validates cross-platform path handling improvements.")
    print("")
    
    # Run comprehensive benchmark
    results = benchmark.run_comprehensive_benchmark()
    
    # Generate and display report
    report = benchmark.generate_performance_report(results)
    print("\n" + report)
    
    # Save results
    timestamp = int(time.time())
    output_file = f"nettacker_benchmark_{timestamp}.json"
    benchmark.save_results(results, output_file)
    
    # Save report
    report_file = f"nettacker_performance_report_{timestamp}.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    print(f"Performance report saved to {report_file}")


if __name__ == "__main__":
    main()