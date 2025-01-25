import time
import threading

class RateLimiter:
    def __init__(self, max_calls, interval):
        self.max_calls = max_calls
        self.interval = interval
        self.call_times = []  
        self.lock = threading.Lock()

    def allow_request(self):
        with self.lock:
            current_time = time.time()
            self.call_times = [t for t in self.call_times if t > current_time - self.interval]

            if len(self.call_times) < self.max_calls:
                self.call_times.append(current_time)
                return True
            else:
                sleep_time = self.interval - (current_time - self.call_times[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    return self.allow_request() 
                else:
                    self.call_times.append(current_time)
                    return True