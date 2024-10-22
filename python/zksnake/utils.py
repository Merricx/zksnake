import os
import random
import time


def get_random_int(n_max):
    """Get random integer in [1, n_max] range"""
    rand = random.SystemRandom()
    return rand.randint(1, n_max)


def get_n_jobs():
    """Get number of supported cores for multiprocessing if enabled"""
    check_env = os.environ.get("ZKSNAKE_PARALLEL_CPU")
    if check_env:
        return int(check_env)
    else:
        return -1


def split_list(data, n):
    """Split data into n chunks"""
    return [data[i : i + n] for i in range(0, len(data), n)]


class Timer:
    def __init__(self, name):
        self.start_time = 0
        self.end_time = 0
        self.name = name

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()
        elapsed_time = self.end_time - self.start_time
        print(f"{self.name}: {elapsed_time:.2f} seconds")
