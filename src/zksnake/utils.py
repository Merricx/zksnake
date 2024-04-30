import os
import random


def get_random_int(n_max):
    """Get random integer in [1, n_max] range"""
    rand = random.SystemRandom()
    return rand.randint(1, n_max)


def get_n_jobs():
    check_env = os.environ.get("ZKSNAKE_PARALLEL_CPU")
    if check_env:
        return int(check_env)
    else:
        return -1
