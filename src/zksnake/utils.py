import threading
import random


def get_random_int(n_max):
    """Get random integer in [1, n_max] range"""
    rand = random.SystemRandom()
    return rand.randint(1, n_max)
