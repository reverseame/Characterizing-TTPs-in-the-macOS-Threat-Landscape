import sys
import os
import time

__author__ = "Daniel Lastanao Miró, Javier Carrillo-Mondéjar and Ricardo J. Rodríguez"
__copyright__ = "Copyright 2025"
__credits__ = ["Daniel Lastanao Miró" , "Javier Carrillo-Mondéjar" ,  "Ricardo J. Rodríguez"]
__license__ = "GPL"
__version__ = "1"
__maintainer__ = "Daniel Lastanao Miró"
__email__ = "reverseame@unizar.es"
__status__ = "Finished"


def custom_progress_bar(message, current, total,start_time = time.time(), bar_length=50):
    """Display a custom progress bar with elapsed and estimated remaining time.

    Args:
        message -- Text label for the progress bar.
        current -- Current progress count.
        total -- Total count for completion.
        start_time -- Default timestamp.
        bar_length -- Length of the bar in characters. Defaults to 50.
    """
    progress = current / total
    block = int(bar_length * progress)
    
    elapsed_time = time.time() - start_time
    if current > 0:
        estimated_total_time = elapsed_time / progress
        estimated_remaining_time = estimated_total_time - elapsed_time
    else:
        estimated_remaining_time = 0  # avoid division by zero
    
    text = (f"\r{message}: [{'#' * block + '-' * (bar_length - block)}] {current}/{total} "
            f"({progress:.1%}) | Elapsed: {elapsed_time:.2f}s | Remaining: {estimated_remaining_time:.2f}s")
    sys.stdout.write(text)
    sys.stdout.flush()

def check_path_and_create(directory):
    """Ensure that a directory exists, creating it if necessary.

    Args:
        directory -- Path to the directory.
    """
    if not os.path.exists(directory):
        os.mkdir(directory)

def remove_path(file):
    """Remove a file if it exists.

    Args:
        path -- Path to the file.
    """
    if os.path.exists(file):
        os.remove(file)


def add_hash_to_file(hash_to_add, file_path):
    """Add a hash to a file if it does not already exist.

    Args:
        hash_to_add -- Hash string to add.
        file_path -- Path to the file.
    """
    hash_exists = False
    with open(file_path, 'r') as file:
        for line in file:
            if line.strip() == hash_to_add:
                hash_exists = True
                break

    if not hash_exists:
        with open(file_path, 'a') as file:
            file.write(hash_to_add + '\n')
