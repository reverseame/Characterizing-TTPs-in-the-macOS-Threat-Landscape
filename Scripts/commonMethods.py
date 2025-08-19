import sys
import os
import time

hashesfile = '../Output/Hashes_info/newcombined_hashes_filtered_output.txt'

def custom_progress_bar(message, current, total,start_time = time.time(), bar_length=50):
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

def checkPathAndCreates(directory):
    if not os.path.exists(directory):
        os.mkdir(directory)

def removePath(file):
    if os.path.exists(file):
        os.remove(file)


def add_hash_to_file(hash_to_add, file_path):
    # First, check if the hash already exists in the file
    hash_exists = False
    with open(file_path, 'r') as file:
        for line in file:
            if line.strip() == hash_to_add:
                hash_exists = True
                break

    # If the hash does not exist, append it to the file
    if not hash_exists:
        with open(file_path, 'a') as file:
            file.write(hash_to_add + '\n')
