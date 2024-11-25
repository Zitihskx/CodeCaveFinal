import os 
import mmap
from concurrent.futures import ProcessPoolExecutor, as_completed

def increase_file_size(binary, additional_size):
    with open(binary, 'a+b') as fil:
        with mmap.mmap(fil.fileno(), 0, access=mmap.ACCESS_WRITE) as map:
            map.resize(os.path.getsize(binary) + additional_size)
            return 1


def process_files(directory):
    valid_count = 0
    with ProcessPoolExecutor() as executor:
        futures = []
        for root, dirs, files in os.walk(directory):
            for filename in files:
                full_name = os.path.join(root, filename)
                futures.append(executor.submit(increase_file_size, full_name, 20480))

        for future in as_completed(futures):
            valid_count += future.result()

    print(f"Total valid processed files: {valid_count}")

if __name__ == "__main__":
    directory = "/home/user/Desktop/CodeCaveFinal-main/KkrunchyCodeCave/SizeIncrease/Krunchy2Test_Increase20480/"
    process_files(directory)