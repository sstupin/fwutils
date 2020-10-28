import sys
import os
import random
import time
from loguru import logger


def print_results(chunk, offset1, offset2, time_elapsed):
    logger.debug(f"Chunk found: {chunk.hex()}")
    logger.info(
        f"Chunk size: {len(chunk):>10} {'0x' + hex(len(chunk))[2:].zfill(8).upper():>12}"
    )
    logger.info(f"Offset in bin1: {offset1:>6} {'0x' + hex(offset1)[2:].zfill(8).upper():>12}")
    logger.info(
        f"Offset in bin2: {offset2:>6} {'0x' + hex(offset2)[2:].zfill(8).upper():>12}"
    )
    logger.info(f"Time elapsed: {time_elapsed} seconds")


def gen_random_bytes_with_chunk(file_size, chunk_size, chunk):
    if chunk is None:
        chunk = os.urandom(chunk_size)

    s1 = random.randint(0, file_size - chunk_size)
    s2 = file_size - chunk_size - s1
    random_bytes = os.urandom(s1) + chunk + os.urandom(s2)
    return s1, len(chunk), s2, random_bytes


def test_with_random_data(total_size, chunk_size, min_chunk_size,
                          max_chunk_size):
    assert total_size > 0, "File size must be positive integer."
    assert chunk_size > 0, "Chunk size must be positive integer."
    assert (
        chunk_size <= total_size
    ), "Chunk size must be less or equal to file size."
    assert (
        chunk_size >= min_chunk_size and chunk_size <= max_chunk_size
    ), "Invalid chunk size."

    bin1_s1, bin1_s2, bin1_s3, bin1 = gen_random_bytes_with_chunk(
        total_size, chunk_size, None
    )
    chunk = bin1[bin1_s1: bin1_s1 + bin1_s2]
    bin2_s1, bin2_s2, bin2_s3, bin2 = gen_random_bytes_with_chunk(
        total_size, chunk_size, chunk
    )
    logger.debug(f"bin1: {bin1_s1} {bin1_s2} {bin1_s3} {bin1.hex()}")
    logger.debug(f"bin2: {bin2_s1} {bin2_s2} {bin2_s3} {bin2.hex()}")
    # logger.info(chunk.hex())

    found_chunk, offset1, offset2, time_elapsed = search_chunk(
        bin1, bin2, min_chunk_size, max_chunk_size
    )
    found_chunk_size = len(found_chunk)
    chunk1 = bin1[offset1: offset1 + found_chunk_size]
    chunk2 = bin2[offset2: offset2 + found_chunk_size]
    # logger.info(chunk1.hex())
    # logger.info(chunk2.hex())
    print_results(found_chunk, offset1, offset2, time_elapsed)

    # false assert when there is the same byte BEFORE chunk in each bin
    # assert offset1 == bin1_s1, "Test failed."
    # assert offset2 == bin2_s1, "Test failed."
    assert chunk1 == chunk2
    # assert chunk.hex().startswith(chunk1.hex())
    if len(chunk) != len(chunk1):
        logger.info(f"ATTENTION: {len(chunk)} != {len(chunk1)}")
    return found_chunk, offset1, offset2


def compare_2hex_files(file1, file2, min_chunk_size, max_chunk_size):
    with open('bin1', 'rb') as f1, open('bin2', 'rb') as f2:
        bin1 = f1.read()
        bin2 = f2.read()
    logger.debug(f"File1: {len(bin1)} Bytes, {bin1.hex()}")
    logger.debug(f"File2: {len(bin2)} Bytes, {bin2.hex()}")

    found_chunk, offset1, offset2, time_elapsed = search_chunk(
        bin1, bin2, min_chunk_size, max_chunk_size
    )
    print_results(found_chunk, offset1, offset2, time_elapsed)
    return found_chunk, offset1, offset2


def search_chunk(bin1, bin2, min_chunk_size, max_chunk_size):
    assert (
        min_chunk_size <= max_chunk_size
    ), "Invalid min / max parameters"
    offset1 = offset2 = -1
    chunk = prev_chunk = None
    cur_chunk_size = min_chunk_size

    start_time = time.perf_counter()
    while offset1 < len(bin1) - cur_chunk_size:
        offset1 += 1
        chunk = bin1[offset1: offset1 + cur_chunk_size]
        prev_offset2 = offset2 = bin2.find(chunk)
        # offset1 + cur_chunk_size <= len(bin1)
        # to search chunk with max length
        while offset2 > -1 and cur_chunk_size <= max_chunk_size:
            prev_chunk = chunk
            prev_offset2 = offset2
            cur_chunk_size += 1
            chunk = bin1[offset1: offset1 + cur_chunk_size]
            offset2 = bin2.find(chunk)
        if prev_offset2 > -1:
            break
    time_elapsed = round(time.perf_counter() - start_time, 2)
    return prev_chunk, offset1, prev_offset2, time_elapsed


if __name__ == "__main__":
    logger.remove()  # remove default stderr logger
    logger.add("bintest_{time}.log", level="DEBUG")  # add file logger
    logger.add(sys.stderr, format="{message}", level="INFO")  # add custom stderr logger

    FILE_TEST = True
    ITERATIONS = 1

    if FILE_TEST:
        compare_2hex_files('bin1', 'bin2', 1024*20, 1024*32)
    else:
        for i in range(ITERATIONS):
            FILE_SIZE = 1024*512
            CHUNK_SIZE = random.randint(1024*20, 1024*32)
            logger.info(f"======Test {i+1:>4}, File size, Bytes: {FILE_SIZE:>6}; Chunk size, Bytes: {CHUNK_SIZE:>6} ======")
            test_with_random_data(FILE_SIZE, CHUNK_SIZE, 1024*20, 1024*32)
    sys.exit(0)
