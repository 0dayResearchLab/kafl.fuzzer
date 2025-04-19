import struct
import pytest
from kafl_fuzzer.technique.havoc import (
    mutate_seq_havoc_array,
    mutate_seq_splice_array,
    mutate_random_sequence,
    mutate_length
)
from kafl_fuzzer.common.util import IRP, interface_manager
import kafl_fuzzer.technique.havoc as havoc

# Setup required for splice and dependency tests
havoc.location_corpus = "/tmp"
havoc.location_dependency = "/tmp"

@pytest.fixture(scope="module", autouse=True)
def setup_irp_interface():
    interface_manager.interface[0x222004] = {
        "InBufferRange": [range(0, 32)],
        "OutBufferRange": [range(0, 8192)]
    }
    interface_manager.interface[0x222001] = {
        "InBufferRange": [range(0, 32)],
        "OutBufferRange": [range(0, 8192)]
    }
    interface_manager.interface[0x222002] = {
        "InBufferRange": [range(0, 64)],
        "OutBufferRange": [range(0, 4096)]
    }
    interface_manager.interface[0x222003] = {
        "InBufferRange": [range(0, 128)],
        "OutBufferRange": [range(0, 2048)]
    }

# Sample IRP generator for testing
# This form must be preserved
def generate_irp_input(data: bytes) -> IRP:
    return IRP(
        IoControlCode=struct.pack('<L', 0x222004),
        InBuffer_length=struct.pack('<L', len(data)),
        OutBuffer_length=struct.pack('<L', 0x2000),
        InBuffer=data,
        Command=b"IOIO"
    )

def generate_multiple_irps(count=5, data=b"abcdef123456"):
    return [generate_irp_input(data) for _ in range(count)]

def dummy_callback(irp_list, label=None):
    assert isinstance(irp_list, list)
    assert len(irp_list) > 0, "IRP list should not be empty"

    for irp in irp_list:
        assert isinstance(irp.InBuffer, (bytes, bytearray)), "InBuffer is not bytes-like"
        assert isinstance(irp.InBuffer_length, int), "InBuffer_length must be int"
        assert isinstance(irp.OutBuffer_length, int), "OutBuffer_length must be int"
        assert len(irp.InBuffer) == irp.InBuffer_length, (
            f"InBuffer length mismatch: expected {irp.InBuffer_length}, got {len(irp.InBuffer)}"
        )

    unique_ids = set(id(irp) for irp in irp_list)
    assert len(unique_ids) == len(irp_list), "IRPs should be unique instances"

    # mutation branch 추적용 (선택적으로 사용될 때만)
    if hasattr(dummy_callback, "original_len"):
        if len(irp_list) < dummy_callback.original_len:
            dummy_callback.delete_called = True
        elif len(irp_list) > dummy_callback.original_len:
            dummy_callback.add_called = True
        elif len(irp_list) == dummy_callback.original_len:
            dummy_callback.replace_called = True


def test_mutate_seq_havoc():
    irp_list = generate_multiple_irps()
    for i in range(len(irp_list)):
        mutate_seq_havoc_array(irp_list, i, dummy_callback, max_iterations=32)
    print("mutate_seq_havoc_array passed")

def test_mutate_seq_splice():
    irp_list = generate_multiple_irps()
    for i in range(len(irp_list)):
        mutate_seq_splice_array(irp_list, i, dummy_callback, max_iterations=16)
    print("mutate_seq_splice_array passed")

def test_mutate_random_sequence_branches():
    irp_list = generate_multiple_irps()
    dummy_callback.original_len = len(irp_list)
    dummy_callback.delete_called = False
    dummy_callback.add_called = False
    dummy_callback.replace_called = False

    for _ in range(50):
        mutate_random_sequence(irp_list, 0, dummy_callback)

    assert dummy_callback.delete_called or dummy_callback.add_called or dummy_callback.replace_called, \
        "No mutation branch was actually invoked!"

    print("mutate_random_sequence branch coverage passed")

def test_mutate_length():
    irp_list = generate_multiple_irps()
    for i in range(len(irp_list)):
        mutate_length(irp_list, i, dummy_callback)
    print("mutate_length passed")

def run_all_tests():
    test_mutate_seq_havoc()
    test_mutate_seq_splice()
    test_mutate_random_sequence_branches()
    test_mutate_length()
    print("All mutation tests passed!")

if __name__ == "__main__":
    run_all_tests()