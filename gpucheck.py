import pycuda.driver as cuda
import pycuda.autoinit

def print_gpu_info():
    # Get the number of devices
    device_count = cuda.Device.count()
    print(f"Number of devices: {device_count}")

    for i in range(device_count):
        device = cuda.Device(i)
        print(f"\nDevice {i}: {device.name()}")
        print(f"  Compute capability: {device.compute_capability()}")
        print(f"  Total memory: {device.total_memory() / (1024**2):.2f} MB")
        print(f"  Multiprocessors: {device.get_attribute(cuda.device_attribute.MULTIPROCESSOR_COUNT)}")
        print(f"  Clock rate: {device.get_attribute(cuda.device_attribute.CLOCK_RATE) / 1e3:.2f} MHz")
        print(f"  Max threads per block: {device.get_attribute(cuda.device_attribute.MAX_THREADS_PER_BLOCK)}")

if __name__ == "__main__":
    print_gpu_info()
