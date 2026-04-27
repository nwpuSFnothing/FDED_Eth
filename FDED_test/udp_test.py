import socket
import time


class FpgaUdpTester:
    def __init__(self, fpga_ip="192.168.0.2", fpga_port=8080,local_port=8080, timeout=2.0):
        self.fpga_addr = (fpga_ip, fpga_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", local_port))
        self.sock.settimeout(timeout)

        print(f"[INFO] Local UDP port: {local_port}")
        print(f"[INFO] FPGA target : {fpga_ip}:{fpga_port}")

    def flush_rx(self):
        self.sock.settimeout(0.01)
        while True:
            try:
                self.sock.recvfrom(2048)
            except socket.timeout:
                break
            except BlockingIOError:
                break
        self.sock.settimeout(2.0)

    def send(self, data: bytes):
        self.sock.sendto(data, self.fpga_addr)

    def recv(self, max_len=2048):
        try:
            return self.sock.recvfrom(max_len)
        except socket.timeout:
            return None, None

    def close(self):
        self.sock.close()


def test_echo():
    tester = FpgaUdpTester(
        fpga_ip="192.168.0.2",
        fpga_port=1234,
        local_port=8080,
        timeout=2.0
    )

    try:
        for i in range(5):
            payload = f"hello_fpga_{i}".encode()

            tester.flush_rx()

            print(f"\n[TX] {payload}")
            tester.send(payload)

            data, addr = tester.recv()

            if data is None:
                print("[ERROR] No response")
            else:
                print(f"[RX] {data} from {addr}")

                if data == payload:
                    print("[OK] Echo correct")
                else:
                    print("[WARN] Data mismatch")

            time.sleep(0.5)

    finally:
        tester.close()


if __name__ == "__main__":
    test_echo()