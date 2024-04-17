import subprocess
import abstract_probe
from ssh_client import SshClient
from atom import AtomPairWithException, OnExceptionActionForward

class MyProbe(abstract_probe.AbstractProbe):
    def parse_input(self, inputs=None):
        config = self.config.input.get('config')
        host = config.get('host')
        port = config.get('port')
        
        assert host, "Host field is required in the configuration."
        assert port, "Port field is required in the configuration."

        self.host = host
        self.port = port

    def requires_credential(self):
        return True

    def initialize(self):
        # Initialize compliance evaluation
        self.set_integer_result(abstract_probe.INTEGER_RESULT_TRUE)

    def evaluate_results(self):
        # Evaluate PCI DSS compliance results.
        if self.has_errors():
            self.set_integer_result(abstract_probe.INTEGER_RESULT_TARGET_EXECUTION_ERROR)
            self.set_pretty_result("Errors occurred during probe execution.")
            return

        compliance_result = self.get_pretty_result()

        if "non utilizza crittografia" in compliance_result or "firewall non è attivo" in compliance_result:
            self.set_integer_result(abstract_probe.INTEGER_RESULT_FALSE)
            self.set_pretty_result("Configuration does not comply with PCI DSS requirements.")
        else:
            self.set_integer_result(abstract_probe.INTEGER_RESULT_TRUE)
            self.set_pretty_result("Configuration complies with PCI DSS requirements.")

    def check_firewall_status(self) -> bool:
        # Check firewall status including iptables.
        ufw_result = self.ssh_client.send_command("sudo ufw status")
        iptables_result = self.ssh_client.send_command("sudo iptables -L")
        ufw_active = "Status: active" in ufw_result['stdout']
        iptables_active = "Chain INPUT" in iptables_result['stdout']
        return ufw_active and iptables_active

    def check_encryption_usage(self, port):
        # Check encryption usage on a specific port.
        result = subprocess.run(["openssl", "s_client", "-connect", f"{self.host}:{port}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0

    def check_encryption_on_ports(self, ports):
        # Check encryption usage on specified ports.
        for port in ports:
            if self.check_encryption_usage(port):
                self.append_pretty_result(f"Port {port} is using encryption.")
            else:
                self.append_pretty_result(f"Port {port} is not using encryption.")

    def check_non_encrypted_connection(self, port):
        # Check if non-encrypted connection is blocked on a specific port.
        try:
            result = subprocess.run(["openssl", "s_client", "-connect", f"{self.host}:{port}", "-no_ssl2", "-no_ssl3", "-no_tls1", "-no_tls1_1", "-no_tls1_2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return True  # Timeout implies that connection is blocked

    def check_non_encrypted_connections(self, ports):
        # Check if non-encrypted connections are blocked on specified ports.
        for port in ports:
            if self.check_non_encrypted_connection(port):
                self.append_pretty_result(f"Non-encrypted connections to port {port} are blocked.")
            else:
                self.append_pretty_result(f"Non-encrypted connections to port {port} are allowed.")

    def test_ports(self):
        # Verify encryption usage on listening ports and firewall status.
        try:
            result = self.ssh_client.send_command("netstat -tuln | grep LISTEN")
            output = result['stdout']
            filtered_ports = [line.split()[3].split(':')[-1] for line in output.split('\n') if line.strip() and line.strip().endswith('LISTEN')]
            self.check_encryption_on_ports(filtered_ports)

            if self.check_firewall_status():
                self.set_pretty_result("Firewall is active.")
            else:
                self.set_pretty_result("Firewall is not active.")

            self.set_integer_result(abstract_probe.INTEGER_RESULT_TRUE)

        except Exception as e:
            self.set_integer_result(abstract_probe.INTEGER_RESULT_TARGET_EXECUTION_ERROR)
            self.set_pretty_result(f"Error occurred during probe execution: {str(e)}")

    def rollback_test_ports(self):
        pass

    def atoms(self) -> [AtomPairWithException]:
        # Register forward and rollback states.
        return [
            AtomPairWithException(
                forward=self.test_ports,
                forward_captured_exceptions=[
                    # Capture assertion exception and perform rollback
                    PunctualExceptionInformationForward(
                        exception_class=AssertionError,
                        action=OnExceptionActionForward.ROLLBACK
                    )
                ],
                rollback=self.rollback_test_ports,
                rollback_captured_exceptions=[
                    # Capture assertion exception during rollback and stop execution
                    PunctualExceptionInformationRollback(
                        exception_class=AssertionError,
                        action=OnExceptionActionForward.STOP
                    )
                ]
            )
        ]

if __name__ == '__main__':
    entrypoint.start_execution(MyProbe)
