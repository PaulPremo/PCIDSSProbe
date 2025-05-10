# PCIDSSProbe


This repository contains a custom probe (`MyProbe`) written in Python to verify a system's compliance with PCI DSS (Payment Card Industry Data Security Standard) requirements. The probe performs checks on the firewall status and the use of encryption on listening network ports.

## Features

The `MyProbe` performs the following checks:

* **Firewall Status:** Verifies if the firewall (using `ufw` and `iptables`) is active on the target system via SSH.
* **Encryption Usage:** Checks if listening network ports are using encryption by attempting an `openssl s_client` connection.
* **Non-Encrypted Connection Blocking:** Verifies if non-encrypted connections are blocked on specific ports.
* **PCI DSS Compliance:** Determines if the system's configuration (firewall status and encryption usage) complies with PCI DSS requirements.

## Prerequisites

Before using this probe, ensure you have the following prerequisites:

* **Python 3.x** installed on the system running the probe.
* The `subprocess`, `abstract_probe` (ensure it's available in your environment), `ssh_client` (ensure it's available in your environment), and `atom` (ensure it's available in your environment) libraries installed.
* The `openssl` executable installed on the system running the probe.
* SSH access to the target system with the necessary credentials to execute commands with `sudo`.

## Installation

1.  Clone this repository (if applicable):
    ```bash
    git clone <YOUR_REPOSITORY_URL>
    cd <REPOSITORY_NAME>
    ```
2.  Ensure you have the necessary dependencies installed (you might need to install `abstract_probe`, `ssh_client`, and `atom` if they are not part of the standard library or your environment):
    ```bash
    # Example (may vary depending on how your dependencies are managed)
    pip install <abstract_probe_package_name>
    pip install <ssh_client_package_name>
    pip install <atom_package_name>
    ```

## Configuration

The probe requires a configuration to specify the host and port of the target system. This configuration should be provided through the `config.input` attribute of the `self` object within the `parse_input` method.

Example of how the configuration might look:

```python
config = {
    'input': {
        'config': {
            'host': 'target_ip_address_or_hostname',
            'port': 22  # Default SSH port (used for commands)
        }
    }
}
