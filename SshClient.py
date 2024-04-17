import io
from fabric import Connection
import paramiko
from dataclasses import dataclass

class SshClient:
    @dataclass
    class onNotZeroExitCodeAction:
        GO_ON: int = 0,
        STOP: int = 1

    def __init__(self, *args, **kwargs):
        self._host: str = kwargs.pop("host")
        self._port: str = kwargs.pop("port")
        self._username: str = kwargs.pop("username")
        self._password: str = kwargs.pop("password")
        self._private_key: str = kwargs.pop("private_key")
        self._private_key_passphrase: str = kwargs.pop("private_key_passphrase")
        self._client: Connection = None

    def connect_ssh(self) -> Connection:
        if self._client is None:
            assert self._host is not None and self._host != "", "[input] host input field not valid"
            assert self._port is not None and self._port != "", "[input] port input field not valid"
            assert self._username is not None and self._username != "", "[input] username input field not valid"
            assert (self._password is not None and self._password != "") or (self._private_key is not None and self._private_key != ""), "[input] password or private key input field not valid"
            private_key: paramiko.PKey = None
            if self._private_key is not None and self._private_key != "":
                private_key = paramiko.RSAKey.from_private_key(io.StringIO(self._private_key),self._private_key_passphrase)
            self._client = Connection(host=self._host, port=self._port,
                                      user=self._username,
                                      connect_kwargs={
                                          "password": self._password,
                                          "pkey": private_key
                                      })
        return self._client

    def send_command(self, command:str, on_not_zero_exit_code):
        assert isinstance(command, str), f"Cmd expected str but got{type(command)}"
        assert self._client is not None, "client connection error -- client is None"
        res: any = self._client.run(command, hide=True,warn=False if on_not_zero_exit_code==SshClient.onNotZeroExitCodeAction.STOP else True) # ignore runtime errors
        out_parse: any = {
            "stdout": res.stdout.rstrip("\n"),
            "stderr": res.stderr.rstrip("\n"),
            "exit_code": res.exited
        }
        return out_parse

    def send_file(self, src, dst):
        assert self._client is not None, "client connection error -- client is None"
        self._client.put(local=src, remote=dst)

    def get_file(self, src, dst):
        assert self._client is not None, "client connection error -- client is None"
        self._client.get(local=src, remote=dst)
