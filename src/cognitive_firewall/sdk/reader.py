"""Bounded credential-separated local reader transport (not an OS sandbox)."""
from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ReaderError(RuntimeError):
    pass


class ReaderData(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    paragraphs: list[str] = Field(max_length=1024)
    facts: list[str] = Field(max_length=1024)


class IsolatedReader:
    def __init__(self, *, worker_path: Path | None = None, timeout: float = 5.0,
                 max_input_bytes: int = 65536, max_output_bytes: int = 131072):
        if not math.isfinite(timeout) or timeout <= 0 or not (
            0 < max_input_bytes <= 1048576 and 0 < max_output_bytes <= 1048576
        ):
            raise ValueError('invalid reader limits')
        self._worker = (Path(worker_path) if worker_path is not None else
                        Path(__file__).with_name('reader_worker.py')).resolve(strict=True)
        self._timeout = timeout
        self._max_input = max_input_bytes
        self._max_output = max_output_bytes

    def read(self, text: str) -> ReaderData:
        if not isinstance(text, str) or len(text.encode('utf-8')) > self._max_input:
            raise ReaderError('reader input exceeds limit')
        wire = json.dumps({'text': text}, ensure_ascii=False).encode('utf-8')
        # Windows needs its OS runtime location; no PATH, HOME, credentials or Python config.
        env = {key: os.environ[key] for key in ('SystemRoot', 'WINDIR') if key in os.environ}
        with tempfile.TemporaryDirectory(prefix='firewall-reader-') as directory:
            env.update(TEMP=directory, TMP=directory, TMPDIR=directory)
            try:
                process = subprocess.Popen(
                    [getattr(sys, '_base_executable', sys.executable), '-I', str(self._worker)], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=directory,
                    env=env, close_fds=True,
                )
            except OSError as exc:
                raise ReaderError('reader unavailable') from exc
            output = []
            finished = threading.Event()

            def receive():
                try:
                    output.append(process.stdout.read(self._max_output + 1))
                finally:
                    finished.set()

            def send():
                try:
                    process.stdin.write(wire)
                    process.stdin.close()
                except (BrokenPipeError, OSError):
                    pass

            receiver = threading.Thread(target=receive, daemon=True)
            sender = threading.Thread(target=send, daemon=True)
            receiver.start()
            sender.start()
            try:
                if not finished.wait(self._timeout):
                    raise ReaderError('reader timed out')
                if not output or len(output[0]) > self._max_output:
                    raise ReaderError('reader output exceeds limit')
                try:
                    process.wait(timeout=self._timeout)
                except subprocess.TimeoutExpired as exc:
                    raise ReaderError('reader timed out') from exc
                if process.returncode != 0:
                    raise ReaderError('reader failed')
                try:
                    return ReaderData.model_validate_json(output[0])
                except (ValidationError, ValueError) as exc:
                    raise ReaderError('reader returned invalid data') from exc
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
                sender.join(timeout=1)
                receiver.join(timeout=1)
                process.stdin.close()
                process.stdout.close()

