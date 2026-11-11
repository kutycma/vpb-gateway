import json
import os
import tempfile
from pathlib import Path

class State:
    def __init__(self, path):
        self.path = Path(path)
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {}

    def save(self, **updates):
        self.data.update(updates)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent)
        try:
            os.chmod(name, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(self.data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(name, self.path)
            os.chmod(self.path, 0o600)
        finally:
            if os.path.exists(name):
                os.unlink(name)
