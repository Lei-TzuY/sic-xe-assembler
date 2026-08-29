class AssemblyError(Exception):
    """A user-facing assembly failure with phase and optional line context."""

    def __init__(self, message, *, phase="assembler", line_number=None):
        self.message = message
        self.phase = phase
        self.line_number = line_number
        super().__init__(str(self))

    def __str__(self):
        location = self.phase
        if self.line_number is not None:
            location += f" line {self.line_number}"
        return f"{location}: {self.message}"
