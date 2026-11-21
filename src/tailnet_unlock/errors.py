"""The errors this package raises. They carry a message for a person and nothing else."""


class ConfigError(ValueError):
    """A configuration file or value is invalid."""


class ContractError(ValueError):
    """Another program's output broke its contract (an approver, a key source, the door)."""


class DoorKeyError(ValueError):
    """A door key is not an ed25519 key in a format this project reads, or is too large to seal."""


class TpmError(RuntimeError):
    """A tpm2-tools command failed."""


class ToolError(RuntimeError):
    """An external tool (dropbearkey, dropbearconvert) failed."""
