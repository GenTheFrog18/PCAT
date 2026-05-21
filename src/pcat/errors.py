class PCATError(Exception):
    exit_code = 1


class InvalidArgumentError(PCATError):
    exit_code = 2


class MissingDependencyError(PCATError):
    exit_code = 3


class InputFileError(PCATError):
    exit_code = 4


class ReportWriteError(PCATError):
    exit_code = 5

