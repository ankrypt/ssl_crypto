class Error(Exception):
  """Indicate a generic error."""
  pass


class Warning(Warning):
  """Warning category class.  It is used by the 'warnings' module."""
  pass


class FormatError(Error):
  """Indicate an error while validating an object's format."""
  pass


class UnsupportedAlgorithmError(Error):
  """Indicate an error while trying to identify a user-specified algorithm."""
  pass


class UnknownKeyError(Error):
  """Indicate an error while verifying key-like objects (e.g., keyids)."""
  pass


class CryptoError(Error):
  """Indicate any cryptography-related errors."""
  pass


class BadSignatureError(CryptoError):
  """Indicate that some metadata file has a bad signature."""

  def __init__(self, metadata_role_name):
    self.metadata_role_name = metadata_role_name

  def __str__(self):
    return repr(self.metadata_role_name) + ' metadata has bad signature.'


class UnknownMethodError(CryptoError):
  """Indicate that a user-specified cryptograpthic method is unknown."""
  pass


class UnsupportedLibraryError(Error):
  """Indicate that a supported library could not be located or imported."""
  pass


class DownloadError(Error):
  """Indicate an error occurred while attempting to download a file."""
  pass


class DownloadLengthMismatchError(DownloadError):
  """Indicate that a mismatch of lengths was seen while downloading a file."""

  def __init__(self, expected_length, observed_length):
    self.expected_length = expected_length #bytes
    self.observed_length = observed_length #bytes

  def __str__(self):
    return 'Observed length (' + repr(self.observed_length)+\
           ') <= expected length (' + repr(self.expected_length) + ').'


class KeyAlreadyExistsError(Error):
  """Indicate that a key already exists and cannot be added."""
  pass