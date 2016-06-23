#!/usr/bin/env python

"""
<Program Name>
  formats.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  Refactored April 30, 2012. -vladimir.v.diaz

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  A central location for all format-related checking of TUF objects.
  Note: 'formats.py' depends heavily on 'schema.py', so the 'schema.py'
  module should be read and understood before tackling this module.

  'formats.py' can be broken down into three sections.  (1) Schemas and object
  matching.  (2) Classes that represent Role Metadata and help produce correctly
  formatted files.  (3) Functions that help produce or verify TUF objects.

  The first section deals with schemas and object matching based on format.
  There are two ways of checking the format of objects.  The first method
  raises a 'ssl_crypto.FormatError' exception if the match fails and the other
  returns a Boolean result.

  ssl_crypto.formats.<SCHEMA>.check_match(object)
  ssl_crypto.formats.<SCHEMA>.matches(object)

  Example:

  rsa_key = {'keytype': 'rsa'
             'keyid': 34892fc465ac76bc3232fab 
             'keyval': {'public': 'public_key',
                        'private': 'private_key'}

  ssl_crypto.formats.RSAKEY_SCHEMA.check_match(rsa_key)
  ssl_crypto.formats.RSAKEY_SCHEMA.matches(rsa_key)

  In this example, if a dict key or dict value is missing or incorrect,
  the match fails.  There are numerous variations of object checking
  provided by 'formats.py' and 'schema.py'.

  The second section deals with the role metadata classes.  There are
  multiple top-level roles, each with differing metadata formats.
  Example:
  
  root_object = ssl_crypto.formats.RootFile.from_metadata(root_metadata_file)
  targets_metadata = ssl_crypto.formats.TargetsFile.make_metadata(...)

  The input and output of these classes are checked against their respective
  schema to ensure correctly formatted metadata.

  The last section contains miscellaneous functions related to the format of
  TUF objects.
  Example: 
  
  signable_object = make_signable(unsigned_object)
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import binascii
import calendar
import re
import string
import datetime
import time

import ssl_crypto
import ssl_crypto.schema as SCHEMA

import six

# Note that in the schema definitions below, the 'SCHEMA.Object' types allow
# additional keys which are not defined. Thus, any additions to them will be
# easily backwards compatible with clients that are already deployed.

# A hexadecimal value in '23432df87ab..' format.
HASH_SCHEMA = SCHEMA.RegularExpression(r'[a-fA-F0-9]+')

# A dict in {'sha256': '23432df87ab..', 'sha512': '34324abc34df..', ...} format.
HASHDICT_SCHEMA = SCHEMA.DictOf(
  key_schema = SCHEMA.AnyString(),
  value_schema = HASH_SCHEMA)

# A hexadecimal value in '23432df87ab..' format.
HEX_SCHEMA = SCHEMA.RegularExpression(r'[a-fA-F0-9]+')

# A key identifier (e.g., a hexadecimal value identifying an RSA key).
KEYID_SCHEMA = HASH_SCHEMA

# A list of KEYID_SCHEMA.
KEYIDS_SCHEMA = SCHEMA.ListOf(KEYID_SCHEMA)

# The method used for a generated signature (e.g., 'RSASSA-PSS').
SIG_METHOD_SCHEMA = SCHEMA.AnyString()

# Supported hash algorithms.
HASHALGORITHMS_SCHEMA = SCHEMA.ListOf(SCHEMA.OneOf(
  [SCHEMA.String('md5'), SCHEMA.String('sha1'),
   SCHEMA.String('sha224'), SCHEMA.String('sha256'),
   SCHEMA.String('sha384'), SCHEMA.String('sha512')]))

# The contents of an encrypted TUF key.  Encrypted TUF keys are saved to files
# in this format.
ENCRYPTEDKEY_SCHEMA = SCHEMA.AnyBytes()

# The minimum number of bits for an RSA key.  Must be 2048 bits, or greater
# (recommended by TUF). Crypto modules like 'pycrypto_keys.py' may set further
# restrictions on keys (e.g., the number of bits must be a multiple of 256).
# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1
RSAKEYBITS_SCHEMA = SCHEMA.Integer(lo=2048)

# The number of hashed bins, or the number of delegated roles.  See
# delegate_hashed_bins() in 'repository_tool.py' for an example.  Note:
# Tools may require further restrictions on the number of bins, such
# as requiring them to be a power of 2. 
NUMBINS_SCHEMA = SCHEMA.Integer(lo=1)

# A PyCrypto signature.
PYCRYPTOSIGNATURE_SCHEMA = SCHEMA.AnyBytes()

# A pyca-cryptography signature.
PYCACRYPTOSIGNATURE_SCHEMA = SCHEMA.AnyBytes()

# An RSA key in PEM format.
PEMRSA_SCHEMA = SCHEMA.AnyString()

# A string representing a password.
PASSWORD_SCHEMA = SCHEMA.AnyString()

# A list of passwords.
PASSWORDS_SCHEMA = SCHEMA.ListOf(PASSWORD_SCHEMA)

# The actual values of a key, as opposed to meta data such as a key type and
# key identifier ('rsa', 233df889cb).  For RSA keys, the key value is a pair of
# public and private keys in PEM Format stored as strings.
KEYVAL_SCHEMA = SCHEMA.Object(
  object_name = 'KEYVAL_SCHEMA',
  public = SCHEMA.AnyString(),
  private = SCHEMA.Optional(SCHEMA.AnyString()))

# Supported TUF key types. 
KEYTYPE_SCHEMA = SCHEMA.OneOf(
  [SCHEMA.String('rsa'), SCHEMA.String('ed25519')])

# A generic TUF key.  All TUF keys should be saved to metadata files in this
# format.
KEY_SCHEMA = SCHEMA.Object(
  object_name = 'KEY_SCHEMA',
  keytype = SCHEMA.AnyString(),
  keyval = KEYVAL_SCHEMA)

# A TUF key object.  This schema simplifies validation of keys that may be
# one of the supported key types.
# Supported key types: 'rsa', 'ed25519'.
ANYKEY_SCHEMA = SCHEMA.Object(
  object_name = 'ANYKEY_SCHEMA',
  keytype = KEYTYPE_SCHEMA,
  keyid = KEYID_SCHEMA,
  keyval = KEYVAL_SCHEMA)

# A list of TUF key objects.
ANYKEYLIST_SCHEMA = SCHEMA.ListOf(ANYKEY_SCHEMA)

# An RSA TUF key.
RSAKEY_SCHEMA = SCHEMA.Object(
  object_name = 'RSAKEY_SCHEMA',
  keytype = SCHEMA.String('rsa'),
  keyid = KEYID_SCHEMA,
  keyval = KEYVAL_SCHEMA)

# An ED25519 raw public key, which must be 32 bytes.
ED25519PUBLIC_SCHEMA = SCHEMA.LengthBytes(32)

# An ED25519 raw seed key, which must be 32 bytes.  
ED25519SEED_SCHEMA = SCHEMA.LengthBytes(32)

# An ED25519 raw signature, which must be 64 bytes.  
ED25519SIGNATURE_SCHEMA = SCHEMA.LengthBytes(64)

# Required installation libraries expected by the repository tools and other
# cryptography modules.
REQUIRED_LIBRARIES_SCHEMA = SCHEMA.ListOf(SCHEMA.OneOf(
  [SCHEMA.String('general'), SCHEMA.String('ed25519'), SCHEMA.String('rsa')]))

# An ed25519 TUF key.
ED25519KEY_SCHEMA = SCHEMA.Object(
  object_name = 'ED25519KEY_SCHEMA',
  keytype = SCHEMA.String('ed25519'),
  keyid = KEYID_SCHEMA,
  keyval = KEYVAL_SCHEMA)

# A list of TARGETFILE_SCHEMA.
TARGETFILES_SCHEMA = SCHEMA.ListOf(TARGETFILE_SCHEMA)

# A single signature of an object.  Indicates the signature, the ID of the
# signing key, and the signing method.
# I debated making the signature schema not contain the key ID and instead have
# the signatures of a file be a dictionary with the key being the keyid and the
# value being the signature schema without the keyid. That would be under
# the argument that a key should only be able to sign a file once. However,
# one can imagine that maybe a key wants to sign multiple times with different
# signature methods.
SIGNATURE_SCHEMA = SCHEMA.Object(
  object_name = 'SIGNATURE_SCHEMA',
  keyid = KEYID_SCHEMA,
  method = SIG_METHOD_SCHEMA,
  sig = HEX_SCHEMA)

# List of SIGNATURE_SCHEMA.
SIGNATURES_SCHEMA = SCHEMA.ListOf(SIGNATURE_SCHEMA)

# A signable object.  Holds the signing role and its associated signatures.
SIGNABLE_SCHEMA = SCHEMA.Object(
  object_name = 'SIGNABLE_SCHEMA',
  signed = SCHEMA.Any(),
  signatures = SCHEMA.ListOf(SIGNATURE_SCHEMA))

# A dict where the dict keys hold a keyid and the dict values a key object.
KEYDICT_SCHEMA = SCHEMA.DictOf(
  key_schema = KEYID_SCHEMA,
  value_schema = KEY_SCHEMA)

# The format used by the key database to store keys.  The dict keys hold a key
# identifier and the dict values any object.  The key database should store
# key objects in the values (e.g., 'RSAKEY_SCHEMA', 'DSAKEY_SCHEMA').
KEYDB_SCHEMA = SCHEMA.DictOf(
  key_schema = KEYID_SCHEMA,
  value_schema = SCHEMA.Any())

# A path hash prefix is a hexadecimal string.
PATH_HASH_PREFIX_SCHEMA = HEX_SCHEMA

# A list of path hash prefixes.
PATH_HASH_PREFIXES_SCHEMA = SCHEMA.ListOf(PATH_HASH_PREFIX_SCHEMA)
