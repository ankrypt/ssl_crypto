#!/usr/bin/env python

"""
<Program Name>
  test_keydb.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 2012.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'keydb.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import logging

from ...ssl_commons import exceptions as ssl_commons__exceptions
from .. import formats as ssl_crypto__formats
from .. import keys as ssl_crypto__keys
from .. import keydb as ssl_crypto__keydb

logger = logging.getLogger('ssl_crypto__test_keydb')


# Generate the three keys to use in our test cases.
KEYS = []
for junk in range(3):
  KEYS.append(ssl_crypto__keys.generate_rsa_key(2048))



class TestKeydb(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    ssl_crypto__keydb.clear_keydb()



  def test_clear_keydb(self):
    # Test condition ensuring 'clear_keydb()' clears the keydb database.
    # Test the length of the keydb before and after adding a key.
    self.assertEqual(0, len(ssl_crypto__keydb._keydb_dict))
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    ssl_crypto__keydb._keydb_dict[keyid] = rsakey
    self.assertEqual(1, len(ssl_crypto__keydb._keydb_dict))
    ssl_crypto__keydb.clear_keydb()
    self.assertEqual(0, len(ssl_crypto__keydb._keydb_dict))

    # Test condition for unexpected argument.
    self.assertRaises(TypeError, ssl_crypto__keydb.clear_keydb, 'unexpected_argument')



  def test_get_key(self):
    # Test conditions using valid 'keyid' arguments.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    ssl_crypto__keydb._keydb_dict[keyid] = rsakey
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']
    ssl_crypto__keydb._keydb_dict[keyid2] = rsakey2
    
    self.assertEqual(rsakey, ssl_crypto__keydb.get_key(keyid))
    self.assertEqual(rsakey2, ssl_crypto__keydb.get_key(keyid2))
    self.assertNotEqual(rsakey2, ssl_crypto__keydb.get_key(keyid))
    self.assertNotEqual(rsakey, ssl_crypto__keydb.get_key(keyid2))

    # Test conditions using invalid arguments.
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.get_key, None)
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.get_key, 123)
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.get_key, ['123'])
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.get_key, {'keyid': '123'})
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.get_key, '')

    # Test condition using a 'keyid' that has not been added yet.
    keyid3 = KEYS[2]['keyid']
    self.assertRaises(ssl_commons__exceptions.UnknownKeyError, ssl_crypto__keydb.get_key, keyid3)

    

  def test_add_key(self):
    # Test conditions using valid 'keyid' arguments.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']
    rsakey3 = KEYS[2]
    keyid3 = KEYS[2]['keyid']
    self.assertEqual(None, ssl_crypto__keydb.add_key(rsakey, keyid))
    self.assertEqual(None, ssl_crypto__keydb.add_key(rsakey2, keyid2))
    self.assertEqual(None, ssl_crypto__keydb.add_key(rsakey3))
    
    self.assertEqual(rsakey, ssl_crypto__keydb.get_key(keyid))
    self.assertEqual(rsakey2, ssl_crypto__keydb.get_key(keyid2))
    self.assertEqual(rsakey3, ssl_crypto__keydb.get_key(keyid3))

    # Test conditions using arguments with invalid formats.
    ssl_crypto__keydb.clear_keydb()
    rsakey3['keytype'] = 'bad_keytype'

    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.add_key, None, keyid)
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.add_key, '', keyid)
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.add_key, ['123'], keyid)
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.add_key, {'a': 'b'}, keyid)
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.add_key, rsakey, {'keyid': ''})
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.add_key, rsakey, 123)
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.add_key, rsakey, False)
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.add_key, rsakey, ['keyid'])
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.add_key, rsakey3, keyid3)
    rsakey3['keytype'] = 'rsa' 
    
    # Test conditions where keyid does not match the rsakey.
    self.assertRaises(ssl_commons__exceptions.Error, ssl_crypto__keydb.add_key, rsakey, keyid2)
    self.assertRaises(ssl_commons__exceptions.Error, ssl_crypto__keydb.add_key, rsakey2, keyid)

    # Test conditions using keyids that have already been added.
    ssl_crypto__keydb.add_key(rsakey, keyid)
    ssl_crypto__keydb.add_key(rsakey2, keyid2)
    self.assertRaises(ssl_commons__exceptions.KeyAlreadyExistsError, ssl_crypto__keydb.add_key, rsakey)
    self.assertRaises(ssl_commons__exceptions.KeyAlreadyExistsError, ssl_crypto__keydb.add_key, rsakey2)


  
  def test_remove_key(self):
    # Test conditions using valid keyids. 
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']
    rsakey3 = KEYS[2]
    keyid3 = KEYS[2]['keyid']
    ssl_crypto__keydb.add_key(rsakey, keyid)
    ssl_crypto__keydb.add_key(rsakey2, keyid2)
    ssl_crypto__keydb.add_key(rsakey3, keyid3)

    self.assertEqual(None, ssl_crypto__keydb.remove_key(keyid))
    self.assertEqual(None, ssl_crypto__keydb.remove_key(keyid2))
    
    # Ensure the keys were actually removed.
    self.assertRaises(ssl_commons__exceptions.UnknownKeyError, ssl_crypto__keydb.get_key, keyid)
    self.assertRaises(ssl_commons__exceptions.UnknownKeyError, ssl_crypto__keydb.get_key, keyid2)

    # Test for 'keyid' not in keydb.
    self.assertRaises(ssl_commons__exceptions.UnknownKeyError, ssl_crypto__keydb.remove_key, keyid)
    
    # Test condition for unknown key argument.
    self.assertRaises(ssl_commons__exceptions.UnknownKeyError, ssl_crypto__keydb.remove_key, '1')

    # Test conditions for arguments with invalid formats.
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.remove_key, None)
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.remove_key, '')
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.remove_key, 123)
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.remove_key, ['123'])
    self.assertRaises(ssl_commons__exceptions.FormatError, ssl_crypto__keydb.remove_key, {'bad': '123'})
    self.assertRaises(ssl_commons__exceptions.Error, ssl_crypto__keydb.remove_key, rsakey3) 



  def test_create_keydb_from_root_metadata(self):
    # Test condition using a valid 'root_metadata' argument.
    rsakey = KEYS[0]
    keyid = KEYS[0]['keyid']
    rsakey2 = KEYS[1]
    keyid2 = KEYS[1]['keyid']
    
    keydict = {keyid: rsakey, keyid2: rsakey2}

    roledict = {'Root': {'keyids': [keyid], 'threshold': 1},
                'Targets': {'keyids': [keyid2, keyid], 'threshold': 1}}
    version = 8
    consistent_snapshot = False
    expires = '1985-10-21T01:21:00Z'
    compression_algorithms = ['gz']
    
    root_metadata = ssl_crypto__formats.RootFile.make_metadata(version,
                                                       expires,
                                                       keydict, roledict,
                                                       consistent_snapshot,
                                                       compression_algorithms)
    self.assertEqual(None, ssl_crypto__keydb.create_keydb_from_root_metadata(root_metadata))
    
    ssl_crypto__keydb.create_keydb_from_root_metadata(root_metadata)
    
    # Ensure 'keyid' and 'keyid2' were added to the keydb database.
    self.assertEqual(rsakey, ssl_crypto__keydb.get_key(keyid))
    self.assertEqual(rsakey2, ssl_crypto__keydb.get_key(keyid2))

    # Test conditions for arguments with invalid formats.
    self.assertRaises(ssl_commons__exceptions.FormatError,
                      ssl_crypto__keydb.create_keydb_from_root_metadata, None)
    self.assertRaises(ssl_commons__exceptions.FormatError,
                      ssl_crypto__keydb.create_keydb_from_root_metadata, '')
    self.assertRaises(ssl_commons__exceptions.FormatError,
                      ssl_crypto__keydb.create_keydb_from_root_metadata, 123)
    self.assertRaises(ssl_commons__exceptions.FormatError,
                      ssl_crypto__keydb.create_keydb_from_root_metadata, ['123'])
    self.assertRaises(ssl_commons__exceptions.FormatError,
                      ssl_crypto__keydb.create_keydb_from_root_metadata, {'bad': '123'})

    # Test conditions for correctly formatted 'root_metadata' arguments but
    # containing incorrect keyids or key types.  In these conditions, the keys
    # should not be added to the keydb database and a warning should be logged.
    ssl_crypto__keydb.clear_keydb()
    
    # 'keyid' does not match 'rsakey2'.
    keydict[keyid] = rsakey2
    
    # Key with invalid keytype.
    rsakey3 = KEYS[2]
    keyid3 = KEYS[2]['keyid']
    rsakey3['keytype'] = 'bad_keytype'
    keydict[keyid3] = rsakey3
    version = 8
    expires = '1985-10-21T01:21:00Z'
    compression_algorithms = ['gz']
    
    root_metadata = ssl_crypto__formats.RootFile.make_metadata(version,
                                                       expires,
                                                       keydict, roledict,
                                                       consistent_snapshot,
                                                       compression_algorithms)
    self.assertEqual(None, ssl_crypto__keydb.create_keydb_from_root_metadata(root_metadata))

    # Ensure only 'keyid2' was added to the keydb database.  'keyid' and
    # 'keyid3' should not be stored.
    self.assertEqual(rsakey2, ssl_crypto__keydb.get_key(keyid2))
    self.assertRaises(ssl_commons__exceptions.UnknownKeyError, ssl_crypto__keydb.get_key, keyid)
    self.assertRaises(ssl_commons__exceptions.UnknownKeyError, ssl_crypto__keydb.get_key, keyid3)
    rsakey3['keytype'] = 'rsa'



# Run unit test.
if __name__ == '__main__':
  unittest.main()
