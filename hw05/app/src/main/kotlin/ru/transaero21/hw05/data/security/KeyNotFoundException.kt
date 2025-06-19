package ru.transaero21.hw05.data.security

import java.security.KeyStoreException

class KeyNotFoundException(keyAlias: String) : KeyStoreException("Key with alias \"$keyAlias\" not found")