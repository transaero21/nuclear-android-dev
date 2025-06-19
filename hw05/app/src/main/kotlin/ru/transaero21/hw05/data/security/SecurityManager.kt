package ru.transaero21.hw05.data.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class SecurityManager(private val keyAlias: String = "secure_message_ke1") {
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val transformation = "AES/CBC/PKCS7Padding"
    private val ivSize = 16

    fun createKeyIfNeeded() {
        if (!keyStore.containsAlias(keyAlias)) {
            createNewKey()
        }
    }

    fun encrypt(plaintext: String): ByteArray {
        val secretKey = keyStore.getKey(keyAlias, null) as SecretKey?
            ?: throw KeyNotFoundException(keyAlias)

        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv
        val encrypted = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
        return iv + encrypted
    }

    fun decrypt(ciphertext: ByteArray): String {
        val secretKey = keyStore.getKey(keyAlias, null) as SecretKey?
            ?: throw KeyNotFoundException(keyAlias)

        val cipher = Cipher.getInstance(transformation)
        val iv = ciphertext.copyOfRange(0, ivSize)
        val encrypted = ciphertext.copyOfRange(ivSize, ciphertext.size)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))

        val decrypted = cipher.doFinal(encrypted)
        return String(decrypted, StandardCharsets.UTF_8)
    }

    private fun createNewKey() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                60,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
            .build()

        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }
}