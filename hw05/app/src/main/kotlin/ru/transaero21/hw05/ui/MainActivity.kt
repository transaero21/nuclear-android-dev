package ru.transaero21.hw05.ui

import android.content.Context

import android.os.Bundle
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import ru.transaero21.hw05.data.storage.FilesManager
import ru.transaero21.hw05.data.security.SecurityManager
import ru.transaero21.hw05.utils.Constants
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.SignatureException
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException

class MainActivity : FragmentActivity() {

    private val securityManager = SecurityManager(keyAlias = Constants.KEY_ALIAS)
    private val filesManager = FilesManager(context = this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            MaterialTheme {
                AppContent(securityManager = securityManager, filesManager = filesManager)
            }
        }
    }

    @Composable
    private fun AppContent(securityManager: SecurityManager, filesManager: FilesManager) {
        val context = LocalContext.current
        var encryptedData by remember { mutableStateOf<ByteArray?>(null) }
        var showFileSelector by remember { mutableStateOf(false) }
        val files by filesManager.files.collectAsState()

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = {
                    if (context is FragmentActivity) {
                        promptUserAuthentication(
                            context,
                            onSuccess = {
                                showToast(context, "Authentication succeeded")
                            },
                            onFailure = { errorMsg ->
                                showToast(context, "Authentication failed: $errorMsg")
                            }
                        )
                    } else {
                        showToast(context, "Authentication requires FragmentActivity context")
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Authenticate")
            }

            Button(
                onClick = {
                    try {
                        securityManager.createKeyIfNeeded()
                        showToast(context, "Key created or already exists")
                    } catch (e: Exception) {
                        handleException(context, e)
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Create Key")
            }

            Button(
                onClick = {
                    try {
                        encryptedData = securityManager.encrypt(Constants.TARGET_MESSAGE)
                        showToast(context, "Text encrypted")
                    } catch (e: Exception) {
                        handleException(context, e)
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Encrypt Text")
            }

            Button(
                onClick = {
                    try {
                        encryptedData?.let { data ->
                            val isVerified = validate(data)
                            if (isVerified) {
                                showToast(context, "Verification succeeded")
                            } else {
                                showToast(context, "Verification failed")
                            }
                        } ?: showToast(context, "No data to verify")
                    } catch (e: Exception) {
                        handleException(context, e)
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Verify Text")
            }

            Button(
                onClick = {
                    try {
                        encryptedData?.let {
                            filesManager.saveEncryptedFile(it)
                            showToast(context, "Encrypted file saved")
                        } ?: showToast(context, "No encrypted data to save")
                    } catch (e: Exception) {
                        handleException(context, e)
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Save Encrypted File")
            }

            Button(
                onClick = {
                    try {
                        showFileSelector = files.isNotEmpty()
                        if (!showFileSelector) {
                            showToast(context, "No files found")
                        }
                    } catch (e: Exception) {
                        handleException(context, e)
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Read Encrypted File")
            }
        }

        if (showFileSelector) {
            AlertDialog(
                onDismissRequest = { showFileSelector = false },
                title = { Text("Select Encrypted File") },
                text = {
                    LazyColumn {
                        items(files.toList()) { (name, uri) ->
                            Text(
                                text = name,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        showFileSelector = false
                                        filesManager.readEncryptedFile(uri)?.let { fileData ->
                                            val isVerified = validate(fileData)
                                            if (isVerified) {
                                                encryptedData = fileData
                                                showToast(context, "File loaded and verified")
                                            } else {
                                                showToast(context, "File verification failed")
                                            }
                                        } ?: showToast(context, "Failed to read file")
                                    }
                                    .padding(8.dp)
                            )
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showFileSelector = false }) {
                        Text("Close")
                    }
                }
            )
        }
    }

    private fun validate(ciphertext: ByteArray) = securityManager.decrypt(ciphertext) == Constants.TARGET_MESSAGE

    private fun handleException(context: Context, e: Exception) {
        // Kang from BasicAndroidKeyStoreFragment.java
        val message = when (e) {
            is NoSuchAlgorithmException ->
                "RSA not supported"
            is InvalidAlgorithmParameterException ->
                "Invalid Algorithm Parameter Exception"
            is NoSuchProviderException ->
                "No such provider: AndroidKeyStore"
            is KeyStoreException ->
                e.message ?: "KeyStore exception occurred"
            is UnrecoverableEntryException ->
                "KeyPair not recovered"
            is UserNotAuthenticatedException ->
                "Unlock device to continue"
            is InvalidKeyException ->
                "Invalid Key"
            is SignatureException ->
                "Invalid Signature"
            is CertificateException ->
                "Error occurred while loading certificates"
            is IOException ->
                "IO Exception"
            else -> throw e
        }

        Log.e(Constants.LOG_TAG, message, e)
        Toast.makeText(context, message, Toast.LENGTH_LONG).show()
    }

    private fun promptUserAuthentication(
        activity: FragmentActivity,
        onSuccess: () -> Unit,
        onFailure: (errorMsg: String) -> Unit
    ) {
        val biometricManager = BiometricManager.from(activity)

        when (biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        ) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                val biometricPrompt = BiometricPrompt(activity, activity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            onSuccess()
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            super.onAuthenticationError(errorCode, errString)
                            onFailure(errString.toString())
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            onFailure("Authentication failed")
                        }
                    })

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Please authenticate")
                    .setSubtitle("Authentication is required to access secure key")
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    )
                    .build()

                biometricPrompt.authenticate(promptInfo)
            }
            else -> {
                onFailure("Biometric authentication not available")
            }
        }
    }

    private fun showToast(context: Context, msg: String) {
        Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
    }
}