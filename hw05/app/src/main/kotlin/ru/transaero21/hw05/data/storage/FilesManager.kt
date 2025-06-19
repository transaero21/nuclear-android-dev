package ru.transaero21.hw05.data.storage

import android.content.ContentUris
import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import android.widget.Toast
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import ru.transaero21.hw05.utils.Constants
import java.io.IOException

class FilesManager(private val context: Context) {

    private val _files = MutableStateFlow<Map<String, Uri>>(emptyMap())
    val files: StateFlow<Map<String, Uri>> = _files.asStateFlow()

    init {
        loadEncryptedFiles()
    }

    private fun loadEncryptedFiles() = CoroutineScope(Dispatchers.IO).launch {
        emitFiles()
    }

    private suspend fun emitFiles() {
        val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
        val projection = arrayOf(
            MediaStore.Downloads._ID,
            MediaStore.Downloads.DISPLAY_NAME
        )
        val selection = "${MediaStore.Downloads.DISPLAY_NAME} LIKE ?"
        val selectionArgs = arrayOf("${Constants.FILE_PREFIX}%")
        val sortOrder = "${MediaStore.Downloads.DATE_MODIFIED} DESC"

        context.contentResolver.query(collection, projection, selection, selectionArgs, sortOrder)?.use { cursor ->
            val idCol = cursor.getColumnIndexOrThrow(MediaStore.Downloads._ID)
            val nameCol = cursor.getColumnIndexOrThrow(MediaStore.Downloads.DISPLAY_NAME)

            val result = mutableMapOf<String, Uri>()
            while (cursor.moveToNext()) {
                val name = cursor.getString(nameCol)
                val id = cursor.getLong(idCol)
                val uri = ContentUris.withAppendedId(collection, id)
                result[name] = uri
            }
            _files.emit(result)
        }
    }

    fun saveEncryptedFile(data: ByteArray) = CoroutineScope(Dispatchers.IO).launch {
        val fileName = "${Constants.FILE_PREFIX}${System.currentTimeMillis() / 1000}.bin"

        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
            put(MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream")
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
        }

        val resolver = context.contentResolver
        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)

        try {
            uri?.let {
                resolver.openOutputStream(it)?.use { stream ->
                    stream.write(data)
                    showToast("File saved: $fileName")
                }
            } ?: throw IOException("Failed to create file")
        } catch (e: Exception) {
            showToast("Save error: ${e.message}")
        }

        emitFiles()
    }

    fun readEncryptedFile(uri: Uri): ByteArray? {
        return try {
            context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        } catch (e: Exception) {
            showToast("Read error: ${e.message}")
            null
        }
    }

    private fun showToast(text: String) {
        CoroutineScope(Dispatchers.Main).launch {
            Toast.makeText(context, text, Toast.LENGTH_SHORT).show()
        }
    }
}
