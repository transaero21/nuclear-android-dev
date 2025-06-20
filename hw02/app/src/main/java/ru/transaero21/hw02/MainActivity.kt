package ru.transaero21.hw02

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.*
import java.text.DecimalFormat

class MainActivity : ComponentActivity() {
    private var bigList: MutableList<ByteArray>? = null
    private val decimalFormat = DecimalFormat("#,##0.00")

    private val updateInterval = 500L
    private var memoryJob: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val runtime = Runtime.getRuntime()
        val memoryState = mutableStateOf(getMemoryInfo(runtime))

        setContent {
            MaterialTheme {
                MemoryScreen(
                    memoryInfo = memoryState.value,
                    onAddMemory = {
                        if (bigList == null) bigList = mutableListOf()
                        repeat(16) { bigList?.add(ByteArray(1024 * 1024)) }
                        Toast.makeText(this, "Added 16MB usage", Toast.LENGTH_SHORT).show()
                        memoryState.value = getMemoryInfo(runtime)
                    },
                    onClearMemory = {
                        bigList = null
                        Toast.makeText(this, "Cleared reference", Toast.LENGTH_SHORT).show()
                        memoryState.value = getMemoryInfo(runtime)
                    },
                    onCallGc = {
                        System.runFinalization()
                        System.gc()
                        Toast.makeText(this, "\uD83E\uDD19 GC called", Toast.LENGTH_SHORT).show()
                        memoryState.value = getMemoryInfo(runtime)
                    }
                )
            }
        }

        memoryJob = lifecycleScope.launch {
            while (isActive) {
                memoryState.value = getMemoryInfo(runtime)
                delay(updateInterval)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        memoryJob?.cancel()
    }

    private fun getMemoryInfo(runtime: Runtime): MemoryInfo {
        val used = (runtime.totalMemory() - runtime.freeMemory()).toDouble()
        val max = runtime.maxMemory().toDouble()
        val usedMB = used / (1024 * 1024)
        val maxMB = max / (1024 * 1024)
        val percent = (used / max) * 100
        return MemoryInfo(
            used = decimalFormat.format(usedMB),
            max = decimalFormat.format(maxMB),
            percent = decimalFormat.format(percent),
            hasReference = bigList != null
        )
    }

    @Composable
    private fun MemoryScreen(
        memoryInfo: MemoryInfo,
        onAddMemory: () -> Unit,
        onClearMemory: () -> Unit,
        onCallGc: () -> Unit
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = """
                Memory Usage:
                Used: ${memoryInfo.used} MB
                Max: ${memoryInfo.max} MB
                Usage: ${memoryInfo.percent}%
                
                Reference Status: 
                Exists: ${if (memoryInfo.hasReference) "yes" else "no"}
                """.trimIndent(),
                style = MaterialTheme.typography.bodyLarge
            )

            Column {
                Button(
                    onClick = onAddMemory,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                ) {
                    Text("Add 16MB Usage")
                }
                Button(
                    onClick = onClearMemory,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                ) {
                    Text("Clear Reference")
                }
                Button(
                    onClick = onCallGc,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                ) {
                    Text("\uD83D\uDCDE GC")
                }
            }
        }
    }
}
