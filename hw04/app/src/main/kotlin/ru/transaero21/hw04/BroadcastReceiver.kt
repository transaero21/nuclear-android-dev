package ru.transaero21.hw04

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class BroadcastReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        Log.i(Application.LOG_TAG, "BroadcastReceiver onReceive()")
    }
}