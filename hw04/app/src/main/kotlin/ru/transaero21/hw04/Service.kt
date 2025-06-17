package ru.transaero21.hw04

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log

class Service : Service() {
    override fun onBind(intent: Intent): IBinder? {
        Log.i(Application.LOG_TAG, "Service onBind()")
        return null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(Application.LOG_TAG, "Service onStartCommand()")
        return START_NOT_STICKY
    }
}