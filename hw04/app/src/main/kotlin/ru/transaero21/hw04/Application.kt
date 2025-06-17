package ru.transaero21.hw04

import android.app.Application
import android.util.Log

class Application : Application() {
    override fun onCreate() {
        super.onCreate()
        Log.i(LOG_TAG, "Application onCreate()")
    }

    companion object {
        const val LOG_TAG = "EntryPoints"
    }
}