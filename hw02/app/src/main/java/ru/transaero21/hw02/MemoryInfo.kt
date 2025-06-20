package ru.transaero21.hw02

data class MemoryInfo(
    val used: String,
    val max: String,
    val percent: String,
    val hasReference: Boolean
)