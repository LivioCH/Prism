package com.example.prism.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** One row per Manual Scan. Permanent history shown in the History tab. */
@Entity(tableName = "scan_history")
data class ScanHistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val input: String,
    val kind: String,                                   // "URL" | "TEXT" | "PHONE"
    val verdict: String,                                // "SAFE" | "SUSPICIOUS" | "DANGEROUS"
    @ColumnInfo(name = "ml_score") val mlScore: Double?, // phishing probability 0..1, null when no ML ran
    val reasons: String,                                // JSON array, see ReasonsJson
    val timestamp: Long
)

/** Hosts (or full normalized URLs) the user chose to trust. Unique per value. */
@Entity(tableName = "whitelist", indices = [Index(value = ["value"], unique = true)])
data class WhitelistEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val value: String,
    @ColumnInfo(name = "created_at") val createdAt: Long
)

/** Result of an earlier heuristic+ML run, so the same URL is not analysed twice. */
@Entity(tableName = "url_cache")
data class UrlCacheEntity(
    @PrimaryKey val key: String,                        // normalized URL, see UrlKeys.cacheKey
    val verdict: String,
    @ColumnInfo(name = "ml_score") val mlScore: Double?,
    val reasons: String,
    @ColumnInfo(name = "cached_at") val cachedAt: Long
)

/** Hosts (or full normalized URLs) the user blocked. Always DANGEROUS; wins over every other check. */
@Entity(tableName = "blacklist", indices = [Index(value = ["value"], unique = true)])
data class BlacklistEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val value: String,
    @ColumnInfo(name = "created_at") val createdAt: Long
)
