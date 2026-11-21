package com.example.prism.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanHistoryDao {
    @Insert
    suspend fun insert(row: ScanHistoryEntity): Long

    @Query("SELECT * FROM scan_history ORDER BY timestamp DESC, id DESC LIMIT 500")
    fun observeAll(): Flow<List<ScanHistoryEntity>>

    @Query("SELECT COUNT(*) FROM scan_history")
    fun observeTotal(): Flow<Int>

    @Query("SELECT COUNT(*) FROM scan_history WHERE verdict = :verdict")
    fun observeCount(verdict: String): Flow<Int>

    @Query("DELETE FROM scan_history")
    suspend fun clear()
}

@Dao
interface WhitelistDao {
    /** Returns -1 when the value is already there (unique index, IGNORE). */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(row: WhitelistEntity): Long

    @Query("DELETE FROM whitelist WHERE value = :value")
    suspend fun delete(value: String)

    @Query("SELECT COUNT(*) FROM whitelist WHERE value IN (:values)")
    suspend fun countMatches(values: List<String>): Int

    @Query("SELECT * FROM whitelist ORDER BY created_at DESC, id DESC")
    fun observeAll(): Flow<List<WhitelistEntity>>
}

@Dao
interface UrlCacheDao {
    @Query("SELECT * FROM url_cache WHERE `key` = :key LIMIT 1")
    suspend fun get(key: String): UrlCacheEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun put(row: UrlCacheEntity)

    @Query("DELETE FROM url_cache WHERE cached_at < :olderThan")
    suspend fun deleteOlderThan(olderThan: Long)
}

@Dao
interface BlacklistDao {
    /** Returns -1 when the value is already there (unique index, IGNORE). */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(row: BlacklistEntity): Long

    @Query("DELETE FROM blacklist WHERE value = :value")
    suspend fun delete(value: String)

    @Query("SELECT COUNT(*) FROM blacklist WHERE value IN (:values)")
    suspend fun countMatches(values: List<String>): Int

    @Query("SELECT value FROM blacklist")
    suspend fun allValues(): List<String>

    @Query("SELECT * FROM blacklist ORDER BY created_at DESC, id DESC")
    fun observeAll(): Flow<List<BlacklistEntity>>
}
