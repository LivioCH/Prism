package com.example.prism.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory
import java.security.SecureRandom

/**
 * Local, offline database. Room on top of SQLCipher, so the file on disk is encrypted (AES-256).
 */
@Database(
    entities = [ScanHistoryEntity::class, WhitelistEntity::class, BlacklistEntity::class, UrlCacheEntity::class],
    version = 2,
    exportSchema = false
)
abstract class PrismDatabase : RoomDatabase() {
    abstract fun historyDao(): ScanHistoryDao
    abstract fun whitelistDao(): WhitelistDao
    abstract fun blacklistDao(): BlacklistDao
    abstract fun urlCacheDao(): UrlCacheDao

    companion object {
        private const val DB_NAME = "prism_secure.db"

        /** v1 -> v2: adds the blacklist table. Existing history, whitelist and cache are kept. */
        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE IF NOT EXISTS `blacklist` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `value` TEXT NOT NULL, `created_at` INTEGER NOT NULL)")
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS `index_blacklist_value` ON `blacklist` (`value`)")
            }
        }

        @Volatile
        private var instance: PrismDatabase? = null

        /**
         * Opens (and creates on first run) the encrypted database. Call from a background thread:
         * it forces the file to open so a bad key shows up here and not on the first query.
         */
        fun open(context: Context): PrismDatabase = instance ?: synchronized(this) {
            instance ?: build(context.applicationContext).also { instance = it }
        }

        private fun build(app: Context): PrismDatabase {
            SQLiteDatabase.loadLibs(app)
            return try {
                create(app).also { it.openHelper.writableDatabase }
            } catch (e: Exception) {
                // Key lost (e.g. app data partly restored) -> the old file can never be read again.
                // Start over with an empty database instead of crashing on every launch.
                app.deleteDatabase(DB_NAME)
                DbKey.reset(app)
                create(app).also { it.openHelper.writableDatabase }
            }
        }

        private fun create(app: Context): PrismDatabase =
            Room.databaseBuilder(app, PrismDatabase::class.java, DB_NAME)
                .openHelperFactory(SupportFactory(DbKey.passphrase(app)))
                .addMigrations(MIGRATION_1_2)
                .build()
    }
}

/**
 * SQLCipher passphrase.
 *
 * HONEST NOTE (proof-of-concept): a random 256-bit key is generated on first launch and kept in the
 * app's private SharedPreferences. It is not hard-coded in the source, and the database file is
 * encrypted on disk, but anyone who can read the app's private storage (rooted device, backup
 * extraction) can read the key too. FUTURE WORK: wrap this key with an Android Keystore key
 * (hardware-backed where available) so it never sits on disk in clear text.
 */
internal object DbKey {
    private const val PREFS = "prism_db"
    private const val KEY = "k"

    /** Fresh copy every call: SupportFactory wipes the array it is given. */
    fun passphrase(context: Context): ByteArray {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val hex = prefs.getString(KEY, null) ?: ByteArray(32).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
            .also { prefs.edit().putString(KEY, it).apply() }
        return hex.toByteArray(Charsets.UTF_8)
    }

    fun reset(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(KEY).apply()
    }
}
