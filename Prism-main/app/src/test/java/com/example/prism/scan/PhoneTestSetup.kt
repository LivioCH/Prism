package com.example.prism.scan

import io.michaelrocks.libphonenumber.android.MetadataLoader
import io.michaelrocks.libphonenumber.android.PhoneNumberUtil
import java.io.File

/**
 * Unit tests have no Android context, so libphonenumber's metadata (normally read from the app's assets)
 * is read from the merged-assets folder that Gradle builds. `unitTests.isIncludeAndroidResources = true`
 * makes sure that folder exists before the tests run. Tests run with the `app` folder as working directory.
 */
object PhoneTestSetup {
    private val assets = File("build/intermediates/assets/debug/mergeDebugAssets")

    private val loader = MetadataLoader { name ->
        PhoneTestSetup::class.java.getResourceAsStream(name)
            ?: File(assets, name.trimStart('/')).takeIf { it.exists() }?.inputStream()
    }

    fun init() = PhoneNumbers.init(PhoneNumberUtil.createInstance(loader))
}
