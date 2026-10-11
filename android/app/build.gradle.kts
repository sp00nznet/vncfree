plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "net.sp00nz.vncfree"
    compileSdk = 36
    // The NDK is only here for its C compiler and linker: ring, under rustls, has some C.
    ndkVersion = "26.1.10909125"

    defaultConfig {
        applicationId = "net.sp00nz.vncfree"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.3.1"
    }

    buildTypes {
        // ponytail: R8 off — there is next to no Kotlin to shrink; the APK is the .so
        release { isMinifyEnabled = false }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1,INDEX.LIST}" }
    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("rustLibs"))
}

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}

// The RFB engine is the Windows client's own Rust, built by cargo for each ABI and
// packaged as libvncfree_jni.so. Always release: a debug build decodes too slowly to
// tell whether a session is laggy because of the network or because of us.
// ponytail: 64-bit only — add armv7-linux-androideabi when someone has a 32-bit phone
val abis = mapOf("arm64-v8a" to "aarch64-linux-android", "x86_64" to "x86_64-linux-android")
val cargo = abis.map { (abi, triple) ->
    tasks.register<Exec>("cargo-$abi") {
        workingDir = rootDir.resolve("jni")
        commandLine("cargo", "build", "--release", "--locked", "--target", triple)
        doFirst {
            val os = System.getProperty("os.name").lowercase()
            val host = when {
                "windows" in os -> "windows-x86_64"
                "mac" in os -> "darwin-x86_64"
                else -> "linux-x86_64"
            }
            val bin = android.ndkDirectory.resolve("toolchains/llvm/prebuilt/$host/bin")
            val clang = bin.resolve(triple + "26-clang" + if ("windows" in os) ".cmd" else "")
            val env = triple.replace('-', '_')
            environment("CARGO_TARGET_${env.uppercase()}_LINKER", clang.path)
            environment("CC_$env", clang.path)
            environment("AR_$env", bin.resolve("llvm-ar").path)
        }
    }
}
val rustLibs = tasks.register<Sync>("rustLibs") {
    dependsOn(cargo)
    into(layout.buildDirectory.dir("rustLibs"))
    abis.forEach { (abi, triple) ->
        from(rootDir.resolve("../target/$triple/release/libvncfree_jni.so")) { into(abi) }
    }
}
tasks.named("preBuild") { dependsOn(rustLibs) }

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.06.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.1")
}
