plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.vulnzoo.bulbbee_app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.vulnzoo.bulbbee_app"
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    lint {
        abortOnError = false
    }
}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
}
