// t3 J-CAT, J-TSCOPE: catalog accessors and test configurations
dependencies {
    implementation(libs.bouncycastle.bcprov)      // want: dep.maven org.bouncycastle:bcprov-jdk18on 1.78
    testImplementation(libs.nimbusJwt)            // want: dep.maven com.nimbusds:nimbus-jose-jwt 10.10 test
    implementation(libs.guava)                    // not crypto: nothing
    implementation(libs.bundles.crypto)           // want: dep.maven com.google.crypto.tink:tink 1.13.0
    println(libs.versions.nimbus.get())           // a version accessor: nothing
}
