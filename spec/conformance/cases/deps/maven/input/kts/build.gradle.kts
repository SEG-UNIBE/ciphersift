plugins { java }

val sshdVersion = "2.12.1"

dependencies {
    implementation("org.apache.sshd:sshd-core:$sshdVersion")
    implementation("at.favre.lib:bcrypt:0.10.2")
    implementation(group = "de.mkammerer", name = "argon2-jvm", version = "2.11")
    implementation(libs.jose4j)
    testImplementation("org.assertj:assertj-core:3.25.3")
}
