/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.wrappers;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

/** The tokeniser and alias list of SPEC 18.6. */
class NameTokensTest {
    @Test
    void tokens() {
        assertEquals(List.of("hmac", "sha512"), NameTokens.tokens("hmacSha512"));
        assertEquals(List.of("hmac", "sha256"), NameTokens.tokens("HMACSha256"));
        assertEquals(List.of("sha3", "256"), NameTokens.tokens("sha3_256"));
        assertEquals(List.of("new", "aesgcm"), NameTokens.tokens("newAESGCM"));
        assertEquals(List.of("x509", "cert"), NameTokens.tokens("x509Cert"));
        assertEquals(List.of("md5", "a"), NameTokens.tokens("md5A"));
        assertEquals(List.of("sha256"), NameTokens.tokens("SHA256"));
        assertEquals(List.of("get", "ed25519", "key"), NameTokens.tokens("get_Ed25519$Key"));
        assertEquals(List.of(), NameTokens.tokens("__"));
    }

    @Test
    void pathologicalNames() {
        assertEquals(Set.of(), NameTokens.families("aes".repeat(43) + "x")); // 130 characters: too long
        assertEquals(Set.of(), NameTokens.families("ecd".repeat(42) + "q")); // many failing branches, memoised
        assertEquals(Set.of("AES"), NameTokens.families("aes" + "with".repeat(30)));
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
        "sha256;SHA2", "sha256d;SHA2", "sha_256;SHA2", "hmac_sha_512;HMAC SHA2", "hmacSha512;HMAC SHA2",
        "HMACSHA256;HMAC SHA2", "SHA256withRSA;RSA SHA2", "sha3_256;SHA3", "sha384;SHA2", "keccak256;SHA3",
        "newAESGCM;AES", "aes_128_gcm;AES", "hashSha3;SHA3", "aes256gcm;AES", "secp256k1;EC", "ecdsa_sign;EC", "createSecp256k1KeyPair;EC",
        "ecies_decrypt_message;EC", "parseX509;x509", "loadKeyStore;java.cert.keystore",
        "ParseX25519Recipient;Curve25519", "ed448Sign;Ed448", "newMLKEM768;ML-KEM", "pbkdf2_hmac;HMAC PBKDF2",
        "tripleDes;DES 3DES", "ecDsa;DSA EC", "loadTrustStore;java.cert.keystore", "desede;3DES", "md5A;MD5", "ripemd160;RIPEMD160", "getSHA1;SHA1",
        "aesthetic;", "description;", "ecb;", "decode;", "rsassa;", "hashTwice;", "digest;", "ec;EC",
        "dh_params;DH", "Blake2b;BLAKE2", "md5sum;MD5", "sha1hex;SHA1", "x25519PK;Curve25519", "chacha20poly1305;ChaCha20 Poly1305"})
    void families(String name, String expected) {
        Set<String> want = expected == null ? Set.of() : Set.of(expected.split(" "));
        assertEquals(want, NameTokens.families(name), name);
    }
}
