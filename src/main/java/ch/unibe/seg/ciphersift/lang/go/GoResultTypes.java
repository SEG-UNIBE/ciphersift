/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.lang.go;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Result types of Go API functions and methods (SPEC 17.12, DECISIONS B-G-B1a): which named type a call
 * returns, by result position, so that {@code k, err := rsa.GenerateKey(r, 2048); k.Sign(…)} types {@code k}.
 * Written from the pkg.go.dev documentation of the listed packages (spec/PROVENANCE.md, "Boosters, round t2");
 * only types that some bundled {@code method} pattern names, or that lead to one, are listed.
 */
final class GoResultTypes {
    private GoResultTypes() {}

    /** Qualified function name ({@code path.F}) or method name ({@code path.T.M}) → result types by position. */
    static final Map<String, List<String>> RESULTS = new HashMap<>();

    private static void r(String fn, String... types) {
        if (RESULTS.put(fn, List.of(types)) != null) {
            throw new IllegalStateException("duplicate " + fn);
        }
    }

    static {
        // crypto/rsa (https://pkg.go.dev/crypto/rsa)
        r("crypto/rsa.GenerateKey", "crypto/rsa.PrivateKey");
        r("crypto/rsa.GenerateMultiPrimeKey", "crypto/rsa.PrivateKey");
        // crypto/ecdsa (https://pkg.go.dev/crypto/ecdsa)
        r("crypto/ecdsa.GenerateKey", "crypto/ecdsa.PrivateKey");
        r("crypto/ecdsa.ParseRawPrivateKey", "crypto/ecdsa.PrivateKey");
        r("crypto/ecdsa.ParseUncompressedPublicKey", "crypto/ecdsa.PublicKey");
        r("crypto/ecdsa.PrivateKey.ECDH", "crypto/ecdh.PrivateKey");
        r("crypto/ecdsa.PublicKey.ECDH", "crypto/ecdh.PublicKey");
        // crypto/ed25519 and its golang.org/x/crypto alias package
        for (String p : List.of("crypto/ed25519", "golang.org/x/crypto/ed25519")) {
            r(p + ".GenerateKey", p + ".PublicKey", p + ".PrivateKey");
            r(p + ".NewKeyFromSeed", p + ".PrivateKey");
        }
        // crypto/elliptic (https://pkg.go.dev/crypto/elliptic)
        for (String c : List.of("P224", "P256", "P384", "P521")) {
            r("crypto/elliptic." + c, "crypto/elliptic.Curve");
        }
        // crypto/ecdh (https://pkg.go.dev/crypto/ecdh)
        for (String c : List.of("P256", "P384", "P521", "X25519")) {
            r("crypto/ecdh." + c, "crypto/ecdh.Curve");
        }
        r("crypto/ecdh.Curve.GenerateKey", "crypto/ecdh.PrivateKey");
        r("crypto/ecdh.Curve.NewPrivateKey", "crypto/ecdh.PrivateKey");
        r("crypto/ecdh.Curve.NewPublicKey", "crypto/ecdh.PublicKey");
        r("crypto/ecdh.PrivateKey.PublicKey", "crypto/ecdh.PublicKey");
        // crypto/mlkem (https://pkg.go.dev/crypto/mlkem)
        for (String n : List.of("768", "1024")) {
            r("crypto/mlkem.GenerateKey" + n, "crypto/mlkem.DecapsulationKey" + n);
            r("crypto/mlkem.NewDecapsulationKey" + n, "crypto/mlkem.DecapsulationKey" + n);
            r("crypto/mlkem.NewEncapsulationKey" + n, "crypto/mlkem.EncapsulationKey" + n);
            r("crypto/mlkem.DecapsulationKey" + n + ".EncapsulationKey", "crypto/mlkem.EncapsulationKey" + n);
        }
        // crypto/x509 (https://pkg.go.dev/crypto/x509)
        r("crypto/x509.ParseCertificate", "crypto/x509.Certificate");
        r("crypto/x509.ParseCertificateRequest", "crypto/x509.CertificateRequest");
        r("crypto/x509.ParseRevocationList", "crypto/x509.RevocationList");
        r("crypto/x509.NewCertPool", "crypto/x509.CertPool");
        r("crypto/x509.SystemCertPool", "crypto/x509.CertPool");
        r("crypto/x509.ParsePKCS1PrivateKey", "crypto/rsa.PrivateKey");
        r("crypto/x509.ParsePKCS1PublicKey", "crypto/rsa.PublicKey");
        r("crypto/x509.ParseECPrivateKey", "crypto/ecdsa.PrivateKey");
        // go-ethereum accounts/keystore (https://pkg.go.dev/github.com/ethereum/go-ethereum/accounts/keystore, DECISIONS T3-G2)
        r("github.com/ethereum/go-ethereum/accounts/keystore.NewKeyStore",
                "github.com/ethereum/go-ethereum/accounts/keystore.KeyStore");
        // golang.org/x/crypto/ssh (https://pkg.go.dev/golang.org/x/crypto/ssh)
        String ssh = "golang.org/x/crypto/ssh";
        for (String f : List.of("NewSignerFromKey", "NewSignerFromSigner", "ParsePrivateKey",
                "ParsePrivateKeyWithPassphrase")) {
            r(ssh + "." + f, ssh + ".Signer");
        }
        r(ssh + ".ParsePublicKey", ssh + ".PublicKey");
        r(ssh + ".NewPublicKey", ssh + ".PublicKey");
        r(ssh + ".ParseAuthorizedKey", ssh + ".PublicKey");
        r(ssh + ".Signer.PublicKey", ssh + ".PublicKey");
        // github.com/sigstore/sigstore/pkg/signature (B2, https://pkg.go.dev/github.com/sigstore/sigstore/pkg/signature)
        r("github.com/sigstore/sigstore/pkg/signature.GetAlgorithmDetails",
                "github.com/sigstore/sigstore/pkg/signature.AlgorithmDetails");
    }

    /** The result type at {@code index} of a call of {@code fn}, or null. */
    static String result(String fn, int index) {
        List<String> l = RESULTS.get(fn);
        return l == null || index >= l.size() ? null : l.get(index);
    }
}
