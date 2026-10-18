package j;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/** OID table entries added by DECISIONS B-A4 (SPEC 5.11). */
class Oids {
    Object[] oids() {
        return new Object[] {
            new ASN1ObjectIdentifier("1.3.36.3.2.1"), // want: java.hash.rmd160 RIPEMD160 oid=1.3.36.3.2.1
            new ASN1ObjectIdentifier("1.3.132.0.26"), // want: java.asym.ec sect233k1 sect233k1 oid=1.3.132.0.26
            new ASN1ObjectIdentifier("1.3.6.1.5.5.8.1.2"), // want: java.mac.hmac HmacSHA1 oid=1.3.6.1.5.5.8.1.2
            new ASN1ObjectIdentifier("1.2.840.113549.1.12.1.3"), // want: java.kdf.pbe PBEWithSHA1AndDESede oid=1.2.840.113549.1.12.1.3
            new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6"), // want: java.sym.3des DESedeWrap oid=1.2.840.113549.1.9.16.3.6
            new ASN1ObjectIdentifier("1.2.156.10197.1.401"), // no Java SM3 rule: nothing
        };
    }
}
