# Repositories used to build and tune CipherSift

Every repository below was seen during CipherSift's development: its findings, recall ground truth, miss analyses
or precision judgments drove rule and heuristic choices, or it served as a development/regression input.
**Do not use any of them to score CipherSift** (or to compare it with other tools); results on them are
in-sample. An independent evaluation must use projects outside this list.

All of A, B and C were used during development; the final tuning round (t3) used 15 projects per language from
them. Commits are the exact snapshots used.

## A. Tuning set: recall ground truth, miss analysis and precision judging drove design decisions
(DECISIONS entries tagged "benchmark-informed")


| Project | Lang | Repo | Tag | Commit |
|---|---|---|---|---|
| shiro | Java | github.com/apache/shiro | shiro-root-3.0.1 | 3dcc3fc2a8dd |
| santuario | Java | github.com/apache/santuario-xml-security-java | xmlsec-4.0.4 | bec6484bbb17 |
| bitcoinj | Java | github.com/bitcoinj/bitcoinj | v0.17.1 | 55125a9ea4ff |
| web3j | Java | github.com/hyperledger-web3j/web3j | v6.0.0 | dee4e2c68d39 |
| pdfbox | Java | github.com/apache/pdfbox | 3.0.8 | 9286e47d89d6 |
| authlib | Python | github.com/lepture/authlib | v1.9.1 | 46b94870d915 |
| asyncssh | Python | github.com/ronf/asyncssh | v2.24.1 | 5dbdf1849458 |
| electrum | Python | github.com/spesmilo/electrum | 4.8.2 | 39cab571526b |
| pyhanko | Python | github.com/MatthiasValvekens/pyHanko | pyhanko-cli/v0.5.0 | 00362ec2772b |
| oauthlib | Python | github.com/oauthlib/oauthlib | v4.0.0 | 145a9a4690cb |
| go-jose | Go | github.com/go-jose/go-jose | v4.1.6 | a0111f82742f |
| sops | Go | github.com/getsops/sops | v3.13.3 | 26e2f4784ca6 |
| cosign | Go | github.com/sigstore/cosign | v3.1.3 | 11926fa5bbbb |
| nebula | Go | github.com/slackhq/nebula | v1.11.2 | 4dbeff889cf6 |
| go-crypto | Go | github.com/ProtonMail/go-crypto | v1.5.2 | 7537b30ff8aa |

## B. Development and regression inputs (micro/mid/large pilot corpus; smoke tests, gauntlet spot checks)

| Project | Lang | Repo | Tag | Commit |
|---|---|---|---|---|
| micro-java, micro-python, micro-go | J/P/Go | hand-written (BF-CBOM corpus) | - | - |
| micro-pyjwt | Python | github.com/jpadilla/pyjwt | 2.9.0 | 868cf4a |
| micro-golang-jwt | Go | github.com/golang-jwt/jwt | v5.3.1 | 7ceae61 |
| mid-jjwt | Java | github.com/jwtk/jjwt | 0.12.6 | 0df9756 |
| mid-jasypt | Java | github.com/jasypt/jasypt | jasypt-1.9.3 | bb8a518 |
| mid-paramiko | Python | github.com/paramiko/paramiko | 3.5.0 | 23f9200 |
| mid-mineru | Python | github.com/opendatalab/MinerU | HEAD | ed50cc1 |
| mid-age | Go | github.com/FiloSottile/age | v1.3.2 | b74dce4 |
| mid-smallstep-crypto | Go | github.com/smallstep/crypto | v0.91.0 | 622be32 |
| large-kafka | Java | github.com/apache/kafka | 3.8.0 | 771b957 |
| large-keycloak | Java | github.com/keycloak/keycloak | 26.0.0 | 632f214 |
| large-ansible | Python | github.com/ansible/ansible | v2.17.0 | a26c0f7 |
| large-vault | Go | github.com/hashicorp/vault | v2.1.2 | 76fdd65 |

## C. Development additions (rounds t2 and t3)

Five projects per language drawn (seeded) from the round-t2 corpus; used for tuning, development and regression.

| Project | Lang | Repo | Tag | Commit |
|---|---|---|---|---|
| b4 | Go | github.com/DanielLavrushin/b4 | v1.87.0 | 5979d13de277 |
| chain33 | Go | github.com/33cn/chain33 | v1.72.7 | b990038f95cc |
| desktop-app | Go | github.com/ivpn/desktop-app | v3.16.1 | 1fd063064f46 |
| node | Go | github.com/mysteriumnetwork/node | 1.39.7 | 46f6d152f58c |
| xray-core | Go | github.com/XTLS/Xray-core | v26.10.17 | 92ccc939aaf4 |
| api-gateway | Java | github.com/membrane/api-gateway | v7.7.1 | 3e2cc274518f |
| cardano-client-lib | Java | github.com/bloxbean/cardano-client-lib | v0.7.3 | f1130177b027 |
| pac4j | Java | github.com/pac4j/pac4j | pac4j-parent-6.5.9 | 0dd628aa3d16 |
| uaa | Java | github.com/cloudfoundry/uaa | v79.9.0 | 76e4b1dbbf6c |
| xchange | Java | github.com/knowm/XChange | xchange-6.0.0 | 320d97c96813 |
| fritap | Python | github.com/fkie-cad/friTap | v2.5.2 | d7398a153755 |
| netexec | Python | github.com/Pennyw0rth/NetExec | v1.5.1 | c7dc286ba65d |
| nutshell | Python | github.com/cashubtc/nutshell | 0.21.0 | a9749146c6bd |
| paperforge | Python | github.com/QJHWC/PaperForge | v3.0.0 | 46d1ad22bc25 |
| privacyidea | Python | github.com/privacyidea/privacyidea | v3.14 | 31db0ecd87bb |

## D. Not repositories, but development input
Official API docs and registries (Oracle JCA standard names, pkg.go.dev, Go api/go1*.txt, docs.python.org,
cryptography.io and other library docs, IANA JOSE/COSE/TLS/SSH registries, NIST) were used to write rules.
