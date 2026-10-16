/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.cli;

import org.slf4j.helpers.NOP_FallbackServiceProvider;

/**
 * SLF4J provider that discards all log events. json-schema-validator logs through SLF4J; without a
 * provider SLF4J would print a warning to standard error. CipherSift does its own logging (SPEC 3.2).
 */
public final class SilentLoggingProvider extends NOP_FallbackServiceProvider {
}
