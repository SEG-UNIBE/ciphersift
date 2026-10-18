/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 The CipherSift Authors
 */
package ch.unibe.seg.ciphersift.wrappers;

import ch.unibe.seg.ciphersift.scan.Features;

/**
 * Which components of wrapper propagation (SPEC 18) are on, per language: name-consistent wrappers
 * (W7) and thin wrappers (W6).
 */
public record WrapperOptions(boolean javaNamed, boolean pythonNamed, boolean goNamed, boolean javaThin,
        boolean pythonThin, boolean goThin, Features features) {
    /** Wrapper propagation off (the behaviour before SPEC 18). */
    public static final WrapperOptions OFF = new WrapperOptions(false, false, false, false, false, false);

    /** Options with the default feature switches. */
    public WrapperOptions(boolean javaNamed, boolean pythonNamed, boolean goNamed, boolean javaThin,
            boolean pythonThin, boolean goThin) {
        this(javaNamed, pythonNamed, goNamed, javaThin, pythonThin, goThin, Features.DEFAULTS);
    }

    /**
     * The defaults of SPEC 18 (table), with Python thin wrappers as given by {@code --python-thin-wrappers}.
     * Go thin wrappers are off (DECISIONS T14: the owner's decision rule, Go precision).
     */
    public static WrapperOptions defaults(boolean pythonThin) {
        return defaults(pythonThin, Features.DEFAULTS);
    }

    /** The defaults with the given feature switches (SPEC 3.1). */
    public static WrapperOptions defaults(boolean pythonThin, Features features) {
        return new WrapperOptions(true, true, true, true, pythonThin, false, features);
    }

    public boolean any() {
        return javaNamed || pythonNamed || goNamed || javaThin || pythonThin || goThin;
    }

    public boolean on(Outline.Lang l) {
        return named(l) || thin(l);
    }

    public boolean named(Outline.Lang l) {
        return switch (l) {
            case JAVA -> javaNamed;
            case PYTHON -> pythonNamed;
            case GO -> goNamed;
        };
    }

    public boolean thin(Outline.Lang l) {
        return switch (l) {
            case JAVA -> javaThin;
            case PYTHON -> pythonThin;
            case GO -> goThin;
        };
    }
}
