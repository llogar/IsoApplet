/*
 * IsoApplet: A Java Card PKI applet aimiing for ISO 7816 compliance.
 * Copyright (C) 2014  Philip Wendland (wendlandphilip@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

package net.pwendland.javacard.pki.isoapplet;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.framework.OwnerPIN;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Key;
import javacard.security.RSAPublicKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacardx.crypto.Cipher;
import javacardx.apdu.ExtendedLength;
import javacard.security.CryptoException;
import javacard.security.Signature;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.KeyAgreement;
import org.globalplatform.GPSystem;

/**
 * \brief The IsoApplet class.
 *
 * This applet has a filesystem and accepts relevant ISO 7816 instructions.
 * Access control is forced through a PIN and a SO PIN. PIN can be unblocked with PUK.
 * The PUK is optional (Set DEF_PUK_MUST_BE_SET). By default PUK is set with SO PIN value.
 * Security Operations are being processed directly in
 * this class. Only private keys are stored as Key-objects. Only security
 * operations with private keys can be performed (decrypt with RSA, sign with RSA,
 * sign with ECDSA).
 *
 * \author Philip Wendland
 */
public class IsoApplet extends Applet implements ExtendedLength {
    /* API Version */
    public static final byte API_VERSION_MAJOR = (byte) 0x00;
    public static final byte API_VERSION_MINOR = (byte) 0x07;

    /* App & token Version */
    public static final byte HW_VERSION = 0x00;
    public static final byte SW_VERSION = 0x07;

    /* Card-specific configuration */
    public static final boolean DEF_EXT_APDU = false;
    public static final boolean DEF_PRIVATE_KEY_IMPORT_ALLOWED = false;
    public static final boolean DEF_PUK_MUST_BE_SET = false;
    public static final byte    DEF_PIN_MAX_TRIES = 3;
    public static final byte    DEF_PIN_MAX_LENGTH = 12;
    public static final byte    DEF_PUK_LENGTH = 12;
    public static final byte    DEF_SOPIN_LENGTH = 12;

    /* ISO constants not in the "ISO7816" interface */
    // File system related INS:
    public static final byte INS_CREATE_FILE = (byte) 0xE0;
    public static final byte INS_UPDATE_BINARY = (byte) 0xD6;
    public static final byte INS_READ_BINARY = (byte) 0xB0;
    public static final byte INS_DELETE_FILE = (byte) 0xE4;
    // Other INS:
    public static final byte INS_VERIFY = (byte) 0x20;
    public static final byte INS_CHANGE_REFERENCE_DATA = (byte) 0x24;
    public static final byte INS_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x46;
    public static final byte INS_RESET_RETRY_COUNTER = (byte) 0x2C;
    public static final byte INS_MANAGE_SECURITY_ENVIRONMENT = (byte) 0x22;
    public static final byte INS_PERFORM_SECURITY_OPERATION = (byte) 0x2A;
    public static final byte INS_GET_RESPONSE = (byte) 0xC0;
    public static final byte INS_PUT_DATA = (byte) 0xDB;
    public static final byte INS_GET_CHALLENGE = (byte) 0x84;
    public static final byte INS_GET_DATA = (byte) 0xCA;
    public static final byte INS_DELETE_KEY = (byte) 0xE5;
    public static final byte INS_INITIALISE_CARD = (byte) 0x51;
    public static final byte INS_ERASE_CARD = (byte) 0x50;
    public static final byte INS_GET_VALUE = (byte) 0x6C;

    // SC-HSM
    // com.licel.jcardsim.card.applet.0.AID=E82B0601040181C31F0201
    // com.licel.jcardsim.card.ATR=3BFE1800008131FE458031815448534D31738021408107FA
    public static final boolean SCHSM = true;
    public static final byte SCHSM_PIN_REF = (byte) 0x81;
    public static final byte SCHSM_SOPIN_REF = (byte) 0x88;
    public static final byte SCHSM_PIN_LENGTH = 6;
    public static final byte SCHSM_SOPIN_LENGTH = 16;
    public static final byte INS_SCHSM_IMPORT_DKEK_SHARE = (byte) 0x52;
    public static final byte INS_SCHSM_UPDATE_BINARY = (byte) 0xD7;
    public static final byte INS_SCHSM_READ_BINARY = (byte) 0xB1;
    public static final byte INS_SCHSM_INIT_CARD = (byte) 0x50;
    public static final byte INS_SCHSM_ENUMERATE_OBJECTS = (byte) 0x58;
    public static final byte INS_SCHSM_SIGN = (byte) 0x68;
    public static final byte INS_SCHSM_DECIPHER = (byte) 0x62;

    // SC-HSM C_DevAut data
    private byte[] c_DevAut = null;
    private ECPrivateKey prk_DevAut = null;

    // GET VALUE P1 parameters:
    public static final byte OPT_P1_SERIAL = (byte) 0x01;
    public static final byte OPT_P1_MEM = (byte) 0x02;
    public static final byte OPT_P1_INITCOUNTER = (byte) 0x03;

    // Status words:
    public static final short SW_PIN_TRIES_REMAINING = 0x63C0; // See ISO 7816-4 section 7.5.1
    public static final short SW_COMMAND_NOT_ALLOWED_GENERAL = 0x6900;
    public static final short SW_NO_PIN_DEFINED = (short)0x9802;
    public static final short SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;
    public static final short SW_REFERENCE_DATA_NOT_FOUND = 0x6A88;

    /* PIN, PUK, SO PIN and key related constants */
    // PIN:
    private static final byte PIN_REF = (byte) 0x01;
    private static final byte PIN_MIN_LENGTH = 4;
    // PUK:
    private static final byte PUK_REF = (byte) 0x02;
    private static final byte PUK_MAX_TRIES = 5;
    // SO PIN:
    private static final byte SOPIN_REF = (byte) 0x0F;
    private static final byte SOPIN_MAX_TRIES = 5;
    // Keys:
    private static final short KEY_MAX_COUNT = 16;

    private static final byte MAX_SERIAL_LEN = 8;
    private static final byte MAX_HISTBYTES_LEN = 8;

    private static final short DEF_RSA_KEYLEN = KeyBuilder.LENGTH_RSA_2048;

    private static final byte ALG_GEN_RSA = (byte) 0xF3;
    private static final byte ALG_RSA_PAD_NONE = (byte) 0x10;
    private static final byte ALG_RSA_PAD_PKCS1 = (byte) 0x11;

    private static final byte ALG_GEN_EC = (byte) 0xEC;
    private static final byte ALG_ECDSA_SHA1 = (byte) 0x21;
    private static final byte ALG_ECDSA_PRECOMPUTED_HASH = (byte) 0x22;
    private static final byte ALG_ECDH = (byte) 0x23;

    private static final short KeyBuilder_LENGTH_RSA_3072 = 3072;

    private static final short LENGTH_EC_FP_224 = 224;
    private static final short LENGTH_EC_FP_256 = 256;
    private static final short LENGTH_EC_FP_320 = 320;
    private static final short LENGTH_EC_FP_384 = 384;
    private static final short LENGTH_EC_FP_512 = 512;
    private static final short LENGTH_EC_FP_521 = 521;

    /* Card/Applet lifecycle states */
    private static final byte STATE_CREATION = (byte) 0x00; // No restrictions, SO PIN not set yet.
    private static final byte STATE_INITIALISATION = (byte) 0x01; // SO PIN set, PIN & PUK not set yet.
    private static final byte STATE_OPERATIONAL_ACTIVATED = (byte) 0x05; // PIN is set, data is secured.
    private static final byte STATE_OPERATIONAL_DEACTIVATED = (byte) 0x04; // Applet usage is deactivated. (Unused at the moment.)
    private static final byte STATE_TERMINATED = (byte) 0x0C; // Applet usage is terminated. (Unused at the moment.)

    private static final short API_FEATURE_EXT_APDU = (short) 0x0001;
    private static final short API_FEATURE_SECURE_RANDOM = (short) 0x0002;
    private static final short API_FEATURE_ECDSA_SHA1 = (short) 0x0004;
    private static final short API_FEATURE_RSA_4096 = (short) 0x0008;
    private static final short API_FEATURE_ECDSA_PRECOMPUTED_HASH = (short) 0x0010;
    private static final short API_FEATURE_ECDH = (short) 0x0020;
    private static final short API_FEATURE_IMPORT_EXPORT = (short) 0x0040;
    private static final short API_FEATURE_ENABLE_IMPORT_EXPORT = (short) 0x0080;
    private static final short API_FEATURE_RSA_PAD_NONE = (short) 0x0100;

    /* Set to exclude IMPORT_EXPORT functionality at compile time */
    public static final boolean ENABLE_IMPORT_EXPORT = false;

    /* Support for card backup/restore */
    private boolean IMPORT_EXPORT = false;

    /* Other constants */
    // "ram_buf" is used for:
    //	* GET RESPONSE (caching for response APDUs):
    //		- GENERATE ASYMMETRIC KEYPAIR: RSA >= 1024 bit and ECC >= 256 bit public key information.
    //	* Command Chaining or extended APDUs (caching of command APDU data):
    //		- DECIPHER (RSA >= 1024 bit).
    //		- GENERATE ASYMMETRIC KEYPAIR: ECC curve parameters if large (> 256 bit) prime fields are used.
    //		- PUT DATA: RSA and ECC private key import.
    private static final short RAM_BUF_SIZE = (short) (SCHSM ? 1320 : 660);
    // "ram_chaining_cache" is used for:
    //		- Caching of the amount of bytes remainung.
    //		- Caching of the current send position.
    //		- Determining how many operations had previously been performed in the chain (re-use CURRENT_POS)
    //		- Caching of the current INS (Only one chain at a time, for one specific instruction).
    //		- Various tag related infos during key import/export
    private static final short RAM_CHAINING_CACHE_SIZE = (short) 5;
    private static final short RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING = (short) 0;
    private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_POS = (short) 1;
    private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_INS = (short) 2;
    private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2 = (short) 3;
    private static final short RAM_CHAINING_CACHE_TAGS_SENT = (short) 4;
    private static final short RAM_CHAINING_CACHE_LAST_TAG = (short) 4;

    private static final short TAG_NONE   = (short)0x0000;
    private static final short RSA_TAG_92 = (short)0x0001;
    private static final short RSA_TAG_93 = (short)0x0002;
    private static final short RSA_TAG_94 = (short)0x0004;
    private static final short RSA_TAG_95 = (short)0x0008;
    private static final short RSA_TAG_96 = (short)0x0010;
    private static final short TAG_ALL    = (short)0x003F;

    private static final short TAG_CONFIG = (short)0xCF;
    private static final byte TAG_PIN_MAX_TRIES = (byte)0x01;
    private static final byte TAG_PUK_MUST_BE_SET = (byte)0x02;
    private static final byte TAG_ENABLE_KEY_IMPORT = (byte)0x03;
    private static final byte TAG_PIN_MAX_LENGTH = (byte)0x04;
    private static final byte TAG_PUK_LENGTH = (byte)0x05;
    private static final byte TAG_SOPIN_LENGTH = (byte)0x06;
    private static final byte TAG_KEY_MAX_COUNT = (byte)0x07;
    private static final byte TAG_HISTBYTES = (byte)0x08;
    private static final byte TAG_TRANSPORT_KEY = (byte)0x09;
    private static final byte TAG_SERIAL = (byte)0x0A;
    private static final byte TAG_IMPORT_EXPORT = (byte)0x0B;
    private static final byte TAG_API_FEATURES = (byte)0x0C;
    private static final byte TAG_INITCOUNT = (byte)0x0D;
    private static final byte TAG_STATE = (byte)0x0E;
    private static final byte TAG_PIN = (byte)0x0F;
    private static final byte TAG_PUK = (byte)0x10;
    private static final byte TAG_SOPIN = (byte)0x11;

    /**
     * \brief OwnerPIN that can return pin value via copyPIN()
     */
    class OwnerPINexp extends OwnerPIN {
        private byte val[] = null;
        public OwnerPINexp(byte tryLimit, byte maxPINSize) {
            super(tryLimit, maxPINSize);
            if (ENABLE_IMPORT_EXPORT) {
                if (IMPORT_EXPORT) {
                    val = new byte[maxPINSize];
                }
            }
        }
        public void update(byte[] pin, short offset, byte length) {
            super.update(pin, offset, length);
            if (ENABLE_IMPORT_EXPORT) {
                if (val != null) {
                    Util.arrayCopy(pin, offset, val, (short)0, length);
                }
            }
        }
        public short copyPIN(byte[] pin, short offset) {
            if (ENABLE_IMPORT_EXPORT) {
                return (short)(Util.arrayCopy(val, (short)0, pin, offset, (short)val.length) - offset);
            } else {
                return (short)0;
            }
        }
        public boolean check() {
            if (ENABLE_IMPORT_EXPORT) {
                if (val != null) {
                    return super.check(val, (short)0, (byte)val.length);
                }
            }
            return false;
        }
        public void clear() {
            if (val != null) {
                Util.arrayFillNonAtomic(val, (short)0, (short)val.length, (byte)0x00);
                val = null;
            }
        }
    }

    /* Member variables: */
    private byte state = STATE_CREATION;
    private IsoFileSystem fs = null;
    private OwnerPINexp pin = null;
    private OwnerPINexp puk = null;
    private OwnerPINexp sopin = null;
    private byte[] currentAlgorithmRef = null;
    private short[] currentPrivateKeyRef = null;
    private Key[] keys = null;
    private byte[] ram_buf = null;
    private short[] ram_chaining_cache = null;
    private Cipher rsaNoPadCipher = null;
    private Cipher rsaPkcs1Cipher = null;
    private Signature ecdsaSignatureSha1 = null;
    private Signature ecdsaSignaturePrecomp = null;
    private boolean ecdsaSHA512;
    private RandomData randomData = null;
    private KeyAgreement ecdh = null;
    private short api_features = 0;
    private byte pin_max_tries = DEF_PIN_MAX_TRIES;
    private boolean puk_must_be_set = DEF_PUK_MUST_BE_SET;
    private boolean private_key_import_allowed = DEF_PRIVATE_KEY_IMPORT_ALLOWED;
    private byte pin_max_length = DEF_PIN_MAX_LENGTH;
    private byte puk_length = DEF_PUK_LENGTH;
    private byte sopin_length = DEF_SOPIN_LENGTH;
    private short key_max_count = KEY_MAX_COUNT;
    private byte[] histBytes = null;
    private boolean histBytesSet = false;
    private boolean puk_is_set = false;
    private byte[] transport_key = null;
    private boolean have_transport_key = false;
    private byte[] serial = null;
    private RSAPrivateCrtKey rsaImportPrKey = null;
    private ECPrivateKey ecImportPrKey = null;
    private short initCounter = 0;

    /**
     * \brief Sets default parameters (serial, etc).
     *
     * \param bInit
     *			true if called from constructor
     * \param bArray
     *			the array containing installation parameters
     * \param bOffset
     *			the starting offset in bArray
     * \param bLength
     *			the length in bytes of the parameter data in bArray
     */
    private void setDefaultValues(boolean bInit, byte[] bArray, short bOffset, short bLength) {
        short Li, Lc, La;
        short bOff;
        short pos, len;
        if (bInit) {
            // Find parameters offset (La) in bArray
            Li = bArray[bOffset];
            Lc = bArray[(short)(bOffset + Li + 1)];
            La = bArray[(short)(bOffset + Li + Lc + 2)];
            bOff = (short)(bOffset + Li + Lc + 3);
            // Ignore CF tag for backward compatibility
            try {
                pos = UtilTLV.findTag(bArray, bOff, La, (byte)TAG_CONFIG);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                pos += UtilTLV.getLengthFieldLength(len);
                bOff = pos;
                La = (byte)len;
            } catch (Exception e) {
            }
        } else {
            La = bLength;
            bOff = bOffset;
        }
        if(La == 0 && bInit) {
            // Default parameters
            state = STATE_CREATION;
            serial = new byte[4];
            RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(serial, (short)0, (short)4);
            pin_max_tries = DEF_PIN_MAX_TRIES;
            api_features = 0;
            key_max_count = KEY_MAX_COUNT;
            histBytes = null;
            histBytesSet = false;
            puk_must_be_set = DEF_PUK_MUST_BE_SET;
            private_key_import_allowed = DEF_PRIVATE_KEY_IMPORT_ALLOWED;
            pin_max_length = SCHSM ? SCHSM_PIN_LENGTH : DEF_PIN_MAX_LENGTH;
            puk_length = DEF_PUK_LENGTH;
            sopin_length = SCHSM ? SCHSM_SOPIN_LENGTH : DEF_SOPIN_LENGTH;
            transport_key = null;
            have_transport_key = false;
            rsaImportPrKey = null;
            ecImportPrKey = null;
            initCounter = 0;
            return;
        }
        try {
            if (!ENABLE_IMPORT_EXPORT) {
                IMPORT_EXPORT = false;
            } else if (bInit || IMPORT_EXPORT) {
                try {
                    pos = UtilTLV.findTag(bArray, bOff, La, TAG_IMPORT_EXPORT);
                    len = UtilTLV.decodeLengthField(bArray, ++pos);
                    if(len != 1) {
                        throw InvalidArgumentsException.getInstance();
                    }
                    IMPORT_EXPORT = GPSystem.getCardState() != GPSystem.CARD_SECURED ? bArray[++pos] != 0 : false;
                } catch (NotFoundException e) {
                    IMPORT_EXPORT = false;
                }
            }
            try {
                pos = UtilTLV.findTag(bArray, bOff, La, TAG_PIN_MAX_TRIES);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    throw InvalidArgumentsException.getInstance();
                }
                pin_max_tries = bArray[++pos];
            } catch (NotFoundException e) {
                pin_max_tries = DEF_PIN_MAX_TRIES;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOff, La, TAG_PUK_MUST_BE_SET);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    throw InvalidArgumentsException.getInstance();
                }
                puk_must_be_set = bArray[++pos] != 0;
            } catch (NotFoundException e) {
                puk_must_be_set = DEF_PUK_MUST_BE_SET;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOff, La, TAG_ENABLE_KEY_IMPORT);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    throw InvalidArgumentsException.getInstance();
                }
                private_key_import_allowed = bArray[++pos] != 0;
            } catch (NotFoundException e) {
                private_key_import_allowed = DEF_PRIVATE_KEY_IMPORT_ALLOWED;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOff, La, TAG_PIN_MAX_LENGTH);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    throw InvalidArgumentsException.getInstance();
                }
                pin_max_length = bArray[++pos];
            } catch (NotFoundException e) {
                pin_max_length = SCHSM ? SCHSM_PIN_LENGTH : DEF_PIN_MAX_LENGTH;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOff, La, TAG_PUK_LENGTH);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    throw InvalidArgumentsException.getInstance();
                }
                puk_length = bArray[++pos];
            } catch (NotFoundException e) {
                puk_length = DEF_PUK_LENGTH;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOff, La, TAG_SOPIN_LENGTH);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    throw InvalidArgumentsException.getInstance();
                }
                sopin_length = bArray[++pos];
            } catch (NotFoundException e) {
                sopin_length = SCHSM ? SCHSM_SOPIN_LENGTH : DEF_SOPIN_LENGTH;
            }
            try {
                pos = UtilTLV.findTag(bArray, bOff, La, TAG_KEY_MAX_COUNT);
                len = UtilTLV.decodeLengthField(bArray, ++pos);
                if(len != 1) {
                    throw InvalidArgumentsException.getInstance();
                }
                key_max_count = bArray[++pos];
            } catch (NotFoundException e) {
                key_max_count = KEY_MAX_COUNT;
            }
            if (bInit || IMPORT_EXPORT) {
                try {
                    pos = UtilTLV.findTag(bArray, bOff, La, TAG_HISTBYTES);
                    len = UtilTLV.decodeLengthField(bArray, ++pos);
                    if(len > MAX_HISTBYTES_LEN) {
                       throw InvalidArgumentsException.getInstance();
                    }
                    histBytes = new byte[len];
                    Util.arrayCopyNonAtomic(bArray, ++pos, histBytes, (short) 0, len);
                    if (bInit) {
                        histBytesSet = false;
                    } else {
                        if (GPSystem.setATRHistBytes(bArray, pos, (byte) histBytes.length)) {
                            histBytesSet = true;
                        }
                    }
                } catch (NotFoundException e) {
                    histBytes = null;
                }
                try {
                    pos = UtilTLV.findTag(bArray, bOff, La, TAG_SERIAL);
                    len = UtilTLV.decodeLengthField(bArray, ++pos);
                    if(len > MAX_SERIAL_LEN) {
                       throw InvalidArgumentsException.getInstance();
                    }
                    serial = new byte[len];
                    Util.arrayCopyNonAtomic(bArray, ++pos, serial, (short) 0, len);
                } catch (NotFoundException e) {
                    serial = new byte[4];
                    RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(serial, (short)0, (short)4);
                }
                try {
                    pos = UtilTLV.findTag(bArray, bOff, La, TAG_TRANSPORT_KEY);
                    len = UtilTLV.decodeLengthField(bArray, ++pos);
                    if (len != 0) {
                        if(len != sopin_length) {
                            throw InvalidArgumentsException.getInstance();
                        }
                        transport_key = new byte[len];
                        Util.arrayCopyNonAtomic(bArray, ++pos, transport_key, (short) 0, len);
                        have_transport_key = true;
                    }
                } catch (NotFoundException e) {
                    transport_key = null;
                    have_transport_key = false;
                }
                if (ENABLE_IMPORT_EXPORT) {
                    try {
                        pos = UtilTLV.findTag(bArray, bOff, La, TAG_STATE);
                        len = UtilTLV.decodeLengthField(bArray, ++pos);
                        if(len != 1) {
                           throw InvalidArgumentsException.getInstance();
                        }
                        state = bArray[++pos];
                    } catch (NotFoundException e) {
                        state = STATE_CREATION;
                    }
                    try {
                        pos = UtilTLV.findTag(bArray, bOff, La, TAG_PIN);
                        len = UtilTLV.decodeLengthField(bArray, ++pos);
                        if(len > pin_max_length) {
                           throw InvalidArgumentsException.getInstance();
                        }
                        Util.arrayFillNonAtomic(ram_buf, (short)0, pin_max_length, (byte) 0x00);
                        Util.arrayCopy(bArray, ++pos, ram_buf, (short)0, len);
                        pin = new OwnerPINexp(pin_max_tries, pin_max_length);
                        pin.update(ram_buf, (short)0, pin_max_length);
                        pin.resetAndUnblock();
                    } catch (NotFoundException e) {
                        pin = null;
                    }
                    try {
                        pos = UtilTLV.findTag(bArray, bOff, La, TAG_SOPIN);
                        len = UtilTLV.decodeLengthField(bArray, ++pos);
                        if(len > sopin_length) {
                           throw InvalidArgumentsException.getInstance();
                        }
                        Util.arrayFillNonAtomic(ram_buf, (short)0, sopin_length, (byte) 0x00);
                        Util.arrayCopy(bArray, ++pos, ram_buf, (short)0, len);
                        if (sopin != null) {
                            // If transport key is used, then SO PIN has already been defined.
                            sopin = null;
                        }
                        sopin = new OwnerPINexp(SOPIN_MAX_TRIES, sopin_length);
                        sopin.update(ram_buf, (short)0, sopin_length);
                        sopin.resetAndUnblock();
                    } catch (NotFoundException e) {
                        sopin = null;
                    }
                    try {
                        pos = UtilTLV.findTag(bArray, bOff, La, TAG_PUK);
                        len = UtilTLV.decodeLengthField(bArray, ++pos);
                        if(len > puk_length + 1) {
                           throw InvalidArgumentsException.getInstance();
                        }
                        Util.arrayFillNonAtomic(ram_buf, (short)0, (short)(puk_length + 1), (byte) 0x00);
                        Util.arrayCopy(bArray, ++pos, ram_buf, (short)0, len);
                        puk = new OwnerPINexp(PUK_MAX_TRIES, puk_length);
                        puk.update(ram_buf, (short)1, puk_length);
                        puk.resetAndUnblock();
                        puk_is_set = ram_buf[0] != 0 ? true : false;
                    } catch (NotFoundException e) {
                        puk = null;
                        puk_is_set = false;
                    }
                    // TAG_API_FEATURES is not restored
                    try {
                        pos = UtilTLV.findTag(bArray, bOff, La, TAG_INITCOUNT);
                        len = UtilTLV.decodeLengthField(bArray, ++pos);
                        if(len != 2) {
                            throw InvalidArgumentsException.getInstance();
                        }
                        initCounter = Util.getShort(bArray, ++pos);
                    } catch (NotFoundException e) {
                        initCounter = 0;
                    }
                }
            }
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    /**
     * \brief Installs this applet.
     *
     * \param bArray
     *			the array containing installation parameters
     * \param bOffset
     *			the starting offset in bArray
     * \param bLength
     *			the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new IsoApplet(bArray, bOffset, bLength);
    }

    /**
     * \brief Only this class's install method should create the applet object.
     */
    protected IsoApplet(byte[] bArray, short bOffset, byte bLength) {
        setDefaultValues(true, bArray, bOffset, bLength);
        if (pin == null) {
            pin = new OwnerPINexp(pin_max_tries, pin_max_length);
        }
        if (puk == null) {
            puk = new OwnerPINexp(PUK_MAX_TRIES, puk_length);
        }
        if (sopin == null) {
            sopin = new OwnerPINexp(SOPIN_MAX_TRIES, sopin_length);
        }
        fs = new IsoFileSystem();
        try {
            Key prKey = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_4096, false);
            prKey = null;
            api_features |= API_FEATURE_RSA_4096;
        } catch (CryptoException e) {
        }
        ram_buf = JCSystem.makeTransientByteArray(RAM_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);

        ram_chaining_cache = JCSystem.makeTransientShortArray(RAM_CHAINING_CACHE_SIZE, JCSystem.CLEAR_ON_DESELECT);

        if (have_transport_key) {
            sopin.update(transport_key, (short) 0, sopin_length);
            sopin.resetAndUnblock();
            if (ENABLE_IMPORT_EXPORT) {
                if (!IMPORT_EXPORT) {
                    Util.arrayFillNonAtomic(transport_key, (short) 0, sopin_length, (byte) 0x00);
                    transport_key = null;
                }
            } else {
                Util.arrayFillNonAtomic(transport_key, (short) 0, sopin_length, (byte) 0x00);
                transport_key = null;
            }
        }

        currentAlgorithmRef = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        currentPrivateKeyRef = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        keys = new Key[key_max_count];

        currentPrivateKeyRef[0] = -1;

        rsaNoPadCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        api_features |= API_FEATURE_RSA_PAD_NONE;
        rsaPkcs1Cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

        try {
            ecdsaSignatureSha1 = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
            api_features |= API_FEATURE_ECDSA_SHA1;
        } catch (CryptoException e) {
            if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                /* Few Java Cards do not support ECDSA at all.
                 * We should not throw an exception in this cases
                 * as this would prevent installation. */
                ecdsaSignatureSha1 = null;
                api_features &= ~API_FEATURE_ECDSA_SHA1;
            } else {
                throw e;
            }
        }

        /* Some 3.0.4 cards support Signature.SIG_CIPHER_ECDSA which can sign arbitrary long input data,
         * cards that don't support this can still sign max 64 bytes of data using ALG_ECDSA_SHA_512 and
         * Signature.signPreComputedHash() */
        try {
            ecdsaSignaturePrecomp = Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL, false);
            ecdsaSHA512 = false;
        } catch (Exception e) {
            ecdsaSignaturePrecomp = null;
        }
        if (ecdsaSignaturePrecomp == null) {
            try {
                ecdsaSignaturePrecomp = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
                ecdsaSHA512 = true;
            } catch (Exception e) {
                ecdsaSignaturePrecomp = null;
            }
        }
        if (ecdsaSignaturePrecomp != null) {
            api_features |= API_FEATURE_ECDSA_PRECOMPUTED_HASH;
        } else {
            api_features &= ~API_FEATURE_ECDSA_PRECOMPUTED_HASH;
        }

        try {
            randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            api_features |= API_FEATURE_SECURE_RANDOM;
        } catch (CryptoException e) {
            if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                randomData = null;
                api_features &= ~API_FEATURE_SECURE_RANDOM;
            } else {
                throw e;
            }
        }

        try {
            ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
            api_features |= API_FEATURE_ECDH;
        } catch (Exception e) {
            ecdh = null;
            api_features &= ~API_FEATURE_ECDH;
        }

        if(DEF_EXT_APDU || SCHSM) {
            api_features |= API_FEATURE_EXT_APDU;
        }

        if (ENABLE_IMPORT_EXPORT) {
            api_features |= API_FEATURE_ENABLE_IMPORT_EXPORT;
            if (IMPORT_EXPORT) {
                api_features |= API_FEATURE_IMPORT_EXPORT;
            }
        }

        register();
    }

    /**
     * \brief This method is called whenever the applet is being deselected.
     */
    public void deselect() {
        pin.reset();
        puk.reset();
        sopin.reset();
        fs.setUserAuthenticated(false);
    }

    /**
     * \brief This method is called whenever the applet is being selected.
     */
    public boolean select() {
        // Disable IMPORT_EXPORT in CARD_SECURED cards
        if (ENABLE_IMPORT_EXPORT) {
            if (IMPORT_EXPORT && GPSystem.getCardState() == GPSystem.CARD_SECURED) {
                pin.clear();
                sopin.clear();
                puk.clear();
                IMPORT_EXPORT = false;
            }
        }
        if(state == STATE_CREATION
                || state == STATE_INITIALISATION) {
            fs.setUserAuthenticated(SOPIN_REF);
        } else {
            fs.setUserAuthenticated(false);
        }
        // Reset file selection state
        fs.selectFile(null);
        return true;
    }

    /**
     * \brief This method is called whenever the applet is being selected in SC-HSM mode
     *
     * Sends the SC-HSM config parameters
     */
    private void selectingAppletSCHSM(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
        buffer[0] = (byte)0x6F;
        buffer[1] = (byte)0x07;
        buffer[2] = (byte)0x82;
        buffer[3] = (byte)0x01;
        buffer[4] = (byte)0x78;
        buffer[5] = (byte)0x85;
        buffer[6] = (byte)0x02;
        buffer[7] = (byte)0x01;
        buffer[8] = (byte)0x02;
        apdu.setOutgoingAndSend((short) 0, (short) 9);
    }

    /**
     * \brief Processes an incoming APDU.
     *
     * \see APDU.
     *
     * \param apdu The incoming APDU.
     */
    public void process(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (state == STATE_TERMINATED) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        // Return the API version if we are being selected.
        // Format:
        //  - byte 0: Major version
        //  - byte 1: Minor version
        //  - byte 2: Feature bitmap (used to distinguish between applet features)
        if(selectingApplet()) {
            if (SCHSM) {
                selectingAppletSCHSM(apdu);
                return;
            }

            // setATRHistBytes can't be invoked from constructor, so do it here.
            if (histBytes != null && !histBytesSet) {
                Util.arrayCopyNonAtomic(histBytes, (short) 0, buffer, (short) 0, (byte) histBytes.length);
                try {
                    if (GPSystem.setATRHistBytes(buffer, (short) 0, (byte) histBytes.length)) {
                        histBytesSet = true;
                    }
                } catch (Exception e) {
                }
            }
            buffer[0] = API_VERSION_MAJOR;
            buffer[1] = API_VERSION_MINOR;
            Util.setShort(buffer, (short)2, api_features);
            buffer[4] = HW_VERSION;
            buffer[5] = SW_VERSION;
            apdu.setOutgoingAndSend((short) 0, (short) 6);
            return;
        }

        // No secure messaging at the moment
        if(apdu.isSecureMessagingCLA()) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        // Command chaining checks
        if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] != 0 || isCommandChainingCLA(apdu)) {
            short p1p2 = Util.getShort(buffer, ISO7816.OFFSET_P1);
            /*
             * Command chaining only for:
             * 	- PERFORM SECURITY OPERATION
             * 	- GENERATE ASYMMETRIC KEYKAIR
             * 	- GET DATA
             * 	- PUT DATA
             * when not using extended APDUs.
             */
            if( DEF_EXT_APDU || SCHSM ||
                    (ins != INS_PERFORM_SECURITY_OPERATION
                     && ins != INS_GENERATE_ASYMMETRIC_KEYPAIR
                     && ins != INS_GET_DATA
                     && ins != INS_PUT_DATA)) {
                ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
            }

            if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] == 0
                    && ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] == 0) {
                /* A new chain is starting - set the current INS and P1P2. */
                if(ins == 0) {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] = ins;
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] = p1p2;
                ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] = TAG_NONE;
            } else if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] != ins
                      || ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] != p1p2) {
                /* The current chain is not yet completed,
                 * but an apdu not part of the chain had been received. */
                ISOException.throwIt(SW_COMMAND_NOT_ALLOWED_GENERAL);
            } else if(!isCommandChainingCLA(apdu)) {
                /* A chain is ending, set the current INS and P1P2 to zero to indicate that. */
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] = 0;
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] = 0;
            }
        }

        // If the card expects a GET RESPONSE, no other operation should be requested.
        if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > 0 && ins != INS_GET_RESPONSE) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED_GENERAL);
        }

        if(apdu.isISOInterindustryCLA()) {
            switch (ins) {
            case ISO7816.INS_SELECT:
                fs.processSelectFile(apdu);
                break;
            case INS_READ_BINARY:
            case INS_SCHSM_READ_BINARY:
                fs.processReadBinary(apdu);
                break;
            case INS_VERIFY:
                processVerify(apdu);
                break;
            case INS_MANAGE_SECURITY_ENVIRONMENT:
                processManageSecurityEnvironment(apdu);
                break;
            case INS_PERFORM_SECURITY_OPERATION:
                processPerformSecurityOperation(apdu);
                break;
            case INS_CREATE_FILE:
                fs.processCreateFile(apdu);
                break;
            case INS_UPDATE_BINARY:
            case INS_SCHSM_UPDATE_BINARY:
                fs.processUpdateBinary(apdu);
                break;
            case INS_CHANGE_REFERENCE_DATA:
                processChangeReferenceData(apdu);
                break;
            case INS_DELETE_FILE:
                fs.processDeleteFile(apdu, SCHSM ? keys : null);
                break;
            case INS_GENERATE_ASYMMETRIC_KEYPAIR:
                processGenerateAsymmetricKeypair(apdu);
                break;
            case INS_RESET_RETRY_COUNTER:
                processResetRetryCounter(apdu);
                break;
            case INS_GET_RESPONSE:
                processGetResponse(apdu);
                break;
            case INS_PUT_DATA:
                processPutData(apdu);
                break;
            case INS_GET_CHALLENGE:
                processGetChallenge(apdu);
                break;
            case INS_GET_DATA:
                processGetData(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            } // switch
        } else {
            switch (ins) {
            // We use VERIFY apdu with proprietary class byte to bypass pinpad firewalled readers
            case INS_VERIFY:
                processVerify(apdu);
                break;
            // We use CHANGE_REFERENCE_DATA apdu with proprietary class byte for
            // implicit transition from STATE_CREATION to STATE_INITIALISATION
            case INS_CHANGE_REFERENCE_DATA:
                processChangeReferenceData(apdu);
                break;
            case INS_DELETE_KEY:
                processDeleteKey(apdu);
                break;
            case INS_INITIALISE_CARD:
                processInitialiseCard(apdu);
                break;
            case INS_ERASE_CARD:
                processEraseCard(apdu);
                break;
            case INS_GET_VALUE:
                processGetValue(apdu);
                break;
            case INS_SCHSM_ENUMERATE_OBJECTS:
                fs.processEnumerateObjects(apdu, SCHSM ? keys : null);
                break;
            case INS_SCHSM_SIGN:
                processSignSCHSM(apdu);
                break;
            case INS_SCHSM_DECIPHER:
                processDecipherSCHSM(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
    }

    /**
     * \brief Parse the apdu's CLA byte to determine if the apdu is the first or second-last part of a chain.
     *
     * The Java Card API version 2.2.2 has a similar method (APDU.isCommandChainingCLA()), but tests have shown
     * that some smartcard platform's implementations are wrong (not according to the JC API specification),
     * specifically, but not limited to, JCOP 2.4.1 R3.
     *
     * \param apdu The apdu.
     *
     * \return true If the apdu is the [1;last[ part of a command chain,
     *			false if there is no chain or the apdu is the last part of the chain.
     */
    static boolean isCommandChainingCLA(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        return ((byte)(buf[0] & (byte)0x10) == (byte)0x10);
    }

    /**
     * \brief Process the VERIFY apdu (INS = 20) in SC-HSM mode.
     *
     * This apdu is used to verify a PIN and authenticate the user. A counter is used
     * to limit unsuccessful tries (i.e. brute force attacks).
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, ISO7816.SW_WRONG_LENGTH, SW_REFERENCE_DATA_NOT_FOUND,  SW_PIN_TRIES_REMAINING, SW_AUTHENTICATION_METHOD_BLOCKED.
     */
    private void processVerifySCHSM(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;

        if (state == STATE_OPERATIONAL_DEACTIVATED) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // Must be User PIN
        if ((p2 != SCHSM_PIN_REF) || (state == STATE_CREATION)) {
            ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
        }

        // Just get remaining tries
        if(lc == 0) {
            if( pin.isValidated() ) {
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
            }
            if (pin.getTriesRemaining() > 0)
                ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
            ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
        }

        // Invalid User PIN length
        if(lc != SCHSM_PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check User PIN
        if(!pin.check(buf, offset_cdata, SCHSM_PIN_LENGTH)) {
            fs.setUserAuthenticated(false);
            if (pin.getTriesRemaining() > 0)
                ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
            ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
        }

        fs.setUserAuthenticated(SCHSM_PIN_REF);
    }

    /**
     * \brief Process the VERIFY apdu (INS = 20).
     *
     * This apdu is used to verify a PIN and authenticate the user. A counter is used
     * to limit unsuccessful tries (i.e. brute force attacks).
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_INCORRECT_P1P2, ISO7816.SW_WRONG_LENGTH, SW_PIN_TRIES_REMAINING, SW_AUTHENTICATION_METHOD_BLOCKED.
     */
    private void processVerify(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short offset_cdata;
        short lc;
        byte ref = buf[ISO7816.OFFSET_P2];

        if (SCHSM) {
            processVerifySCHSM(apdu);
            return;
        }

        /* P1 FF means logout. */
        if (buf[ISO7816.OFFSET_P1] == (byte)0xFF) {
            pin.reset();
            puk.reset();
            sopin.reset();
            fs.setUserAuthenticated(false);
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }

        // P1 00 only at the moment. (key-reference 01 = PIN, key-reference 0F = SO PIN)
        if(buf[ISO7816.OFFSET_P1] != 0x00 || (ref != PIN_REF && ref != SOPIN_REF)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // Lc might be 0, in this case the caller checks if verification is required.
        if (ref == PIN_REF) {
            if((lc > 0 && (lc < PIN_MIN_LENGTH) || lc > pin_max_length)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        } else if (ref == SOPIN_REF) {
            if(lc > 0 && lc != sopin_length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }

        // Caller asks if verification is needed.
        if(lc == 0) {
            if (ref == PIN_REF) {
                if (state == STATE_CREATION || state == STATE_INITIALISATION) {
                    ISOException.throwIt(SW_NO_PIN_DEFINED);
                } else if (state == STATE_OPERATIONAL_ACTIVATED) {
                    if( pin.isValidated() ) {
                        ISOException.throwIt(ISO7816.SW_NO_ERROR);
                    }
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
                } else if (state == STATE_OPERATIONAL_DEACTIVATED) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            } else if (ref == SOPIN_REF) {
                if (state == STATE_CREATION) {
                    if (!have_transport_key || sopin.isValidated()) {
                        // No verification required.
                        ISOException.throwIt(ISO7816.SW_NO_ERROR);
                    }
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                } else if (state == STATE_INITIALISATION || state == STATE_OPERATIONAL_ACTIVATED) {
                    if( sopin.isValidated() ) {
                        ISOException.throwIt(ISO7816.SW_NO_ERROR);
                    }
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                } else if (state == STATE_OPERATIONAL_DEACTIVATED) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            } else {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }

        if (ref == PIN_REF) {
            // Pad the PIN if not done by caller, so no garbage from the APDU will be part of the PIN.
            Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(pin_max_length - lc), (byte) 0x00);

            // Check the PIN.
            if(!pin.check(buf, offset_cdata, pin_max_length)) {
                fs.setUserAuthenticated(false);
                if (pin.getTriesRemaining() > 0)
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
                ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
            } else {
                fs.setUserAuthenticated(PIN_REF);
            }
        } else if (ref == SOPIN_REF) {
            // Check the SOPIN.
            if(!sopin.check(buf, offset_cdata, sopin_length)) {
                fs.setUserAuthenticated(false);
                if (sopin.getTriesRemaining() > 0)
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                if (have_transport_key)
                    state = STATE_TERMINATED;
                ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
            } else {
                fs.setUserAuthenticated(SOPIN_REF);
                if(state == STATE_CREATION && have_transport_key) {
                    // Set PUK (may be re-set during PIN creation)
                    puk.update(buf, offset_cdata, (byte)lc);
                    puk.resetAndUnblock();
                    puk_is_set = true;
                    // Increment init counter
                    if (initCounter < 32677)
                        initCounter++;
                    state = STATE_INITIALISATION;
                }
            }
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * \brief convertSOPIN_SCHSM helper function
     */
    private byte hex2ascii(byte b) {
        return b > '9' ? (byte)('A' + b - 10) : (byte)('0' + b);
    }

    /**
     * \brief Convert SC-HSM SOPIN to friendlier form
     */
    private short convertSOPIN_SCHSM(byte[] src, short pos, byte[] dst) {
            for (short n = 0; n < SCHSM_SOPIN_LENGTH/2; n++) {
                dst[(short)(n*2 + 0)] = hex2ascii((byte)(src[(short)(pos + n)] >> 4));
                dst[(short)(n*2 + 1)] = hex2ascii((byte)(src[(short)(pos + n)] & 0x0F));
            }
            return SCHSM_SOPIN_LENGTH;
    }

    /**
     * \brief Process the CHANGE REFERENCE DATA apdu (INS = 24) in SC-HSM mode.
     *
     * In a "later" state the user must authenticate himself to be able to change the PIN.
     *
     * \param apdu The apdu.
     *
     * \throws ISOException ISO7816.SW_WRONG_LENGTH, ISO7816.SW_CONDITIONS_NOT_SATISFIED, ISO7816.SW_INCORRECT_P1P2,
     *			SW_AUTHENTICATION_METHOD_BLOCKED, SW_PIN_TRIES_REMAINING, SW_REFERENCE_DATA_NOT_FOUND
     */
    private void processChangeReferenceDataSCHSM(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        if(state == STATE_CREATION) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if (p1 != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (p2 == SCHSM_PIN_REF) {
            if (lc != 2*SCHSM_PIN_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (!pin.check(buf, offset_cdata, SCHSM_PIN_LENGTH)) {
                if (pin.getTriesRemaining() > 0)
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
                ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
            }
            pin.update(buf, (byte)(offset_cdata + SCHSM_PIN_LENGTH), SCHSM_PIN_LENGTH);
            pin.resetAndUnblock();
        } else if (p2 == SCHSM_SOPIN_REF) {
            if (lc != 2*SCHSM_SOPIN_LENGTH/2) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (convertSOPIN_SCHSM(buf, offset_cdata, ram_buf) != SCHSM_SOPIN_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (!sopin.check(ram_buf, (byte) 0, SCHSM_SOPIN_LENGTH)) {
                if (sopin.getTriesRemaining() > 0)
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                state = STATE_TERMINATED;
                ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
            }
            if (convertSOPIN_SCHSM(buf, (byte)(offset_cdata + SCHSM_SOPIN_LENGTH/2), ram_buf) != SCHSM_SOPIN_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            sopin.update(ram_buf, (byte) 0, SCHSM_SOPIN_LENGTH);
            sopin.resetAndUnblock();
        } else {
                ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
        }

    }

    /**
     * \brief Process the CHANGE REFERENCE DATA apdu (INS = 24).
     *
     * If the state is STATE_CREATION, we can set the SO PIN without verification.
     * The state will advance to STATE_INITIALISATION (i.e. the SO PIN must be set before the PIN).
     * In a "later" state the user must authenticate himself to be able to change the PIN.
     *
     * \param apdu The apdu.
     *
     * \throws ISOException SW_INCORRECT_P1P2, ISO7816.SW_WRONG_LENGTH, SW_PIN_TRIES_REMAINING.
     */
    private void processChangeReferenceData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;

        if (SCHSM) {
            processChangeReferenceDataSCHSM(apdu);
            return;
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        if(state == STATE_CREATION) {
            // We _set_ the SO PIN in this state.
            // Key reference must be 0F (SO PIN). P1 must be 01 because no verification data should be present in this state.
            if(p1 != 0x01 || p2 != SOPIN_REF) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            // We set the SO PIN and advance to STATE_INITIALISATION.

            if (lc == 0) {
                if (!have_transport_key) {
                    ISOException.throwIt(SW_NO_PIN_DEFINED);
                }
                // Implicit change to STATE_INITIALISATION as SO PIN has been verified for ERASE_CARD apdu processing
                if (sopin.isValidated()) {
                    // PUK should also be set, as it was cleared in ERASE_CARD, but we don't know the SO PIN
                    // puk.update(buf, offset_cdata, (byte)lc);
                    // puk.resetAndUnblock();
                    // puk_is_set = true;

                    fs.setUserAuthenticated(SOPIN_REF);

                    // Increment init counter
                    if (initCounter < 32677)
                        initCounter++;

                    state = STATE_INITIALISATION;

                    ISOException.throwIt(ISO7816.SW_NO_ERROR);
                } else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
            }

            // Check length.
            if(lc != sopin_length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            if(have_transport_key && !sopin.check(buf, offset_cdata, (byte) lc)) {
                ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
            }

            // Set SO PIN
            sopin.update(buf, offset_cdata, (byte)lc);
            sopin.resetAndUnblock();
            sopin.check(buf, offset_cdata, (byte) lc);
            fs.setUserAuthenticated(SOPIN_REF);

            // Set PUK (may be re-set during PIN creation)
            puk.update(buf, offset_cdata, (byte)lc);
            puk.resetAndUnblock();
            puk_is_set = true;

            // Increment init counter
            if (initCounter < 32677)
                initCounter++;

            state = STATE_INITIALISATION;
        } else if(state == STATE_INITIALISATION) {
            if(p1 != 0x01) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            // We _set_ the PIN (P2=01) or PUK (P2=02)
            if(p2 == PIN_REF) {
                // We are supposed to set the PIN right away - no PUK will be set, ever.
                // This might me forbidden because of security policies:
                if(puk_must_be_set && !puk_is_set) {
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                }

                // Check the PIN length.
                if(lc < PIN_MIN_LENGTH || lc > pin_max_length) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                // Pad the PIN upon creation, so no garbage from the APDU will be part of the PIN.
                Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(pin_max_length - lc), (byte) 0x00);

                // Set PIN.
                pin.update(buf, offset_cdata, pin_max_length);
                pin.resetAndUnblock();

                state = STATE_OPERATIONAL_ACTIVATED;
            } else if(p2 == PUK_REF) {
                // Check length.
                if(lc != puk_length) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                // Set PUK.
                puk.update(buf, offset_cdata, (byte)lc);
                puk.resetAndUnblock();
                puk_is_set = true;
            } else {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

        } else {
            // P1 must be 00 as the old PIN/SOPIN must be provided, followed by new PIN/SOPIN without delimitation.
            if(p1 != 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (p2 == PIN_REF) {
                // We _change_ the PIN (P2=01).
                // Both PINs must already padded (otherwise we can not tell when the old PIN ends.)

                // Check PIN lengths: PINs must be padded, i.e. Lc must be 2*pin_max_length.
                if(lc != (short)(2*pin_max_length)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                // Check the old PIN.
                if(!pin.check(buf, offset_cdata, pin_max_length)) {
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
                }

                // UPDATE PIN
                pin.update(buf, (short) (offset_cdata+pin_max_length), pin_max_length);
            } else if (p2 == SOPIN_REF) {
                // We _change_ the SO PIN (P2=0F).

                // Check PIN lengths: PINs must be padded, i.e. Lc must be 2*sopin_length.
                if(lc != (short)(2*sopin_length)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }

                // Check the old SO PIN.
                if(!sopin.check(buf, offset_cdata, sopin_length)) {
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                }

                // UPDATE SO PIN
                sopin.update(buf, (short) (offset_cdata+sopin_length), sopin_length);
            } else {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }// end if(state == STATE_CREATION)
    }// end processChangeReferenceData()

    /**
     * \brief Process the RESET RETRY COUNTER apdu (INS = 2C) in SC-HSM mode.
     *
     * This is used to unblock the PIN with the PUK and set a new PIN value.
     *
     * \param apdu The RESET RETRY COUNTER apdu.
     *
     * \throw ISOException SW_WRONG_LENGTH, SW_REFERENCE_DATA_NOT_FOUND, SW_PIN_TRIES_REMAINING, SW_AUTHENTICATION_METHOD_BLOCKED
     *			SW_INCORRECT_P1P2
     */
    private void processResetRetryCounterSCHSM(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        if (p2 != SCHSM_PIN_REF) {
            ISOException.throwIt(SW_REFERENCE_DATA_NOT_FOUND);
        }

        if (p1 == 0x00) {
            if (lc != (SCHSM_PIN_LENGTH + SCHSM_SOPIN_LENGTH/2)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (convertSOPIN_SCHSM(buf, offset_cdata, ram_buf) != SCHSM_SOPIN_LENGTH ) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (!sopin.check(ram_buf, (byte) 0, SCHSM_SOPIN_LENGTH)) {
                fs.setUserAuthenticated(false);
                if (sopin.getTriesRemaining() > 0)
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                state = STATE_TERMINATED;
                ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
            }
            pin.update(buf, (short)(offset_cdata + SCHSM_SOPIN_LENGTH/2),SCHSM_PIN_LENGTH);
            pin.resetAndUnblock();
            if (state == STATE_INITIALISATION) {
                state = STATE_OPERATIONAL_ACTIVATED;
            }
        } else if (p1 == 0x01) {
            if (lc != SCHSM_SOPIN_LENGTH/2) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (convertSOPIN_SCHSM(buf, offset_cdata, ram_buf) != SCHSM_SOPIN_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (!sopin.check(ram_buf, (byte) 0, SCHSM_SOPIN_LENGTH)) {
                fs.setUserAuthenticated(false);
                if (sopin.getTriesRemaining() > 0)
                    ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | sopin.getTriesRemaining()));
                state = STATE_TERMINATED;
                ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * \brief Process the RESET RETRY COUNTER apdu (INS = 2C).
     *
     * This is used to unblock the PIN with the PUK and set a new PIN value.
     *
     * \param apdu The RESET RETRY COUNTER apdu.
     *
     * \throw ISOException SW_COMMAND_NOT_ALLOWED, ISO7816.SW_WRONG_LENGTH, SW_INCORRECT_P1P2,
     *			SW_PIN_TRIES_REMAINING.
     */
    public void	processResetRetryCounter(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short offset_cdata;

        if (SCHSM) {
            processResetRetryCounterSCHSM(apdu);
            return;
        }

        if(state != STATE_OPERATIONAL_ACTIVATED) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // Length of data field.
        if(lc < (short)(puk_length + PIN_MIN_LENGTH)
                || lc > (short)(puk_length + pin_max_length)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // We expect the PUK followed by a new PIN.
        if(p1 != (byte) 0x00 || p2 != PIN_REF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Check the PUK.
        if(!puk.check(buf, offset_cdata, puk_length)) {
            ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | puk.getTriesRemaining()));
        }

        // If we're here, the PUK was correct.
        // Pad the new PIN, if not done by caller. We don't want any gargabe from the APDU buffer to be part of the new PIN.
        Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(puk_length + pin_max_length - lc), (byte) 0x00);

        // Set the PIN.
        pin.update(buf, (short)(offset_cdata+puk_length), pin_max_length);
        pin.resetAndUnblock();
    }

    /**
     * \brief Initialize a RSA public key with the parameters from buf.
     *
     * \param buf The buffer containing the RSA parameters. It must be TLV with the following format:
     * 				82 - public exponent
     *
     * \param bOff The offset at where the first entry is located.
     *
     * \param bLen The remaining length of buf.
     *
     * \param key The RSA public key to initialize.
     *
     * \throw NotFoundException Parts of the data needed to fully initialize
     *                          the key were missing.
     *
     * \throw InvalidArgumentsException The ASN.1 sequence was malformatted.
     */
    private void initRsaParams(byte[] buf, short bOff, short bLen, RSAPublicKey key) throws NotFoundException, InvalidArgumentsException {
        short pos = bOff;
        short len;

        /* Search for the public exponent */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x82);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setExponent(buf, pos, len); // "public exponent"
    }

    /**
     * \brief Initialize an EC key with the curve parameters from buf.
     *
     * \param buf The buffer containing the EC curve parameters. It must be TLV with the following format:
     * 				81 - prime
     * 				82 - coefficient A
     * 				83 - coefficient B
     * 				84 - base point G
     * 				85 - order
     * 				87 - cofactor
     *
     * \param bOff The offset at where the first entry is located.
     *
     * \param bLen The remaining length of buf.
     *
     * \param key The EC key to initialize.
     *
     * \throw NotFoundException Parts of the data needed to fully initialize
     *                          the key were missing.
     *
     * \throw InvalidArgumentsException The ASN.1 sequence was malformatted.
     */
    private void initEcParams(byte[] buf, short bOff, short bLen, ECKey key) throws NotFoundException, InvalidArgumentsException {
        short pos = bOff;
        short len;

        /* Search for the prime */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x81);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setFieldFP(buf, pos, len); // "p"

        /* Search for coefficient A */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x82);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setA(buf, pos, len);

        /* Search for coefficient B */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x83);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setB(buf, pos, len);

        /* Search for base point G */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x84);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setG(buf, pos, len); // G(x,y)

        /* Search for order */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x85);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        key.setR(buf, pos, len); // Order of G - "q"

        /* Search for cofactor */
        pos = UtilTLV.findTag(buf, bOff, bLen, (byte) 0x87);
        pos++;
        len = UtilTLV.decodeLengthField(buf, pos);
        pos += UtilTLV.getLengthFieldLength(len);
        if(len == 2) {
            key.setK(Util.getShort(buf, pos));
        } else if(len == 1) {
            key.setK(buf[pos]);
        } else {
            throw InvalidArgumentsException.getInstance();
        }
    }

    /**
     * \brief Return Certificate Holder Reference (CHR) from c_DevAut
     *
     * \param data buffer to search for CHR
     *
     * \param dest buffer to store CHR to
     *
     * \param chrPos offset to store CHR at
     *
     * returns CHR length
     */
    private short getCHR(byte[] data, byte[] dest, short chrPos) {
        short pos = 0, len = (short)data.length;
        short cbPos = 0, cbLen = 0;
        try {
            // Cardholder certificate
            pos = UtilTLV.findTag(data, pos, (short)(len - pos), (byte) 0x7F);
            if (data[++pos] != 0x21) {
                throw NotFoundException.getInstance();
            }
            len = UtilTLV.decodeLengthField(data, ++pos);
            pos += UtilTLV.getLengthFieldLength(len);

            // Certificate body
            cbPos = UtilTLV.findTag(data, pos, len, (byte) 0x7F);
            if (data[++cbPos] != 0x4E) {
                throw NotFoundException.getInstance();
            }
            cbLen = UtilTLV.decodeLengthField(data, ++cbPos);
            cbPos += UtilTLV.getLengthFieldLength(cbLen);

            // Certificate profile identifier
            pos = UtilTLV.findTag(data, cbPos, cbLen, (byte) 0x5F);
            if (data[++pos] != 0x29) {
                throw NotFoundException.getInstance();
            }
            len = UtilTLV.decodeLengthField(data, ++pos);
            pos += UtilTLV.getLengthFieldLength(len);
            pos += len;

            // Certification authority reference
            pos = UtilTLV.findTag(data, pos, (short)(cbLen - (pos - cbPos)), (byte) 0x42);
            len = UtilTLV.decodeLengthField(data, ++pos);
            pos += UtilTLV.getLengthFieldLength(len);
            pos += len;

            // Public key
            pos = UtilTLV.findTag(data, pos, (short)(cbLen - (pos - cbPos)), (byte) 0x7F);
            if (data[++pos] != 0x49) {
                throw NotFoundException.getInstance();
            }
            len = UtilTLV.decodeLengthField(data, ++pos);
            pos += UtilTLV.getLengthFieldLength(len);
            pos += len;

            // Certification holder reference
            pos = UtilTLV.findTag(data, pos, (short)(cbLen - (pos - cbPos)), (byte) 0x5F);
            if (data[++pos] != 0x20) {
                throw NotFoundException.getInstance();
            }
            len = UtilTLV.decodeLengthField(data, ++pos);
            pos += UtilTLV.getLengthFieldLength(len);

            Util.arrayCopy(data, pos, dest, chrPos, len);
        } catch (NotFoundException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        return len;
    }

    /**
     * \brief Convert OpenSSL ECDSA signature to RS format
     *
     * \param data buffer that holds input signature
     *
     * \param sigPos offset into buffer
     *
     * \param sigLen signature length
     *
     * returns RS length
     */
    private short signature2rs(byte[] data, short sigPos, short sigLen) {
        short pos = 0, len = 0;
        short rPos = 0, rLen = 0;
        short sPos = 0, sLen = 0;

        try {
            pos = UtilTLV.findTag(data, sigPos, sigLen, (byte) 0x30);
            len = UtilTLV.decodeLengthField(data, ++pos);
            pos += UtilTLV.getLengthFieldLength(len);

            // Get R
            pos = UtilTLV.findTag(data, pos, (short)(sigLen - (pos - sigPos)), (byte) 0x2);
            len = UtilTLV.decodeLengthField(data, ++pos);
            pos += UtilTLV.getLengthFieldLength(len);
            rPos = pos;
            rLen = len;
            if (data[rPos] == 0x00) {
                pos++;
                rPos++;
                rLen--;
            }

            // Get S
            pos += rLen;
            pos = UtilTLV.findTag(data, pos, (short)(sigLen - (pos - sigPos)), (byte) 0x2);
            len = UtilTLV.decodeLengthField(data, ++pos);
            pos += UtilTLV.getLengthFieldLength(len);
            sPos = pos;
            sLen = len;
            if (data[sPos] == 0x00) {
                pos++;
                sPos++;
                sLen--;
            }

            // Concatenate RS
            Util.arrayCopy(data, rPos, data, sigPos, rLen);
            Util.arrayCopy(data, sPos, data, (short)(sigPos + rLen), sLen);
        } catch (Exception e) {
            rLen = 0;
            sLen = 0;
        }

        return (short)(rLen + sLen);
    }

    /**
     * \brief Sign SC-HSM Authenticated Request using RSA private key
     */
    private short signRequestRSA(RSAPrivateCrtKey privKey, short inPos, short inLen, short outPos) {
        Signature sign = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1, false);
        sign.init(privKey, Signature.MODE_SIGN);
        return sign.sign(ram_buf, inPos, inLen, ram_buf, outPos);
    }

    /**
     * \brief Sign SC-HSM Authenticated Request using ECC private key and convert it to RS format
     */
    private short signRequestEC(ECPrivateKey privKey, short inPos, short inLen, short outPos) {
        short outLen;

        Signature sign = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sign.init(privKey, Signature.MODE_SIGN);
        outLen = sign.sign(ram_buf, inPos, inLen, ram_buf, outPos);

        return signature2rs(ram_buf, outPos, outLen);
    }

    /**
     * \brief Move tag value to fill the unused length data
     */
    private short adjustTagPos(byte[] data, short tag, short pos, short len) throws InvalidArgumentsException {
        short deltaLen = (short)(3 - UtilTLV.getLengthFieldLength(len));
        if (deltaLen != 0) {
            short tagLen = tag > 0xFF ? (short)2 : (short)1;
            Util.arrayCopy(data, (short)(pos + tagLen + 3), data, (short)(pos + tagLen + 3 - deltaLen), len);
        }
        return deltaLen;
    }

    /**
     * \brief Process the GENERATE ASYMMETRIC KEY PAIR apdu (INS = 46) in SC-HSM mode
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_INCORRECT_P1P2, SW_DATA_INVALID, SW_FUNC_NOT_SUPPORTED
     */
    public void processGenerateAsymmetricKeypairSCHSM(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short offset_cdata;
        short pos, len;
        short cpiPos = 0, cpiLen = 0;
        short carPos = 0, carLen = 0;
        short pkaPos = 0, pkaLen = 0;
        boolean ecc = false, rsa = false;
        short chrPos = 0, chrLen = 0;
        short primePos = 0, primeLen = 0;
        short rsaLenPos = 0, rsaLenLen = 0;
        short sigPos = 0, sigLen = 0;
        KeyPair kp = null;
        ECPrivateKey privKeyEC = null;
        ECPublicKey pubKeyEC = null;
        RSAPrivateCrtKey privKeyRSA = null;
        RSAPublicKey pubKeyRSA = null;

        if( ! pin.isValidated() && state != STATE_CREATION ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if(p2 != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        len = doChainingOrExtAPDU(apdu);
        pos = 0;

        short privKeyRef = p1;
        if (privKeyRef < 0 || privKeyRef >= key_max_count) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        try {
            // Certificate profile Identifier (CPI)
            cpiPos = UtilTLV.findTag(ram_buf, pos, (short)(len - pos), (byte) 0x5F);
            if (ram_buf[++cpiPos] != 0x29) {
                throw NotFoundException.getInstance();
            }
            cpiLen = UtilTLV.decodeLengthField(ram_buf, ++cpiPos);
            cpiPos += UtilTLV.getLengthFieldLength(cpiLen);
            pos = (short)(cpiPos + cpiLen);

            // Certification authority reference (CAR)
            carPos = UtilTLV.findTag(ram_buf, pos, (short)(len - pos), (byte) 0x42);
            carLen = UtilTLV.decodeLengthField(ram_buf, ++carPos);
            carPos += UtilTLV.getLengthFieldLength(carLen);
            pos = (short)(carPos + carLen);

            // Public Key Algorithm (PKA)
            pkaPos = UtilTLV.findTag(ram_buf, pos, (short)(len - pos), (byte) 0x7F);
            if (ram_buf[++pkaPos] != 0x49) {
                throw NotFoundException.getInstance();
            }
            pkaLen = UtilTLV.decodeLengthField(ram_buf, ++pkaPos);
            pkaPos += UtilTLV.getLengthFieldLength(pkaLen);
            pos = (short)(pkaPos + pkaLen);

            // Certificate Holder Reference (CHR)
            chrPos = UtilTLV.findTag(ram_buf, pos, (short)(len - pos), (byte) 0x5F);
            if (ram_buf[++chrPos] != 0x20) {
                throw NotFoundException.getInstance();
            }
            chrLen = UtilTLV.decodeLengthField(ram_buf, ++chrPos);
            chrPos += UtilTLV.getLengthFieldLength(chrLen);
            pos = (short)(chrPos + chrLen);

            // Get key type
            if ((ram_buf[pkaPos] != 0x06) || (ram_buf[(short)(pkaPos + 1)] != 0x0A)) {
                throw InvalidArgumentsException.getInstance();
            }
            if (ram_buf[(short)(pkaPos + 10)] == 0x01) {
                rsa = true;
            } else if (ram_buf[(short)(pkaPos + 10)] == 0x02) {
                ecc = true;
            } else {
                throw InvalidArgumentsException.getInstance();
            }

            if (rsa) {
                /* Search for keylength tag 0x02 */
                rsaLenPos = UtilTLV.findTag(ram_buf, pkaPos, pkaLen, (byte) 0x02);
                rsaLenLen = UtilTLV.decodeLengthField(ram_buf, ++rsaLenPos);
                if (rsaLenLen != 2) {
                    throw InvalidArgumentsException.getInstance();
                }
            }
            if (ecc) {
                /* Search for prime */
                primePos = UtilTLV.findTag(ram_buf, pkaPos, pkaLen, (byte) 0x81);
                primeLen = UtilTLV.decodeLengthField(ram_buf, ++primePos);
            }
        } catch (NotFoundException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        if (rsa) {
            short rsa_len = Util.getShort(ram_buf, ++rsaLenPos);

            // Try to instantiate key objects of that length
            try {
                privKeyRSA = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, rsa_len, false);
                pubKeyRSA = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, rsa_len, false);
                kp = new KeyPair(pubKeyRSA, privKeyRSA);
            } catch(CryptoException e) {
                if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            try {
                initRsaParams(ram_buf, pkaPos, pkaLen, pubKeyRSA);
            } catch (NotFoundException e) {
                // Parts of the data needed to initialize the RSA keys were missing.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                // Malformatted ASN.1.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            try {
                kp.genKeyPair();
            } catch (CryptoException e) {
                if(e.getReason() == CryptoException.ILLEGAL_VALUE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
            }
            if(keys[privKeyRef] != null) {
                keys[privKeyRef].clearKey();
            }
            keys[privKeyRef] = privKeyRSA;
        }
        if (ecc) {
            short field_len = getEcFpFieldLength(primeLen);

            // Try to instantiate key objects of that length
            try {
                privKeyEC = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, field_len, false);
                pubKeyEC = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, field_len, false);
                kp = new KeyPair(pubKeyEC, privKeyEC);
            } catch(CryptoException e) {
                if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            try {
                initEcParams(ram_buf, pkaPos, pkaLen, pubKeyEC);
                initEcParams(ram_buf, pkaPos, pkaLen, privKeyEC);
            } catch (NotFoundException e) {
                // Parts of the data needed to initialize the EC keys were missing.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                // Malformatted ASN.1.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            try {
                kp.genKeyPair();
            } catch (CryptoException e) {
                if(e.getReason() == CryptoException.ILLEGAL_VALUE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
            }
            if(keys[privKeyRef] != null) {
                keys[privKeyRef].clearKey();
            }
            keys[privKeyRef] = privKeyEC;
            if (state == STATE_CREATION) {
                /* We can reuse pkaPos as scratch buffer for cloneKey() */
                prk_DevAut = cloneKey(privKeyEC, pkaPos);
            }
        }
        if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }

        // Make room for response data, move CHR to PKA location as we don't need PKA any more
        pos = Util.arrayCopy(ram_buf, chrPos, ram_buf, pkaPos, chrLen);
        chrPos = pkaPos;

        // Start of output buffer, right after input buffer
        short pos0 = pos;

        try {
            // authenticated request (AR)
            short arPos = pos, arLen = 0x100;
            pos += UtilTLV.writeTagAndLen((byte) 0x67, arLen, ram_buf, pos);

            // Certificate (CRT)
            short crtPos = pos, crtLen = 0x100;
            pos += UtilTLV.writeTagAndLen((short) 0x7F21, crtLen, ram_buf, pos);

            // Certifiicate body (CB)
            short cbPos = pos, cbLen = 0x100;
            pos += UtilTLV.writeTagAndLen((short) 0x7F4E, cbLen, ram_buf, pos);

            // Certificate profile Identifier (CPI)
            pos += UtilTLV.writeTagAndLen((short) 0x5F29, cpiLen, ram_buf, pos);
            pos = Util.arrayCopy(ram_buf, cpiPos, ram_buf, pos, cpiLen);

            // Certification authority reference (CAR)
            pos += UtilTLV.writeTagAndLen((short) 0x42, carLen, ram_buf, pos);
            pos = Util.arrayCopy(ram_buf, carPos, ram_buf, pos, carLen);

            // Public Key Algorithm (PKA)
            if (rsa) {
                pos = encodeRSAPublicKey(pubKeyRSA, pos);
            }
            if (ecc) {
                pos = encodeECPublicKey(pubKeyEC, pos);
            }

            // Certificate Holder Reference (CHR)
            pos += UtilTLV.writeTagAndLen((short) 0x5F20, chrLen, ram_buf, pos);
            pos = Util.arrayCopy(ram_buf, chrPos, ram_buf, pos, chrLen);

            // Certificate body up to here
            cbLen = (short)(pos - (cbPos + 2 + UtilTLV.getLengthFieldLength(cbLen)));
            // Fix Certificate body tag len
            UtilTLV.writeTagAndLen((short) 0x7F4E, cbLen, ram_buf, cbPos);
            pos -= adjustTagPos(ram_buf, (short) 0x7F4E, cbPos, cbLen);

            // Digital signature (SIG) with the new key
            sigPos = (short)(pos + 5);
            sigLen = (short)(2 + UtilTLV.getLengthFieldLength(cbLen) + cbLen);
            if (rsa) {
                sigLen = signRequestRSA(privKeyRSA, cbPos, sigLen, sigPos);
            }
            if (ecc) {
                sigLen = signRequestEC(privKeyEC, cbPos, sigLen, sigPos);
            }
            pos += UtilTLV.writeTagAndLen((short) 0x5F37, sigLen, ram_buf, pos);
            pos = Util.arrayCopy(ram_buf, sigPos, ram_buf, pos, sigLen);

            // Certificate up to here
            crtLen = (short)(pos - (crtPos + 2 + UtilTLV.getLengthFieldLength(crtLen)));
            // Fix Certificate tag len
            UtilTLV.writeTagAndLen((short) 0x7F21, crtLen, ram_buf, crtPos);
            pos -= adjustTagPos(ram_buf, (short) 0x7F21, crtPos, crtLen);

            if (state != STATE_CREATION) {
                // DevAut CHR as CAR
                chrPos = (short)(pos + 5);
                chrLen = getCHR(c_DevAut, ram_buf, chrPos);
                pos += UtilTLV.writeTagAndLen((short) 0x42, chrLen, ram_buf, pos);
                pos = Util.arrayCopy(ram_buf, chrPos, ram_buf, pos, chrLen);
                // Outer digital signature (SIG) with prk_DevAut
                sigPos = (short)(pos + 5);
                sigLen = (short)((2 + UtilTLV.getLengthFieldLength(crtLen) + crtLen) + (1 + UtilTLV.getLengthFieldLength(chrLen) + chrLen));
                // Sign with prk_DevAut and write tag
                sigLen = signRequestEC(prk_DevAut, crtPos, sigLen, sigPos);
                pos += UtilTLV.writeTagAndLen((short) 0x5F37, sigLen, ram_buf, pos);
                pos = Util.arrayCopy(ram_buf, sigPos, ram_buf, pos, sigLen);
            }

            // Authenticated request up to here
            arLen = (short)(pos - (arPos + 1 + UtilTLV.getLengthFieldLength(arLen)));
            // authenticatedrequest
            UtilTLV.writeTagAndLen((byte) 0x67, arLen, ram_buf, arPos);
            pos -= adjustTagPos(ram_buf, (byte) 0x67, arPos, arLen);
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (NotEnoughSpaceException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Store DevAut key
        ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
        apdu.setOutgoing();
        sendLargeData(apdu, pos0, (short)(pos - pos0));
    }

    /**
     * \brief Import SC-HSM DevAut key from initial 2F02 file
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_DATA_INVALID
     */
    public short importDevAutKeySCHSM(byte[] data) throws ISOException {
        short pos = 0, len = (short)data.length;
        short cpiPos = 0, cpiLen = 0;
        short carPos = 0, carLen = 0;
        short prkPos = 0, prkLen = 0;
        short pkaPos = 0, pkaLen = 0;
        short chrPos = 0, chrLen = 0;
        short primePos = 0, primeLen = 0;
        short sPos = 0, sLen = 0;

        try {
            // Certificate profile Identifier (CPI)
            cpiPos = UtilTLV.findTag(data, pos, (short)(len - pos), (byte) 0x5F);
            if (data[++cpiPos] != 0x29) {
                throw NotFoundException.getInstance();
            }
            cpiLen = UtilTLV.decodeLengthField(data, ++cpiPos);
            cpiPos += UtilTLV.getLengthFieldLength(cpiLen);
            pos = (short)(cpiPos + cpiLen);

            // Certification authority reference (CAR)
            carPos = UtilTLV.findTag(data, pos, (short)(len - pos), (byte) 0x42);
            carLen = UtilTLV.decodeLengthField(data, ++carPos);
            carPos += UtilTLV.getLengthFieldLength(carLen);
            pos = (short)(carPos + carLen);

            // Private Key wrapper
            prkPos = UtilTLV.findTag(data, pos, (short)(len - pos), (byte) 0x7F);
            if (data[++prkPos] != 0x48) {
                throw NotFoundException.getInstance();
            }
            prkLen = UtilTLV.decodeLengthField(data, ++prkPos);
            prkPos += UtilTLV.getLengthFieldLength(prkLen);
            pos = (short)(prkPos + prkLen);

            // Private key
            sPos = UtilTLV.findTag(data, prkPos, prkLen, (byte) 0x88);
            sLen = UtilTLV.decodeLengthField(data, ++sPos);

            // Public Key Algorithm (PKA)
            pkaPos = UtilTLV.findTag(data, pos, (short)(len - pos), (byte) 0x7F);
            if (data[++pkaPos] != 0x49) {
                throw NotFoundException.getInstance();
            }
            pkaLen = UtilTLV.decodeLengthField(data, ++pkaPos);
            pkaPos += UtilTLV.getLengthFieldLength(pkaLen);
            pos = (short)(pkaPos + pkaLen);

            // Certificate Holder Reference (CHR)
            chrPos = UtilTLV.findTag(data, pos, (short)(len - pos), (byte) 0x5F);
            if (data[++chrPos] != 0x20) {
                throw NotFoundException.getInstance();
            }
            chrLen = UtilTLV.decodeLengthField(data, ++chrPos);
            chrPos += UtilTLV.getLengthFieldLength(chrLen);
            pos = (short)(chrPos + chrLen);

            // Search for prime
            primePos = UtilTLV.findTag(data, pkaPos, pkaLen, (byte) 0x81);
            primeLen = UtilTLV.decodeLengthField(data, ++primePos);
        } catch (NotFoundException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short field_len = getEcFpFieldLength(primeLen);

        // Try to instantiate key objects of that length
        try {
            prk_DevAut = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, field_len, false);
        } catch(CryptoException e) {
            if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        try {
            initEcParams(data, pkaPos, pkaLen, prk_DevAut);
            prk_DevAut.setS(data, ++sPos, sLen);
            // Zeroize private key
            Util.arrayFillNonAtomic(data, (short)0, pos, (byte)0x00);
        } catch (NotFoundException e) {
            // Parts of the data needed to initialize the EC keys were missing.
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (InvalidArgumentsException e) {
            // Malformatted ASN.1.
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        return pos;
    }

    /**
     * \brief Process the GENERATE ASYMMETRIC KEY PAIR apdu (INS = 46).
     *
     * A MANAGE SECURITY ENVIRONMENT must have succeeded earlier to set parameters for key
     * generation.
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_WRONG_LENGTH, SW_INCORRECT_P1P2, SW_CONDITIONS_NOT_SATISFIED,
     *			SW_SECURITY_STATUS_NOT_SATISFIED.
     */
    public void processGenerateAsymmetricKeypair(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short privKeyRef = currentPrivateKeyRef[0];
        short lc;
        KeyPair kp = null;
        ECPrivateKey privKey = null;
        ECPublicKey pubKey = null;

        if (SCHSM) {
            processGenerateAsymmetricKeypairSCHSM(apdu);
            return;
        }

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        switch(currentAlgorithmRef[0]) {
        case ALG_GEN_RSA:
            if(p1 != (byte) 0x42 || p2 != (byte) 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }

            // Bytes received must be Lc.
            lc = apdu.setIncomingAndReceive();
            if(lc != apdu.getIncomingLength()) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            short offset_cdata = apdu.getOffsetCdata();

            /* Search for keyLength */
            short keyLength = DEF_RSA_KEYLEN;
            try {
                short pos = UtilTLV.findTag(buf, offset_cdata, lc, (byte) 0x91);
                if(buf[++pos] != (byte) 0x02) { // Length: must be 2.
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                keyLength = (short) ((buf[++pos] << 8) + buf[++pos]);
            } catch (NotFoundException e) {
                keyLength = DEF_RSA_KEYLEN;
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            switch (keyLength) {
            case KeyBuilder.LENGTH_RSA_1024:
            case KeyBuilder.LENGTH_RSA_1536:
            case KeyBuilder.LENGTH_RSA_2048:
            case KeyBuilder_LENGTH_RSA_3072:
            case KeyBuilder.LENGTH_RSA_4096:
                break;
            default:
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // Command chaining might be used for ECC, but not for RSA.
            if(isCommandChainingCLA(apdu)) {
                ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
            }
            try {
                kp = new KeyPair(KeyPair.ALG_RSA_CRT, keyLength);
            } catch(CryptoException e) {
                if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            kp.genKeyPair();
            if(keys[privKeyRef] != null) {
                keys[privKeyRef].clearKey();
            }
            keys[privKeyRef] = kp.getPrivate();
            if(JCSystem.isObjectDeletionSupported()) {
                JCSystem.requestObjectDeletion();
            }

            // Return pubkey. See ISO7816-8 table 3.
            sendRSAPublicKey(apdu, ((RSAPublicKey)(kp.getPublic())));

            break;

        case ALG_GEN_EC:
            if((p1 != (byte) 0x00) || p2 != (byte) 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            lc = doChainingOrExtAPDU(apdu);

            /* Search for prime */
            short pos = 0;
            try {
                pos = UtilTLV.findTag(ram_buf, (short) 0, lc, (byte) 0x81);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            pos++;
            short len = 0;
            try {
                len = UtilTLV.decodeLengthField(ram_buf, pos);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            // Try to calculate field length frome prime length.
            short field_len = getEcFpFieldLength(len);

            // Try to instantiate key objects of that length
            try {
                privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, field_len, false);
                pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, field_len, false);
                kp = new KeyPair(pubKey, privKey);
            } catch(CryptoException e) {
                if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            try {
                initEcParams(ram_buf, (short) 0, lc, pubKey);
                initEcParams(ram_buf, (short) 0, lc, privKey);
            } catch (NotFoundException e) {
                // Parts of the data needed to initialize the EC keys were missing.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                // Malformatted ASN.1.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            try {
                kp.genKeyPair();
            } catch (CryptoException e) {
                if(e.getReason() == CryptoException.ILLEGAL_VALUE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
            }
            if(keys[privKeyRef] != null) {
                keys[privKeyRef].clearKey();
            }
            keys[privKeyRef] = privKey;
            if(JCSystem.isObjectDeletionSupported()) {
                JCSystem.requestObjectDeletion();
            }

            Util.arrayFillNonAtomic(ram_buf, (short)0, RAM_BUF_SIZE, (byte)0x00);
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
            // Return pubkey. See ISO7816-8 table 3.
            try {
                sendECPublicKey(apdu, pubKey);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            } catch (NotEnoughSpaceException e) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            break;

        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * \brief Encode a >= 1024 bit RSAPublicKey according to ISO7816-8 table 3 and send it as a response,
     * using an extended APDU.
     *
     * \see ISO7816-8 table 3.
     *
     * \param apdu The apdu to answer. setOutgoing() must not be called already.
     *
     * \param key The RSAPublicKey to send.
     * 			Can be null for the secound part if there is no support for extended apdus.
     */
    private void sendRSAPublicKey(APDU apdu, RSAPublicKey key) {
        short le = apdu.setOutgoing();
        short pos = 0;
        short keyLength = (short) (key.getSize() / 8);

        ram_buf[pos++] = (byte) 0x7F; // Interindustry template for nesting one set of public key data objects.
        ram_buf[pos++] = (byte) 0x49; // "
        ram_buf[pos++] = (byte) 0x82; // Length field: 3 Bytes.
        ram_buf[pos++] = (byte) ((short) (keyLength + 9) / 256); // Length + 9
        ram_buf[pos++] = (byte) ((short) (keyLength + 9) % 256); // "

        ram_buf[pos++] = (byte) 0x81; // RSA public key modulus tag.
        ram_buf[pos++] = (byte) 0x82; // Length field: 3 Bytes.
        ram_buf[pos++] = (byte) (keyLength / 256); // Length
        ram_buf[pos++] = (byte) (keyLength % 256); // "
        pos += key.getModulus(ram_buf, pos);
        ram_buf[pos++] = (byte) 0x82; // RSA public key exponent tag.
        ram_buf[pos++] = (byte) 0x03; // Length: 3 Bytes.
        pos += key.getExponent(ram_buf, pos);

        sendLargeData(apdu, (short)0, pos);
    }


    /**
     * \brief Process the GET RESPONSE APDU (INS = C0).
     *
     * If there is content available in ram_buf that could not be sent in the last operation,
     * the host should use this APDU to get the data. The data is cached in ram_buf.
     *
     * \param apdu The GET RESPONSE apdu.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_UNKNOWN, SW_CORRECT_LENGTH.
     */
    private void processGetResponse(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short le = apdu.setOutgoing();

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] <= (short) 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short expectedLe = ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > 256 ?
                           256 : ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING];
        if(le != expectedLe) {
            ISOException.throwIt( (short)(ISO7816.SW_CORRECT_LENGTH_00 | expectedLe) );
        }

        sendLargeData(apdu, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS],
                      ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING]);
    }

    /**
     * \brief Send the data from ram_buf, using either extended APDUs or GET RESPONSE.
     *
     * \param apdu The APDU object, in STATE_OUTGOING state.
     *
     * \param pos The position in ram_buf at where the data begins
     *
     * \param len The length of the data to be sent. If zero, 9000 will be
     *            returned
     */
    private void sendLargeData(APDU apdu, short pos, short len) {
        if(len <= 0) {
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = 0;
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
            ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] = TAG_NONE;
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }

        if((short)(pos + len) > RAM_BUF_SIZE) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        if(DEF_EXT_APDU || SCHSM) {
            apdu.setOutgoingLength(len);
            apdu.sendBytesLong(ram_buf, pos, len);
        } else {
            // We have 256 Bytes send-capacity per APDU.
            // Send directly from ram_buf, then prepare for chaining.
            short sendLen = len > 256 ? 256 : len;
            apdu.setOutgoingLength(sendLen);
            apdu.sendBytesLong(ram_buf, pos, sendLen);
            short bytesLeft = (short)(len - sendLen);
            if(bytesLeft > 0) {
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = bytesLeft;
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short)(pos + sendLen);
                short getRespLen = bytesLeft > 256 ? 256 : bytesLeft;
                if (ENABLE_IMPORT_EXPORT) {
                    if (IMPORT_EXPORT) {
                        if (bytesLeft <= 256) {
                            if (ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] != TAG_NONE) {
                                /* Remove data already sent */
                                Util.arrayCopy(ram_buf, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS], ram_buf, (short)0, bytesLeft);
                                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
                                try {
                                    /* Add as much new data as possible into ram_chaining_cache */
                                    bytesLeft = exportRSAPrivateKey(bytesLeft);
                                } catch (Exception e) {
                                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                                }
                                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = bytesLeft;
                                getRespLen = bytesLeft > 256 ? 256 : bytesLeft;
                            }
                        }
                    }
                }
                ISOException.throwIt( (short)(ISO7816.SW_BYTES_REMAINING_00 | getRespLen) );
                // The next part of the data is now in ram_buf, metadata is in ram_chaining_cache.
                // It can be fetched by the host via GET RESPONSE.
            } else {
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = 0;
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
                ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] = TAG_NONE;
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
            }
        }
    }

    /**
     * \brief Encode a ECPublicKey according to ISO7816-8 table 3 and send it as a response,
     * using an extended APDU.
     *
     * \see ISO7816-8 table 3.
     *
     * \param The apdu to answer. setOutgoing() must not be called already.
     *
     * \throw InvalidArgumentsException Field length of the EC key provided can not be handled.
     *
     * \throw NotEnoughSpaceException ram_buf is too small to contain the EC key to send.
     */
    private void sendECPublicKey(APDU apdu, ECPublicKey key) throws InvalidArgumentsException, NotEnoughSpaceException {
        short pos = 0;
        final short field_bytes = (key.getSize()%8 == 0) ? (short)(key.getSize()/8) : (short)(key.getSize()/8+1);
        short len, r;

        // Return pubkey. See ISO7816-8 table 3.
        len = (short)(7 // We have: 7 tags,
                      + (key.getSize() >= LENGTH_EC_FP_512 ? 9 : 7) // 7 length fields, of which 2 are 2 byte fields when using 521 bit curves,
                      + 8 * field_bytes + 4); // 4 * field_len + 2 * 2 field_len + cofactor (2 bytes) + 2 * uncompressed tag
        pos += UtilTLV.writeTagAndLen((short)0x7F49, len, ram_buf, pos);

        // Prime - "P"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x81, len, ram_buf, pos);
        r = key.getField(ram_buf, pos);
        if(r < len) {
            // If the parameter has fewer bytes than the field length, we fill
            // the MSB's with zeroes.
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // First coefficient - "A"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x82, len, ram_buf, pos);
        r = key.getA(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Second coefficient - "B"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x83, len, ram_buf, pos);
        r = key.getB(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Generator - "PB"
        len = (short)(1 + 2 * field_bytes);
        pos += UtilTLV.writeTagAndLen((short)0x84, len, ram_buf, pos);
        r = key.getG(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Order - "Q"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x85, len, ram_buf, pos);
        r = key.getR(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Public key - "PP"
        len = (short)(1 + 2 * field_bytes);
        pos += UtilTLV.writeTagAndLen((short)0x86, len, ram_buf, pos);
        r = key.getW(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Cofactor
        len = 2;
        pos += UtilTLV.writeTagAndLen((short)0x87, len, ram_buf, pos);
        Util.setShort(ram_buf, pos, key.getK());
        pos += 2;

        // ram_buf now contains the complete public key.
        apdu.setOutgoing();
        sendLargeData(apdu, (short)0, pos);
    }

    /**
     * \brief Encode a RSAPublicKey in a SC-HSM fashion
     *
     * \throw InvalidArgumentsException Field length of the RSA key provided can not be handled.
     *
     * \throw NotEnoughSpaceException ram_buf is too small to contain the EC key to send.
     */
    private short encodeRSAPublicKey(RSAPublicKey key, short offset) throws InvalidArgumentsException, NotEnoughSpaceException {
        short pos = offset;
        short len;

        pos += UtilTLV.writeTagAndLen((short)0x7F49, (short)0x100, ram_buf, pos);

        if (SCHSM) {
            // id-TA-RSA-v1-5-SHA-256 - 0.4.0.127.0.7.2.2.2.1.2
            len = 10;
            pos += UtilTLV.writeTagAndLen((short)0x06, len, ram_buf, pos);
            ram_buf[pos++] = 0x04;
            ram_buf[pos++] = 0x00;
            ram_buf[pos++] = 0x7F;
            ram_buf[pos++] = 0x00;
            ram_buf[pos++] = 0x07;
            ram_buf[pos++] = 0x02;
            ram_buf[pos++] = 0x02;
            ram_buf[pos++] = 0x02;
            ram_buf[pos++] = 0x01;
            ram_buf[pos++] = 0x02;
        }

        // Public key
        len = key.getModulus(ram_buf, pos);
        pos += UtilTLV.writeTagAndLen((short)0x81, len, ram_buf, pos);
        pos += key.getModulus(ram_buf, pos);

        // Exponent
        len = key.getExponent(ram_buf, pos);
        pos += UtilTLV.writeTagAndLen((short)0x82, len, ram_buf, pos);
        pos += key.getExponent(ram_buf, pos);

        len = (short)(pos - offset - 5);
        UtilTLV.writeTagAndLen((short)0x7F49, len, ram_buf, offset);
        pos -= adjustTagPos(ram_buf, (short) 0x7F49, offset, len);

        return pos;
    }

    /**
     * \brief Encode a ECPublicKey in a SC-HSM fashion
     *
     * \throw InvalidArgumentsException Field length of the RSA key provided can not be handled.
     *
     * \throw NotEnoughSpaceException ram_buf is too small to contain the EC key to send.
     */
    private short encodeECPublicKey(ECPublicKey key, short offset) throws InvalidArgumentsException, NotEnoughSpaceException {
        short pos = offset;
        final short field_bytes = (key.getSize()%8 == 0) ? (short)(key.getSize()/8) : (short)(key.getSize()/8+1);
        short len, r;

        // Return pubkey. See ISO7816-8 table 3.
        len = (short)(7 // We have: 7 tags,
                      + (SCHSM ? 11 : 0) // OID
                      + (key.getSize() >= LENGTH_EC_FP_512 ? 9 : 7) // 7 length fields, of which 2 are 2 byte fields when using 521 bit curves,
                      + 8 * field_bytes + 4); // 4 * field_len + 2 * 2 field_len + cofactor (2 bytes) + 2 * uncompressed tag
        pos += UtilTLV.writeTagAndLen((short)0x7F49, len, ram_buf, pos);

        if (SCHSM) {
            // id-TA-ECDSA-SHA-256 - 0.4.0.127.0.7.2.2.2.2.3
            len = 10;
            pos += UtilTLV.writeTagAndLen((short)0x06, len, ram_buf, pos);
            ram_buf[pos++] = 0x04;
            ram_buf[pos++] = 0x00;
            ram_buf[pos++] = 0x7F;
            ram_buf[pos++] = 0x00;
            ram_buf[pos++] = 0x07;
            ram_buf[pos++] = 0x02;
            ram_buf[pos++] = 0x02;
            ram_buf[pos++] = 0x02;
            ram_buf[pos++] = 0x02;
            ram_buf[pos++] = 0x03;
        }

        // Prime - "P"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x81, len, ram_buf, pos);
        r = key.getField(ram_buf, pos);
        if(r < len) {
            // If the parameter has fewer bytes than the field length, we fill
            // the MSB's with zeroes.
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // First coefficient - "A"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x82, len, ram_buf, pos);
        r = key.getA(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Second coefficient - "B"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x83, len, ram_buf, pos);
        r = key.getB(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Generator - "PB"
        len = (short)(1 + 2 * field_bytes);
        pos += UtilTLV.writeTagAndLen((short)0x84, len, ram_buf, pos);
        r = key.getG(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Order - "Q"
        len = field_bytes;
        pos += UtilTLV.writeTagAndLen((short)0x85, len, ram_buf, pos);
        r = key.getR(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Public key - "PP"
        len = (short)(1 + 2 * field_bytes);
        pos += UtilTLV.writeTagAndLen((short)0x86, len, ram_buf, pos);
        r = key.getW(ram_buf, pos);
        if(r < len) {
            Util.arrayCopyNonAtomic(ram_buf, pos, ram_buf, (short)(pos+len-r), r);
            Util.arrayFillNonAtomic(ram_buf, pos, (short)(len-r), (byte)0x00);
        } else if (r > len) {
            throw InvalidArgumentsException.getInstance();
        }
        pos += len;

        // Cofactor
        len = 1;
        pos += UtilTLV.writeTagAndLen((short)0x87, len, ram_buf, pos);
        ram_buf[pos] = (byte) key.getK();
        pos += 1;

        return pos;
    }

    /**
     * \brief Process the MANAGE SECURITY ENVIRONMENT apdu (INS = 22).
     *
     * \attention Only SET is supported. RESTORE will reset the security environment.
     *				The security environment will be cleared upon deselection of the applet.
     * 				STOREing and ERASEing of security environments is not supported.
     *
     * \param apdu The apdu.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_WRONG_LENGTH, SW_DATA_INVALID,
     *						SW_INCORRECT_P1P2, SW_FUNC_NOT_SUPPORTED, SW_COMMAND_NOT_ALLOWED.
     */
    public void processManageSecurityEnvironment(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        short pos = 0;
        short offset_cdata;
        byte algRef = 0;
        short privKeyRef = -1;

        // Allow MANAGE SECURITY ENVIRONMENT APDU in SCHSM mode only if private key import is enabled
        if (SCHSM && !private_key_import_allowed) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED_GENERAL);
        }

        // Check PIN
        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        // TLV structure consistency check.
        if( ! UtilTLV.isTLVconsistent(buf, offset_cdata, lc)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        /* Extract data: */
        switch(p1) {
        case (byte) 0x41:
            // SET Computation, decipherment, internal authentication and key agreement.

            // Algorithm reference.
            try {
                pos = UtilTLV.findTag(buf, offset_cdata, (byte) lc, (byte) 0x80);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(buf[++pos] != (byte) 0x01) { // Length must be 1.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            // Set the current algorithm reference.
            algRef = buf[++pos];

            // Private key reference (Index in keys[]-array).
            try {
                pos = UtilTLV.findTag(buf, offset_cdata, (byte) lc, (byte) 0x84);
            } catch (NotFoundException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(buf[++pos] != (byte) 0x01 // Length: must be 1 - only one key reference (byte) provided.
                    || buf[++pos] >= key_max_count) { // Value: key_max_count may not be exceeded. Valid key references are from 0..key_max_count.
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            privKeyRef = buf[pos];
            break;

        case (byte) 0xF3:
            // RESTORE // Set sec env constants to default values.
            algRef = 0;
            privKeyRef = -1;
            break;

        case (byte) 0x81: // SET Verification, encipherment, external authentication and key agreement.
        case (byte) 0xF4: // ERASE
        case (byte) 0xF2: // STORE
        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        /* Perform checks (Note: Nothing is updated yet) */
        switch(p2) {
        case (byte) 0x00:
            /* *****************
             * Key generation. *
             *******************/

            if(algRef != ALG_GEN_EC
                    && algRef != ALG_GEN_RSA) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            // Check: We need a private key reference.
            if(privKeyRef < 0) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if(algRef == ALG_GEN_EC && ecdsaSignatureSha1 == null && ecdsaSignaturePrecomp == null) {
                // There are cards that do not support ECDSA at all.
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            break;

        case (byte) 0xB6:
            /* ***********
             * Signature *
             *************/

            // Check: We need a private key reference.
            if(privKeyRef == -1) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // Supported signature algorithms: RSA with or without PKCS1 padding, ECDSA with raw input.
            if((algRef == ALG_RSA_PAD_NONE) || (algRef == ALG_RSA_PAD_PKCS1)) {
                // Key reference must point to a RSA private key.
                if(keys[privKeyRef].getType() != KeyBuilder.TYPE_RSA_CRT_PRIVATE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

            } else if(algRef == ALG_ECDSA_SHA1 || algRef == ALG_ECDSA_PRECOMPUTED_HASH) {
                // Key reference must point to a EC private key.
                if(keys[privKeyRef].getType() != KeyBuilder.TYPE_EC_FP_PRIVATE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                if(ecdsaSignatureSha1 == null && ecdsaSignaturePrecomp == null) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }

            } else {
                // No known or supported signature algorithm.
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            break;

        case (byte) 0xB7:
            /* ************
             * Derive *
             **************/

            // For derivation, only ECDH is supported.
            if(algRef == ALG_ECDH) {
                // Check: We need a private key reference.
                if(privKeyRef == -1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                // Key reference must point to a EC private key.
                if(keys[privKeyRef].getType() != KeyBuilder.TYPE_EC_FP_PRIVATE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                if(ecdh == null) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
            } else {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            break;

        case (byte) 0xB8:
            /* ************
             * Decryption *
             **************/

            // For decryption, only RSA with PKCS1 padding is supported.
            if(algRef == ALG_RSA_PAD_PKCS1) {
                // Check: We need a private key reference.
                if(privKeyRef == -1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                // Key reference must point to a RSA private key.
                if(keys[privKeyRef].getType() != KeyBuilder.TYPE_RSA_CRT_PRIVATE) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
            } else {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            break;

        default:
            /* Unsupported or unknown P2. */
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        // Reset key import data
        rsaImportPrKey = null;
        ecImportPrKey = null;

        // Finally, update the security environment.
        JCSystem.beginTransaction();
        currentAlgorithmRef[0] = algRef;
        currentPrivateKeyRef[0] = privKeyRef;
        JCSystem.commitTransaction();

    }

    /**
     * \brief Process the PERFORM SECURITY OPERATION apdu (INS = 2A).
     *
     * This operation is used for cryptographic operations
     * (Computation of digital signatures, decrypting.).
     *
     * \param apdu The PERFORM SECURITY OPERATION apdu.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_INCORRECT_P1P2 and
     * 			the ones from computeDigitalSignature() and decipher().
     */
    private void processPerformSecurityOperation(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if(p1 == (byte) 0x9E && p2 == (byte) 0x9A) {
            computeDigitalSignature(apdu);
        } else if(p1 == (byte) 0x80 && p2 == (byte) 0x86) {
            decipher(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

    }

    /**
     * \brief Decipher (or ECDH derive) the data from the apdu using the private key referenced by
     * 			an earlier MANAGE SECURITY ENVIRONMENT apdu.
     *
     * \param apdu The PERFORM SECURITY OPERATION apdu with P1=80 and P2=86.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_WRONG_LENGTH and
     *						SW_WRONG_DATA
     */
    private void decipher(APDU apdu) {
        RSAPrivateCrtKey rsaKey;
        short offset_cdata;
        short lc;
        short decLen = -1;
        short derLen = -1;

        lc = doChainingOrExtAPDU(apdu);
        offset_cdata = 0;

        // Padding indicator should be "No further indication".
        if(ram_buf[offset_cdata] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        switch(currentAlgorithmRef[0]) {

        case ALG_RSA_PAD_NONE:
            // Get the key - it must be an RSA private key,
            // checks have been done in MANAGE SECURITY ENVIRONMENT.
            rsaKey = (RSAPrivateCrtKey) keys[currentPrivateKeyRef[0]];

            // Check the length of the cipher.
            if(lc != (short)(rsaKey.getSize()/8)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            rsaNoPadCipher.init(rsaKey, Cipher.MODE_DECRYPT);
            try {
                decLen = rsaNoPadCipher.doFinal(ram_buf, (short)(offset_cdata+1), (short)(lc-1),
                                                ram_buf, (short) 0);
            } catch(CryptoException e) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            // A single short APDU can handle only 256 bytes - we use sendLargeData instead
            apdu.setOutgoing();
            sendLargeData(apdu, (short)0, decLen);
            break;

        case ALG_RSA_PAD_PKCS1:
            // Get the key - it must be an RSA private key,
            // checks have been done in MANAGE SECURITY ENVIRONMENT.
            rsaKey = (RSAPrivateCrtKey) keys[currentPrivateKeyRef[0]];

            // Check the length of the cipher.
            // Note: The first byte of the data field is the padding indicator
            //		 and therefor not part of the ciphertext.
            if((short)(lc-1) !=  (short)(rsaKey.getSize() / 8)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            rsaPkcs1Cipher.init(rsaKey, Cipher.MODE_DECRYPT);
            try {
                decLen = rsaPkcs1Cipher.doFinal(ram_buf, (short)(offset_cdata+1), (short)(lc-1),
                                                ram_buf, (short) 0);
            } catch(CryptoException e) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            // A single short APDU can handle only 256 bytes - we use sendLargeData instead
            apdu.setOutgoing();
            sendLargeData(apdu, (short)0, decLen);
            break;

        case ALG_ECDH:
            // Check if we support ECDH
            if (ecdh == null) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }

            // Get the key - it must be an ECC private key,
            // checks have been done in MANAGE SECURITY ENVIRONMENT.
            ECPrivateKey ecKey = (ECPrivateKey) keys[currentPrivateKeyRef[0]];

            // Perform ECDH
            // Note: The first byte of the data field is the padding indicator
            //		 and therefore not part of the data.
            ecdh.init(ecKey);
            derLen = ecdh.generateSecret(ram_buf, (short)(offset_cdata+1), (short)(lc-1),
                                         ram_buf, (short) 0);

            // A single short APDU can handle only 256 bytes - we use sendLargeData instead
            short le = apdu.setOutgoing();
            if(le < derLen) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            sendLargeData(apdu, (short)0, derLen);
            break;

        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    /**
     * \brief Fit the data in the buffer to the length of the selected key size.
     * 			If data length is shorter then key length, data will be filled up with zeros in front of data
     * 			If data length is bigger then key length, the input data will will be truncated to the key lengths leftmost bytes
     *
     * \param keySize Key size in bits
     *
     * \param in Contains the data
     *
     * \param inOffset Offset in the buffer where the data begins
     *
     * \param inLen Length of the data in the buffer
     *
     * \param dataBuff Output buffer
     *
     * \return Number of bytes of signature output in dataBuff
     */
    private short fitDataToKeyLength(short keySize, byte[] in, short inOffset, short inLen, byte[] dataBuff) {
        keySize += 7;
        keySize /= 8;
        if (inLen < keySize) {
            Util.arrayCopyNonAtomic(in, inOffset, dataBuff, (short) (keySize - inLen), inLen);
            Util.arrayFillNonAtomic(dataBuff, (short) 0, (short) (keySize - inLen), (byte) 0);
        } else {
            Util.arrayCopyNonAtomic(in, inOffset, dataBuff, (short) 0, keySize);
        }
        return keySize;
    }

    /**
     * \brief Compute a digital signature of the data from the apdu
     * 			using the private key referenced by	an earlier
     *			MANAGE SECURITY ENVIRONMENT apdu.
     *
     * \attention The apdu should contain a hash, not raw data for RSA keys.
     * 				PKCS1 padding will be applied if neccessary.
     *
     * \param apdu The PERFORM SECURITY OPERATION apdu with P1=9E and P2=9A.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_WRONG_LENGTH
     * 						and SW_UNKNOWN.
     */
    private void computeDigitalSignature(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short offset_cdata;
        short lc;
        short sigLen = 0;
        RSAPrivateCrtKey rsaKey;
        ECPrivateKey ecKey;
        short keyLength;
        short le;

        switch(currentAlgorithmRef[0]) {
        case ALG_RSA_PAD_NONE:

            lc = doChainingOrExtAPDU(apdu);
            offset_cdata = 0;

            // RSA signature operation.
            rsaKey = (RSAPrivateCrtKey) keys[currentPrivateKeyRef[0]];
            keyLength = (short) (keys[currentPrivateKeyRef[0]].getSize() / 8);

            if(lc != keyLength) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            rsaNoPadCipher.init(rsaKey, Cipher.MODE_ENCRYPT);
            sigLen = rsaNoPadCipher.doFinal(ram_buf, offset_cdata, lc, ram_buf, (short)0);

            if(sigLen != keyLength) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }

            // A single short APDU can handle only 256 bytes - we use sendLargeData instead
            apdu.setOutgoing();
            sendLargeData(apdu, (short)0, sigLen);
            break;

        case ALG_RSA_PAD_PKCS1:
            // Receive.
            // Bytes received must be Lc.
            lc = apdu.setIncomingAndReceive();
            if(lc != apdu.getIncomingLength()) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            offset_cdata = apdu.getOffsetCdata();

            // RSA signature operation.
            rsaKey = (RSAPrivateCrtKey) keys[currentPrivateKeyRef[0]];
            keyLength = (short) (keys[currentPrivateKeyRef[0]].getSize() / 8);

            if(lc > (short) (keyLength - 9)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            rsaPkcs1Cipher.init(rsaKey, Cipher.MODE_ENCRYPT);
            sigLen = rsaPkcs1Cipher.doFinal(buf, offset_cdata, lc, ram_buf, (short)0);

            if(sigLen != keyLength) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }

            // A single short APDU can handle only 256 bytes - we use sendLargeData instead
            apdu.setOutgoing();
            sendLargeData(apdu, (short)0, sigLen);
            break;

        case ALG_ECDSA_SHA1:
            // Get the key - it must be a EC private key,
            // checks have been done in MANAGE SECURITY ENVIRONMENT.
            ecKey = (ECPrivateKey) keys[currentPrivateKeyRef[0]];

            // Initialisation should be done when:
            // 	- No command chaining is performed at all.
            //	- Command chaining is performed and this is the first apdu in the chain.
            if(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] == (short) 0) {
                ecdsaSignatureSha1.init(ecKey, Signature.MODE_SIGN);
                if(isCommandChainingCLA(apdu)) {
                    ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short) 1;
                }
            }

            short recvLen = apdu.setIncomingAndReceive();
            offset_cdata = apdu.getOffsetCdata();

            // Receive data. For extended APDUs, the data is received piecewise
            // and aggregated in the hash. When using short APDUs, command
            // chaining is performed.
            while (recvLen > 0) {
                ecdsaSignatureSha1.update(buf, offset_cdata, recvLen);
                recvLen = apdu.receiveBytes(offset_cdata);
            }

            if(!isCommandChainingCLA(apdu)) {
                sigLen = ecdsaSignatureSha1.sign(buf, (short)0, (short)0, buf, (short) 0);
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = (short) 0;
                apdu.setOutgoingAndSend((short) 0, sigLen);
            } else {
                ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS]++;
            }
            break;

        case ALG_ECDSA_PRECOMPUTED_HASH:
            // Check if supported
            if (ecdsaSignaturePrecomp == null) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }

            // Receive assuming that all input data fit inside 1 APDU
            // Bytes received must be Lc.
            lc = apdu.setIncomingAndReceive();
            if(lc != apdu.getIncomingLength()) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            offset_cdata = apdu.getOffsetCdata();

            // ECDSA signature operation.
            ecKey = (ECPrivateKey) keys[currentPrivateKeyRef[0]];

            // Not recommended (FIPS 186-4, 6.4)
            // if (lc < MessageDigest.LENGTH_SHA_256) {
            //     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            // }

            // Sign data in one go
            ecdsaSignaturePrecomp.init(ecKey, Signature.MODE_SIGN);
            if (ecdsaSHA512) {
                short fittedLength = fitDataToKeyLength(ecKey.getSize() > 8*MessageDigest.LENGTH_SHA_512 ? 8*MessageDigest.LENGTH_SHA_512 : ecKey.getSize(), buf, offset_cdata, lc, ram_buf);
                sigLen = ecdsaSignaturePrecomp.signPreComputedHash(ram_buf, (short) 0, MessageDigest.LENGTH_SHA_512, ram_buf, (short) 0);
            } else {
                sigLen = ecdsaSignaturePrecomp.signPreComputedHash(buf, offset_cdata, lc, ram_buf, (short) 0);
            }

            // A single short APDU can handle only 256 bytes - we use sendLargeData instead
            le = apdu.setOutgoing();
            if(le < sigLen) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            sendLargeData(apdu, (short) 0, sigLen);
            break;

        default:
            // Wrong/unknown algorithm.
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * \brief Process the GET DATA apdu (INS = CA).
     *
     * GET DATA is currently used for obtaining directory listing and IMPORT_EXPORT.
     *
     * \throw ISOException SW_INCORRECT_P1P2, SW_FILE_INVALID, SW_UNKNOWN
     */
    private void processGetData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if(ENABLE_IMPORT_EXPORT) {
            // export non-sensitive part of config
            try {
                if (p1 == (byte) 0x3F && p2 == (byte) 0xCF) {
                    exportConfig(apdu);
                    return;
                }
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            } catch (NotEnoughSpaceException e) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            if(IMPORT_EXPORT) {
                try {
                    if (p1 == (byte) 0x3F && p2 == (byte) 0xFF) {
                        exportPrivateKey(apdu);
                        return;
                    }
                } catch (InvalidArgumentsException e) {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                } catch (NotEnoughSpaceException e) {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
            }
        }

        // Return directory entries
        if(p1 == 0x01 && p2 == 0) {
            fs.processGetData(apdu);
            return;
        }
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    private void exportConfigSCHSM(APDU apdu) throws InvalidArgumentsException, NotEnoughSpaceException {
        short pos, len;

        // Reset export private key data
        ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] = TAG_NONE;

        if(ENABLE_IMPORT_EXPORT) {
            if(IMPORT_EXPORT) {
                if (state != STATE_CREATION && state != STATE_INITIALISATION) {
                    if (pin.check()) {
                        fs.setUserAuthenticated(PIN_REF);
                    }
                }
            }
        }

        pos = 3;

        pos += UtilTLV.writeTagAndLen(TAG_PIN_MAX_TRIES, (short)1, ram_buf, pos);
        ram_buf[pos++] = pin_max_tries;

        pos += UtilTLV.writeTagAndLen(TAG_KEY_MAX_COUNT, (short)1, ram_buf, pos);
        ram_buf[pos++] = (byte)key_max_count;

        pos += UtilTLV.writeTagAndLen(TAG_IMPORT_EXPORT, (short)1, ram_buf, pos);
        ram_buf[pos++] = IMPORT_EXPORT ? (byte)1 : (byte)0;

        pos += UtilTLV.writeTagAndLen(TAG_STATE, (short)1, ram_buf, pos);
        ram_buf[pos++] = state;

        if(ENABLE_IMPORT_EXPORT) {
            if(IMPORT_EXPORT) {
                if (state != STATE_CREATION && state != STATE_INITIALISATION) {
                    len = pin.copyPIN(ram_buf, pos);
                    pos += UtilTLV.writeTagAndLen(TAG_PIN, len, ram_buf, pos);
                    pos += pin.copyPIN(ram_buf, pos);
                }
            }
        }

        if(ENABLE_IMPORT_EXPORT) {
            if(IMPORT_EXPORT) {
                if (state != STATE_CREATION) {
                    len = sopin.copyPIN(ram_buf, pos);
                    pos += UtilTLV.writeTagAndLen(TAG_SOPIN, len, ram_buf, pos);
                    pos += sopin.copyPIN(ram_buf, pos);
                }
            }
        }

        /* Write outer tag and adjust for tag length */
        len = UtilTLV.writeTagAndLen(TAG_CONFIG, (short)(pos - 3), ram_buf, (short)0);
        if (len != 3) {
            Util.arrayCopy(ram_buf, (short)3, ram_buf, len, (short)(pos - 3));
            pos -= (3 - len);
        }

        apdu.setOutgoing();
        sendLargeData(apdu, (short)0, pos);
    }

    /**
     * \brief Export global card config data.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED
    */
    private void exportConfig(APDU apdu) throws InvalidArgumentsException, NotEnoughSpaceException {
        short pos, len;

        if (SCHSM) {
            exportConfigSCHSM(apdu);
            return;
        }

        // Reset export private key data
        ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] = TAG_NONE;

        if(ENABLE_IMPORT_EXPORT) {
            if(IMPORT_EXPORT) {
                if (state != STATE_CREATION && state != STATE_INITIALISATION) {
                    if (pin.check()) {
                        fs.setUserAuthenticated(PIN_REF);
                    }
                }
                if( have_transport_key && state != STATE_CREATION ) {
                    if (sopin.check()) {
                        fs.setUserAuthenticated(SOPIN_REF);
                    }
                }
            }
        }

        pos = 3;

        pos += UtilTLV.writeTagAndLen(TAG_PIN_MAX_TRIES, (short)1, ram_buf, pos);
        ram_buf[pos++] = pin_max_tries;

        pos += UtilTLV.writeTagAndLen(TAG_PUK_MUST_BE_SET, (short)1, ram_buf, pos);
        ram_buf[pos++] = puk_must_be_set ? (byte)1 : (byte)0;

        pos += UtilTLV.writeTagAndLen(TAG_ENABLE_KEY_IMPORT, (short)1, ram_buf, pos);
        ram_buf[pos++] = private_key_import_allowed ? (byte)1 : (byte)0;

        pos += UtilTLV.writeTagAndLen(TAG_PIN_MAX_LENGTH, (short)1, ram_buf, pos);
        ram_buf[pos++] = pin_max_length;

        pos += UtilTLV.writeTagAndLen(TAG_PUK_LENGTH, (short)1, ram_buf, pos);
        ram_buf[pos++] = puk_length;

        pos += UtilTLV.writeTagAndLen(TAG_SOPIN_LENGTH, (short)1, ram_buf, pos);
        ram_buf[pos++] = sopin_length;

        pos += UtilTLV.writeTagAndLen(TAG_KEY_MAX_COUNT, (short)1, ram_buf, pos);
        ram_buf[pos++] = (byte)key_max_count;

        if (histBytes != null) {
            len = (short)histBytes.length;
            pos += UtilTLV.writeTagAndLen(TAG_HISTBYTES, len, ram_buf, pos);
            Util.arrayCopy(histBytes, (short) 0, ram_buf, pos, len);
            pos += len;
        }

        if (have_transport_key) {
            boolean done = false;
            if(ENABLE_IMPORT_EXPORT) {
                if(IMPORT_EXPORT) {
                    len = (short)transport_key.length;
                    pos += UtilTLV.writeTagAndLen(TAG_TRANSPORT_KEY, len, ram_buf, pos);
                    Util.arrayCopy(transport_key, (short) 0, ram_buf, pos, len);
                    pos += len;
                    done = true;
                }
            }
            if (!done) {
                pos += UtilTLV.writeTagAndLen(TAG_TRANSPORT_KEY, (short)0, ram_buf, pos);
            }
        }

        len = (short)serial.length;
        pos += UtilTLV.writeTagAndLen(TAG_SERIAL, len, ram_buf, pos);
        Util.arrayCopy(serial, (short) 0, ram_buf, pos, len);
        pos += len;

        pos += UtilTLV.writeTagAndLen(TAG_IMPORT_EXPORT, (short)1, ram_buf, pos);
        ram_buf[pos++] = IMPORT_EXPORT ? (byte)1 : (byte)0;

        pos += UtilTLV.writeTagAndLen(TAG_API_FEATURES, (short)2, ram_buf, pos);
        Util.setShort(ram_buf, pos, api_features);
        pos += 2;

        pos += UtilTLV.writeTagAndLen(TAG_INITCOUNT, (short)2, ram_buf, pos);
        Util.setShort(ram_buf, pos, initCounter);
        pos += 2;

        if(ENABLE_IMPORT_EXPORT) {
            if(IMPORT_EXPORT) {
                pos += UtilTLV.writeTagAndLen(TAG_STATE, (short)1, ram_buf, pos);
                ram_buf[pos++] = state;

                if (state != STATE_CREATION && state != STATE_INITIALISATION) {
                    len = pin.copyPIN(ram_buf, pos);
                    pos += UtilTLV.writeTagAndLen(TAG_PIN, len, ram_buf, pos);
                    pos += pin.copyPIN(ram_buf, pos);
                }

                if (state != STATE_CREATION) {
                    len = puk.copyPIN(ram_buf, pos);
                    pos += UtilTLV.writeTagAndLen(TAG_PUK, (short)(len + 1), ram_buf, pos);
                    ram_buf[pos++] = puk_is_set ? (byte)1 : (byte)0;
                    pos += puk.copyPIN(ram_buf, pos);
                }

                if (state != STATE_CREATION) {
                    len = sopin.copyPIN(ram_buf, pos);
                    pos += UtilTLV.writeTagAndLen(TAG_SOPIN, len, ram_buf, pos);
                    pos += sopin.copyPIN(ram_buf, pos);
                }
            }
        }

        /* Write outer tag and adjust for tag length */
        len = UtilTLV.writeTagAndLen(TAG_CONFIG, (short)(pos - 3), ram_buf, (short)0);
        if (len != 3) {
            Util.arrayCopy(ram_buf, (short)3, ram_buf, len, (short)(pos - 3));
            pos -= (3 - len);
        }

        apdu.setOutgoing();
        sendLargeData(apdu, (short)0, pos);
    }

    /**
     * \brief Export parts of private key that fit into ram_buf
     *
     * \param pos Position in ram_buf at which to put additional data
     *
     * \throw InvalidArgumentsException, NotEnoughSpaceException, ISOException SW_UNKNOWN
     */
    private short exportRSAPrivateKey(short pos) throws InvalidArgumentsException, NotEnoughSpaceException, ISOException {

        short tags_to_send = 0, tot_len, len, tag_len;
        short privKeyRef = currentPrivateKeyRef[0];

        if (privKeyRef < 0 || privKeyRef >= key_max_count)
            ISOException.throwIt(ISO7816.SW_UNKNOWN);

        RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) keys[privKeyRef];

        tot_len = pos;

        /* Get P size */
        if ((ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] & RSA_TAG_92) == 0) {
            len = rsaKey.getP(ram_buf, pos);
            tag_len = UtilTLV.writeTagAndLen((short)0x92, len, ram_buf, pos);
            if ((short)(tot_len + tag_len + len) <= RAM_BUF_SIZE) {
                tot_len += tag_len;
                tot_len += len;
                tags_to_send |= RSA_TAG_92;
            }
        }

        /* Get Q size */
        if ((ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] & RSA_TAG_93) == 0) {
            len = rsaKey.getQ(ram_buf, pos);
            tag_len = UtilTLV.writeTagAndLen((short)0x93, len, ram_buf, pos);
            if ((short)(tot_len + tag_len + len) <= RAM_BUF_SIZE) {
                tot_len += tag_len;
                tot_len += len;
                tags_to_send |= RSA_TAG_93;
            }
        }

        /* Get PQ (1/q mod p) */
        if ((ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] & RSA_TAG_94) == 0) {
            len = rsaKey.getPQ(ram_buf, pos);
            tag_len = UtilTLV.writeTagAndLen((short)0x94, len, ram_buf, pos);
            if ((short)(tot_len + tag_len + len) <= RAM_BUF_SIZE) {
                tot_len += tag_len;
                tot_len += len;
                tags_to_send |= RSA_TAG_94;
            }
        }

        /* Get DP1 (d mod (p-1)) */
        if ((ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] & RSA_TAG_95) == 0) {
            len = rsaKey.getDP1(ram_buf, pos);
            tag_len = UtilTLV.writeTagAndLen((short)0x95, len, ram_buf, pos);
            if ((short)(tot_len + tag_len + len) <= RAM_BUF_SIZE) {
                tot_len += tag_len;
                tot_len += len;
                tags_to_send |= RSA_TAG_95;
            }
        }

        /* Get DQ1 (d mod (q-1)) */
        if ((ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] & RSA_TAG_96) == 0) {
            len = rsaKey.getDQ1(ram_buf, pos);
            tag_len = UtilTLV.writeTagAndLen((short)0x96, len, ram_buf, pos);
            if ((short)(tot_len + tag_len + len) < RAM_BUF_SIZE) {
                tot_len += tag_len;
                tot_len += len;
                tags_to_send |= RSA_TAG_96;
            }
        }

        /*
         *
         * Now write tags
         *
         */

        /* Write P */
        if ((tags_to_send & RSA_TAG_92) != 0) {
            len = rsaKey.getP(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x92, len, ram_buf, pos);
            pos += rsaKey.getP(ram_buf, pos);
            ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] |= RSA_TAG_92;
        }

        /* Write Q */
        if ((tags_to_send & RSA_TAG_93) != 0) {
            len = rsaKey.getQ(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x93, len, ram_buf, pos);
            pos += rsaKey.getQ(ram_buf, pos);
            ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] |= RSA_TAG_93;
        }

        /* Write PQ (1/q mod p) */
        if ((tags_to_send & RSA_TAG_94) != 0) {
            len = rsaKey.getPQ(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x94, len, ram_buf, pos);
            pos += rsaKey.getPQ(ram_buf, pos);
            ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] |= RSA_TAG_94;
        }

        /* Write DP1 (d mod (p-1)) */
        if ((tags_to_send & RSA_TAG_95) != 0) {
            len = rsaKey.getDP1(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x95, len, ram_buf, pos);
            pos += rsaKey.getDP1(ram_buf, pos);
            ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] |= RSA_TAG_95;
        }

        /* Write DQ1 (d mod (q-1)) */
        if ((tags_to_send & RSA_TAG_96) != 0) {
            len = rsaKey.getDQ1(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x96, len, ram_buf, pos);
            pos += rsaKey.getDQ1(ram_buf, pos);
            ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] |= RSA_TAG_96;
        }

        /* All done? */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] == TAG_ALL) {
            ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] = TAG_NONE;
            currentPrivateKeyRef[0] = -1;
        }

        return pos;
    }

    /**
     * \brief Export private key.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_DATA_INVALID, SW_CONDITIONS_NOT_SATISFIED.
     */
    private void exportPrivateKey(APDU apdu) throws InvalidArgumentsException, NotEnoughSpaceException, ISOException {
        byte[] buf = apdu.getBuffer();
        short offset_cdata, lc;
        short pos, len;
        short tags_len = 0;
        byte privKeyRef = -1, algRef = -1;

        if(!IMPORT_EXPORT) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        if (state != STATE_CREATION && state != STATE_INITIALISATION) {
            if( ! pin.isValidated() ) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }

        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength() || lc != 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset_cdata = apdu.getOffsetCdata();

        privKeyRef = buf[offset_cdata];
        if (privKeyRef < 0 || privKeyRef >= key_max_count) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (keys[privKeyRef] == null) {
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }

        switch (keys[privKeyRef].getType()) {
            case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
                algRef = ALG_GEN_RSA;
                break;
            case KeyBuilder.TYPE_EC_FP_PRIVATE:
                algRef = ALG_GEN_EC;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        switch(algRef) {
        case ALG_GEN_RSA:
            // RSA key export.

            /* Store it for later */
            currentPrivateKeyRef[0] = privKeyRef;

            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) keys[privKeyRef];

            /*
             *
             * Get outer tag length
             *
             */

            /* Key position */
            len = 1;
            tags_len += UtilTLV.writeTagAndLen((short)0x1D, len, ram_buf, (short)0);
            tags_len += len;

            /* Key length */
            len = 2;
            tags_len += UtilTLV.writeTagAndLen((short)0x91, len, ram_buf, (short)0);
            tags_len += len;

            /* P */
            len = rsaKey.getP(ram_buf, (short)0);
            tags_len += UtilTLV.writeTagAndLen((short)0x92, len, ram_buf, (short)0);
            tags_len += len;

            /* Q */
            len = rsaKey.getQ(ram_buf, (short)0);
            tags_len += UtilTLV.writeTagAndLen((short)0x93, len, ram_buf, (short)0);
            tags_len += len;

            /* PQ */
            len = rsaKey.getPQ(ram_buf, (short)0);
            tags_len += UtilTLV.writeTagAndLen((short)0x94, len, ram_buf, (short)0);
            tags_len += len;

            /* DP1 */
            len = rsaKey.getDP1(ram_buf, (short)0);
            tags_len += UtilTLV.writeTagAndLen((short)0x95, len, ram_buf, (short)0);
            tags_len += len;

            /* DQ1 */
            len = rsaKey.getDQ1(ram_buf, (short)0);
            tags_len += UtilTLV.writeTagAndLen((short)0x96, len, ram_buf, (short)0);
            tags_len += len;

            /* Write outer tag */
            pos = UtilTLV.writeTagAndLen((short)0x7F48, tags_len, ram_buf, (short)0);

            /* Write Key position */
            len = 1;
            pos += UtilTLV.writeTagAndLen((short)0x1D, len, ram_buf, pos);
            ram_buf[pos] = privKeyRef;
            pos += len;

            /* Write Key length */
            len = 2;
            pos += UtilTLV.writeTagAndLen((short)0x91, len, ram_buf, pos);
            Util.setShort(ram_buf, pos, rsaKey.getSize());
            pos += len;

            /* Add as much data as possible into ram_chaining_cache */
            ram_chaining_cache[RAM_CHAINING_CACHE_TAGS_SENT] = TAG_NONE;
            pos = exportRSAPrivateKey(pos);

            // ram_buf now contains complete private key, or whatever could fit in
            if (SCHSM) {
                // Extended APDU magic
                short total_len = (short)(2 + UtilTLV.getLengthFieldLength(tags_len) + tags_len);
                apdu.setOutgoing();
                apdu.setOutgoingLength(total_len);
                while (total_len > 0) {
                    apdu.sendBytesLong(ram_buf, (short)0, pos);
                    total_len -= pos;
                    pos = exportRSAPrivateKey((short)0);
                }
            } else {
                apdu.setOutgoing();
                sendLargeData(apdu, (short)0, pos);
            }

            break;
        case ALG_GEN_EC:
            // EC key export.

            ECPrivateKey ecKey = (ECPrivateKey) keys[privKeyRef];

            // Make space for outer tag, len can be encoded as 1 or 2 bytes
            pos = 4;

            /* Write key position */
            pos += UtilTLV.writeTagAndLen((short)0x1D, (short)1, ram_buf, pos);
            ram_buf[pos++] = privKeyRef;

            /* Prime - "P" */
            len = ecKey.getField(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x81, len, ram_buf, pos);
            pos += ecKey.getField(ram_buf, pos);

            /* First coefficient - "A" */
            len = ecKey.getA(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x82, len, ram_buf, pos);
            pos += ecKey.getA(ram_buf, pos);

            /*/ Second coefficient - "B" */
            len = ecKey.getB(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x83, len, ram_buf, pos);
            pos += ecKey.getB(ram_buf, pos);

            /* Generator - "PB" */
            len = ecKey.getG(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x84, len, ram_buf, pos);
            pos += ecKey.getG(ram_buf, pos);

            /* Order - "Q" */
            len = ecKey.getR(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x85, len, ram_buf, pos);
            pos += ecKey.getR(ram_buf, pos);

            /* Cofactor */
            len = 2;
            pos += UtilTLV.writeTagAndLen((short)0x87, len, ram_buf, pos);
            Util.setShort(ram_buf, pos, ecKey.getK());
            pos += 2;

            /* Private key - "S" */
            len = ecKey.getS(ram_buf, pos);
            pos += UtilTLV.writeTagAndLen((short)0x88, len, ram_buf, pos);
            pos += ecKey.getS(ram_buf, pos);

            /* Write outer tag and adjust for tag length */
            len = UtilTLV.writeTagAndLen((short)0xE0, (short)(pos - 4), ram_buf, (short)0);
            if (len != 4) {
                Util.arrayCopy(ram_buf, (short)4, ram_buf, len, (short)(pos - 4));
                pos -= (4 - len);
            }

            // ram_buf now contains the complete private key.
            apdu.setOutgoing();
            sendLargeData(apdu, (short)0, pos);

            break;
        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * \brief Process the PUT DATA apdu (INS = DB).
     *
     * PUT DATA is currently used for private key import.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_INCORRECT_P1P2
     */
    private void processPutData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if(p1 == (byte) 0x3F && p2 == (byte) 0xFF) {
            boolean import_allowed = private_key_import_allowed;
            if(ENABLE_IMPORT_EXPORT) {
                if(IMPORT_EXPORT) {
                    import_allowed = true;
                }
            }
            if( ! import_allowed) {
                ISOException.throwIt(SW_COMMAND_NOT_ALLOWED_GENERAL);
            }
            try {
                importPrivateKey(apdu);
            } catch (InvalidArgumentsException e) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * \brief Make sure, whole tag is loaded
     *
     * Make sure all of the tag data is available in ram_buf. If tag is specified it should
     * be the first in line. Throw exception otherwise.
     *
     * \param apdu The incoming APDU.
     *
     * \param tag The tag we want or 0 for any tag
     *
     * \throw ISOException.SW_NO_ERROR if the data is to be read
     *        ISOException.SW_DATA_INVALID
     *        InvalidArgumentsException
     */
    private void loadTag(APDU apdu, byte tag) throws ISOException, InvalidArgumentsException {
        short len = 0;
        short pos = 1;
        /* Make sure, we have enough data to read tag and first byte of tag len */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] < 2)
            ISOException.throwIt(isCommandChainingCLA(apdu) ? ISO7816.SW_NO_ERROR : ISO7816.SW_DATA_INVALID);
        if (ram_buf[1] > 0) {
            /* < 128 is encoded as 1 byte - nn */
            pos += 1;
            len = (short)(pos + UtilTLV.decodeLengthField(ram_buf, (short)1));
        } else if (ram_buf[1] == (byte)0x81) {
            /* < 256 is encoded as 2 bytes - 0x81 nn */
            pos += 2;
            if (ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] < pos)
                ISOException.throwIt(isCommandChainingCLA(apdu) ? ISO7816.SW_NO_ERROR : ISO7816.SW_DATA_INVALID);
            len = (short)(pos + UtilTLV.decodeLengthField(ram_buf, (short)1));
        } else if (ram_buf[1] == (byte)0x82) {
            /* >= 256 is encoded as 3 bytes - 0x82 nn nn */
            pos += 3;
            if (ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] < pos)
                ISOException.throwIt(isCommandChainingCLA(apdu) ? ISO7816.SW_NO_ERROR : ISO7816.SW_DATA_INVALID);
            len = (short)(pos + UtilTLV.decodeLengthField(ram_buf, (short)1));
        }
        /* Make sure, we have whole tag read. If chaining is active SW_NO_ERROR means load more data */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] < len) {
            ISOException.throwIt(isCommandChainingCLA(apdu) ? ISO7816.SW_NO_ERROR : ISO7816.SW_DATA_INVALID);
        }
        /* If tag was specified, it should match */
        if (tag != 0 && ram_buf[0] != tag) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    /**
     * \brief Skip processed data, so the ram_buf can be reused
     *
     * Copy the next-in-line tag (if present) to the front of the ram_buf
     *
     * \param apdu The incoming APDU.
     */
    private void skipTag() throws InvalidArgumentsException {
        short pos = 1;
        short len = UtilTLV.decodeLengthField(ram_buf, pos);
        /* Get the position of first byte after current tag */
        pos += UtilTLV.getLengthFieldLength(len);
        pos += len;
        if (pos > ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS])
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        /* Copy them to the front */
        ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] -= pos;
        Util.arrayCopy(ram_buf, pos, ram_buf, (short)0, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS]);
    }

    /**
     * \brief Upload and import a usable private key.
     *
     * A preceeding MANAGE SECURITY ENVIRONMENT is necessary (like with key-generation).
     * The format of the data (of the apdu) must be BER-TLV,
     * Tag 7F48 ("T-L pair to indicate a private key data object") for RSA or tag 0xE0
     * for EC keys, containing the curve parameters and private key D .
     *
     * For RSA, the data to be submitted is quite large. It is required that the tags come in 
     * the right order so they can be processed as received.
     *
     * \throw ISOException SW_SECURITY_STATUS_NOT_SATISFIED, SW_WRONG_LENGTH, SW_DATA_INVALID, InvalidArgumentsException
     */
    private void importPrivateKey(APDU apdu) throws ISOException, InvalidArgumentsException {
        byte[] buf = apdu.getBuffer();
        short recvLen = apdu.setIncomingAndReceive();
        short offset_cdata = apdu.getOffsetCdata();
        short pos = 0, len;

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        /* Receive data (short or extended) */
        while (recvLen > 0) {
            if((short)(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] + recvLen) > RAM_BUF_SIZE) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayCopyNonAtomic(buf, offset_cdata, ram_buf, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS], recvLen);
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] += recvLen;
            recvLen = apdu.receiveBytes(offset_cdata);
        }
        recvLen = ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS];

        /* First we need to skip the outer tag */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == TAG_NONE) {
            /* We can't use loadTag as the outer tag is too big */
            if (recvLen < 5)
                ISOException.throwIt(isCommandChainingCLA(apdu) ? ISO7816.SW_NO_ERROR : ISO7816.SW_DATA_INVALID);
            if (ram_buf[0] == (byte)0x7F && ram_buf[1] == (byte)0x48) {
                /* 0x7F48 outer tag is RSA key */
                pos = 2;
                len = UtilTLV.decodeLengthField(ram_buf, pos);
                pos += UtilTLV.getLengthFieldLength(len);
                currentAlgorithmRef[0] = ALG_GEN_RSA;
                ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x7F48;
            } else if (ram_buf[0] == (byte)0xE0) {
                /* 0xE0 outer tag is EC key */
                pos = 1;
                len = UtilTLV.decodeLengthField(ram_buf, pos);
                pos += UtilTLV.getLengthFieldLength(len);
                currentAlgorithmRef[0] = ALG_GEN_EC;
                ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0xE0;
            } else
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            /* Skip outer tag header */
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] -= pos;
            Util.arrayCopy(ram_buf, pos, ram_buf, (short)0, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS]);
        }

        /* Next comes the KeyRef */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x7F48 || ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0xE0) {
            /* Ensure we have all of the tag data present */
            loadTag(apdu, (byte)0x00);
            /* KeyRef tag (0x1D) is optional */
            if (ram_buf[0] == (byte)0x1D) {
                pos = 1;
                len = UtilTLV.decodeLengthField(ram_buf, pos);
                pos += UtilTLV.getLengthFieldLength(len);
                if (len != 1)
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                currentPrivateKeyRef[0] = ram_buf[pos];
                skipTag();
            }
            /* Mark tag 0x1D processed */
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x1D;
        }

        /* AlgorithmRef & KeyRef should be known by now */
        if (currentAlgorithmRef[0] == 0 || currentPrivateKeyRef[0] == -1)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        /* Create temporary key objects used during initialisation */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x1D) {
            if (currentAlgorithmRef[0] == ALG_GEN_RSA) {
                /* Ensure we have all of the tag data present */
                loadTag(apdu, (byte)0x00);
                /* RSA key length tag (0x91) is optional */
                short keyLength = DEF_RSA_KEYLEN;
                if (ram_buf[0] == (byte)0x91) {
                    pos = 1;
                    len = UtilTLV.decodeLengthField(ram_buf, pos);
                    pos += UtilTLV.getLengthFieldLength(len);
                    if (len != 2)
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    keyLength = Util.getShort(ram_buf, pos);
                    skipTag();
                }
                switch (keyLength) {
                case KeyBuilder.LENGTH_RSA_1024:
                case KeyBuilder.LENGTH_RSA_1536:
                case KeyBuilder.LENGTH_RSA_2048:
                case KeyBuilder_LENGTH_RSA_3072:
                case KeyBuilder.LENGTH_RSA_4096:
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                /* Build the key */
                rsaImportPrKey = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, keyLength, false);
                ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x91;
            }
            if (currentAlgorithmRef[0] == ALG_GEN_EC) {
                /* Ensure we have whole tag 0x81 present */
                loadTag(apdu, (byte)0x81);
                pos = 1;
                len = UtilTLV.decodeLengthField(ram_buf, pos);
                pos += UtilTLV.getLengthFieldLength(len);
                /* Build the key */
                short field_len = getEcFpFieldLength(len);
                ecImportPrKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, field_len, false);
                /* Store prime "p" */
                ecImportPrKey.setFieldFP(ram_buf, pos, len);
                skipTag();
                ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x81;
            }
        }

        /*
         *
         * RSA key importing
         *
         */

        /* Set P */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x91) {
            loadTag(apdu, (byte)0x92);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos += UtilTLV.getLengthFieldLength(len);
            rsaImportPrKey.setP(ram_buf, pos, len);
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x92;
        }

        /* Set Q */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x92) {
            loadTag(apdu, (byte)0x93);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos += UtilTLV.getLengthFieldLength(len);
            rsaImportPrKey.setQ(ram_buf, pos, len);
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x93;
        }

        /* Set PQ (1/q mod p) */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x93) {
            loadTag(apdu, (byte)0x94);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos += UtilTLV.getLengthFieldLength(len);
            rsaImportPrKey.setPQ(ram_buf, pos, len);
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x94;
        }

        /* Set DP1 (d mod (p-1)) */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x94) {
            loadTag(apdu, (byte)0x95);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos += UtilTLV.getLengthFieldLength(len);
            rsaImportPrKey.setDP1(ram_buf, pos, len);
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x95;
        }

        /* Set DQ1 (d mod (q-1)) */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x95) {
            loadTag(apdu, (byte)0x96);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos += UtilTLV.getLengthFieldLength(len);
            rsaImportPrKey.setDQ1(ram_buf, pos, len);
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x96;
        }

        /* All done */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x96) {
            if(rsaImportPrKey.isInitialized()) {
                /* If the key is usable, it MUST NOT remain in buf. */
                JCSystem.beginTransaction();
                Util.arrayFillNonAtomic(ram_buf, (short)0, RAM_BUF_SIZE, (byte)0x00);
                if(keys[currentPrivateKeyRef[0]] != null) {
                    keys[currentPrivateKeyRef[0]].clearKey();
                }
                keys[currentPrivateKeyRef[0]] = rsaImportPrKey;
                rsaImportPrKey = null;
                if(JCSystem.isObjectDeletionSupported()) {
                    JCSystem.requestObjectDeletion();
                }
                JCSystem.commitTransaction();
            } else {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = TAG_NONE;
        }

        /*
         *
         * ECC key importing
         *
         */

        /* Search for coefficient A */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x81) {
            loadTag(apdu, (byte)0x82);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos += UtilTLV.getLengthFieldLength(len);
            ecImportPrKey.setA(ram_buf, pos, len);
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x82;
        }

        /* Search for coefficient B */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x82) {
            loadTag(apdu, (byte)0x83);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos += UtilTLV.getLengthFieldLength(len);
            ecImportPrKey.setB(ram_buf, pos, len);
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x83;
        }

        /* Search for base point G */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x83) {
            loadTag(apdu, (byte)0x84);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos += UtilTLV.getLengthFieldLength(len);
            ecImportPrKey.setG(ram_buf, pos, len);
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x84;
        }

        /* Search for order */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x84) {
            loadTag(apdu, (byte)0x85);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos += UtilTLV.getLengthFieldLength(len);
            ecImportPrKey.setR(ram_buf, pos, len);
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x85;
        }

        /* Search for cofactor */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x85) {
            loadTag(apdu, (byte)0x87);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos += UtilTLV.getLengthFieldLength(len);
            if(len == 2) {
                ecImportPrKey.setK(Util.getShort(ram_buf, pos));
            } else if(len == 1) {
                ecImportPrKey.setK(ram_buf[pos]);
            } else {
                throw InvalidArgumentsException.getInstance();
            }
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x87;
        }

        /* Set the private component "private D" */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x87) {
            loadTag(apdu, (byte)0x88);
            pos = 1;
            len = UtilTLV.decodeLengthField(ram_buf, pos);
            pos = (short)(1 + UtilTLV.getLengthFieldLength(len));
            ecImportPrKey.setS(ram_buf, pos, len);
            skipTag();
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = 0x88;
        }

        /* All done */
        if (ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] == 0x88) {
            if(ecImportPrKey.isInitialized()) {
                /* If the key is usable, it MUST NOT remain in buf. */
                JCSystem.beginTransaction();
                Util.arrayFillNonAtomic(ram_buf, (short)0, RAM_BUF_SIZE, (byte)0x00);
                if(keys[currentPrivateKeyRef[0]] != null) {
                    keys[currentPrivateKeyRef[0]].clearKey();
                }
                keys[currentPrivateKeyRef[0]] = ecImportPrKey;
                if (SCHSM && currentPrivateKeyRef[0] == 0x00) {
                    prk_DevAut = cloneKey(ecImportPrKey, (short)0);
                }
                ecImportPrKey = null;
                if(JCSystem.isObjectDeletionSupported()) {
                    JCSystem.requestObjectDeletion();
                }
                JCSystem.commitTransaction();
            } else {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            ram_chaining_cache[RAM_CHAINING_CACHE_LAST_TAG] = TAG_NONE;
        }
    }

    /**
     * \brief Receive the data sent by chaining or extended apdus and store it in ram_buf.
     *
     * This is a convienience method if large data has to be accumulated using command chaining
     * or extended apdus. The apdu must be in the INITIAL state, i.e. setIncomingAndReceive()
     * might not have been called already.
     *
     * \param apdu The apdu object in the initial state.
     *
     * \throw ISOException SW_WRONG_LENGTH
     */
    private short doChainingOrExtAPDU(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short recvLen = apdu.setIncomingAndReceive();
        short offset_cdata = apdu.getOffsetCdata();

        // Receive data (short or extended).
        while (recvLen > 0) {
            if((short)(ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] + recvLen) > RAM_BUF_SIZE) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayCopyNonAtomic(buf, offset_cdata, ram_buf, ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS], recvLen);
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] += recvLen;
            recvLen = apdu.receiveBytes(offset_cdata);
        }

        if(isCommandChainingCLA(apdu)) {
            // We are still in the middle of a chain, otherwise there would not have been a chaining CLA.
            // Make sure the caller does not forget to return as the data should only be interpreted
            // when the chain is completed (when using this method).
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
            return (short)0;
        } else {
            // Chain has ended or no chaining.
            // We did receive the data, everything is fine.
            // Reset the current position in ram_buf.
            recvLen = (short) (recvLen + ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS]);
            ram_chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
            return recvLen;
        }
    }

    /**
     * \brief Get the field length of an EC FP key using the amount of bytes
     * 			of a parameter (e.g. the prime).
     *
     * \return The bit length of the field.
     *
     * \throw ISOException SC_FUNC_NOT_SUPPORTED.
     */
    private short getEcFpFieldLength(short bytes) {
        switch(bytes) {
        case 24:
            return KeyBuilder.LENGTH_EC_FP_192;
        case 28:
            return LENGTH_EC_FP_224;
        case 32:
            return LENGTH_EC_FP_256;
        case 40:
            return LENGTH_EC_FP_320;
        case 48:
            return LENGTH_EC_FP_384;
        case 64:
            return LENGTH_EC_FP_512;
        case 66:
            return LENGTH_EC_FP_521;
        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            return 0;
        }
    }

    /**
     * \brief Process the GET CHALLENGE instruction (INS = 84).
     *
     * The host may request a random number of length "Le". This random number
     * is currently _not_ used for any cryptographic function (e.g. secure
     * messaging) by the applet.
     *
     * \param apdu The GET CHALLENGE apdu with P1P2=0000.
     *
     * \throw ISOException SW_INCORRECT_P1P2, SW_WRONG_LENGTH, SW_FUNC_NOT_SUPPORTED.
     */
    private void processGetChallenge(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if(randomData == null) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        doChainingOrExtAPDU(apdu);

        if(p1 != 0x00 || p1 != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // A single short APDU can handle only 256 bytes - we use sendLargeData instead
        short le = apdu.setOutgoing();
        if(le <= 0 || le > ram_buf.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        randomData.generateData(ram_buf, (short)0, le);
        sendLargeData(apdu, (short)0, le);
    }

    /**
     * \brief Process the DELETE KEY instruction (INS = E5).
     *
     * Returns selected data
     *
     * \param apdu The DELETE_KEY apdu
     *
     * \throw ISOException ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, ISO7816.SW_DATA_INVALID.
     */
    private void processDeleteKey(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short offset_cdata;
        short lc;
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short privKeyRef = (short)p2;

        if (SCHSM) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED_GENERAL);
        }

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (p1 != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if(privKeyRef < 0 || privKeyRef >= key_max_count) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        if(keys[privKeyRef] == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if(keys[privKeyRef].isInitialized()) {
            keys[privKeyRef].clearKey();
        }
        keys[privKeyRef] = null;
    }

    /**
     * \brief Process the INITIALISE_CARD instruction (INS = 51).
     *
     * \param apdu The INITIALISE_CARD apdu with P1P2=0000.
     *
     * \throw ISOException SW_INCORRECT_P1P2.
     */
    private void processInitialiseCard(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if (SCHSM) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED_GENERAL);
        }

        if(p1 != 0x00 || p2 != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if( state != STATE_CREATION ) {
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }

        /**
         * Card fs may be in an invalid state due to aborted create_pkcs15 process
         */
        if (fs != null) {
            try {
                fs.clearContents();
            } catch (Exception e) {
            }
            fs = null;
        }
        if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
        fs = new IsoFileSystem();
    }

    /*
     * \brief Copies EC domain parameters
     */
    private void copyDomainParameters(ECKey from, ECKey to, short pos) {
        to.setA(ram_buf, pos, from.getA(ram_buf, pos));
        to.setB(ram_buf, pos, from.getB(ram_buf, pos));
        to.setFieldFP(ram_buf, pos, from.getField(ram_buf, pos));
        to.setG(ram_buf, pos, from.getG(ram_buf, pos));
        to.setK(from.getK());
        to.setR(ram_buf, pos, from.getR(ram_buf, pos));
    }

    /*
     * \brief Rreturns a clone of existing EC private key
     */
    private ECPrivateKey cloneKey(ECPrivateKey ecKey, short pos) {
        short primeLen = ecKey.getField(ram_buf, pos);
        short fieldLen = getEcFpFieldLength(primeLen);
        short privateLen;
        ECPrivateKey privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, fieldLen, false);
        copyDomainParameters(ecKey, privKey, pos);
        privateLen = ecKey.getS(ram_buf, pos);
        privKey.setS(ram_buf, pos, privateLen);
        return privKey;
    }

    /**
     * \brief Process the ERASE_CARD instruction (INS = 50) in SC-HSM mode
     * Returns nothing
     *
     * \param apdu The ERASE_CARD apdu
     *
     * \throw ISOException SW_INCORRECT_P1P2.
     */
    private void processEraseCardSCHSM(APDU apdu, short lc, short offset_cdata) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if (ENABLE_IMPORT_EXPORT) {
            if (IMPORT_EXPORT) {
                // Import data
                if (lc > 2 && buf[offset_cdata] == (byte) 0xCF) {
                    try {
                        short posCF, lenCF;
                        short pos, len;

                        posCF = UtilTLV.findTag(buf, offset_cdata, lc, (byte) 0xCF);
                        lenCF = UtilTLV.decodeLengthField(buf, ++posCF);
                        posCF++;

                        prk_DevAut = null;
                        c_DevAut = null;

                        // Reset file system
                        if (fs != null) {
                            try {
                                fs.clearContents();
                            } catch (Exception e) {
                            }
                            fs = null;
                        }
                        fs = new IsoFileSystem();

                        // Clear keys
                        if (keys != null) {
                            for (short i = 0; i < key_max_count; i++) {
                                if(keys[i] != null) {
                                    keys[i].clearKey();
                                }
                                keys[i] = null;
                            }
                            keys = null;
                        }

                        pos = UtilTLV.findTag(buf, posCF, lenCF, TAG_PIN_MAX_TRIES);
                        len = UtilTLV.decodeLengthField(buf, ++pos);
                        if(len != 1) {
                            throw InvalidArgumentsException.getInstance();
                        }
                        pin_max_tries = buf[++pos];

                        pos = UtilTLV.findTag(buf, posCF, lenCF, TAG_KEY_MAX_COUNT);
                        len = UtilTLV.decodeLengthField(buf, ++pos);
                        if(len != 1) {
                            throw InvalidArgumentsException.getInstance();
                        }
                        key_max_count = buf[++pos];
                        keys = new Key[key_max_count];

                        pos = UtilTLV.findTag(buf, posCF, lenCF, TAG_IMPORT_EXPORT);
                        len = UtilTLV.decodeLengthField(buf, ++pos);
                        if(len != 1) {
                            throw InvalidArgumentsException.getInstance();
                        }
                        IMPORT_EXPORT = buf[++pos] != 0;

                        pos = UtilTLV.findTag(buf, posCF, lenCF, TAG_STATE);
                        len = UtilTLV.decodeLengthField(buf, ++pos);
                        if(len != 1) {
                            throw InvalidArgumentsException.getInstance();
                        }
                        state = buf[++pos];

                        try {
                            pos = UtilTLV.findTag(buf, posCF, lenCF, TAG_PIN);
                            len = UtilTLV.decodeLengthField(buf, ++pos);
                            if(len != SCHSM_PIN_LENGTH) {
                                throw InvalidArgumentsException.getInstance();
                            }
                            pin.update(buf, ++pos, SCHSM_PIN_LENGTH);
                            pin.resetAndUnblock();
                        } catch (NotFoundException e) {
                        }
                        if (pin.check()) {
                            fs.setUserAuthenticated(SCHSM_PIN_REF);
                        }

                        try {
                            pos = UtilTLV.findTag(buf, posCF, lenCF, TAG_SOPIN);
                            len = UtilTLV.decodeLengthField(buf, ++pos);
                            if(len != SCHSM_SOPIN_LENGTH) {
                                throw InvalidArgumentsException.getInstance();
                            }
                            sopin.update(buf, ++pos, SCHSM_SOPIN_LENGTH);
                            sopin.resetAndUnblock();
                        } catch (NotFoundException e) {
                        }

                    } catch (Exception e) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    }
                    if(JCSystem.isObjectDeletionSupported()) {
                        JCSystem.requestObjectDeletion();
                    }
                    return;
                }
            }
        }

        // If DevAut key does not yet exist, try to import it from 2F02 file
        if (state == STATE_CREATION) {
            byte initData[];
            short importDataLen = 0;
            initData = fs.get2F02();
            if (initData == null || initData.length == 0) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            if (initData[0] == (byte) 0x5F && initData[1] == (byte) 0x29) {
                importDataLen = importDevAutKeySCHSM(initData);
                keys[0] = cloneKey(prk_DevAut, (short) 0);
            }
            if (c_DevAut == null) {
                c_DevAut = new byte[(short)(initData.length - importDataLen)];
                Util.arrayCopy(initData, importDataLen, c_DevAut, (short)0, (short)c_DevAut.length);
                fs.set2F02(c_DevAut);
            }
            state = STATE_INITIALISATION;
            return;
        } else if (c_DevAut == null) {
            // We get here after full card import
            byte initData[] = fs.get2F02();
            if (initData == null || initData.length == 0) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            c_DevAut = new byte[initData.length];
            Util.arrayCopy(initData, (short)0, c_DevAut, (short)0, (short)c_DevAut.length);
            return;
        }

        // Empty init
        if (lc == 0x16) {
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }

        if (lc != 0x19) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Regular SC-HSM init
        try {
            short posSOPin, lenSOPin;
            short posPin, lenPin;

            // Tag 0x82 - initial SO PIN
            posSOPin = UtilTLV.findTag(buf, offset_cdata, lc, (byte) 0x82);
            lenSOPin = UtilTLV.decodeLengthField(buf, ++posSOPin);
            if(lenSOPin != SCHSM_SOPIN_LENGTH/2) {
                throw InvalidArgumentsException.getInstance();
            }
            if (convertSOPIN_SCHSM(buf, ++posSOPin, ram_buf) != SCHSM_SOPIN_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (state != STATE_INITIALISATION) {
                // SO PIN has to be authenticated
                if (!sopin.check(ram_buf, (byte) 0, SCHSM_SOPIN_LENGTH)) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
            }
            sopin.update(ram_buf, (short) 0, SCHSM_SOPIN_LENGTH);
            sopin.resetAndUnblock();

            // Tag 0x81 - initial PIN
            posPin = UtilTLV.findTag(buf, offset_cdata, lc, (byte) 0x81);
            lenPin = UtilTLV.decodeLengthField(buf, ++posPin);
            if(lenPin != SCHSM_PIN_LENGTH) {
                throw InvalidArgumentsException.getInstance();
            }
            pin.update(buf, ++posPin, SCHSM_PIN_LENGTH);
            pin.resetAndUnblock();

            state = STATE_OPERATIONAL_ACTIVATED;
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Reset file system
        if (fs != null) {
            try {
                fs.clearContents();
            } catch (Exception e) {
            }
            fs = null;
        }
        fs = new IsoFileSystem();
        fs.add2F02(c_DevAut);

        // Clear keys
        if (keys != null) {
            for (short i = 0; i < key_max_count; i++) {
                if(keys[i] != null) {
                    keys[i].clearKey();
                }
            keys[i] = null;
            }
            keys = null;
        }
        keys = new Key[key_max_count];
        keys[0] = cloneKey(prk_DevAut, (short) 0);

        if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
    }

    /**
     * \brief Process the ERASE_CARD instruction (INS = 50).
     * Returns nothing
     *
     * \param apdu The ERASE_CARD apdu with P1P2=0000.
     *
     * \throw ISOException SW_INCORRECT_P1P2.
     */
    private void processEraseCard(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc = apdu.setIncomingAndReceive();
        short offset_cdata = apdu.getOffsetCdata();

        if (SCHSM) {
            processEraseCardSCHSM(apdu, lc, offset_cdata);
            return;
        }

        if(p1 != 0x00 || p2 != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Card restore can be done without SO PIN
        if (ENABLE_IMPORT_EXPORT) {
            if (IMPORT_EXPORT) {
                if(have_transport_key) {
                    sopin.check();
                }
            }
        }

        if( have_transport_key && state != STATE_CREATION && !sopin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // Erase PIN, PUK & SO PIN (only if transport key was not set)
        if (pin != null) {
            pin.clear();
            pin = null;
        }
        if (puk != null) {
            puk.clear();
            puk = null;
        }
        puk_is_set = false;
        if (!have_transport_key && sopin != null) {
            sopin.clear();
            sopin = null;
        }
        // Erase file system
        if (fs != null) {
            try {
                fs.clearContents();
            } catch (Exception e) {
            }
            fs = null;
        }
        // Clear keys
        if (keys != null) {
            for (short i = 0; i < key_max_count; i++) {
                if(keys[i] != null) {
                    keys[i].clearKey();
                }
                keys[i] = null;
            }
            keys = null;
        }
        // Set sec env constants to default values.
        currentAlgorithmRef[0] = 0;
        currentPrivateKeyRef[0] = -1;
        // Garbage collection...
        if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
        state = STATE_CREATION;

        // Check for new config
        try {
            short pos = UtilTLV.findTag(buf, offset_cdata, lc, (byte)TAG_CONFIG);
            short len = UtilTLV.decodeLengthField(buf, ++pos);
            pos += UtilTLV.getLengthFieldLength(len);
            setDefaultValues(false, buf, pos, len);
            offset_cdata = pos;
            lc = len;
        } catch (Exception e) {
        }

        // Create new objects
        if (pin == null) {
            pin = new OwnerPINexp(pin_max_tries, pin_max_length);
        }
        if (puk == null) {
            puk = new OwnerPINexp(PUK_MAX_TRIES, puk_length);
        }
        if (sopin == null) {
            sopin = new OwnerPINexp(SOPIN_MAX_TRIES, sopin_length);
            if (have_transport_key) {
                sopin.update(transport_key, (short) 0, sopin_length);
                sopin.resetAndUnblock();
                if (ENABLE_IMPORT_EXPORT) {
                    if (!IMPORT_EXPORT) {
                        Util.arrayFillNonAtomic(transport_key, (short) 0, sopin_length, (byte) 0x00);
                        transport_key = null;
                    }
                } else {
                    Util.arrayFillNonAtomic(transport_key, (short) 0, sopin_length, (byte) 0x00);
                    transport_key = null;
                }
            }
        }
        fs = new IsoFileSystem();
        keys = new Key[key_max_count];

        api_features &= ~API_FEATURE_IMPORT_EXPORT;
        if (ENABLE_IMPORT_EXPORT) {
            if (IMPORT_EXPORT) {
                api_features |= API_FEATURE_IMPORT_EXPORT;
                // In case PIN was provided mark fs authenticated
                try {
                    UtilTLV.findTag(buf, offset_cdata, lc, TAG_PIN);
                    if(pin.check()) {
                        fs.setUserAuthenticated(PIN_REF);
                    }
                } catch (Exception e) {
                }
                try {
                    UtilTLV.findTag(buf, offset_cdata, lc, TAG_SOPIN);
                    if(sopin.check()) {
                        fs.setUserAuthenticated(SOPIN_REF);
                    }
                } catch (Exception e) {
                }
                if(state == STATE_CREATION || state == STATE_INITIALISATION) {
                    fs.setUserAuthenticated(SOPIN_REF);
                }
            }
        }

        // All done
        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }

    /**
     * \brief Process the GET VALUE instruction (INS = 6C).
     *
     * Returns selected data
     *
     * \param apdu The GET VALUE apdu
     *
     * \throw ISOException SW_INCORRECT_P1P2, SW_WRONG_LENGTH.
     */
    private void processGetValue(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if (SCHSM) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED_GENERAL);
        }

        if(p1 == OPT_P1_SERIAL && p2 == 0x00) {
            // Get serial
            short le = apdu.setOutgoing();
            if(le < serial.length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayCopyNonAtomic(serial, (short)0, buf, (short)0, (short)serial.length);
            apdu.setOutgoingLength((short) serial.length);
            apdu.sendBytes((short) 0, (short) serial.length);
        } else if(p1 == OPT_P1_MEM) {
            // Get memory
            short le = apdu.setOutgoing();
            if(le < 4) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            JCSystem.getAvailableMemory(ram_chaining_cache, (short) 0, p2);
            buf[0] = (byte)(ram_chaining_cache[0] >> 8);
            buf[1] = (byte)(ram_chaining_cache[0] & 0xFF);
            buf[2] = (byte)(ram_chaining_cache[1] >> 8);
            buf[3] = (byte)(ram_chaining_cache[1] & 0xFF);
            apdu.setOutgoingLength((short) 4);
            apdu.sendBytes((short) 0, (short) 4);
        } else if(p1 == OPT_P1_INITCOUNTER && p2 == 0x00) {
            // Get memory
            short le = apdu.setOutgoing();
            if(le < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            buf[0] = (byte)(initCounter >> 8);
            buf[1] = (byte)(initCounter & 0xFF);
            apdu.setOutgoingLength((short) 2);
            apdu.sendBytes((short) 0, (short) 2);
        } else
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    /**
     * \brief Process the SCHSM_SIGN instruction (INS = 68).
     */
    private void processSignSCHSM(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc, le;
        short sigLen = 0;

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        lc = doChainingOrExtAPDU(apdu);

        short privKeyRef = p1;
        if (privKeyRef < 0 || privKeyRef >= key_max_count) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (keys[privKeyRef] == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Raw RSA
        if(p2 == (byte) 0x20) {
            if (!(keys[privKeyRef] instanceof RSAPrivateCrtKey)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // RSA signature operation.
            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) keys[privKeyRef];

            if(lc != (short)(rsaKey.getSize()/8)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            rsaPkcs1Cipher.init(rsaKey, Cipher.MODE_ENCRYPT);
            try {
                sigLen = rsaPkcs1Cipher.doFinal(ram_buf, (short) 0, lc, ram_buf, (short) 0);
            } catch(CryptoException e) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }

        // ECDSA
        if(p2 == (byte) 0x70) {
            if (!(keys[privKeyRef] instanceof ECPrivateKey)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            if (ecdsaSignaturePrecomp == null) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }

            // ECDSA signature operation.
            ECPrivateKey ecKey = (ECPrivateKey) keys[privKeyRef];

            // Sign data in one go
            ecdsaSignaturePrecomp.init(ecKey, Signature.MODE_SIGN);
            if (ecdsaSHA512) {
                short fittedLength = fitDataToKeyLength(ecKey.getSize() > 8*MessageDigest.LENGTH_SHA_512 ? 8*MessageDigest.LENGTH_SHA_512 : ecKey.getSize(), ram_buf, (short) 0, lc, ram_buf);
                sigLen = ecdsaSignaturePrecomp.signPreComputedHash(ram_buf, (short) 0, MessageDigest.LENGTH_SHA_512, ram_buf, (short) 0);
            } else {
                sigLen = ecdsaSignaturePrecomp.signPreComputedHash(ram_buf, (short) 0, lc, ram_buf, (short) 0);
            }
        }

        if (sigLen == 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // A single short APDU can handle only 256 bytes - we use sendLargeData instead
        le = apdu.setOutgoing();
        if(le < sigLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        sendLargeData(apdu, (short) 0, sigLen);
    }

    /**
     * \brief Process the SCHSM_DECIPHER instruction (INS = 62).
     */
    private void processDecipherSCHSM(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc, le;
        short decLen = -1;

        if( ! pin.isValidated() ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        lc = doChainingOrExtAPDU(apdu);

        short privKeyRef = p1;
        if (privKeyRef < 0 || privKeyRef >= key_max_count) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (keys[privKeyRef] == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // RSA
        if(p2 == (byte) 0x21) {
            if (!(keys[privKeyRef] instanceof RSAPrivateCrtKey)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) keys[privKeyRef];

            // Check the length of the cipher.
            if(lc !=  (short)(rsaKey.getSize() / 8)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            rsaPkcs1Cipher.init(rsaKey, Cipher.MODE_DECRYPT);
            try {
                decLen = rsaPkcs1Cipher.doFinal(ram_buf, (short) 0, lc,
                                                ram_buf, (short) 0);
            } catch(CryptoException e) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }

        // ECDH
        if(p2 == (byte) 0x80) {
            if (!(keys[privKeyRef] instanceof ECPrivateKey)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            if (ecdsaSignaturePrecomp == null) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }

            ECPrivateKey ecKey = (ECPrivateKey) keys[privKeyRef];

            // Perform ECDH
            // Note: The first byte of the data field is the padding indicator
            //		 and therefore not part of the data.
            ecdh.init(ecKey);
            decLen = ecdh.generateSecret(ram_buf, (short) 0, lc,
                                         ram_buf, (short) 1);

            ram_buf[0] = 0x04;
            Util.arrayFillNonAtomic(ram_buf, (short)(decLen + 1), decLen, (byte)0xFF);
            decLen = (short)(1 + 2*decLen);
        }

        if (decLen == -1) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // A single short APDU can handle only 256 bytes - we use sendLargeData instead
        le = apdu.setOutgoing();
        if(le < decLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        sendLargeData(apdu, (short) 0, decLen);
    }

} // class IsoApplet
