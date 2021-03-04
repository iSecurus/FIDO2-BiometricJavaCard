/**
 * Copyright (C) 2019-2021 Malte Kruse
 *
 * This file is part of FIDO2-BiometricJavaCard.
 *
 *  FIDO2-BiometricJavaCard is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  FIDO2-BiometricJavaCard is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with FIDO2-BiometricJavaCard.  If not, see <https://www.gnu.org/licenses/>.
 */
package de.krusemal.fido2;

/**
 * Constants needed by FIDO2.
 * 
 * @author Malte Kruse
 * @version v1.0, 15.08.2019
 * 
 */
class Constants {

	/*
	 * FIDO constants for token configuration
	 */
	/**
	 * The CTAP versions supported by the authenticator, encoded in bytes. <br>
	 * <br>
	 * Following possibilities are configurable, by setting the byte string:
	 * <ul>
	 * <li>Only CTAP2: FIDO_2_0 <b>(currently)</b>
	 * <li>Only CTAP1/U2F: U2F_V2
	 * <li>Both: U2F_V2
	 * </ul>
	 * 
	 * <b>Note:</b> The distinction between "Only CTAP1/U2F" and "Both" is made upon the authenticatorGetInfo call.
	 */
	static final byte[] FIDO_VERSIONS = { (byte) 0x46, (byte) 0x49, (byte) 0x44, (byte) 0x4f, (byte) 0x5f, (byte) 0x32, (byte) 0x5f, (byte) 0x30 };

	/**
	 * 128-bit identifier to distinguish between different authenticator models of all manufacturers. Uniquely chosen by the manufacturer. Identical tokens of
	 * one manufacturer must use identical AAGUIDs.
	 */
	static final byte[] FIDO_AAGUID = { (byte) 0x46, (byte) 0x49, (byte) 0x44, (byte) 0x4f, (byte) 0x5f, (byte) 0x32, (byte) 0x5f, (byte) 0x30,
			(byte) 0x46, (byte) 0x49, (byte) 0x44, (byte) 0x4f, (byte) 0x5f, (byte) 0x32, (byte) 0x5f, (byte) 0x30 };

	/**
	 * Maximum CBOR message size supported by the authenticator, based on the CDATA.
	 * 
	 * <b>Note:</b> Specified minimum must be 1024.
	 */
	static final short FIDO_MAX_MSG_SIZE = (short) 1024;

	/**
	 * Maximum APDU length of an extended length APDU.
	 */
	static final short APDU_SUPPORTED_MAX_LENGTH = (short) (FIDO_MAX_MSG_SIZE + 7); // header bytes EXT APDU

	/**
	 * Defines the size of the RAM buffer, which can be used to store intermediate results etc.
	 */
	static final short RAM_BUFFER_LENGTH = (short) 512;

	/**
	 * Protocol Version used for clientPin.
	 * 
	 * Currently possible versions:
	 * <ul>
	 * <li>Version 1</li>
	 * </ul>
	 */
	static final byte FIDO_PIN_AUTH_VERSION = (byte) 1;

	/**
	 * Minimum clientPin length.
	 * 
	 * <b>Note:</b> Specified minimum must be 4.
	 */
	static final byte FIDO_MINIMUM_PIN_LENGTH = (byte) 4;

	/**
	 * Maximum clientPin length.
	 * 
	 * <b>Note:</b> Specified minimum must be 63.
	 */
	static final byte FIDO_MAXIMUM_PIN_LENGTH = (byte) 63;

	/**
	 * Maximum number of clientPin retries.
	 * 
	 * <b>Note:</b> Specified maximum is 8.
	 */
	static final byte FIDO_MAXIMUM_RETRIES = (byte) 8;

	/**
	 * Maximum number of clientPin retries in the current power cycle. Used to prevent brute-force attacks by Malware etc.
	 * 
	 * * <b>Note:</b> Specified maximum is 3.
	 */
	static final byte FIDO_SUBSEQUENT_RETRIES = (byte) 3;

	/*
	 * SoCM Parameters
	 * 
	 * Those parameters are specific to the used smart card and are required to communicate
	 * with the biometric component
	 * 
	 */
	/**
	 * AID of the SoC-Manager. Required for biometric component on the specific card. Defaulted to zero.
	 */
	static final byte[] SOCM_AID = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00 };
	/**
	 * Parameter to initialize SoC-Manager, to retrieve the ShrableBioTemplate. Defaulted to zero. Required.
	 */
	static final byte SOCM_PARAM = (byte) 0x00;

	/*
	 * CBOR Major Type Encodings
	 */
	static final byte CBOR_MAJOR_TYPE_UINT = 0x00;
	static final byte CBOR_MAJOR_TYPE_INT = 0x01; // neg.
	static final byte CBOR_MAJOR_TYPE_BYTE_STRING = 0x02;
	static final byte CBOR_MAJOR_TYPE_TEXT_STRING = 0x03; // UTF-8 enc.
	static final byte CBOR_MAJOR_TYPE_ARRAY = 0x04;
	static final byte CBOR_MAJOR_TYPE_MAP = 0x05; // map of pairs
	static final byte CBOR_MAJOR_TYPE_TAG = 0x06; // optional semantic to other major types, unsupported in this implementation
	static final byte CBOR_MAJOR_TYPE_SIMPLE_VALUES = 0x07; // floating point numbers and simple data types without content

	/*
	 * Encodes the length of the following bytes used to determine length of content or the content itself. Indefinite CBOR is not supported!
	 */
	/**
	 * Length encoding of value or the value itself is in the following byte.
	 */
	static final byte CBOR_LENGTH_1BYTE = (byte) 24;

	/**
	 * Length encoding of value or the value itself is in the following two bytes.
	 */
	static final byte CBOR_LENGTH_2BYTE = (byte) 25;

	/**
	 * Length encoding of value or the value itself is in the following four bytes.
	 */
	static final byte CBOR_LENGTH_4BYTE = (byte) 26;

	/**
	 * Length encoding of value or the value itself is in the following eight bytes.
	 */
	static final byte CBOR_LENGTH_8BYTE = (byte) 27;

	/*
	 * Bytes used to specify Major type 7 CBOR_LENGTH_1BYTE is also used as specified for other major types to define values 32-255 in the following byte
	 * (currently unassigned)
	 */
	static final byte CBOR_FALSE = (byte) 20;
	static final byte CBOR_TRUE = (byte) 21;
	static final byte CBOR_NULL = (byte) 22;
	static final byte CBOR_UNDEFINED_VALUE = (byte) 23;

	/**
	 * Indicates encoding of simple values 32 - 255 in the next byte. Currently no supported values exists.
	 */
	static final byte CBOR_SIMPLE_VALUE_1BYTE = (byte) 24;
	static final byte CBOR_HALF_PRECISION_FLOAT = (byte) 25;
	static final byte CBOR_SINGLE_PRECISION_FLOAT = (byte) 26;
	static final byte CBOR_DOUBLE_PRECISION_FLOAT = (byte) 27;
	
	/*
	 * FIDO errors
	 */
	/**
	 * CTAP1/U2F status word to indicate success of the operation.
	 */
	static final byte CTAP1_ERR_SUCCESS = 0x00;
	static final byte CTAP2_OK = 0x00;
	static final byte CTAP1_ERR_INVALID_COMMAND = 0x01;
	static final byte CTAP1_ERR_INVALID_PARAMETER = 0x02;
	static final byte CTAP1_ERR_INVALID_LENGTH = 0x03;
	static final byte CTAP1_ERR_INVALID_SEQ = 0x04;
	static final byte CTAP1_ERR_TIMEOUT = 0x05;
	static final byte CTAP1_ERR_CHANNEL_BUSY = 0x06;
	static final byte CTAP1_ERR_LOCK_REQUIRED = 0x0A;
	static final byte CTAP1_ERR_INVALID_CHANNEL = 0x0B;

	static final byte CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11;
	static final byte CTAP2_ERR_INVALID_CBOR = 0x12;
	static final byte CTAP2_ERR_MISSING_PARAMETER = 0x14;
	static final byte CTAP2_ERR_LIMIT_EXCEEDED = 0x15;
	static final byte CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x16;
	static final byte CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19;
	static final byte CTAP2_ERR_PROCESSING = 0x21;
	static final byte CTAP2_ERR_INVALID_CREDENTIAL = 0x22;
	static final byte CTAP2_ERR_USER_ACTION_PENDING = 0x23;
	static final byte CTAP2_ERR_OPERATION_PENDING = 0x24;
	static final byte CTAP2_ERR_NO_OPERATIONS = 0x25;
	static final byte CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26;
	static final byte CTAP2_ERR_OPERATION_DENIED = 0x27;
	static final byte CTAP2_ERR_KEY_STORE_FULL = 0x28;
	static final byte CTAP2_ERR_NO_OPERATION_PENDING = 0x2A;
	static final byte CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B;
	static final byte CTAP2_ERR_INVALID_OPTION = 0x2C;
	static final byte CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D;
	static final byte CTAP2_ERR_NO_CREDENTIALS = 0x2E;
	static final byte CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F;
	static final byte CTAP2_ERR_NOT_ALLOWED = 0x30;
	static final byte CTAP2_ERR_PIN_INVALID = 0x31;
	static final byte CTAP2_ERR_PIN_BLOCKED = 0x32;
	static final byte CTAP2_ERR_PIN_AUTH_INVALID = 0x33;
	static final byte CTAP2_ERR_PIN_AUTH_BLOCKED = 0x34;
	static final byte CTAP2_ERR_PIN_NOT_SET = 0x35;
	static final byte CTAP2_ERR_PIN_REQUIRED = 0x36;
	static final byte CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37;
	static final byte CTAP2_ERR_PIN_TOKEN_EXPIRED = 0x38;
	static final byte CTAP2_ERR_REQUEST_TOO_LARGE = 0x39;
	static final byte CTAP2_ERR_ACTION_TIMEOUT = 0x3A;
	static final byte CTAP2_ERR_UP_REQUIRED = 0x3B;
	static final byte CTAP1_ERR_OTHER = 0x7F;
	static final byte CTAP2_ERR_SPEC_LAST = (byte) 0xDF; // Maybe not needed?
	
	/**
	 * Vendor specific error indicating something went wrong during message encoding.
	 */
	static final byte CTAP2_ERR_ENCODING_ERROR = (byte) 0xF0;

	/*
	 * FIDO instructions
	 */
	static final byte FIDO_INS_AUTHENTICATOR_MAKE_CREDENTIAL = 0x01;
	static final byte FIDO_INS_AUTHENTICATOR_GET_ASSERTION = 0x02;
	static final byte FIDO_INS_AUTHENTICATOR_GET_INFO = 0x04;
	static final byte FIDO_INS_AUTHENTICATOR_CLIENT_PIN = 0x06;
	static final byte FIDO_INS_AUTHENTICATOR_RESET = 0x07;
	static final byte FIDO_INS_AUTHENTICATOR_GET_NEXT_ASSERTION = 0x08;

	static final byte FIDO_SUBCMD_CLIENT_PIN_GET_RETRIES = 0x01;
	static final byte FIDO_SUBCMD_CLIENT_PIN_GET_KEY_AGREEMENT = 0x02;
	static final byte FIDO_SUBCMD_CLIENT_PIN_SET_PIN = 0x03;
	static final byte FIDO_SUBCMD_CLIENT_PIN_CHANGE_PIN = 0x04;
	static final byte FIDO_SUBCMD_CLIENT_PIN_GET_PIN_TOKEN = 0x05;

	/**
	 * Implementation specific instruction, used once to initialize the authenticator before usage.
	 */
	static final byte FIDO_INS_INITIALIZE = 0x40;

	/*
	 * COSE Algorithm Identifiers
	 */
	/**
	 * COSE Encoding of ES256 (ECDSA_SHA_256).
	 */
	static final short IANA_COSE_ES256 = (short) -7; // ECDSA_SHA_256

	/*
	 * String constants in HEX
	 * 
	 * Used to encode or determine string parameters
	 */
	/**
	 * Byte string encoding of <i>icon</i>.
	 */
	static final byte[] STRING_ICON = { 0x69, 0x63, 0x6f, 0x6e };

	/**
	 * Byte string encoding of <i>id</i>.
	 */
	static final byte[] STRING_ID = { 0x69, 0x64 };

	/**
	 * Byte string encoding of <i>name</i>.
	 */
	static final byte[] STRING_NAME = { 0x6e, 0x61, 0x6d, 0x65 };

	/**
	 * Byte string encoding of <i>displayname</i>.
	 */
	static final byte[] STRING_DISPLAYNAME = { (byte) 100, (byte) 105, (byte) 115, (byte) 112, (byte) 108, (byte) 97, (byte) 121, (byte) 78, (byte) 97,
			(byte) 109,	(byte) 101 };

	/**
	 * Byte string encoding of <i>alg</i>.
	 */
	static final byte[] STRING_ALG = { (byte) 97, (byte) 108, (byte) 103 };

	/**
	 * Byte string encoding of <i>rk</i>.
	 */
	static final byte[] STRING_RK = { (byte) 114, (byte) 107 };

	/**
	 * Byte string encoding of <i>uv</i>.
	 */
	static final byte[] STRING_UV = { (byte) 117, (byte) 118 };

	/**
	 * Byte string encoding of <i>up</i>.
	 */
	static final byte[] STRING_UP = { (byte) 117, (byte) 112 };

	/**
	 * Byte string encoding of <i>type</i>.
	 */
	static final byte[] STRING_TYPE = { (byte) 116, (byte) 121, (byte) 112, (byte) 101 };

	/**
	 * Byte string encoding of <i>public-key</i>.
	 */
	static final byte[] STRING_PUBLIC_KEY = { (byte) 112, (byte) 117, (byte) 98, (byte) 108, (byte) 105, (byte) 99, (byte) 45, (byte) 107, (byte) 101,
			(byte) 121 };

	/**
	 * Byte string encoding of <i>packed</i>.
	 */
	static final byte[] STRING_PACKED = { (byte) 112, (byte) 97, (byte) 99, (byte) 107, (byte) 101, (byte) 100 };

	/**
	 * Byte string encoding of <i>sig</i>.
	 */
	static final byte[] STRING_SIG = { 0x73, 0x69, 0x67 };

	/**
	 * Byte string encoding of <i>x5c</i>.
	 */
	static final byte[] STRING_X5C = { 0x78, 0x35, 0x63 };

	/**
	 * Byte string encoding of <i>clientPin</i>.
	 */
	static final byte[] STRING_CLIENT_PIN = { 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x50, 0x69, 0x6e };

	/*
	 * Internal Authenticator States
	 */
	static final byte STATE_NOT_INITIALIZED = 0x00;
	static final byte STATE_READY = 0x01;
	static final byte STATE_SHORT_LENGTH = 0x02;
	static final byte STATE_CHAINING = 0x03;
	static final byte STATE_EXTENDED_LENGTH = 0x04;
	static final byte STATE_RESPONSE_CHAINING = 0x05;
	static final byte STATE_PIN_UNSET = 0x06;

	/*
	 * Secp256r1 curve parameters (according to secg.org/SEC2-Ver-1.0.pdf)
	 */
	static final byte[] SECP256R1_FP = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff };
	
	static final byte[] SECP256R1_A = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xfc };
	
	static final byte[] SECP256R1_B = { (byte) 0x5a, (byte) 0xc6, (byte) 0x35, (byte) 0xd8, (byte) 0xaa, (byte) 0x3a, (byte) 0x93, (byte) 0xe7,
			(byte) 0xb3, (byte) 0xeb, (byte) 0xbd, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xbc, (byte) 0x65, (byte) 0x1d, (byte) 0x06,
			(byte) 0xb0, (byte) 0xcc, (byte) 0x53, (byte) 0xb0, (byte) 0xf6, (byte) 0x3b, (byte) 0xce, (byte) 0x3c, (byte) 0x3e, (byte) 0x27, (byte) 0xd2,
			(byte) 0x60, (byte) 0x4b };
	
	static final byte[] SECP256R1_G = { (byte) 0x04, (byte) 0x6b, (byte) 0x17, (byte) 0xd1, (byte) 0xf2, (byte) 0xe1, (byte) 0x2c, (byte) 0x42,
			(byte) 0x47, (byte) 0xf8, (byte) 0xbc, (byte) 0xe6, (byte) 0xe5, (byte) 0x63, (byte) 0xa4, (byte) 0x40, (byte) 0xf2, (byte) 0x77, (byte) 0x03,
			(byte) 0x7d, (byte) 0x81, (byte) 0x2d, (byte) 0xeb, (byte) 0x33, (byte) 0xa0, (byte) 0xf4, (byte) 0xa1, (byte) 0x39, (byte) 0x45, (byte) 0xd8,
			(byte) 0x98, (byte) 0xc2, (byte) 0x96, (byte) 0x4f, (byte) 0xe3, (byte) 0x42, (byte) 0xe2, (byte) 0xfe, (byte) 0x1a, (byte) 0x7f, (byte) 0x9b,
			(byte) 0x8e, (byte) 0xe7, (byte) 0xeb, (byte) 0x4a, (byte) 0x7c, (byte) 0x0f, (byte) 0x9e, (byte) 0x16, (byte) 0x2b, (byte) 0xce, (byte) 0x33,
			(byte) 0x57, (byte) 0x6b, (byte) 0x31, (byte) 0x5e, (byte) 0xce, (byte) 0xcb, (byte) 0xb6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xbf,
			(byte) 0x51, (byte) 0xf5 };

	static final byte[] SECP256R1_R = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xbc, (byte) 0xe6, (byte) 0xfa,
			(byte) 0xad, (byte) 0xa7, (byte) 0x17, (byte) 0x9e, (byte) 0x84, (byte) 0xf3, (byte) 0xb9, (byte) 0xca, (byte) 0xc2, (byte) 0xfc, (byte) 0x63,
			(byte) 0x25, (byte) 0x51 };
	
	static final byte SECP256R1_K = (byte) 0x01;
}
