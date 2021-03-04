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

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.UserException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.biometry.SharedBioTemplate;
import javacardx.crypto.Cipher;

/**
 * FIDO2Applet class implementing the CTAP2 protocol methods for an biometric FIDO2 authenticator. The authenticator is based on basic attestation.
 * 
 * @author Malte Kruse
 * @version v1.0, 15.08.2019
 * @see <a href=
 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html</a>
 *
 */
public class FIDO2Applet extends Applet implements ExtendedLength {

	private byte internalState;

	private CBORDecoder decoder;
	private CBOREncoder encoder;

	/*
	 * Used to store needed values for the current or later commands.
	 */
	private byte[] ram;

	/*
	 * Buffer used to store incoming APDUs (extended and chained). Also used to generate response APDUs.
	 */
	private byte[] apduBuffer;
	private short apduBufferOffset;
	private short apduBufferResponseEndOffset;

	private RandomData randomGenerator;

	/*
	 * ES256 = NIST P-256 + SHA256
	 */
	private Signature es256 = null;
	private MessageDigest sha256 = null;
	
	/*
	 * Used for symmetric cryptography to secure the private key
	 */
	private Cipher aes256 = null;
	private AESKey encryptionKey;
	private byte[] secret;

	/*
	 * 16-byte initialization vector used for aes256 encryption
	 */
	private byte[] iv;
	
	/*
	 * The private key and the corresponding certificate of the authenticator
	 */
	private ECPrivateKey privateAttestationKey;
	private byte[] x5c;

	/*
	 * CredentialKeyPair used to generate a new KeyPair on every make credential call
	 */
	private KeyPair credentialKeyPair = null;

	/*
	 * 4-byte-counter, incremented on every signing operation inside authenticatorGet(Next)Assertion. Used to recognize cloned authenticators on client side.
	 */
	private short[] signCounter;

	/*
	 * Used to indicate the number of credentials send during authenticatorGetAssertion command. Used to indicate which credential must be returned with the
	 * next authenticatorGetNextAssertion call.
	 */
	private short numberOfCredentials;
	private short credentialCounter;

	/*
	 * Used to toggle between clientPin and fingerprint verification.
	 */
	private boolean useClientPin;
	private boolean pinInitialized;

	/*
	 * Value used for the clientPin-Verification. Key and pinToken will be newly generated once every power cylce (there are some exceptions).
	 */
	private KeyPair authenticatorKeyAgreementKey = null;
	private byte[] pinToken = null;


	private byte retries;
	private byte subsequentRetries;

	private KeyAgreement ecdh_p256 = null;
	private HMAC hmac_sha256 = null;
	private AESKey sharedSecret;

	/*
	 * First 16 bit of the HMAC-SHA256 over the user pin.
	 */
	private byte[] pinHash = null;

	/*
	 * Used to realize functions, that are only done once in a power cycle.
	 */
	private byte[] poweredUp;

	/*
	 * Interface of the fingerprint applet, used to receive the current status of verification.
	 */
	private SharedBioTemplate fingerprint = null;

	/**
	 * FIDO2Applet class instantiates the applet and most of the needed Objects.
	 * 
	 * @param bArray
	 *            Unused.
	 * @param bOffset
	 *            Unused.
	 * @param bLength
	 *            Unused.
	 */
	private FIDO2Applet(byte[] bArray, short bOffset, byte bLength) {

		/*
		 * Installation only. We need to initialize the token later on by setting the certificate and contacting the fingerprint API.
		 */
		this.internalState = Constants.STATE_NOT_INITIALIZED;

		this.decoder = new CBORDecoder();
		this.encoder = new CBOREncoder();

		this.ram = JCSystem.makeTransientByteArray(Constants.RAM_BUFFER_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		this.apduBuffer = JCSystem.makeTransientByteArray(Constants.APDU_SUPPORTED_MAX_LENGTH, JCSystem.CLEAR_ON_DESELECT);
		this.apduBufferOffset = 0;
		this.apduBufferResponseEndOffset = 0;

		this.randomGenerator = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

		/*
		 * Instantiate specified crypto algorithms.
		 */
		this.es256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		this.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

		// Create the AES Key to protect the private keys generated during authenticatorMakeCredential
		this.aes256 = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		
		this.encryptionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
		
		this.secret = new byte[32];
		this.randomGenerator.generateData(this.secret, (short) 0, (short) 32);
		
		this.encryptionKey.setKey(this.secret, (short) 0);
		this.iv = new byte[16];

		/*
		 * Initialize the key material needed for credential generation parts taken from:
		 * https://github.com/LedgerHQ/ledger-u2f-javacard/blob/master/src/main/java/com/ledger/u2f/Secp256r1.java
		 */
		this.credentialKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
		
		ECPrivateKey privKey = (ECPrivateKey) this.credentialKeyPair.getPrivate();
		ECPublicKey pubKey = (ECPublicKey) this.credentialKeyPair.getPublic();

		ECKeyBuilder.setSecp251r1CurveParameters(privKey);
		ECKeyBuilder.setSecp251r1CurveParameters(pubKey);

		/*
		 * Initialize 4-byte sign count
		 */
		this.signCounter = new short[2];
		
		/*
		 * clientPIN can be enabled by setting this flag manually to true.
		 */
		this.useClientPin = false; // default is false

		/*
		 * false until the clientPin was set by the user for the first time.
		 */
		this.pinInitialized = false;

		/*
		 * Initialize clientPin-objects
		 */
		this.authenticatorKeyAgreementKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);

		privKey = (ECPrivateKey) this.authenticatorKeyAgreementKey.getPrivate();
		pubKey = (ECPublicKey) this.authenticatorKeyAgreementKey.getPublic();

		ECKeyBuilder.setSecp251r1CurveParameters(privKey);
		ECKeyBuilder.setSecp251r1CurveParameters(pubKey);

		this.pinToken = new byte[32];

		/*
		 * Set to 0 until the clientPin was set by the user for the first time.
		 */
		this.retries = 0;

		/*
		 * Initialize crypto algorithms for the clienPin
		 */
		this.ecdh_p256 = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
		this.hmac_sha256 = new HMAC(MessageDigest.ALG_SHA_256);
		this.sharedSecret = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);

		this.pinHash = new byte[16];

		this.poweredUp = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);

		register();
	}

	/**
	 * Initializes the token by setting the certificate and the corresponding privateKey needed for basic attestation. After initialization the authenticator is
	 * ready to use.<br>
	 * <br>
	 * <b>Expects extended APDU!</b><br>
	 * Layout: 80 | 10 | 0000 | 00 | L_h L_l | 40 | 32-Byte EC private Key | Corresponding Certificate | 0000
	 * 
	 * @param apdu
	 *            Extended length APDU as described above.
	 */
	private void initialize(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		
		/*
		 * Establish the connection to the fingerprint applet.
		 */
		AID aid = JCSystem.lookupAID(Constants.SOCM_AID, (short) 0, (byte) Constants.SOCM_AID.length);
		this.fingerprint = (SharedBioTemplate) JCSystem.getAppletShareableInterfaceObject(aid, Constants.SOCM_PARAM);

		// Skip the instruction-byte (40)
		short bOffset = (short) (apdu.getOffsetCdata() + 1);

		/*
		 * Set the 32-byte private Key
		 */
		this.privateAttestationKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
		privateAttestationKey.setS(buffer, bOffset, (short) 32);

		ECKeyBuilder.setSecp251r1CurveParameters(this.privateAttestationKey);

		/*
		 * Calculate the length of the certificate and set it.
		 */
		bOffset += 32;
		this.x5c = new byte[(short) ((apdu.getOffsetCdata() + apdu.getIncomingLength()) - bOffset)];
		Util.arrayCopyNonAtomic(buffer, bOffset, this.x5c, (short) 0, (short) this.x5c.length);

		this.internalState = Constants.STATE_READY;
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		// Create the FIDO2Applet
		new FIDO2Applet(bArray, bOffset, bLength);
	}

	public boolean select() {
		// Generate the authenticatorKeyAgreementKey and pinToken only once every power up, not every select.
		if (useClientPin && this.poweredUp[0] == 0x00) {
			this.authenticatorKeyAgreementKey.genKeyPair();

			randomGenerator.generateData(this.pinToken, (byte) 0, (byte) this.pinToken.length);

			this.subsequentRetries = Constants.FIDO_SUBSEQUENT_RETRIES;
			this.poweredUp[0] = 0x01;
		}
		
		// Invalidates the fingerprint status for the current session.
		if (this.internalState != Constants.STATE_NOT_INITIALIZED) {
			fingerprint.reset();
		}
		return true;
	}

	public void deselect() {

	}

	/**
	 * Processes the incoming APDUs.<br>
	 * <br>
	 * The APDU format is specified in: <a href=
	 * "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#transport-specific-bindings">Client to
	 * Authenticator Protocol (CTAP) - Transport-specific Bindings</a>. <br>
	 * <br>
	 * Message encoding is specified in:
	 * <a href= "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding">Client to
	 * Authenticator Protocol (CTAP) - Message Encoding</a>.
	 *
	 * @param apdu
	 *            APDU as described above.
	 */
	@Override
	public void process(APDU apdu) throws ISOException {
		short bytesRead = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		short length = apdu.getIncomingLength();
		
		/*
		 * Check SELECT APDU command and return the supported FIDO2 version string, if authenticator is read to use.
		 */
		if (selectingApplet()) {
			if (this.internalState == Constants.STATE_READY) {
				apdu.setOutgoing();
				short bOffset = Util.arrayCopyNonAtomic(Constants.FIDO_VERSIONS, (short) 0, buffer, (short) 0, (short) Constants.FIDO_VERSIONS.length);
				apdu.setOutgoingLength(bOffset);
				apdu.sendBytes((short) 0, bOffset);
			}
			return;
		}
		
		/*
		 * Check if authenticator was already initialized. If not, only the initialize APDU will be accepted by the authenticator.
		 */
		if (this.internalState == Constants.STATE_NOT_INITIALIZED) {
			short bOffset = 0;
			if (buffer[apdu.getOffsetCdata()] == Constants.FIDO_INS_INITIALIZE) {
				initialize(apdu);
				bOffset = this.encoder.setFIDOReturnSW(Constants.CTAP2_OK, buffer);
			} else {
				bOffset = this.encoder.setFIDOReturnSW(Constants.CTAP2_ERR_OPERATION_DENIED, buffer);
			}

			this.encoder.prepare(apdu);
			this.encoder.send(apdu, bOffset);
			return;
		}

		/*
		 * Filter for response chaining mechanism. Filtering all chaining APDUs and send the next response bytes.
		 */
		if (this.internalState == Constants.STATE_RESPONSE_CHAINING && buffer[ISO7816.OFFSET_INS] == (byte) 0xC0) {
			this.encoder.prepare(apdu);
			this.apduBufferOffset = this.encoder.sendShortAPDUChain(apdu, this.apduBuffer, this.apduBufferOffset, this.apduBufferResponseEndOffset);

			// If last response bytes were send, reset internal state to ready.
			if (this.apduBufferOffset >= this.apduBufferResponseEndOffset) {
				this.internalState = Constants.STATE_READY;
				return;
			} else {
				ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
			}
		}
		// If this is a new command or we need command APDU chaining, we need to check the structure of the incoming APDU.
		else if (buffer[ISO7816.OFFSET_INS] != (byte) 0x10 || apdu.getIncomingLength() > Constants.FIDO_MAX_MSG_SIZE) {
			this.internalState = Constants.STATE_READY;
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}


		/*
		 * Handle the command APDU chaining and extended length APDUs.
		 */
		if (this.internalState == Constants.STATE_CHAINING) {
			this.apduBufferOffset = Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), this.apduBuffer, this.apduBufferOffset, length);
			if (buffer[ISO7816.OFFSET_CLA] != (byte) 0x90) {
				this.internalState = Constants.STATE_SHORT_LENGTH;
			} else {
				return;
			}
		}
		// Indicates the command will be chained.
		else if (buffer[ISO7816.OFFSET_CLA] == (byte) 0x90) {
			this.apduBufferOffset = Util.arrayCopyNonAtomic(buffer, (short) 0, this.apduBuffer, (short) 0, (short) (length + apdu.getOffsetCdata()));
			this.internalState = Constants.STATE_CHAINING;
			return;
		}
		// Extended or unchained short APDU.
		else {
			this.apduBufferOffset = Util.arrayCopyNonAtomic(buffer, (short) 0, this.apduBuffer, (short) 0, (short) (length + apdu.getOffsetCdata()));
			if (apdu.getOffsetCdata() != ISO7816.OFFSET_CDATA) {
				this.internalState = Constants.STATE_EXTENDED_LENGTH;
			} else {
				this.internalState = Constants.STATE_SHORT_LENGTH;
			}
		}

		/*
		 * Filter the FIDO2 instruction byte (first byte of CDATA) and invoke the corresponding method.
		 */
		try {
			switch (apduBuffer[apdu.getOffsetCdata()]) {
				case Constants.FIDO_INS_AUTHENTICATOR_MAKE_CREDENTIAL:
					authenticatorMakeCredential(apdu);

					// Only used, when response APDU chaining needed.
					if (this.internalState == Constants.STATE_RESPONSE_CHAINING) {
						if (this.apduBufferOffset < this.apduBufferResponseEndOffset) {
							ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
						}
					} 
				
					this.internalState = Constants.STATE_READY;
					return;
				case Constants.FIDO_INS_AUTHENTICATOR_GET_ASSERTION:
					authenticatorGetAssertion(apdu);
					
					// Only used, when response APDU chaining needed.
					if (this.internalState == Constants.STATE_RESPONSE_CHAINING) {
						if (this.apduBufferOffset < this.apduBufferResponseEndOffset) {
							ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
						}
					}

					this.internalState = Constants.STATE_READY;
					return;
				case Constants.FIDO_INS_AUTHENTICATOR_CLIENT_PIN:
					authenticatorClientPin(apdu);
					this.internalState = Constants.STATE_READY;
					return;
				case Constants.FIDO_INS_AUTHENTICATOR_GET_NEXT_ASSERTION:
					authenticatorGetNextAssertion(apdu);

					// Only used, when response APDU chaining needed.
					if (this.internalState == Constants.STATE_RESPONSE_CHAINING) {
						if (this.apduBufferOffset < this.apduBufferResponseEndOffset) {
							ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
						}
					}

					this.internalState = Constants.STATE_READY;
					return;
				case Constants.FIDO_INS_AUTHENTICATOR_GET_INFO:
					authenticatorGetInfo(apdu);
					this.internalState = Constants.STATE_READY;
					return;
				case Constants.FIDO_INS_AUTHENTICATOR_RESET:
					authenticatorReset(apdu);
					return;
				default:
					this.internalState = Constants.STATE_READY;
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		} catch (CardException e) {
			// UserExceptions will return the corresponding FIDO2-SW-Byte
			// Layout: FIDO2-SW-Byte | 9000
			if (e instanceof UserException) {
				this.encoder.prepare(apdu);
				short bOffset = this.encoder.setFIDOReturnSW((byte) (e.getReason() & 0xFF), buffer);
				this.encoder.send(apdu, bOffset);
			}
			// Reset the internal state on every exception always to STATE_READY.
			this.internalState = Constants.STATE_READY;
		}

		return;
	}

	/**
	 * Generate a new credential for the requesting web site.<br>
	 * <br>
	 * The CDATA contain the following CBOR encoded parameters:
	 * <ol>
	 * <li>(mandatory) clientDataHash</li>
	 * <li>(mandatory) rp</li>
	 * <li>(mandatory) user</li>
	 * <li>(mandatory) pubKeyCredParams</li>
	 * <li>(optional) excludeList</li>
	 * <li>(optional) extensions</li>
	 * <li>(optional) options</li>
	 * <li>(optional) pinAuth</li>
	 * <li>(optional) pinProtocol</li>
	 * </ol>
	 * <br>
	 * At successful execution, the response APDU contains following map entries:
	 * <ol>
	 * <li>(mandatory) fmd</li>
	 * <li>(mandatory) authData</li>
	 * <li>(mandatory) attStmt</li>
	 * </ol>
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_MISSING_PARAMETER</b> when mandatory parameters, map entries or array entries are missing.</li>
	 *             <li><b>CTAP2_ERR_UNSUPPORTED_ALGORITHM</b> when the RP does not support {@link Constants#IANA_COSE_ES256} algorithm.</li>
	 *             <li><b>CTAP2_ERR_INVALID_OPTION</b> when the rk or uv option are set to an unsupported value for this option.</li>
	 *             <li><b>CTAP2_ERR_UNSUPPORTED_OPTION</b> when the up option was sent either by the RP.</li>
	 *             <li><b>CTAP2_ERR_PIN_AUTH_INVALID</b> when the pinAuth send by the RP was made with an other pinToken than the current one of the
	 *             authenticator (changes on every power up).</li>
	 *             <li><b>CTAP2_ERR_PIN_REQUIRED</b> when clientPin is set and the user has to enter the pin code.</li>
	 *             <li><b>CTAP2_ERR_PIN_NOT_SET</b> when clientPin is used and the pin has to be initialized by the user for the first time.</li>
	 *             <li><b>CTAP2_ERR_OPERATION_DENIED</b> when user verification was not granted.</li>
	 *             <li><b>CTAP2_ERR_PROCESSING</b> when some error occurs during credential key pair generation.</li>
	 *             <li>See also {@link CBORDecoder}.
	 *             </ul>
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential</a>
	 */
	public void authenticatorMakeCredential(APDU apdu) throws UserException {
		byte[] buffer = this.apduBuffer;

		decoder.init(this.apduBufferOffset, apdu.getOffsetCdata());

		/*
		 * Step 1 - Check CBOR encoded parameters and parse their offsets.
		 */
		// All parameters are passed as map
		decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, true);
		short paramListLength = decoder.valueLength;

		// Check if all mandatory parameters are present
		if (paramListLength < 4 || 9 < paramListLength) {
			UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
		}

		// 0x01 - Client Data Hash - MANDATORY
		short clientDataHash = decoder.parseExpectedParam((byte) 0x01, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
		short clientDataHashValueOffset = decoder.valueOffset;
		short clientDataHashLength = decoder.valueLength;

		// 0x02 - rp - MANDATORY
		short rp = decoder.parseExpectedParam((byte) 0x02, Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, true);
		short rpListLength = decoder.valueLength;

		// Check if all mandatory entries are present
		if (rpListLength < 0 || 3 < rpListLength) {
			UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
		}

		// rp id - MANDATORY
		short rpId = decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_ID, Constants.CBOR_MAJOR_TYPE_TEXT_STRING, buffer,
				decoder.nextOffset, true);
		short rpIdValueOffset = decoder.valueOffset;
		short rpIdValueLength = decoder.valueLength;

		// rp icon - OPTIONAL
		short rpIcon = decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_ICON, Constants.CBOR_MAJOR_TYPE_TEXT_STRING,
				buffer,
				decoder.nextOffset, false);
		short rpIconValueOffset = decoder.valueOffset;
		short rpIconLength = decoder.valueLength;

		// rp name - OPTIONAL
		short rpName = decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_NAME, Constants.CBOR_MAJOR_TYPE_TEXT_STRING,
				buffer,
				decoder.nextOffset, false);
		short rpNameValueOffset = decoder.valueOffset;
		short rpNameLength = decoder.valueLength;

		// 0x03 - user - MANDATORY
		short user = decoder.parseExpectedParam((byte) 0x03, Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, true);
		short userParamLength = decoder.valueLength;

		// Check if all mandatory entries are present
		if (userParamLength < 1 || 4 < userParamLength) {
			UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
		}

		// user id - MANDATORY
		short userId = decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_ID, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer,
				decoder.nextOffset, true);
		short userIdValueOffset = decoder.valueOffset;
		short userIdLength = decoder.valueLength;

		// user icon - OPTIONAL
		short userIcon = decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_ICON, Constants.CBOR_MAJOR_TYPE_TEXT_STRING,
				buffer,
				decoder.nextOffset, false);
		short userIconValueOffset = decoder.valueOffset;
		short userIconLength = decoder.valueLength;

		// user name - OPTIONAL
		short userName = decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_NAME, Constants.CBOR_MAJOR_TYPE_TEXT_STRING,
				buffer,
				decoder.nextOffset, false);
		short userNameValueOffset = decoder.valueOffset;
		short userNameLength = decoder.valueLength;

		// user displayName - OPTIONAL
		short userDisplayName = decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_DISPLAYNAME,
				Constants.CBOR_MAJOR_TYPE_TEXT_STRING, buffer, decoder.nextOffset, false);
		short userDisplayNameValueOffset = decoder.valueOffset;
		short userDisplayNameLength = decoder.valueLength;

		// 0x04 pubKeyCredParams - MANDATORY
		short pubKeyCredParams = decoder.parseExpectedParam((byte) 0x04, Constants.CBOR_MAJOR_TYPE_ARRAY, buffer, decoder.nextOffset, true);
		short pubKeyCredParamsValueOffset = decoder.valueOffset;
		short pubKeyCredParamsLength = decoder.valueLength;

		// Check if all mandatory entries are present
		if (pubKeyCredParamsLength < 1) {
			UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
		}

		for (short i = 0; i < (short) (pubKeyCredParamsLength * 5); i++) {
			decoder.skipNext(buffer, decoder.nextOffset);
		}

		// 0x05 - excludeList - OPTIONAL
		short excludeListParams = decoder.parseExpectedParam((byte) 0x05, Constants.CBOR_MAJOR_TYPE_ARRAY, buffer, decoder.nextOffset, false);
		short excludeListValueOffset = decoder.valueOffset;
		short excludeListLength = decoder.valueLength;

		// 0x06 - extensions - OPTIONAL
		short extensionsParams = decoder.parseExpectedParam((byte) 0x06, Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, false);
		short extensionsLength = decoder.valueLength;

		for (short i = 0; i < (short) (excludeListLength * 2) && extensionsParams != -1; i++) {
			decoder.skipNext(buffer, decoder.nextOffset);
		}

		// 0x07 - options - OPTIONAL
		short optionsParams = decoder.parseExpectedParam((byte) 0x07, Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, false);
		short optionsFirstEntry = decoder.nextOffset;
		short optionsLength = decoder.valueLength;

		for (short i = 0; i < (short) (optionsLength * 2) && optionsParams != -1; i++) {
			decoder.skipNext(buffer, decoder.nextOffset);
		}

		// 0x08 - pinAuth - OPTIONAL
		short pinAuthParams = decoder.parseExpectedParam((byte) 0x08, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, false);
		short pinAuthOffset = decoder.valueOffset;
		short pinAuthLength = decoder.valueLength;

		// 0x09 - pinProcotol - OPTIONAL
		short pinProcotolParams = decoder.parseExpectedParam((byte) 0x09, Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false);

		/*
		 * Step 2 - Process the data according to the specification of authenticatorMakeCredential
		 */
		// 1. The excludeList parameter can be ignored, cause we do not store any credentials.
		// 2. Check the supported algorithms of the RP. The authenticator only supports ECDSA_SHA_256. Algorithms are encoded according to the COSE Algorithm
		// Identifiers.
		boolean algMatched = false;
		short entryMapAlgValue = 0;

		for (short i = 0; i < pubKeyCredParamsLength; i++) {
			short entryMap = decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_MAP, buffer, pubKeyCredParamsValueOffset, true);
			short entryMapLength = decoder.valueLength;

			// Each algorithm is encoded as map of two pairs.
			if (entryMapLength != 2) {
				UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
			}

			// Check algorithm entry, could be both, a negative or a positive integer
			short entryMapAlgOffset = decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_ALG, Constants.CBOR_MAJOR_TYPE_UINT,
					buffer,	decoder.nextOffset, false);

			if (entryMapAlgOffset == -1) {
				entryMapAlgOffset = decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_ALG, Constants.CBOR_MAJOR_TYPE_INT,
						buffer, decoder.nextOffset, true);

				entryMapAlgValue = decoder.readINT(buffer, entryMapAlgOffset);
			} else {
				entryMapAlgValue = decoder.readUINT(buffer, entryMapAlgOffset);
			}

			// Check type entry
			short entryMapTypeOffset = decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_TYPE,
					Constants.CBOR_MAJOR_TYPE_TEXT_STRING, buffer, decoder.nextOffset, true);

			if (!decoder.isExpectedValueOf(Constants.STRING_PUBLIC_KEY, buffer, decoder.valueOffset, decoder.valueLength)) {
				UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
			}

			// Check whether the authenticator supports the current algorithm or not. If not, check the next entry.
			if (entryMapAlgValue == Constants.IANA_COSE_ES256) {
				algMatched = true;
				break;
			}

			pubKeyCredParamsValueOffset = decoder.nextOffset;
		}

		// Check, whether we found a supported algorithm or not.
		if (!algMatched) {
			UserException.throwIt(Constants.CTAP2_ERR_UNSUPPORTED_ALGORITHM);
		}

		// 3. Process the options parameter. We have to support rk (resident key) and uv (user verification) options but also we must understand the up (user
		// presence) option.
		boolean rk = false; // default value
		boolean uv = false; // default value

		if (optionsParams != -1) {
			short entryOffset = optionsFirstEntry;
			for (short i = 0; i < optionsLength; i++) {
				decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, buffer, entryOffset, true);

				if (decoder.isExpectedValueOf(Constants.STRING_RK, buffer, decoder.valueOffset, (short) Constants.STRING_RK.length)) {
					short optionsRk = decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_SIMPLE_VALUES, buffer, decoder.nextOffset, false);

					short optionsRkValue = optionsRk != -1 ? decoder.readSimpleValue(buffer, optionsRk) : Constants.CBOR_NULL;

					// We can't store any key material on the device, so only CBOR_FALSE is an valid option
					switch (optionsRkValue) {
						case Constants.CBOR_FALSE:
							rk = false;
						break;
						case Constants.CBOR_TRUE:
						case Constants.CBOR_NULL:
						default:
							UserException.throwIt(Constants.CTAP2_ERR_INVALID_OPTION);
					}
				} else if (decoder.isExpectedValueOf(Constants.STRING_UV, buffer, entryOffset, (short) Constants.STRING_UV.length)) {
					short optionsUv = decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_SIMPLE_VALUES, buffer, decoder.nextOffset, false);

					short optionsUvValue = optionsUv != -1 ? decoder.readSimpleValue(buffer, optionsUv) : Constants.CBOR_NULL;

					switch (optionsUvValue) {
						case Constants.CBOR_TRUE:
						case Constants.CBOR_FALSE:
							uv = optionsUvValue == Constants.CBOR_TRUE;
						break;
						case Constants.CBOR_NULL:
						default:
							UserException.throwIt(Constants.CTAP2_ERR_INVALID_OPTION);
					}
				} else if (decoder.isExpectedValueOf(Constants.STRING_UP, buffer, entryOffset, (short) Constants.STRING_UP.length)) {
					UserException.throwIt(Constants.CTAP2_ERR_UNSUPPORTED_OPTION); // TODO: Maybe ERR_INVALID_OPTION?
				} else {
					decoder.skipNext(buffer, decoder.nextOffset);
				}

				entryOffset = decoder.nextOffset;
			}

		}

		// 4. Check the extensions parameter and process all supported extensions. We will ignore this, because we are currently not supporting any extensions.

		// 5. - 8. Check for user verification, either through clientPin via pinProtocol and pinAuth or through fingerprint.
		boolean userVerified = false;
		if (useClientPin && pinAuthParams != -1 && pinAuthLength > 0 && pinProcotolParams != -1
				&& this.decoder.readUINT(buffer, pinProcotolParams) == 0x01) {

			// Generate HMAC-SHA256 over the clientDataHash using pinToken
			hmac_sha256.init(this.pinToken, (short) 0, (short) this.pinToken.length);
			hmac_sha256.doFinal(buffer, clientDataHashValueOffset, clientDataHashLength, this.ram, (short) 0);

			// Check the first 16 byte of the generate HMAC-SHA256 against the pinAuth parameter to verify the clientPin
			if (Util.arrayCompare(buffer, pinAuthOffset, this.ram, (short) 0, (short) 16) == 0) {
				userVerified = true;
			} else {
				UserException.throwIt(Constants.CTAP2_ERR_PIN_AUTH_INVALID);
			}

		} else if (useClientPin && (pinAuthParams == -1 || pinAuthLength == 0)) {
			this.internalState = Constants.STATE_READY;

			if (this.pinInitialized) {
				UserException.throwIt(Constants.CTAP2_ERR_PIN_REQUIRED);
			} else {
				UserException.throwIt(Constants.CTAP2_ERR_PIN_NOT_SET);
			}
		} else {
			userVerified = fingerprint.isValidated();
		}

		if (!userVerified) {
			UserException.throwIt(Constants.CTAP2_ERR_OPERATION_DENIED);
		}

		// 9. Generate new credential key pair
		try {
			credentialKeyPair.genKeyPair();
		} catch (Exception e) {
			UserException.throwIt(Constants.CTAP2_ERR_PROCESSING);
		}

		// 10. Process the rk option. We ignore it, because we do not support resident keys. Our credentials are stored on the RP.

		// 11. Generate the attestation statement using clientDataHash
		short ramOffset = 0;
		short rpIdRAMOffset = ramOffset;
		ramOffset = this.decoder.readString(buffer, rpIdValueOffset, rpIdValueLength, this.ram, rpIdRAMOffset);

		/* Prepare flags */
		// Set user presence (0x01), user verification (0x04) and attestedCredentialData (0x40) bit
		byte flags = (byte) 0x00;
		flags = userVerified ? (byte) (flags ^ 0x01) : flags;
		flags = uv && userVerified ? (byte) (flags ^ 0x04) : flags;
		flags ^= 0x40;

		/* Prepare authData */
		// Encode credential Data
		short credentialIdRAMOffset = ramOffset;
		ramOffset = this.encoder.setMapType((short) 4, this.ram, ramOffset);

		// 1 - type
		ramOffset = this.encoder.setUIntValue((short) 1, this.ram, ramOffset);
		ramOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, (short) Constants.STRING_PUBLIC_KEY.length, this.ram, ramOffset);
		ramOffset = Util.arrayCopy(Constants.STRING_PUBLIC_KEY, (short) 0, this.ram, ramOffset, (short) Constants.STRING_PUBLIC_KEY.length);

		// 2 - privateKey
		ramOffset = this.encoder.setUIntValue((short) 2, this.ram, ramOffset);
		ramOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, (short) (credentialKeyPair.getPrivate().getSize() / 8),
				this.ram, ramOffset);
		ramOffset += ((ECPrivateKey) credentialKeyPair.getPrivate()).getS(this.ram, ramOffset);

		// 3 - rpID
		ramOffset = this.encoder.setUIntValue((short) 3, this.ram, ramOffset);
		ramOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, rpIdValueLength, this.ram, ramOffset);
		ramOffset = Util.arrayCopy(this.ram, rpIdRAMOffset, this.ram, ramOffset, rpIdValueLength);

		// 4 - userHandle
		ramOffset = this.encoder.setUIntValue((short) 4, this.ram, ramOffset);
		ramOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, userIdLength, this.ram, ramOffset);
		ramOffset = this.decoder.readString(buffer, userIdValueOffset, userIdLength, this.ram, ramOffset);

		short credentialIdLength = (short) (ramOffset - credentialIdRAMOffset);
		short paddingLength = (short) (16 - (credentialIdLength % 16)); // Used for AES256-CBC
		credentialIdLength += paddingLength > 0 ? paddingLength : 0;
		// TODO: signCounter?
		if (paddingLength < 16 && paddingLength > 0) {
			ramOffset = this.encoder.setByte((byte) (paddingLength & 0xFF), this.ram, (short) (credentialIdLength - 1));
		}

		/* Prepare public key */
		// Write the credentials public key in COSE_KEY format into RAM
		short pubKeyRAMOffset = ramOffset;
		ramOffset += ((ECPublicKey) credentialKeyPair.getPublic()).getW(this.ram, pubKeyRAMOffset);

		short credentialPublicKeyRAMOffset = ramOffset;
		ramOffset = this.encoder.setMapType((short) 5, this.ram, credentialPublicKeyRAMOffset);

		// 1 - Key Type
		ramOffset = this.encoder.setUIntValue((short) 1, this.ram, ramOffset);
		ramOffset = this.encoder.setUIntValue((short) 2, this.ram, ramOffset);

		// 3 - algorithm identifier
		ramOffset = this.encoder.setUIntValue((short) 3, this.ram, ramOffset);
		ramOffset = this.encoder.setIntValue(Constants.IANA_COSE_ES256, this.ram, ramOffset);

		// -1 - curve
		ramOffset = this.encoder.setIntValue((short) -1, this.ram, ramOffset);
		ramOffset = this.encoder.setUIntValue((short) 1, this.ram, ramOffset);

		// -2 - x-coordinate
		ramOffset = this.encoder.setIntValue((short) -2, this.ram, ramOffset);
		ramOffset = this.encoder.setByte((byte) 0x58, this.ram, ramOffset);
		ramOffset = this.encoder.setByte((byte) 0x20, this.ram, ramOffset);
		ramOffset = this.encoder.setBytes(this.ram, (short) (pubKeyRAMOffset + 1), (short) 32, this.ram, ramOffset);

		// -3 - y-coordinate
		ramOffset = this.encoder.setIntValue((short) -3, this.ram, ramOffset);
		ramOffset = this.encoder.setByte((byte) 0x58, this.ram, ramOffset);
		ramOffset = this.encoder.setByte((byte) 0x20, this.ram, ramOffset);
		ramOffset = this.encoder.setBytes(this.ram, (short) (pubKeyRAMOffset + 33), (short) 32, this.ram, ramOffset);

		short credentialPublicKeyLength = (short) (ramOffset - credentialPublicKeyRAMOffset);
		short encCredentialIdLength = (short) (credentialIdLength + 16);
		short authenticatorDataLength = (short) (37 + 18 + credentialPublicKeyLength + encCredentialIdLength);

		short clientDataHashRAMOffset = ramOffset;
		ramOffset = this.decoder.readString(buffer, clientDataHashValueOffset, clientDataHashLength, this.ram, ramOffset);
		
		/*
		 * Step 3 - Generate the response
		 */
		// Start encoding the response
		short bOffset = this.encoder.prepare(apdu);
		bOffset = this.encoder.setMapType((short) 3, buffer, bOffset);

		/* 0x01 - fmt - MANDATORY */
		bOffset = this.encoder.setUIntValue((short) 1, buffer, bOffset);
		bOffset = this.encoder.setTextString(Constants.STRING_PACKED, (short) 6, buffer, bOffset);

		/* 0x02 - authData - MANDATORY */
		bOffset = this.encoder.setUIntValue((short) 2, buffer, bOffset);
		bOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, authenticatorDataLength, buffer, bOffset);

		short offsetAuthData = bOffset;
		// Hash of rpID
		bOffset += sha256.doFinal(this.ram, rpIdRAMOffset, rpIdValueLength, buffer, bOffset);

		// flags
		bOffset = this.encoder.setByte(flags, buffer, bOffset);

		// signCounter
		bOffset = this.encoder.setByte((byte) ((signCounter[0] >> 8) & 0xFF), buffer, bOffset);
		bOffset = this.encoder.setByte((byte) (signCounter[0] & 0xFF), buffer, bOffset);
		bOffset = this.encoder.setByte((byte) ((signCounter[1] >> 8) & 0xFF), buffer, bOffset);
		bOffset = this.encoder.setByte((byte) (signCounter[1] & 0xFF), buffer, bOffset);

		// aaguid
		bOffset = this.encoder.setBytes(Constants.FIDO_AAGUID, (short) 0, (short) Constants.FIDO_AAGUID.length, buffer, bOffset);

		// length of credentialId
		bOffset = this.encoder.setByte((byte) ((encCredentialIdLength >> 8) & 0xFF), buffer, bOffset);
		bOffset = this.encoder.setByte((byte) (encCredentialIdLength), buffer, bOffset);

		// credentialId - AES256 encoded
		this.randomGenerator.generateData(this.iv, (short) 0, (short) 16);
		this.aes256.init(this.encryptionKey, Cipher.MODE_ENCRYPT, this.iv, (short) 0, (short) this.iv.length);

		bOffset += this.aes256.doFinal(this.ram, credentialIdRAMOffset, credentialIdLength, buffer, bOffset);
		bOffset = this.encoder.setBytes(this.iv, (short) 0, (short) this.iv.length, buffer, bOffset);

		// credentialPublicKey
		bOffset = this.encoder.setBytes(this.ram, credentialPublicKeyRAMOffset, credentialPublicKeyLength, buffer, bOffset);

		/* 0x03 - attStmt - MANDATORY */
		bOffset = this.encoder.setUIntValue((short) 3, buffer, bOffset);
		bOffset = this.encoder.setMapType((short) 3, buffer, bOffset);
		
		// Encode signature algorithm
		bOffset = this.encoder.setTextString(Constants.STRING_ALG, (short) 3, buffer, bOffset);
		bOffset = this.encoder.setIntValue(Constants.IANA_COSE_ES256, buffer, bOffset);

		// Generate ES256(privateAttestationKey, authData | clientDataHash)
		es256.init(this.privateAttestationKey, Signature.MODE_SIGN);
		es256.update(buffer, offsetAuthData, authenticatorDataLength);
		es256.update(this.ram, clientDataHashRAMOffset, clientDataHashLength);
		
		bOffset = this.encoder.setTextString(Constants.STRING_SIG, (short) 3, buffer, bOffset);
		short signLength = es256.sign(null, (short) 0, (short) 0, this.ram, (short) 0);
		bOffset = this.encoder.setByteString(this.ram, signLength, buffer, bOffset);

		// authenticator certificate
		bOffset = this.encoder.setTextString(Constants.STRING_X5C, (short) 3, buffer, bOffset);
		bOffset = this.encoder.setArrayType((short) 1, buffer, bOffset);
		bOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, (short) this.x5c.length, buffer, bOffset);
		bOffset = this.encoder.setBytes(this.x5c, (short) 0, (short) this.x5c.length, buffer, bOffset);

		this.encoder.setFIDOReturnSW((byte) 0x00, buffer);
	
		if (this.internalState == Constants.STATE_EXTENDED_LENGTH) {
			Util.arrayCopyNonAtomic(this.apduBuffer, (short) 0, apdu.getBuffer(), (short) 0, bOffset);
			this.encoder.send(apdu, bOffset);
		} else {
			this.apduBufferResponseEndOffset = bOffset;
			this.apduBufferOffset = 0;
			this.apduBufferOffset = this.encoder.sendShortAPDUChain(apdu, this.apduBuffer, this.apduBufferOffset, this.apduBufferResponseEndOffset);
			this.internalState = Constants.STATE_RESPONSE_CHAINING;
		}
	}

	/**
	 * Generates cryptographic proof of user authentication and user consent.<br>
	 * <br>
	 * When more than one credential is send via allowList, subsequent calls to authenticatorGetNextAssertion are necessary. (Should not happen) <br>
	 * <br>
	 * The CDATA contain the following CBOR encoded parameters:
	 * <ol>
	 * <li>(mandatory) rpId</li>
	 * <li>(mandatory) clientDataHash</li>
	 * <li>(mandatory) allowList</li>
	 * <li>(optional) extensions</li>
	 * <li>(optional) options</li>
	 * <li>(optional) pinAuth</li>
	 * <li>(optional) pinProtocol</li>
	 * </ol>
	 * 
	 * <br>
	 * At successful execution, the response APDU contains following map entries:
	 * <ol>
	 * <li>(optional) credential</li>
	 * <li>(mandatory) authData</li>
	 * <li>(mandatory) signature</li>
	 * <li>(optional) user</li>
	 * <li>(optional) numberOfCredentials</li>
	 * </ol>
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_MISSING_PARAMETER</b> when mandatory parameters, map entries or array entries are missing.</li>
	 *             <li><b>CTAP2_ERR_INVALID_OPTION</b> when the up or uv option are set to an unsupported value for this option.</li>
	 *             <li><b>CTAP2_ERR_UNSUPPORTED_OPTION</b> when the rk option was sent either by the RP.</li>
	 *             <li><b>CTAP2_ERR_PIN_AUTH_INVALID</b> when the pinAuth send by the RP was generated with an other pinToken than the current one of the
	 *             authenticator (changes on every power up).</li>
	 *             <li><b>CTAP2_ERR_PIN_REQUIRED</b> when clientPin is set and the user has to enter the pin code.</li>
	 *             <li><b>CTAP2_ERR_PIN_NOT_SET</b> when clientPin is used and the pin has to be initialized by the user for the first time.</li>
	 *             <li><b>CTAP2_ERR_OPERATION_DENIED</b> when user verification was not granted.</li>
	 *             <li>See also {@link CBORDecoder}.
	 *             </ul>
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion</a>
	 */
	public void authenticatorGetAssertion(APDU apdu) throws UserException {
		byte[] buffer = this.apduBuffer;

		this.decoder.init(this.apduBufferOffset, apdu.getOffsetCdata());

		/*
		 * Step 1 - Check CBOR encoded parameters and parse their offsets.
		 */
		// All parameters are passed as map
		this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, true);
		
		// Check if all mandatory parameters are present
		if (decoder.valueLength < 2 || decoder.valueLength > 7) {
			UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
		}
		
		// 0x01 - rpId - MANDATORY
		short rpId = this.decoder.parseExpectedParam((byte) 0x01, Constants.CBOR_MAJOR_TYPE_TEXT_STRING, buffer, decoder.nextOffset, true);
		short rpIdValueOffset = this.decoder.valueOffset;
		short rpIdLength = this.decoder.valueLength;

		// 0x02 - clientDataHash - MANDATORY
		short clientDataHash = this.decoder.parseExpectedParam((byte) 0x02, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
		short clientDataHashValueOffset = this.decoder.valueOffset;
		short clientDataHashLength = this.decoder.valueLength;

		// 0x03 - allowList - MANDATORY (because authenticator does not store any credentials)
		short allowList = this.decoder.parseExpectedParam((byte) 0x03, Constants.CBOR_MAJOR_TYPE_ARRAY, buffer, decoder.nextOffset, true);
		short allowListValueOffset = this.decoder.valueOffset;
		short allowListLength = this.decoder.valueLength;
		short allowListFirstEntry = this.decoder.nextOffset;

		for (short i = 0; i < allowListLength && allowList != -1; i++) {
			this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, true);
			short entryLength = decoder.valueLength;
			for (short j = 0; j < (short) (entryLength * 2); j++) {
				decoder.skipNext(buffer, decoder.nextOffset);
			}
		}

		short allowListEnd = this.decoder.nextOffset; // needed to save CBOR parameters from rpId to end of allowList into RAM.

		// 0x04 - extensions - OPTIONAL
		short extensions = this.decoder.parseExpectedParam((byte) 0x04, Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, false);
		short extensionsValueOffset = this.decoder.valueOffset;
		short extensionsLength = this.decoder.valueLength;

		for (short i = 0; i < (short) (extensionsLength * 2) && extensions != -1; i++) {
			decoder.skipNext(buffer, decoder.nextOffset);
		}

		// 0x05 - options - OPTIONAL
		short options = this.decoder.parseExpectedParam((byte) 0x05, Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, false);
		short optionsValueOffset = this.decoder.valueOffset;
		short optionsFirstEntry = this.decoder.nextOffset;
		short optionsLength = this.decoder.valueLength;

		for (short i = 0; i < (short) (optionsLength * 2) && options != -1; i++) {
			decoder.skipNext(buffer, decoder.nextOffset);
		}

		// 0x06 - pinAuth - OPTIONAL
		short pinAuth = this.decoder.parseExpectedParam((byte) 0x06, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, false);
		short pinAuthValueOffset = this.decoder.valueOffset;
		short pinAuthLength = this.decoder.valueLength;

		// 0x07 - pinProtocol - OPTIONAL
		short pinProtocol = this.decoder.parseExpectedParam((byte) 0x07, Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false);

		/*
		 * Step 2 - Process the data according to the specification of authenticatorGetAssertion
		 */
		// 1. Locate credentials - therefore we check the allowList and set the numberOfCredentials to the allowList. In this case this should be one value out
		// of 0 or 1.
		this.numberOfCredentials = allowList != -1 ? allowListLength : 0;

		// 2. - 4 Check for user verification, either through clientPin via pinProtocol and pinAuth or through fingerprint.
		boolean userVerified = false;
		if (useClientPin && pinAuth != -1 && pinAuthLength > 0 && pinProtocol != -1 && this.decoder.readUINT(buffer, pinProtocol) == 0x01) {

			// Generate HMAC-SHA256 over clientDataHash using pinToken
			hmac_sha256.init(this.pinToken, (short) 0, (short) this.pinToken.length);
			hmac_sha256.doFinal(buffer, clientDataHashValueOffset, clientDataHashLength, this.ram, (short) 0);

			// Check the first 16 byte of the generate HMAC-SHA256 against the pinAuth parameter to verify the clientPin
			if (Util.arrayCompare(buffer, pinAuthValueOffset, this.ram, (short) 0, (short) 16) == 0) {
				userVerified = true;
			} else {
				UserException.throwIt(Constants.CTAP2_ERR_PIN_AUTH_INVALID);
			}

		} else if (useClientPin && (pinAuth == -1 || pinAuthLength == 0)) {
			this.internalState = Constants.STATE_READY;

			if (this.pinInitialized) {
				UserException.throwIt(Constants.CTAP2_ERR_PIN_REQUIRED);
			} else {
				UserException.throwIt(Constants.CTAP2_ERR_PIN_NOT_SET);
			}
		} else {
			userVerified = fingerprint.isValidated();
		}

		// 5. Process the options parameter. We have to support up (user presence) and uv (user verification) options but also we must understand the rk
		// (resident key) option.
		boolean up = true; // default value
		boolean uv = false; // default value

		if (options != -1) {
			short entryOffset = optionsFirstEntry;
			for (short i = 0; i < optionsLength; i++) {
				decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, buffer, entryOffset, true);

				if (decoder.isExpectedValueOf(Constants.STRING_RK, buffer, decoder.valueOffset, (short) Constants.STRING_RK.length)) {
					UserException.throwIt(Constants.CTAP2_ERR_UNSUPPORTED_OPTION); // TODO: Maybe ERR_INVALID_OPTION?
				} else if (decoder.isExpectedValueOf(Constants.STRING_UV, buffer, decoder.valueOffset, (short) Constants.STRING_UV.length)) {
					short optionsUv = decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_SIMPLE_VALUES, buffer, decoder.nextOffset, false);

					short optionsUvValue = optionsUv != -1 ? decoder.readSimpleValue(buffer, optionsUv) : Constants.CBOR_NULL;

					switch (optionsUvValue) {
						case Constants.CBOR_TRUE:
						case Constants.CBOR_FALSE:
							uv = optionsUvValue == Constants.CBOR_TRUE;
						break;
						case Constants.CBOR_NULL:
						default:
							UserException.throwIt(Constants.CTAP2_ERR_INVALID_OPTION);
					}
				} else if (decoder.isExpectedValueOf(Constants.STRING_UP, buffer, decoder.valueOffset, (short) Constants.STRING_UP.length)) {
					short optionsUp = decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_SIMPLE_VALUES, buffer, decoder.nextOffset, false);

					short optionsUpValue = optionsUp != -1 ? decoder.readSimpleValue(buffer, optionsUp) : Constants.CBOR_NULL;

					switch (optionsUpValue) {
						case Constants.CBOR_FALSE:
						case Constants.CBOR_TRUE:
							up = optionsUpValue == Constants.CBOR_TRUE;
							break;
						case Constants.CBOR_NULL:
						default:
							UserException.throwIt(Constants.CTAP2_ERR_INVALID_OPTION);
					}
				} else {
					decoder.skipNext(buffer, decoder.nextOffset);
				}

				entryOffset = decoder.nextOffset;
			}

		}

		// 6. Check the extensions parameter and process all supported extensions. We will ignore this, because we are currently not supporting any extensions.

		// 7. Check for user consent - in this check, if fingerprint verification was successful.
		if (!userVerified) {
			UserException.throwIt(Constants.CTAP2_ERR_OPERATION_DENIED);
		}

		// 8. Throw error, if numberOfCredentials is empty. Because we are not storing any credentials, the server has to send minimum one credential via
		// allowList to the authenticator.
		if (numberOfCredentials == 0) {
			UserException.throwIt(Constants.CTAP2_ERR_NO_CREDENTIALS);
		}

		// 9. Ignore this, because credentials have not timestamp.
		// 10. Prepare everything for authenticatorGetNextAssertion if more than one credential was sent via allowList

		short responseMapEntries = 3; // mandatory entries
		short ramOffset = 0;

		rpId -= 1; // because current offset is set to the encoded rpId value, but also we want to have the key byte of this entry
		ramOffset = Util.arrayCopyNonAtomic(buffer, rpId, this.ram, ramOffset, (short) (allowListEnd - rpId));

		// If multiple credentials were sent, we need to respond also with the numberOfCredentials
		if (numberOfCredentials > 1) {
			// TODO: Maybe start timer! Currently we will ignore it.
			responseMapEntries += 1;
			credentialCounter = 0;
		}

		// 11. Ignore step 11, because authenticator has no display.
		
		// 12. Generate the signature over the first allowList entry
		// Calculate this offset out of the information gathered in step 1
		short rpIdRAMOffset = (short) (rpIdValueOffset - rpId);
		short clientDataHashRAMOffset = (short) (clientDataHashValueOffset - rpId);
		
		allowListFirstEntry = this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_MAP, this.ram, (short) (allowListFirstEntry - rpId), true);
		short allowListFirstEntryID = this.decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_ID,
				Constants.CBOR_MAJOR_TYPE_BYTE_STRING, this.ram, decoder.nextOffset, true);
		short firstEntryLength = decoder.valueLength;

		// Extract credentialId, any problem with the credentialId has to be treated as CTAP2_ERR_MISSING_PARAMETER
		short apduBufferOffset = 0;
		short credentialIDapduBufferOffset = apduBufferOffset;

		// TODO: Rewrite this section?
		try {

			this.aes256.init(this.encryptionKey, Cipher.MODE_DECRYPT, this.ram, (short) (decoder.nextOffset - 16), (short) 16);
			this.apduBufferOffset += this.aes256.doFinal(this.ram, decoder.valueOffset, (short) (firstEntryLength - 16), this.apduBuffer,
					credentialIDapduBufferOffset);

			// credentialId was structured as CBOR Map in authenticatorMakeCredential
			this.decoder.skipNext(this.apduBuffer, credentialIDapduBufferOffset); // Map;
			this.decoder.skipNext(this.apduBuffer, decoder.nextOffset); // 0x01
			this.decoder.skipNext(this.apduBuffer, decoder.nextOffset); // packed_string

			short privKeyParamID = this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_UINT, this.apduBuffer, decoder.nextOffset, true);
			if (this.decoder.readUINT(this.apduBuffer, privKeyParamID) != 2) {
				UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
			}

			// This is the needed value (privKey!)
			this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, this.apduBuffer, decoder.nextOffset, true);
		} catch (Exception e) {
			UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
		}

		apduBufferOffset = decoder.nextOffset;

		ECPrivateKey privateKey = (ECPrivateKey) this.credentialKeyPair.getPrivate();
		privateKey.setS(this.apduBuffer, decoder.valueOffset, decoder.valueLength);

		// set user presence (0x01), user verification (0x04)
		byte flags = (byte) 0x00;
		flags = up ? (byte) (flags ^ 0x01) : flags;
		flags = uv && userVerified ? (byte) (flags ^ 0x04) : flags;

		incrementSignCounter();

		/*
		 * Step 3 - Generate the response
		 */
		this.encoder.prepare(apdu);
		short responseOffset = apduBufferOffset;

		short bOffset = this.encoder.setMapType(responseMapEntries, this.apduBuffer, responseOffset);

		/* 0x01 - credential - OPTIONAL */
		bOffset = this.encoder.setUIntValue((short) 1, this.apduBuffer, bOffset);

		this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_MAP, this.ram, allowListFirstEntry, true);
		short entries = this.decoder.valueLength;

		for (short i = 0; i < (short) (entries * 2); i++) {
			this.decoder.skipNext(this.ram, decoder.nextOffset);
		}

		firstEntryLength = (short) (decoder.nextOffset - allowListFirstEntry);

		bOffset = this.encoder.setBytes(this.ram, allowListFirstEntry, firstEntryLength, this.apduBuffer, bOffset);

		/* 0x02 - authData - MANDATORY - excluding attestedCredentialData */
		bOffset = this.encoder.setUIntValue((short) 2, this.apduBuffer, bOffset);
		bOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, (short) 37, this.apduBuffer, bOffset);

		short offsetAuthData = bOffset;
		// Hash of rpID
		bOffset += sha256.doFinal(this.ram, rpIdRAMOffset, rpIdLength, this.apduBuffer, bOffset);

		// flags
		bOffset = this.encoder.setByte(flags, this.apduBuffer, bOffset);

		// signCounter
		bOffset = this.encoder.setByte((byte) ((signCounter[0] >> 8) & 0xFF), buffer, bOffset);
		bOffset = this.encoder.setByte((byte) (signCounter[0] & 0xFF), buffer, bOffset);
		bOffset = this.encoder.setByte((byte) ((signCounter[1] >> 8) & 0xFF), buffer, bOffset);
		bOffset = this.encoder.setByte((byte) (signCounter[1] & 0xFF), buffer, bOffset);

		/* 0x03 - signature - MANDATORY */
		short clientDataHashStart = bOffset;
		bOffset = this.encoder.setBytes(this.ram, clientDataHashRAMOffset, clientDataHashLength, this.apduBuffer, bOffset);

		short signDataLength = (short) ((bOffset - offsetAuthData));
		short signDataOffset = (short) (bOffset + 5); // enough space to write the first bytes of cbor encoding

		// Generate ES256(credentialPrivateKey, authData | clientDataHash)
		es256.init(this.credentialKeyPair.getPrivate(), Signature.MODE_SIGN);
		signDataLength = es256.sign(this.apduBuffer, offsetAuthData, signDataLength, this.apduBuffer, signDataOffset);
		bOffset = clientDataHashStart;

		bOffset = this.encoder.setUIntValue((short) 3, this.apduBuffer, bOffset);
		bOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, signDataLength, this.apduBuffer, bOffset);
		bOffset = this.encoder.setBytes(this.apduBuffer, signDataOffset, signDataLength, this.apduBuffer, bOffset);

		/* 0x05 - numberOfCredentials - OPTIONAL */
		if (numberOfCredentials > 1) {
			bOffset = this.encoder.setUIntValue((byte) 0x05, this.apduBuffer, bOffset);
			bOffset = this.encoder.setUIntValue(numberOfCredentials, this.apduBuffer, bOffset);
			credentialCounter = 1;
		}

		// Set the FIDO2 status word manually, because we are not writing at the beginning of the apduBuffer.
		responseOffset -= 1;
		this.apduBuffer[responseOffset] = Constants.CTAP2_OK;

		if (this.internalState == Constants.STATE_EXTENDED_LENGTH) {
			Util.arrayCopyNonAtomic(this.apduBuffer, responseOffset, apdu.getBuffer(), (short) 0, (short) (bOffset - responseOffset));
			this.encoder.send(apdu, bOffset);
		} else {
			this.apduBufferResponseEndOffset = bOffset;
			this.apduBufferOffset = responseOffset;
			this.apduBufferOffset = this.encoder.sendShortAPDUChain(apdu, this.apduBuffer, this.apduBufferOffset, this.apduBufferResponseEndOffset);
			this.internalState = Constants.STATE_RESPONSE_CHAINING;
		}
	}

	/**
	 * Subsequent calls to authenticatorGetNextAssertion are made right after an {@link FIDO2Applet#authenticatorGetAssertion(APDU)} which detects more than one
	 * possible credential fitting the requesting RP. <br>
	 * <br>
	 * Generates cryptographic proof of user authentication and user consent to list all credentials connected to the current RP on the authenticator to the
	 * user. Should only be invoked for authenticators, which are supporting resident key option. <br>
	 * <br>
	 * <b>This function takes no parameters via the authenticatorGetNextAssertion APDU. The needed parameters has to be saved from the previous
	 * {@link FIDO2Applet#authenticatorGetAssertion(APDU)} call. </b>
	 * 
	 * <br>
	 * At successful execution, the response APDU contains following map entries:
	 * <ol>
	 * <li>(mandatory) credential</li>
	 * <li>(mandatory) authData</li>
	 * <li>(mandatory) signature</li>
	 * <li>(optional) user</li>
	 * </ol>
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_NOT_ALLOWED</b> when all listed credentials were signed or we can not remember any parameters passed by
	 *             {@link FIDO2Applet#authenticatorGetAssertion(APDU)}.</li>
	 *             <li><b>CTAP2_ERR_INVALID_CREDENTIAL</b> when the credential is not correctly within the allowList entry.</li>
	 *             <li>See also {@link CBORDecoder}.
	 *             </ul>
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetNextAssertion">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetNextAssertion</a>
	 */
	public void authenticatorGetNextAssertion(APDU apdu) throws UserException {
		byte[] buffer = this.ram;

		/*
		 * Step 1 - Check whether we remember any CBOR encoded parameters and parse their offsets.
		 * 
		 * AND
		 * 
		 * Step 2 - Process the data according to the specification of authenticatorGetNextAssertion
		 */
		this.decoder.init((short) buffer.length, (short) -1); // -1 because we start right at the beginning of the buffer.

		// 2. Check, whether all credentials were signed.
		if (credentialCounter >= numberOfCredentials) {
			UserException.throwIt(Constants.CTAP2_ERR_NOT_ALLOWED);
		}

		// 0x01 - rpId - MANDATORY
		short rpId = this.decoder.parseExpectedParam((byte) 0x01, Constants.CBOR_MAJOR_TYPE_TEXT_STRING, buffer, decoder.nextOffset, false);
		short rpIdValueOffset = this.decoder.valueOffset;
		short rpIdLength = this.decoder.valueLength;

		// 1. Check, whether we remember any data of authenticatorGetAssertion.
		if (rpId == -1) {
			UserException.throwIt(Constants.CTAP2_ERR_NOT_ALLOWED);
		}

		// 0x02 - clientDataHash - MANDATORY
		short clientDataHash = this.decoder.parseExpectedParam((byte) 0x02, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
		short clientDataHashValueOffset = this.decoder.valueOffset;
		short clientDataHashLength = this.decoder.valueLength;

		// 0x03 - allowList - MANDATORY (because authenticator does not store any credentials)
		short allowList = this.decoder.parseExpectedParam((byte) 0x03, Constants.CBOR_MAJOR_TYPE_ARRAY, buffer, decoder.nextOffset, true);
		short allowListValueOffset = this.decoder.valueOffset;
		short allowListLength = this.decoder.valueLength;

		// 3. Ignore timer, because we did not start any in authenticatorGetAssertion
		// TODO: Add timer?

		// 4. Generate the signature over the next allowList entry
		// Search for the next entry to be signed.
		short allowListCurrentEntry = this.decoder.nextOffset;

		for (short i = 0; i < allowListLength && allowList != -1; i++) {
			this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, true);
			short entryLength = decoder.valueLength;

			for (short j = 0; j < (short) (entryLength * 2); j++) {
				decoder.skipNext(buffer, decoder.nextOffset);
			}

			if (i == (short) (credentialCounter - 1)) {
				allowListCurrentEntry = this.decoder.nextOffset;
			}
		}

		allowListCurrentEntry = this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_MAP, buffer, allowListCurrentEntry, true);
		short allowListCurrentEntryID = this.decoder.parseExpectedMapEntry(Constants.CBOR_MAJOR_TYPE_TEXT_STRING, Constants.STRING_ID,
				Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
		short currentEntryLength = decoder.valueLength;

		// Extract credentialId
		short apduBufferOffset = (short) 0;
		short credentialIDRAMOffset = apduBufferOffset;

		this.aes256.init(this.encryptionKey, Cipher.MODE_DECRYPT, buffer, (short) (decoder.nextOffset - 16), (short) 16);
		this.aes256.doFinal(buffer, decoder.valueOffset, (short) (currentEntryLength - 16), this.apduBuffer, credentialIDRAMOffset);

		// credentialId was structured as CBOR Map in authenticatorMakeCredential
		this.decoder.skipNext(this.apduBuffer, credentialIDRAMOffset); // Map
		this.decoder.skipNext(this.apduBuffer, decoder.nextOffset); // 0x01
		this.decoder.skipNext(this.apduBuffer, decoder.nextOffset); // packed_string

		short privKeyParamID = this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_UINT, this.apduBuffer, decoder.nextOffset, true);
		if (this.decoder.readUINT(this.apduBuffer, privKeyParamID) != 2) {
			UserException.throwIt(Constants.CTAP2_ERR_INVALID_CREDENTIAL);
		}

		// This is the needed value (privKey!)
		this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, this.apduBuffer, decoder.nextOffset, true);
		apduBufferOffset = this.decoder.nextOffset;

		ECPrivateKey privateKey = (ECPrivateKey) this.credentialKeyPair.getPrivate();
		privateKey.setS(this.apduBuffer, decoder.valueOffset, decoder.valueLength);


		// set user presence (0x01), user verification (0x04)
		// TODO: Check, whether we have to set those flags or not?
		byte flags = (byte) 0x00;
		flags = (byte) (flags ^ 0x01);
		flags = (byte) (flags ^ 0x04);

		incrementSignCounter();

		/*
		 * Step 3 - Generate the response
		 */
		this.encoder.prepare(apdu);
		short responseOffset = apduBufferOffset;

		short responseMapEntries = 3;
		short bOffset = this.encoder.setMapType(responseMapEntries, this.apduBuffer, responseOffset);

		/* 0x01 - credential - MANDATORY */
		bOffset = this.encoder.setUIntValue((short) 1, this.apduBuffer, bOffset);

		apduBufferOffset = this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_MAP, this.ram, allowListCurrentEntry, true);
		short entries = this.decoder.valueLength;
		
		for (short i = 0; i < (short) (entries * 2); i++) {
			this.decoder.skipNext(this.ram, decoder.nextOffset);
		}

		currentEntryLength = (short) (decoder.nextOffset - allowListCurrentEntry);

		bOffset = this.encoder.setBytes(this.ram, allowListCurrentEntry, currentEntryLength, this.apduBuffer, bOffset);

		/* 0x02 - authData - MANDATORY - excluding attestedCredentialData */
		bOffset = this.encoder.setUIntValue((short) 2, this.apduBuffer, bOffset);
		bOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, (short) 37, this.apduBuffer, bOffset);

		short offsetAuthData = bOffset;
		// Hash of rpID
		bOffset += sha256.doFinal(this.ram, rpIdValueOffset, rpIdLength, this.apduBuffer, bOffset);

		// flags
		bOffset = this.encoder.setByte(flags, this.apduBuffer, bOffset);

		// signCounter
		bOffset = this.encoder.setByte((byte) ((signCounter[0] >> 8) & 0xFF), buffer, bOffset);
		bOffset = this.encoder.setByte((byte) (signCounter[0] & 0xFF), buffer, bOffset);
		bOffset = this.encoder.setByte((byte) ((signCounter[1] >> 8) & 0xFF), buffer, bOffset);
		bOffset = this.encoder.setByte((byte) (signCounter[1] & 0xFF), buffer, bOffset);

		/* 0x03 - signature - MANDATORY */
		short clientDataHashStart = bOffset;
		bOffset = this.encoder.setBytes(this.ram, clientDataHashValueOffset, clientDataHashLength, this.apduBuffer, bOffset);

		short signDataLength = (short) ((bOffset - offsetAuthData));
		short signDataOffset = (short) (bOffset + 5); // enough space to write the first bytes of CBOR encoding

		// Generate ES256(credentialPrivateKey, authData | clientDataHash)
		es256.init(this.credentialKeyPair.getPrivate(), Signature.MODE_SIGN);
		signDataLength = es256.sign(this.apduBuffer, offsetAuthData, signDataLength, this.apduBuffer, signDataOffset);
		bOffset = clientDataHashStart;

		bOffset = this.encoder.setUIntValue((short) 3, this.apduBuffer, bOffset);
		bOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, signDataLength, this.apduBuffer, bOffset);
		bOffset = this.encoder.setBytes(this.apduBuffer, signDataOffset, signDataLength, this.apduBuffer, bOffset);

		// 6. Increment credential counter
		credentialCounter += 1;
		
		// Set the FIDO2 status word manually, because we are not writing at the beginning of the apduBuffer.
		responseOffset -= 1;
		this.apduBuffer[responseOffset] = Constants.CTAP2_OK;

		if (this.internalState == Constants.STATE_EXTENDED_LENGTH) {
			Util.arrayCopyNonAtomic(this.apduBuffer, responseOffset, apdu.getBuffer(), (short) 0, (short) (bOffset - responseOffset));
			this.encoder.send(apdu, bOffset);
		} else {
			this.apduBufferResponseEndOffset = bOffset;
			this.apduBufferOffset = responseOffset;
			this.apduBufferOffset = this.encoder.sendShortAPDUChain(apdu, this.apduBuffer, this.apduBufferOffset, this.apduBufferResponseEndOffset);
			this.internalState = Constants.STATE_RESPONSE_CHAINING;
		}
	}
	
	/**
	 * Used to establish key agreement, manage the PIN settings and get the pinToken needed in other commands.<br>
	 * <br>
	 * This command is divided into the following subcommands:
	 * <ol>
	 * <li>{@link FIDO2Applet#clientPinGetRetries(APDU)}</li>
	 * <li>{@link FIDO2Applet#clientPinGetKeyAgreement(APDU)}</li>
	 * <li>{@link FIDO2Applet#clientPinSetPin(APDU)}</li>
	 * <li>{@link FIDO2Applet#clientPinChangePin(APDU)}</li>
	 * <li>{@link FIDO2Applet#clientPinGetPinToken(APDU)}</li>
	 * </ol>
	 * <br>
	 * The CDATA contain the following CBOR encoded parameters:
	 * <ol>
	 * <li>(mandatory) pinProtocol</li>
	 * <li>(mandatory) subCommand</li>
	 * <li>(optional) keyAgreement</li>
	 * <li>(optional) pinAuth</li>
	 * <li>(optional) newPinEnc</li>
	 * <li>(optional) pinHashEnc</li>
	 * </ol>
	 * <br>
	 * <br>
	 * <b>Check the specific subcommand, to know which optional parameters are required.</b><br>
	 * <br>
	 * At successful execution, the response APDU contains following map entries:
	 * <ol>
	 * <li>(optional) KeyAgreement</li>
	 * <li>(optional) pinToken</li>
	 * <li>(optional) retries</li>
	 * </ol>
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_MISSING_PARAMETER</b> when mandatory parameters, map entries or array entries are missing.</li>
	 *             <li><b>CTAP2_ERR_PIN_POLICY_VIOLATION</b> when pinProtocol of the client does not match the pinProtocol of the authenticator.</li>
	 *             <li><b>CTAP2_ERR_PIN_AUTH_INVALID</b> when the pinAuth send by the RP was generated with an other pinToken than the current one (changes on
	 *             every power up).</li>
	 *             <li><b>CTAP2_ERR_PIN_BLOCKED</b> when the retries count is 0.</li>
	 *             <li><b>CTAP2_ERR_NOT_ALLOWED</b> when the encoded subcommand does not exist.</li>
	 *             <li>See also the subcommands listed above.</li>
	 *             </ul>
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN</a>
	 */
	public void authenticatorClientPin(APDU apdu) throws UserException {
		byte[] buffer = this.apduBuffer;

		this.decoder.init(this.apduBufferOffset, apdu.getOffsetCdata());

		/*
		 * Step 1 - Check CBOR encoded parameters and parse their offsets.
		 */
		// All parameters are passed as map
		this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, true);

		// Check if all mandatory parameters are present
		if (decoder.valueLength < 2 || decoder.valueLength > 6) {
			UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
		}
		
		// 0x01 - pinProtocol - MANDATORY
		short pinProtocol = this.decoder.parseExpectedParam((byte) 0x01, Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, true);
		if (this.decoder.readUINT(buffer, pinProtocol) != Constants.FIDO_PIN_AUTH_VERSION) {
			UserException.throwIt(Constants.CTAP2_ERR_PIN_POLICY_VIOLATION); // TODO: ??
		}

		// 0x02 - subCommand - MANDATORY
		short subCmd = this.decoder.parseExpectedParam((byte) 0x02, Constants.CBOR_MAJOR_TYPE_UINT, apduBuffer, decoder.nextOffset, true);
		switch ((byte) (this.decoder.readUINT(apduBuffer, subCmd) & 0xFF)) {
			case Constants.FIDO_SUBCMD_CLIENT_PIN_GET_RETRIES:
				clientPinGetRetries(apdu);
				return;
			case Constants.FIDO_SUBCMD_CLIENT_PIN_GET_KEY_AGREEMENT:
				clientPinGetKeyAgreement(apdu);
				return;
			case Constants.FIDO_SUBCMD_CLIENT_PIN_SET_PIN:
				if (this.pinInitialized) {
					UserException.throwIt(Constants.CTAP2_ERR_PIN_AUTH_INVALID);
				}
				clientPinSetPin(apdu);
				return;
			case Constants.FIDO_SUBCMD_CLIENT_PIN_CHANGE_PIN:
				if (this.retries > 0) {
					clientPinChangePin(apdu);
					return;
				}
				UserException.throwIt(Constants.CTAP2_ERR_PIN_BLOCKED);
			break; // satisfying the compiler
			case Constants.FIDO_SUBCMD_CLIENT_PIN_GET_PIN_TOKEN:
				if (this.retries > 0) {
					clientPinGetPinToken(apdu);
					return;
				}
				UserException.throwIt(Constants.CTAP2_ERR_PIN_BLOCKED);
			break; // satisfying the compiler
			default:
				UserException.throwIt(Constants.CTAP2_ERR_NOT_ALLOWED);
		}

	}

	/**
	 * Returns the current retries count of possible pin inputs. Subcommand 0x01 of {@link FIDO2Applet#authenticatorClientPin(APDU)}. <br>
	 * <br>
	 * The CDATA contain the following CBOR encoded parameters:
	 * <ul>
	 * <li>pinProtocol</li>
	 * <li>subCommand = 0x01</li>
	 * </ul>
	 * <br>
	 * <br>
	 * At successful execution, the response APDU contains following map entries:
	 * <ul>
	 * <li>0x03 - retries</li>
	 * </ul>
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingRetries">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingRetries</a>
	 */
	private void clientPinGetRetries(APDU apdu) {
		/*
		 * Step 1 - Generate the response
		 */
		short bOffset = this.encoder.prepare(apdu);

		bOffset = this.encoder.setMapType((short) 1, apdu.getBuffer(), bOffset);

		// 0x03 - retries - MANDATORY
		bOffset = this.encoder.setUIntValue((short) 3, apdu.getBuffer(), bOffset);
		bOffset = this.encoder.setByte(this.retries, apdu.getBuffer(), bOffset);
		this.encoder.setFIDOReturnSW(Constants.CTAP2_OK, apdu.getBuffer());
		this.encoder.send(apdu, bOffset);
		return;
	}

	/**
	 * Returns the public portion of the current authenticatorKeyAgreementKey to derive the sharedSecret via ECDH. Subcommand 0x02 of
	 * {@link FIDO2Applet#authenticatorClientPin(APDU)}. <br>
	 * <br>
	 * The CDATA contain the following CBOR encoded parameters:
	 * <ul>
	 * <li>pinProtocol</li>
	 * <li>subCommand = 0x02</li>
	 * </ul>
	 * <br>
	 * <br>
	 * At successful execution, the response APDU contains following map entries:
	 * <ul>
	 * <li>0x01 - KeyAgreement</li>
	 * </ul>
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingSharedSecret">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingSharedSecret</a>
	 */
	private void clientPinGetKeyAgreement(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short bOffset = this.encoder.prepare(apdu);

		/*
		 * Step 1 - Get the public key into RAM
		 */
		short ramOffset = 0;
		short pubKeyRAMOffset = ramOffset;
		ramOffset += ((ECPublicKey) authenticatorKeyAgreementKey.getPublic()).getW(this.ram, pubKeyRAMOffset);

		/*
		 * Step 2 - Generate the response
		 */
		bOffset = this.encoder.setMapType((short) 1, buffer, bOffset);

		// 0x01 - KeyAgreement - MANDATORY
		bOffset = this.encoder.setUIntValue((short) 1, buffer, bOffset);

		// Write the credentials public key in COSE_KEY format into response buffer
		bOffset = this.encoder.setMapType((short) 5, buffer, bOffset);

		// 1 - Key Type
		bOffset = this.encoder.setUIntValue((short) 1, buffer, bOffset);
		bOffset = this.encoder.setUIntValue((short) 2, buffer, bOffset);

		// 3 - algorithm identifier
		bOffset = this.encoder.setUIntValue((short) 3, buffer, bOffset);
		bOffset = this.encoder.setIntValue(Constants.IANA_COSE_ES256, buffer, bOffset);

		// -1 - curve
		bOffset = this.encoder.setIntValue((short) -1, buffer, bOffset);
		bOffset = this.encoder.setUIntValue((short) 1, buffer, bOffset);

		// -2 - x-coordinate
		bOffset = this.encoder.setIntValue((short) -2, buffer, bOffset);
		bOffset = this.encoder.setByte((byte) 0x58, buffer, bOffset);
		bOffset = this.encoder.setByte((byte) 0x20, buffer, bOffset);
		bOffset = this.encoder.setBytes(this.ram, (short) (pubKeyRAMOffset + 1), (short) 32, buffer, bOffset);

		// -3 - y-coordinate
		bOffset = this.encoder.setIntValue((short) -3, buffer, bOffset);
		bOffset = this.encoder.setByte((byte) 0x58, buffer, bOffset);
		bOffset = this.encoder.setByte((byte) 0x20, buffer, bOffset);
		bOffset = this.encoder.setBytes(this.ram, (short) (pubKeyRAMOffset + 33), (short) 32, buffer, bOffset);

		this.encoder.setFIDOReturnSW(Constants.CTAP2_OK, buffer);
		this.encoder.send(apdu, bOffset);
		return;
	}

	/**
	 * Sets the clientPin for the first time. Subcommand 0x03 of {@link FIDO2Applet#authenticatorClientPin(APDU)}. <br>
	 * <br>
	 * The CDATA contain the following CBOR encoded parameters:
	 * <ul>
	 * <li>pinProtocol</li>
	 * <li>subCommand = 0x03</li>
	 * <li>keyAgreement</li>
	 * <li>newPinEnc</li>
	 * <li>pinAuth</li>
	 * </ul>
	 * <br>
	 * At successful execution, the authenticator returns {@link Constants#CTAP2_OK}.
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_PIN_AUTH_INVALID</b> when the pinAuth send by the RP was generated with an other pinToken than the current one (changes on
	 *             every power up).</li>
	 *             <li><b>CTAP2_ERR_PIN_POLICY_VIOLATION</b> when the pin does not meet the requirements.</li>
	 *             <li>See also {@link CBORDecoder} and {@link CBOREncoder}.</li>
	 *             </ul>
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#settingNewPin">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#settingNewPin</a>
	 */
	private void clientPinSetPin(APDU apdu) throws UserException {
		byte[] buffer = apdu.getBuffer();

		this.decoder.init(this.apduBufferOffset, apdu.getOffsetCdata());

		/*
		 * Step 1 - Check CBOR encoded parameters and parse their offsets.
		 */
		// Skip the first two parameters of the map
		this.decoder.skipNext(buffer, decoder.nextOffset); // map
		this.decoder.parseExpectedParam((byte) 0x01, Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false); // 0x01 - pinProtocol
		this.decoder.parseExpectedParam((byte) 0x02, Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false); // 0x02 - subCommand
		
		// 0x03 - keyAgreement - MANDATORY
		this.decoder.parseExpectedParam((byte) 0x03, Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, true);
		short COSEKeyLength = this.decoder.valueLength;
		
		short ramOffset = 0;

		// Decode the COSE Key Format an prepare the public key of the RP in ANSI X9.62 encoding.
		short pubKeyOffset = ramOffset;
		this.ram[pubKeyOffset] = 0x04;
		ramOffset += 1;
		for (short i = 0; i < COSEKeyLength; i++) {
			// We need to distinguish between positive and negative integer values in the COSE Key Format. All positive integers have to be skipped.
			if (this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false) != -1) {
				this.decoder.skipNext(buffer, decoder.nextOffset);
			} else if(this.decoder.readINT(buffer, decoder.nextOffset) == -2) {
				// Extract the x-coordinate
				this.decoder.skipNext(buffer, decoder.nextOffset);
				this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
				ramOffset = this.decoder.readString(buffer, decoder.valueOffset, decoder.valueLength, this.ram, ramOffset);
			} else if (this.decoder.readINT(buffer, decoder.nextOffset) == -3) {
				// Extract the y-coordinate
				this.decoder.skipNext(buffer, decoder.nextOffset);
				this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
				ramOffset = this.decoder.readString(buffer, decoder.valueOffset, decoder.valueLength, this.ram, ramOffset);
			} else {
				this.decoder.skipNext(buffer, decoder.nextOffset);
				this.decoder.skipNext(buffer, decoder.nextOffset);
			}
		}
		short pubKeyLength = (short) (ramOffset - pubKeyOffset);

		// 0x04 - pinAuth - MANDATORY
		short pinAuth = this.decoder.parseExpectedParam((byte) 0x04, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
		short pinAuthValueLength = this.decoder.valueLength;
		short pinAuthValueOffset = this.decoder.valueOffset;

		// 0x05 - newPinEnc - MANDATORY
		short newPinEnc = this.decoder.parseExpectedParam((byte) 0x05, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
		short newPinEncValueLength = this.decoder.valueLength;
		short newPinEncValueOffset = this.decoder.valueOffset;
		

		/*
		 * Step 2 - Process the data according to the specification of authenticatorGetNextAssertion
		 */

		/* Generate sharedSecret = SHA256(ECDH_P256()) */
		short sharedSecretOffset = ramOffset;

		// ECDH_P256(authenticatorKeyAgreementKey.priv, public key of the RP in ANSI X9.62)
		ecdh_p256.init(this.authenticatorKeyAgreementKey.getPrivate());
		short sharedSecretLength = ecdh_p256.generateSecret(this.ram, pubKeyOffset, pubKeyLength, this.ram, ramOffset);
		ramOffset += sharedSecretLength;

		// SHA256(ECDH_P256())
		ramOffset = sharedSecretOffset;
		sharedSecretLength = sha256.doFinal(this.ram, sharedSecretOffset, sharedSecretLength, this.ram, sharedSecretOffset);
		ramOffset += sharedSecretLength;
		
		// Generate HMAC-SHA256(sharedSecret, newPinEnc)
		short hmac = ramOffset;
		hmac_sha256.init(this.ram, sharedSecretOffset, sharedSecretLength);
		ramOffset += hmac_sha256.doFinal(buffer, newPinEncValueOffset, newPinEncValueLength, this.ram, hmac);

		// Verify pinAuth against LEFT(HMAC-SHA256(sharedSecret, newPinEnc), 16)
		if (Util.arrayCompare(this.ram, hmac, buffer, pinAuthValueOffset, (short) 16) != 0) {
			UserException.throwIt(Constants.CTAP2_ERR_PIN_AUTH_INVALID);
		}
		
		/* Decode Pin */
		// Use the sharedSecret as AES256-Key to decode the pinEnc parameter.
		this.sharedSecret.setKey(this.ram, sharedSecretOffset);
		aes256.init(this.sharedSecret, Cipher.MODE_DECRYPT);

		// Decode the PIN. The resulting PIN is in UTF-8 representation.
		short pinOffset = hmac;
		ramOffset = hmac;
		short pinLength = aes256.doFinal(buffer, newPinEncValueOffset, newPinEncValueLength, this.ram, hmac);

		// Check whether the decoded PIN is of correct length. Should always be length 64, due to the fact that the RP pads the PIN with 0s up to 64 digits.
		// TODO: maybe multiple of 64?
		if (pinLength > (short) (Constants.FIDO_MAXIMUM_PIN_LENGTH + 1)) {
			UserException.throwIt(Constants.CTAP2_ERR_PIN_POLICY_VIOLATION);
		}

		// Verify that the unpadded PIN has a length of 4 to 63 digits. Therefore check for the first 0-byte, indicating the end of the pin.
		// Avoid some kind of side channel, introduced by pinLength - loop over all digits
		for (short i = 0; i < pinLength; i++) {
			if (i < Constants.FIDO_MINIMUM_PIN_LENGTH && this.ram[(short) (pinOffset + i)] == 0x00) {
				UserException.throwIt(Constants.CTAP2_ERR_PIN_POLICY_VIOLATION);
			} else if (i > 0 && this.ram[(short) (pinOffset + i)] == 0x00 && this.ram[(short) (pinOffset + i - 1)] != 0x00) {
				pinLength = i;
			}
		}

		// Generates the pinHash and stores the first 16 Bytes on the authenticator.
		// pinHash is used for further clientPin verifications.
		short pinHashOff = pinOffset;
		ramOffset = pinOffset;
		sha256.doFinal(this.ram, pinOffset, pinLength, this.ram, ramOffset);

		Util.arrayCopyNonAtomic(this.ram, pinHashOff, this.pinHash, (short) 0, (short) this.pinHash.length);

		// Set the retries count to its maximum and indicate to the device that the PIN was successfully initialized.
		this.retries = Constants.FIDO_MAXIMUM_RETRIES;
		this.pinInitialized = true;

		/*
		 * Step 3 - Generate the response
		 */
		short bOffset = this.encoder.prepare(apdu);
		this.encoder.setFIDOReturnSW(Constants.CTAP2_OK, buffer);
		this.encoder.send(apdu, bOffset);
		return;
	}

	/**
	 * Changes the current clientPIN. Subcommand 0x04 of {@link FIDO2Applet#authenticatorClientPin(APDU)}. <br>
	 * <br>
	 * The CDATA contain the following CBOR encoded parameters:
	 * <ul>
	 * <li>pinProtocol</li>
	 * <li>subCommand = 0x04</li>
	 * <li>keyAgreement</li>
	 * <li>pinHashEnc</li>
	 * <li>newPinEnc</li>
	 * <li>pinAuth</li>
	 * </ul>
	 * <br>
	 * At successful execution, the authenticator returns {@link Constants#CTAP2_OK}.
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_PIN_AUTH_INVALID</b> when the pinAuth send by the RP was generated with an other pinToken than the current one (changes on
	 *             every power up).</li>
	 *             <li><b>CTAP2_ERR_PIN_BLOCKED</b> when the retries count is 0.</li>
	 *             <li><b>CTAP2_ERR_PIN_AUTH_BLOCKED</b> when the subsequentRetries count is 0.</li>
	 *             <li><b>CTAP2_ERR_PIN_POLICY_VIOLATION</b> when the pin does not meet the requirements.</li>
	 *             <li>See also {@link CBORDecoder} and {@link CBOREncoder}.</li>
	 *             </ul>
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#changingExistingPin">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#changingExistingPin</a>
	 */
	private void clientPinChangePin(APDU apdu) throws UserException {
		byte[] buffer = apdu.getBuffer();

		this.decoder.init(this.apduBufferOffset, apdu.getOffsetCdata());

		/*
		 * Step 1 - Check CBOR encoded parameters and parse their offsets.
		 */
		// Skip the first two parameters of the map
		this.decoder.skipNext(buffer, decoder.nextOffset); // map
		this.decoder.parseExpectedParam((byte) 0x01, Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false); // 0x01 - pinProtocol
		this.decoder.parseExpectedParam((byte) 0x02, Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false); // 0x02 - subCommand

		// 0x03 - keyAgreement - MANDATORY
		this.decoder.parseExpectedParam((byte) 0x03, Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, true);
		short COSEKeyLength = this.decoder.valueLength;

		short ramOffset = 0;

		// Decode the COSE Key Format an prepare the public key of the RP in ANSI X9.62 encoding.
		short pubKeyOffset = ramOffset;
		this.ram[pubKeyOffset] = 0x04;
		ramOffset += 1;
		for (short i = 0; i < COSEKeyLength; i++) {
			// We need to distinguish between positive and negative integer values in the COSE Key Format. All positive integers have to be skipped.
			if (this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false) != -1) {
				this.decoder.skipNext(buffer, decoder.nextOffset);
			} else if (this.decoder.readINT(buffer, decoder.nextOffset) == -2) {
				// Extract the x-coordinate
				this.decoder.skipNext(buffer, decoder.nextOffset);
				this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
				ramOffset = this.decoder.readString(buffer, decoder.valueOffset, decoder.valueLength, this.ram, ramOffset);
			} else if (this.decoder.readINT(buffer, decoder.nextOffset) == -3) {
				// Extract the y-coordinate
				this.decoder.skipNext(buffer, decoder.nextOffset);
				this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
				ramOffset = this.decoder.readString(buffer, decoder.valueOffset, decoder.valueLength, this.ram, ramOffset);
			} else {
				this.decoder.skipNext(buffer, decoder.nextOffset);
				this.decoder.skipNext(buffer, decoder.nextOffset);
			}
		}
		short pubKeyLength = (short) (ramOffset - pubKeyOffset);

		// 0x04 - pinAuth - MANDATORY
		short pinAuth = this.decoder.parseExpectedParam((byte) 0x04, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
		short pinAuthValueLength = this.decoder.valueLength;
		short pinAuthValueOffset = this.decoder.valueOffset;

		// 0x05 - newPinEnc - MANDATORY
		short newPinEnc = this.decoder.parseExpectedParam((byte) 0x05, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
		short newPinEncValueLength = this.decoder.valueLength;
		short newPinEncValueOffset = this.decoder.valueOffset;

		// 0x06 - pinHashEnc - MANDATORY
		short pinHashEnc = this.decoder.parseExpectedParam((byte) 0x06, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
		short pinHashEncValueLength = this.decoder.valueLength;
		short pinHashEncValueOffset = this.decoder.valueOffset;

		/*
		 * Step 2 - Process the data according to the specification of authenticatorGetNextAssertion
		 */
		// Concatenation of newPinEnc || pinHashEnc
		short concatinationOffset = ramOffset;
		ramOffset = this.decoder.readString(buffer, newPinEncValueOffset, newPinEncValueLength, this.ram, ramOffset);
		ramOffset = this.decoder.readString(buffer, pinHashEncValueOffset, pinHashEncValueLength, this.ram, ramOffset);

		/* Generate sharedSecret = SHA256(ECDH_P256()) */
		short sharedSecretOffset = ramOffset;

		// ECDH_P256(authenticatorKeyAgreementKey.priv, public key of the RP in ANSI X9.62)
		ecdh_p256.init(this.authenticatorKeyAgreementKey.getPrivate());
		short sharedSecretLength = ecdh_p256.generateSecret(this.ram, pubKeyOffset, pubKeyLength, this.ram, ramOffset);
		ramOffset += sharedSecretLength;

		// SHA256(ECDH_P256())
		ramOffset = sharedSecretOffset;
		sharedSecretLength = sha256.doFinal(this.ram, sharedSecretOffset, sharedSecretLength, this.ram, sharedSecretOffset);
		ramOffset += sharedSecretLength;

		// Generate HMAC-SHA256(sharedSecret, newPinEnc || pinHashEnc)
		short hmac = ramOffset;
		hmac_sha256.init(this.ram, sharedSecretOffset, sharedSecretLength);
		ramOffset += hmac_sha256.doFinal(this.ram, concatinationOffset, (short) (sharedSecretOffset - concatinationOffset), this.ram, hmac);

		// Verify pinAuth against LEFT(HMAC-SHA256(sharedSecret, newPinEnc), 16)
		if (Util.arrayCompare(this.ram, hmac, buffer, pinAuthValueOffset, (short) 16) != 0) {
			UserException.throwIt(Constants.CTAP2_ERR_PIN_AUTH_INVALID);
		}

		// If successful, decrement retries
		this.retries -= (byte) 1;

		/* Decode pinHashEnc */
		// Use the sharedSecret as AES256-Key to decode the pinEnc parameter.
		this.sharedSecret.setKey(this.ram, sharedSecretOffset);
		aes256.init(this.sharedSecret, Cipher.MODE_DECRYPT);

		// Decode the pinHash
		short pinOffset = ramOffset;
		short pinLength = aes256.doFinal(buffer, pinHashEncValueOffset, pinHashEncValueLength, this.ram, pinOffset);

		// Check, whether the encoded pinHashEnc matches the pinHash of the authenticator. If not, fail with the corresponding error.
		if (Util.arrayCompare(this.ram, pinOffset, this.pinHash, (short) 0, (short) this.pinHash.length) != 0) {
			// If pin verification fails, a new key pair is generated.
			authenticatorKeyAgreementKey.genKeyPair();

			this.subsequentRetries = this.subsequentRetries == 0 ? (byte) 0 : (byte) (this.subsequentRetries - 1);
			byte sw = Constants.CTAP2_ERR_PIN_INVALID;
			if (this.retries == (byte) 0) {
				sw = Constants.CTAP2_ERR_PIN_BLOCKED;
			} else if (this.subsequentRetries == (byte) 0) {
				sw = Constants.CTAP2_ERR_PIN_AUTH_BLOCKED;
			}
			UserException.throwIt(sw);
		}

		// At success, reset the retries counters
		this.retries = Constants.FIDO_MAXIMUM_RETRIES;
		this.subsequentRetries = Constants.FIDO_SUBSEQUENT_RETRIES;

		/* Decode newPinEnc */
		// Decode the PIN. The resulting PIN is in UTF-8 representation.
		pinOffset = hmac;
		ramOffset = hmac;
		pinLength = aes256.doFinal(buffer, newPinEncValueOffset, newPinEncValueLength, this.ram, hmac);

		// Check whether the decoded PIN is of correct length. Should always be length 64, due to the fact that the RP pads the PIN with 0s up to 64 digits.
		// TODO: maybe multiple of 64?
		if (pinLength > (short) (Constants.FIDO_MAXIMUM_PIN_LENGTH + 1)) {
			UserException.throwIt(Constants.CTAP2_ERR_PIN_POLICY_VIOLATION);
		}

		// Verify that the unpadded PIN has a length of 4 to 63 digits. Therefore check for the first 0-byte, indicating the end of the pin.
		// Avoid some kind of side channel, introduced by pinLength - loop over all digits
		for (short i = 0; i < pinLength; i++) {
			if (i < Constants.FIDO_MINIMUM_PIN_LENGTH && this.ram[(short) (pinOffset + i)] == 0x00) {
				UserException.throwIt(Constants.CTAP2_ERR_PIN_POLICY_VIOLATION);
			} else if (i > 0 && this.ram[(short) (pinOffset + i)] == 0x00 && this.ram[(short) (pinOffset + i - 1)] != 0x00) {
				pinLength = i;
			}
		}

		// Generates the new pinHash and stores the first 16 Bytes on the authenticator.
		// The new pinHash is used for further clientPin verifications.
		short pinHashOff = pinOffset;
		ramOffset = pinOffset;
		sha256.doFinal(this.ram, pinOffset, pinLength, this.ram, ramOffset);

		Util.arrayCopyNonAtomic(this.ram, pinHashOff, this.pinHash, (short) 0, (short) this.pinHash.length);

		/*
		 * Step 3 - Generate the response
		 */
		short bOffset = this.encoder.prepare(apdu);
		this.encoder.setFIDOReturnSW(Constants.CTAP2_OK, buffer);
		this.encoder.send(apdu, bOffset);
		return;
	}

	/**
	 * Returns the current pinToken of the authenticator. Is performed once for the lifetime of the authenticator/platform handle. Subcommand 0x05 of
	 * {@link FIDO2Applet#authenticatorClientPin(APDU)}. <br>
	 * <br>
	 * The CDATA contain the following CBOR encoded parameters:
	 * <ul>
	 * <li>pinProtocol</li>
	 * <li>subCommand = 0x05</li>
	 * <li>keyAgreement</li>
	 * <li>pinHashEnc</li>
	 * </ul>
	 * <br>
	 * At successful execution, the response APDU contains following map entries:
	 * <ul>
	 * <li>0x02 - pinToken</li>
	 * </ul>
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_PIN_AUTH_INVALID</b> when the pinAuth send by the RP was generated with an other pinToken than the current one (changes on
	 *             every power up).</li>
	 *             <li><b>CTAP2_ERR_PIN_BLOCKED</b> when the retries count is 0.</li>
	 *             <li><b>CTAP2_ERR_PIN_AUTH_BLOCKED</b> when the subsequentRetries count is 0.</li>
	 *             <li>See also {@link CBORDecoder} and {@link CBOREncoder}.</li>
	 *             </ul>
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingPinToken">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingPinToken</a>
	 */
	private void clientPinGetPinToken(APDU apdu) throws UserException {
		byte[] buffer = apdu.getBuffer();

		this.decoder.init(this.apduBufferOffset, apdu.getOffsetCdata());

		/*
		 * Step 1 - Check CBOR encoded parameters and parse their offsets.
		 */
		// Skip the first two parameters of the map
		this.decoder.skipNext(buffer, decoder.nextOffset); // map
		this.decoder.parseExpectedParam((byte) 0x01, Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false); // 0x01 - pinProtocol
		this.decoder.parseExpectedParam((byte) 0x02, Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false); // 0x02 - subCommand

		// 0x03 - keyAgreement - MANDATORY
		this.decoder.parseExpectedParam((byte) 0x03, Constants.CBOR_MAJOR_TYPE_MAP, buffer, decoder.nextOffset, true);
		short COSEKeyLength = this.decoder.valueLength;
		
		short ramOffset = 0;

		// Decode the COSE Key Format an prepare the public key of the RP in ANSI X9.62 encoding.
		short pubKeyOffset = ramOffset;
		this.ram[pubKeyOffset] = 0x04;
		ramOffset += 1;
		for (short i = 0; i < COSEKeyLength; i++) {
			// We need to distinguish between positive and negative integer values in the COSE Key Format. All positive integers have to be skipped.
			if (this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_UINT, buffer, decoder.nextOffset, false) != -1) {
				this.decoder.skipNext(buffer, decoder.nextOffset);
			} else if(this.decoder.readINT(buffer, decoder.nextOffset) == -2) {
				// Extract the x-coordinate
				this.decoder.skipNext(buffer, decoder.nextOffset);
				this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
				ramOffset = this.decoder.readString(buffer, decoder.valueOffset, decoder.valueLength, this.ram, ramOffset);
			} else if (this.decoder.readINT(buffer, decoder.nextOffset) == -3) {
				// Extract the y-coordinate
				this.decoder.skipNext(buffer, decoder.nextOffset);
				this.decoder.parseExpected(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
				ramOffset = this.decoder.readString(buffer, decoder.valueOffset, decoder.valueLength, this.ram, ramOffset);
			} else {
				this.decoder.skipNext(buffer, decoder.nextOffset);
				this.decoder.skipNext(buffer, decoder.nextOffset);
			}
		}
		short pubKeyLength = (short) (ramOffset - pubKeyOffset);

		// 0x06 - pinHashEnc - MANDATORY
		short pinHashEnc = this.decoder.parseExpectedParam((byte) 0x06, Constants.CBOR_MAJOR_TYPE_BYTE_STRING, buffer, decoder.nextOffset, true);
		short pinHashEncValueLength = this.decoder.valueLength;
		short pinHashEncValueOffset = this.decoder.valueOffset;

		/*
		 * Step 2 - Process the data according to the specification of authenticatorGetNextAssertion
		 */
		/* Generate sharedSecret = SHA256(ECDH_P256()) */
		short sharedSecretOffset = ramOffset;

		// ECDH_P256(authenticatorKeyAgreementKey.priv, public key of the RP in ANSI X9.62)
		ecdh_p256.init(this.authenticatorKeyAgreementKey.getPrivate());
		short sharedSecretLength = ecdh_p256.generateSecret(this.ram, pubKeyOffset, pubKeyLength, this.ram, ramOffset);
		ramOffset += sharedSecretLength;

		// SHA256(ECDH_P256())
		ramOffset = sharedSecretOffset;
		sharedSecretLength = sha256.doFinal(this.ram, sharedSecretOffset, sharedSecretLength, this.ram, sharedSecretOffset);
		ramOffset += sharedSecretLength;

		// Decrement the retries counter
		this.retries -= (byte) 1;

		/* Decode pinHashEnc */
		// Use the sharedSecret as AES256-Key to decode the pinEnc parameter.
		this.sharedSecret.setKey(this.ram, sharedSecretOffset);
		aes256.init(this.sharedSecret, Cipher.MODE_DECRYPT);

		// Decode the pinHash.
		short pinOffset = ramOffset;
		short pinLength = aes256.doFinal(buffer, pinHashEncValueOffset, pinHashEncValueLength, this.ram, pinOffset);

		// Check, whether the encoded pinHashEnc matches the pinHash of the authenticator. If not, fail with the corresponding error.
		if (Util.arrayCompare(this.ram, pinOffset, this.pinHash, (short) 0, (short) this.pinHash.length) != 0) {
			// If pin verification fails, a new key pair is generated.
			authenticatorKeyAgreementKey.genKeyPair();

			this.subsequentRetries = this.subsequentRetries == 0 ? (byte) 0 : (byte) (this.subsequentRetries - 1);
			byte sw = Constants.CTAP2_ERR_PIN_INVALID;
			if (this.retries == (byte) 0) {
				sw = Constants.CTAP2_ERR_PIN_BLOCKED;
			} else if (this.subsequentRetries == (byte) 0) {
				sw = Constants.CTAP2_ERR_PIN_AUTH_BLOCKED;
			}
			UserException.throwIt(sw);
		}

		// At success, reset the retries counters
		this.retries = Constants.FIDO_MAXIMUM_RETRIES;
		this.subsequentRetries = Constants.FIDO_MAXIMUM_RETRIES;
		
		/*
		 * Step 3 - Generate the response
		 */
		// Use the sharedSecret as AES256-Key to encode the pinToken parameter.
		aes256.init(this.sharedSecret, Cipher.MODE_ENCRYPT);

		short bOffset = this.encoder.prepare(apdu);
		bOffset = this.encoder.setMapType((short) 1, apdu.getBuffer(), bOffset);

		// 0x02 - pinToken - MANDATORY
		bOffset = this.encoder.setUIntValue((short) 2, apdu.getBuffer(), bOffset);
		bOffset = this.encoder.setMajorType(Constants.CBOR_MAJOR_TYPE_BYTE_STRING, (short) this.pinToken.length, buffer, bOffset);
		bOffset += aes256.doFinal(this.pinToken, (short) 0, (short) this.pinToken.length, buffer, bOffset);

		this.encoder.setFIDOReturnSW(Constants.CTAP2_OK, buffer);
		this.encoder.send(apdu, bOffset);
		return;
	}

	/**
	 * Executes a factory reset of the authenticator. The command takes no input. <br>
	 * <br>
	 * At successful execution, the authenticator returns {@link Constants#CTAP2_OK}.
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorReset">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorReset</a>
	 */
	public void authenticatorReset(APDU apdu) {
		/*
		 * Step 1 - Execute the factory reset
		 */
		// Reset the sign counter
		this.signCounter[0] = 0;
		this.signCounter[1] = 0;

		// Reset all data
		this.numberOfCredentials = 0;
		this.credentialCounter = 0;
		
		// Disable clientPin
		this.useClientPin = false;

		// Reset the retries counter and set pinInitialized to false
		this.retries = 0;
		this.subsequentRetries = Constants.FIDO_SUBSEQUENT_RETRIES;
		this.pinInitialized = false;

		// Delete the current PIN set
		for (short i = 0; i < (short) this.pinHash.length; i++) {
			this.pinHash[i] = 0x00;
		}

		// TODO: Reset the aes-key-Data and other Keys?!?

		// Reset internalState to STATE_READY
		this.internalState = Constants.STATE_READY;
		
		/*
		 * Step 2 - Generate the response
		 */
		short bOffset = this.encoder.prepare(apdu);
		this.encoder.setFIDOReturnSW(Constants.CTAP2_OK, apdu.getBuffer());
		this.encoder.send(apdu, bOffset);
	}

	/**
	 * Returns a list of all authenticator capabilities and supported versions. The command takes no input. <br>
	 * <br>
	 * The response APDU contains following map entries:
	 * <ol>
	 * <li>(mandatory) versions</li>
	 * <li>(optional) extensions</li>
	 * <li>(mandatory) aagui</li>
	 * <li>(optional) options</li>
	 * <li>(optional) maxMsgSize</li>
	 * <li>(optional) pinProtocols</li>
	 * </ol>
	 * 
	 * @param apdu
	 *            Incoming command APDU.
	 * @throws UserException
	 *             See {@link CBOREncoder#setSimpleValue(byte, byte[], byte[], short)}.
	 * @see <a href=
	 *      "https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo">https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo</a>
	 */
	public void authenticatorGetInfo(APDU apdu) throws UserException {
		byte[] buffer = apdu.getBuffer();

		/*
		 * Step 1 - Generate the response
		 */
		short bOffset = this.encoder.prepare(apdu);

		bOffset = this.encoder.setMapType((short) 5, buffer, bOffset);

		// 0x01 - versions - MANDATORY
		// Supported FIDO Protocol versions
		bOffset = this.encoder.setUIntValue((short) 1, buffer, bOffset);
		bOffset = this.encoder.setArrayType((short) 1, buffer, bOffset);
		bOffset = this.encoder.setTextString(Constants.FIDO_VERSIONS, (short) Constants.FIDO_VERSIONS.length, buffer, bOffset);

		// 0x03 - aaguid - MANDATORY
		bOffset = this.encoder.setUIntValue((short) 3, buffer, bOffset);
		bOffset = this.encoder.setByteString(Constants.FIDO_AAGUID, (short) Constants.FIDO_AAGUID.length, buffer, bOffset);

		// 0x04 - options - OPTIONAl
		// Map of supported options
		bOffset = this.encoder.setUIntValue((short) 4, buffer, bOffset);
		bOffset = this.encoder.setMapType((short) 4, buffer, bOffset);

		// set up to true, if clientPin is not used
		bOffset = this.encoder.setTextString(Constants.STRING_UP, (short) Constants.STRING_UP.length, buffer, bOffset);
		bOffset = this.encoder.setSimpleValue(useClientPin ? Constants.CBOR_FALSE : Constants.CBOR_TRUE, null, buffer, bOffset);

		// set uv to true, if clientPin is not used
		bOffset = this.encoder.setTextString(Constants.STRING_UV, (short) Constants.STRING_UV.length, buffer, bOffset);
		bOffset = this.encoder.setSimpleValue(useClientPin ? Constants.CBOR_FALSE : Constants.CBOR_TRUE, null, buffer, bOffset);

		// set rk to false, because resident keys are not supported
		bOffset = this.encoder.setTextString(Constants.STRING_RK, (short) Constants.STRING_RK.length, buffer, bOffset);
		bOffset = this.encoder.setSimpleValue(Constants.CBOR_FALSE, null, buffer, bOffset);

		// set clientPin to false, if clientPin is not used or not initialized
		bOffset = this.encoder.setTextString(Constants.STRING_CLIENT_PIN, (short) Constants.STRING_CLIENT_PIN.length, buffer, bOffset);
		bOffset = this.encoder.setSimpleValue(this.pinInitialized && useClientPin ? Constants.CBOR_TRUE : Constants.CBOR_FALSE, null, buffer, bOffset);
		
		// 0x05 - maxMsgSize - OPTIONAL
		// Max. supported CBOR Message Size - minimum has to be 1024
		bOffset = this.encoder.setUIntValue((short) 5, buffer, bOffset);
		bOffset = this.encoder.setUIntValue((short) 1024, buffer, bOffset);

		// 0x06 - pinProtocol - OPTIONAL
		// supported pinProtocol versions - currently only version 1 is supported.
		bOffset = this.encoder.setUIntValue((short) 6, buffer, bOffset);
		bOffset = this.encoder.setArrayType((short) 1, buffer, bOffset);
		bOffset = this.encoder.setByte(Constants.FIDO_PIN_AUTH_VERSION, buffer, bOffset);

		this.encoder.setFIDOReturnSW(Constants.CTAP2_OK, buffer);
		this.encoder.send(apdu, bOffset);
	}
	
	/**
	 * Increments the sign counter correctly
	 */
	private void incrementSignCounter() {
		this.signCounter[1] += 1;
		if (this.signCounter[1] == 0) {
			this.signCounter[0] += 1;
		}
	}
}
