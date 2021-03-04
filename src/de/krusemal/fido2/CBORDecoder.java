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

import javacard.framework.UserException;
import javacard.framework.Util;

/**
 * CBORDecoder class is used to decode an incoming Canonical CBOR encoded message.<br>
 * <br>
 * <b>Note:</b> Indefinite CBOR length encoding and MajorType 6 (TAG Type) are not supported.
 * 
 * @author Malte Kruse
 * @version v1.0, 15.08.2019
 * @see <a href="https://tools.ietf.org/html/rfc7049#section-3.9">https://tools.ietf.org/html/rfc7049#section-3.9</a>
 */
public class CBORDecoder {
	short messageLength;

	short nextOffset;
	short valueOffset;
	short valueLength;

	/**
	 * Constructor
	 */
	CBORDecoder() {
		this.nextOffset = 0;
		this.valueOffset = 0;
		this.valueLength = 0;
	}

	/**
	 * Initializes the CBOR decoder. Should always be invoked before decoding a message, to reset the decoder.
	 * 
	 * @param messageLength
	 *            Length of the message to decode.
	 * @param bOffset
	 *            Offset inside the buffer indicating the start of the message.
	 */
	public void init(short messageLength, short bOffset) {
		this.nextOffset = (short) (bOffset + 1); // first byte of cdata is INS byte for FIDO2
		this.valueOffset = (short) (bOffset + 1);
		this.messageLength = (short) (messageLength + bOffset);
	}
	
	/**
	 * Parses the next CBOR encoded object in the given message and updates the following member variables:
	 * 
	 * <ul>
	 * <li><b>nextOffset:</b> Offset of the next MajorType in this message.
	 * <li><b>valueOffset:</b> Offset, where the encoding of the raw value starts.
	 * <li><b>valueLength:</b> Length of the encoded raw value.
	 * </ul>
	 * 
	 * <b>Note:</b> Indefinite CBOR length encoding and MajorType 6 (TAG Type) are not supported.
	 * 
	 * @param buffer
	 *            Buffer containing the message to decode.
	 * @param bOffset
	 *            Offset of the next value to decode in the buffer.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_CBOR_UNEXPECTED_TYPE</b> when unsupported or wrong MajorType encoding was found.</i>
	 *             <li><b>CTAP2_ERR_INVALID_CBOR</b> when wrong or unsupported length / value encoding was found.</i>
	 *             </ul>
	 */
	private void parse(byte[] buffer, short bOffset) throws UserException {
		this.nextOffset = bOffset;
		this.valueOffset = bOffset;
		this.valueLength = 0;

		byte b = buffer[bOffset];
		byte type = (byte) ((b >> 5) & 0x07);
		byte code = (byte) (0x1f & b);

		switch (type) {
			case Constants.CBOR_MAJOR_TYPE_UINT:
			case Constants.CBOR_MAJOR_TYPE_INT:
				switch (code) {
					case Constants.CBOR_LENGTH_1BYTE:
						this.nextOffset += 2;
					break;
					case Constants.CBOR_LENGTH_2BYTE:
						this.nextOffset += 3;
					break;
					case Constants.CBOR_LENGTH_4BYTE:
						this.nextOffset += 5;
					break;
					case Constants.CBOR_LENGTH_8BYTE:
						this.nextOffset += 9;
					break;
					default:
						if (code > Constants.CBOR_LENGTH_1BYTE) {
							UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
						}

						this.nextOffset += 1;
				}

			break;
			case Constants.CBOR_MAJOR_TYPE_SIMPLE_VALUES:
				switch (code) {
					case Constants.CBOR_FALSE:
					case Constants.CBOR_TRUE:
					case Constants.CBOR_NULL:
					case Constants.CBOR_UNDEFINED_VALUE:
						this.nextOffset += 1;
					break;
					case Constants.CBOR_LENGTH_1BYTE:
						this.nextOffset += 2;
					break;
					case Constants.CBOR_HALF_PRECISION_FLOAT:
						this.nextOffset += 3;
					break;
					case Constants.CBOR_SINGLE_PRECISION_FLOAT:
						this.nextOffset += 5;
					break;
					case Constants.CBOR_DOUBLE_PRECISION_FLOAT:
						this.nextOffset += 9;
					break;
					default:
						/*
						 * Not listed codes are without meaning
						 */
						UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
				}

			break;
			case Constants.CBOR_MAJOR_TYPE_BYTE_STRING:
			case Constants.CBOR_MAJOR_TYPE_TEXT_STRING:
				switch (code) {
					case Constants.CBOR_LENGTH_1BYTE:
						this.valueOffset += 2;
						this.valueLength = (short) (buffer[(short) (bOffset + 1)] & 0xFF);
						this.nextOffset += this.valueLength + 2;
					break;
					case Constants.CBOR_LENGTH_2BYTE:
						this.valueOffset += 3;
						this.valueLength = (short) (buffer[(short) (bOffset + 1)] << 8);
						this.valueLength = (short) (this.valueLength | buffer[(short) (bOffset + 2)]);
						this.nextOffset += this.valueLength + 3;
					break;
					// CBOR_LENGTH_4BYTE and CBOR_LENGTH_8BYTE must not be supported because of Constants.FIDO_MAX_MSG_SIZE = 1024.
					case Constants.CBOR_LENGTH_4BYTE:
					case Constants.CBOR_LENGTH_8BYTE:
						UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
					break;
					default:
						if (code > Constants.CBOR_LENGTH_1BYTE) {
							UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
						}

						this.valueLength = code;
						this.valueOffset += 1;
						this.nextOffset += code + 1;
				}

			break;
			case Constants.CBOR_MAJOR_TYPE_ARRAY:
			case Constants.CBOR_MAJOR_TYPE_MAP:
				switch (code) {
					case Constants.CBOR_LENGTH_1BYTE:
						this.valueLength = (short) (buffer[(short) (bOffset + 1)] & 0xFF);
						this.valueOffset += 2;
						this.nextOffset += 2;
					break;
					case Constants.CBOR_LENGTH_2BYTE:
						this.valueOffset += 3;
						this.valueLength = (short) (buffer[(short) (bOffset + 1)] << 8);
						this.valueLength = (short) (this.valueLength | buffer[(short) (bOffset + 2)]);
						this.nextOffset += 3;
					break;
					// CBOR_LENGTH_4BYTE and CBOR_LENGTH_8BYTE must not be supported because of Constants.FIDO_MAX_MSG_SIZE = 1024.
					case Constants.CBOR_LENGTH_4BYTE:
					case Constants.CBOR_LENGTH_8BYTE:
						UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
					break;
					default:
						if (code > Constants.CBOR_LENGTH_1BYTE) {
							UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
						}
						this.valueOffset += 1;
						this.valueLength = code;
						this.nextOffset += 1;
				}

			break;
			case Constants.CBOR_MAJOR_TYPE_TAG:
			default:
				UserException.throwIt(Constants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
		}
	}

	/**
	 * Parses the next CBOR encoded object in the given message and checks whether it is of the expected MajorType or not.
	 * 
	 * @param majorType
	 *            The expected MajorType.
	 * @param buffer
	 *            Buffer containing the message to decode.
	 * @param bOffset
	 *            Offset of the CBOR object to be decoded.
	 * @param failIfNotExpected
	 *            If true, the method will throw an UserException if the MajorTypes do not match. Otherwise -1 will be returned.
	 * @return bOffset or -1
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_MISSING_PARAMETER</b> when expected MajorType does not match the encoded MajorType.</li>
	 *             <li>See also {@link CBORDecoder#parse(byte[], short)}</li>
	 *             </ul>
	 *
	 */
	public short parseExpected(byte majorType, byte[] buffer, short bOffset, boolean failIfNotExpected) throws UserException {
		byte b = buffer[bOffset];
		byte type = (byte) ((b >> 5) & 0x07);
		
		if (type != majorType || bOffset > this.messageLength) {
			if (failIfNotExpected) {
				UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
			} else {
				// reset offset for next request
				this.nextOffset = bOffset;
				return -1;
			}
		}
		
		parse(buffer, bOffset);

		return bOffset;
	}

	/**
	 * Parses the next CBOR encoded parameter of an FIDO2-command and checks whether it is the expected parameter with expected value type or not. Parameters in
	 * commands are always encoded in maps as pairs of <b>(int, value)</b>.
	 * 
	 * @param token
	 *            Expected int of the Parameter.
	 * @param majorTypeValue
	 *            Expected type of the corresponding value.
	 * @param buffer
	 *            Buffer containing the CBOR encoded parameter to decode.
	 * @param bOffset
	 *            Offset of the CBOR encoded parameter to be decoded.
	 * @param failIfNotExpected
	 *            If true, the method will throw an UserException if it is not the expected parameter or the MajorType of the value do not match the expected
	 *            MajorType. Otherwise -1 will be returned.
	 * @return Starting offset of the CBOR encoded value or -1 if it is not the expected value
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_MISSING_PARAMETER</b> when it is not the expected parameter or the expected MajorType of the value does not match the
	 *             encoded MajorType.</li>
	 *             <li>See also {@link CBORDecoder#parse(byte[], short)}</li>
	 *             </ul>
	 */
	public short parseExpectedParam(byte token, byte majorTypeValue, byte[] buffer, short bOffset, boolean failIfNotExpected)
			throws UserException {
		short startOffset = bOffset;
		if (bOffset >= 0 && bOffset < this.messageLength) {
			bOffset = this.parseExpected(Constants.CBOR_MAJOR_TYPE_UINT, buffer, bOffset, false);
		} else {
			bOffset = -1;
		}
		if (bOffset == -1 || token != this.readUINT(buffer, bOffset) || bOffset > this.messageLength) {
			if (failIfNotExpected) {
				UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
			} else {
				// reset offset for next request
				this.nextOffset = startOffset;
				return -1;
			}
		}

		bOffset = this.parseExpected(majorTypeValue, buffer, this.nextOffset, false);

		if (bOffset == -1) {
			this.nextOffset = startOffset;
		}

		return bOffset;
	}

	/**
	 * Skips any next MajorType in the encoded message.
	 * 
	 * @param buffer
	 *            The buffer containing the message.
	 * @param bOffset
	 *            The offset of the skipable MajorType.
	 * @return bOffset
	 * @throws UserException
	 *             <ul>
	 *             <li>See {@link CBORDecoder#parse(byte[], short)}</li>
	 *             </ul>
	 * 
	 */
	public short skipNext(byte[] buffer, short bOffset) throws UserException {
		parse(buffer, bOffset);
		return bOffset;
	}

	/**
	 * Parses the next CBOR encoded map entry of any kind and checks whether the key equals the given token or not. Also it will be checked, whether the key and
	 * the value are of the expected MajorTypes or not. Parameters in maps are always encoded as pairs of (key, value).
	 * 
	 * @param majorTypeToken
	 *            Expected MajorType of the key.
	 * @param token
	 *            Expected key value of the Parameter.
	 * @param majorTypeValue
	 *            Expected type of the corresponding value.
	 * @param buffer
	 *            Buffer containing the CBOR encoded map entry to decode.
	 * @param bOffset
	 *            Offset of the CBOR encoded map entry to be decoded.
	 * @param failIfNotExpected
	 *            If true, the method will throw an UserException if it is not the expected map entry or the MajorTypes of the pair do not match the expected
	 *            MajorTypes. Otherwise -1 will be returned.
	 * @return Starting offset of the CBOR encoded value or -1 if it is not the expected value
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_MISSING_PARAMETER</b> when it is not the expected map entry or the expected MajorTypes do not match the encoded
	 *             MajorTypes.</li>
	 *             <li>See also {@link CBORDecoder#parse(byte[], short)}</li>
	 *             </ul>
	 */
	public short parseExpectedMapEntry(byte majorTypeToken, byte[] token, byte majorTypeValue, byte[] buffer, short bOffset, boolean failIfNotExpected)
			throws UserException {
		short startOffset = bOffset;

		if (bOffset >= 0 && bOffset < this.messageLength) {
			bOffset = this.parseExpected(majorTypeToken, buffer, bOffset, false);
		} else {
			bOffset = -1;
		}

		if (bOffset == -1 || !this.isExpectedValueOf(token, buffer, this.valueOffset, this.valueLength)) {
			if (failIfNotExpected) {
				UserException.throwIt(Constants.CTAP2_ERR_MISSING_PARAMETER);
			} else {
				// reset offset for next request
				this.nextOffset = startOffset;
				return -1;
			}
		}

		bOffset = this.parseExpected(majorTypeValue, buffer, this.nextOffset, false);

		// if the token is correct, but the value is of a wrong type,
		// we have to reset the nextOffset for the next request
		if (bOffset == -1) {
			this.nextOffset = startOffset;
		}

		return bOffset;
	}
	
	/**
	 * Decodes the value of a CBOR encoded positive integer of {@link Constants#CBOR_MAJOR_TYPE_UINT} with a max length of {@link Constants#CBOR_LENGTH_2BYTE}.
	 * <br>
	 * <br>
	 * <b>For {@link Constants#CBOR_LENGTH_4BYTE} or {@link Constants#CBOR_LENGTH_8BYTE} values use
	 * {@link CBORDecoder#readString(byte[], short, short, byte[], short)}</b>
	 * 
	 * @param buffer
	 *            The buffer containing the integer to decode.
	 * @param bOffset
	 *            Offset, where the encoded positive integer starts.
	 * @return The decoded positive value.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_CBOR_UNEXPECTED_TYPE</b> when the encoded value is not of MajorType {@link Constants#CBOR_MAJOR_TYPE_UINT}</li>
	 *             <li><b>CTAP2_ERR_INVALID_CBOR</b> when the encoded value is invalid or of {@link Constants#CBOR_LENGTH_4BYTE} or
	 *             {@link Constants#CBOR_LENGTH_8BYTE} length.</li>
	 *             </ul>
	 */
	public short readUINT(byte[] buffer, short bOffset) throws UserException {
		byte b = buffer[bOffset];
		byte majorType = (byte) ((b >> 5) & 0x07);
		byte code = (byte) (b & 0x1F);
		short value = 0;
		
		if (majorType != Constants.CBOR_MAJOR_TYPE_UINT) {
			UserException.throwIt(Constants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
		}
		
		switch (code) {
			case Constants.CBOR_LENGTH_1BYTE:
				value = buffer[(short) (bOffset + 1)];
			break;
			case Constants.CBOR_LENGTH_2BYTE:
				value = (short) ((buffer[(short) (bOffset + 1)] & 0xFF) << 8);
				value = (short) (value | buffer[(short) (bOffset + 2)]);
			break;
			// Can be ignored in this case, because only two-byte data types are supported
			case Constants.CBOR_LENGTH_4BYTE:
			case Constants.CBOR_LENGTH_8BYTE:
				UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
			break;
			default:
				if (code > Constants.CBOR_LENGTH_1BYTE) {
					UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
				}
				
				value = code;
		}
		
		return value;
	}
	
	/**
	 * Decodes the value of a CBOR encoded negative integer of {@link Constants#CBOR_MAJOR_TYPE_INT} with a max length of {@link Constants#CBOR_LENGTH_2BYTE}.
	 * <br>
	 * <br>
	 * <b>For {@link Constants#CBOR_LENGTH_4BYTE} or {@link Constants#CBOR_LENGTH_8BYTE} values use
	 * {@link CBORDecoder#readString(byte[], short, short, byte[], short)}</b>
	 * 
	 * @param buffer
	 *            The buffer containing the integer to decode.
	 * @param bOffset
	 *            Offset, where the encoded negative integer starts.
	 * @return The decoded negative value.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_CBOR_UNEXPECTED_TYPE</b> when the encoded value is not of MajorType {@link Constants#CBOR_MAJOR_TYPE_INT}</li>
	 *             <li><b>CTAP2_ERR_INVALID_CBOR</b> when the encoded value is invalid or of {@link Constants#CBOR_LENGTH_4BYTE} or
	 *             {@link Constants#CBOR_LENGTH_8BYTE} length.</li>
	 *             </ul>
	 */
	public short readINT(byte[] buffer, short bOffset) throws UserException {
		byte b = buffer[bOffset];
		byte majorType = (byte) ((b >> 5) & 0x07);
		byte code = (byte) (b & 0x1F);
		short value = 0;
		
		if (majorType != Constants.CBOR_MAJOR_TYPE_INT) {
			UserException.throwIt(Constants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
		}
		
		switch (code) {
			case Constants.CBOR_LENGTH_1BYTE:
				value = buffer[(short) (bOffset + 1)];
			break;
			case Constants.CBOR_LENGTH_2BYTE:
				value = (short) ((buffer[(short) (bOffset + 1)] & 0xFF) << 8);
				value = (short) (value | buffer[(short) (bOffset + 2)]);
			break;
			// Can be ignored in this case, because only two-byte data types are supported
			case Constants.CBOR_LENGTH_4BYTE:
			case Constants.CBOR_LENGTH_8BYTE:
				UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
			break;
			default:
				if (code > Constants.CBOR_LENGTH_1BYTE) {
					UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
				}
				
				value = code;
		}
		
		return (short) (- 1 - value);
	}

	/**
	 * Decodes the value of a CBOR encoded negative integer of {@link Constants#CBOR_MAJOR_TYPE_SIMPLE_VALUES} including all constants,
	 * {@link Constants#CBOR_SIMPLE_VALUE_1BYTE} and {@link Constants#CBOR_HALF_PRECISION_FLOAT}.<br>
	 * <br>
	 * <b>For {@link Constants#CBOR_SINGLE_PRECISION_FLOAT} or {@link Constants#CBOR_DOUBLE_PRECISION_FLOAT} values use
	 * {@link CBORDecoder#readString(byte[], short, short, byte[], short)}</b>
	 * 
	 * @param buffer
	 *            The buffer containing the simple value to decode.
	 * @param bOffset
	 *            Offset, where the encoded simple value starts.
	 * @return The decoded negative value.
	 * @throws UserException
	 *             <ul>
	 *             <li><b>CTAP2_ERR_CBOR_UNEXPECTED_TYPE</b> when the encoded value is not of MajorType {@link Constants#CBOR_MAJOR_TYPE_SIMPLE_VALUES}</li>
	 *             <li><b>CTAP2_ERR_INVALID_CBOR</b> when the encoded value is of {@link Constants#CBOR_SINGLE_PRECISION_FLOAT} or
	 *             {@link Constants#CBOR_DOUBLE_PRECISION_FLOAT} length.</li>
	 *             </ul>
	 */
	public short readSimpleValue(byte[] buffer, short bOffset) throws UserException {
		byte b = buffer[bOffset];
		byte majorType = (byte) ((b >> 5) & 0x07);
		byte code = (byte) (b & 0x1F);
		short value = 0;
		
		if (majorType != Constants.CBOR_MAJOR_TYPE_SIMPLE_VALUES) {
			UserException.throwIt(Constants.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
		}
		
		switch (code) {
			case Constants.CBOR_TRUE:
			case Constants.CBOR_FALSE:
			case Constants.CBOR_NULL:
			case Constants.CBOR_UNDEFINED_VALUE:
				value = code;
			break;
			case Constants.CBOR_SIMPLE_VALUE_1BYTE:
				value = buffer[(short) (bOffset + 1)];
			break;
			case Constants.CBOR_HALF_PRECISION_FLOAT:
				value = (short) ((buffer[(short) (bOffset + 1)] & 0xFF) << 8);
				value = (short) (value | buffer[(short) (bOffset + 2)]);
			break;
			// Can be ignored in this case, because only two-byte data types are supported.
			case Constants.CBOR_SINGLE_PRECISION_FLOAT:
			case Constants.CBOR_DOUBLE_PRECISION_FLOAT:
			default:
				UserException.throwIt(Constants.CTAP2_ERR_INVALID_CBOR);
		}
		
		return value;
	}
	
	/**
	 * Reads a string of any kind into the destination.<br>
	 * <br>
	 * <b>This will not decode any kind of CBOR encoding</b>
	 * 
	 * @param buffer
	 *            The buffer to read from.
	 * @param bOffset
	 *            The offset, where to start reading.
	 * @param length
	 *            The length of the string to be read.
	 * @param dest
	 *            The destination where to write the string into.
	 * @param destOffset
	 *            The offset where to start writing.
	 * @return destOffset + length;
	 */
	public short readString(byte[] buffer, short bOffset, short length, byte[] dest, short destOffset) {
		return Util.arrayCopy(buffer, bOffset, dest, destOffset, length);
	}

	/**
	 * Check whether the given value matches the expected value in the CBOR encoded message.
	 * 
	 * @param value
	 *            The value to be expected.
	 * @param buffer
	 *            The buffer containing the CBOR encoded message.
	 * @param bOffset
	 *            The offset where the value is expected.
	 * @param length
	 *            The length of the expected value.
	 * @return <i>true</i> if value matches the buffer content at the given offset, <i>false</i> otherwise.
	 */
	public boolean isExpectedValueOf(byte[] value, byte[] buffer, short bOffset, short length) {
		byte res = Util.arrayCompare(value, (short) 0, buffer, bOffset, length);
		if (res != 0) {
			return false;
		}
		return true;
	}
}
