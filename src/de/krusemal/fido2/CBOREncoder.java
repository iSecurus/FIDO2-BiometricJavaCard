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

import javacard.framework.APDU;
import javacard.framework.UserException;
import javacard.framework.Util;

/**
 * CBOR Encoding class to encode outgoing response APDUs in CBOR. <b>Tags (MajorType 6) are unsupported by this encoder!</b> <br>
 * <br>
 * Encoding of data types:
 * <ul>
 * <li>1. Byte: MajorType (Higher 3 Bits) | Length or Value (Lower 5 bits)</li>
 * <li>If 24 &lt; Length or Value &lt;= 27: According to value of Length / Value 1-, 2-, 4- or 8-Byte encoding of the value length</li>
 * <li>Value of encoded Length</li>
 * </ul>
 * 
 * @author Malte Kruse
 * @version v1.0, 15.08.2019
 * @see <a href="https://tools.ietf.org/html/rfc7049#section-2">https://tools.ietf.org/html/rfc7049#section-2</a>
 * 
 */
public class CBOREncoder {

	/**
	 * Prepares the APDU to be outgoing.
	 * 
	 * @param apdu
	 *            The APDU to be outgoing.
	 * @return Starting position in the response buffer.
	 */
	public short prepare(APDU apdu) {
		apdu.setOutgoing();

		return 1;
	}

	/**
	 * Sets the FIDO2 status word byte in the response.
	 * 
	 * @param word
	 *            The status word to be returned.
	 * @param buffer
	 *            The response buffer.
	 * @return Next position in the response buffer (equals the starting position).
	 */
	public short setFIDOReturnSW(byte word, byte[] buffer) {
		buffer[0] = word;
		
		return 1;
	}
	
	/**
	 * Encodes a <b>positive</b> value (MajorType 0) as short as possible. Bytes need to be casted to short values. <br>
	 * For encoding negative values see {@link #setIntValue(short, byte[], short)}. <br>
	 * <br>
	 * <b> Only values of max. 2 bytes length are encoded.</b>
	 * 
	 * @param value
	 *            The value to be encoded as short.
	 * @param buffer
	 *            The response buffer.
	 * @param bOffset
	 *            Offset, where to start writing in the response buffer.
	 * @return bOffset + encoded length of given value.
	 * @see <a href="https://tools.ietf.org/html/rfc7049#section-2.1">https://tools.ietf.org/html/rfc7049#section-2.1</a>
	 */
	public short setUIntValue(short value, byte[] buffer, short bOffset) {
		byte b = Constants.CBOR_MAJOR_TYPE_UINT << 5;

		if (value < Constants.CBOR_LENGTH_1BYTE) {
			b |= (byte) (value & 0xFF);
			buffer[bOffset] = b;
		} else if (Constants.CBOR_LENGTH_1BYTE <= value && value <= 0xFF) {
			b |= Constants.CBOR_LENGTH_1BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) (value >> 8 & 0xFF);
		} else if (0xFF < value || (value >> 15) == 1) {
			b |= Constants.CBOR_LENGTH_2BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) ((value >> 8) & 0xFF);
			bOffset += 1;
			buffer[bOffset] = (byte) (value & 0xFF);
		}

		return (short) (bOffset + 1);
	}

	/**
	 * Encodes a <b>negative</b> value (MajorType 1) as short as possible. Bytes need to be casted to short values.<br>
	 * For encoding positive values see {@link #setUIntValue(short, byte[], short)}. <br>
	 * <br>
	 * <b>Important:</b> Negative values are encoded as positive values and are interpreted by decoding as: -1 - (UINT).<br>
	 * <b>Example 1</b>: If value = -500 value, it becomes an encoded 499. The decoding: -1 - (499) = -500.<br>
	 * <b>Example 2</b>: If value = 500, it is encoded as 499. The decoding: -1 - (499) = -500. <br>
	 * <br>
	 * <b> Only values of max. 2 bytes length are encoded.</b>
	 * 
	 * @param value
	 *            The value to be encoded as short.
	 * @param buffer
	 *            The response buffer.
	 * @param bOffset
	 *            Offset, where to start writing in the response buffer.
	 * @return bOffset + encoded length of given value.
	 * @see <a href="https://tools.ietf.org/html/rfc7049#section-2.1">https://tools.ietf.org/html/rfc7049#section-2.1</a>
	 */
	public short setIntValue(short value, byte[] buffer, short bOffset) {
		byte b = Constants.CBOR_MAJOR_TYPE_INT << 5;
		
		if (value < 0) {
			value = (short) (value * -1);	
		}
		
		value -= 1;

		if (value < Constants.CBOR_LENGTH_1BYTE) {
			b |= (byte) (value & 0xFF);
			buffer[bOffset] = b;
		} else if (Constants.CBOR_LENGTH_1BYTE <= value && value <= 0xFF) {
			b |= Constants.CBOR_LENGTH_1BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) (value >> 8 & 0xFF);
		} else if (0xFF < value || (value >> 15) == 1) {
			b |= Constants.CBOR_LENGTH_2BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) ((value >> 8) & 0xFF);
			bOffset += 1;
			buffer[bOffset] = (byte) (value & 0xFF);
		}

		return (short) (bOffset + 1);
	}

	/**
	 * Encodes a <b>byte string</b> (MajorType 2) as short as possible.<br>
	 * <br>
	 * <b> Only byte strings, whose length can be encoded in max. 2 Bytes are accepted.</b>
	 * 
	 * @param value
	 *            The value to be encoded as byte string.
	 * @param length
	 *            The length of the byte string.
	 * @param buffer
	 *            The response buffer.
	 * @param bOffset
	 *            Offset, where to start writing in the response buffer.
	 * @return bOffset + encoded length of byte string.
	 * @see <a href="https://tools.ietf.org/html/rfc7049#section-2.1">https://tools.ietf.org/html/rfc7049#section-2.1</a>
	 */
	public short setByteString(byte[] value, short length, byte[] buffer, short bOffset) {
		byte b = Constants.CBOR_MAJOR_TYPE_BYTE_STRING << 5;
		
		if (length < Constants.CBOR_LENGTH_1BYTE) {
			b |= (byte) (length & 0x1F);
			buffer[bOffset] = b;
		} else if (Constants.CBOR_LENGTH_1BYTE <= length && length <= 0xFF) {
			b |= Constants.CBOR_LENGTH_1BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) (length & 0xFF);
		} else if (0xFF < length || (length >> 15) == 1) {
			b |= Constants.CBOR_LENGTH_2BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) ((length >> 8) & 0xFF);
			bOffset += 1;
			buffer[bOffset] = (byte) (length & 0xFF);
		}

		bOffset += 1;
		bOffset = Util.arrayCopy(value, (short) 0, buffer, bOffset, length);

		return bOffset;
	}

	/**
	 * Encodes a <b>text string</b> (MajorType 3) as short as possible.<br>
	 * <br>
	 * <b> Only text strings, whose length can be encoded in max. 2 Bytes are accepted.</b>
	 * 
	 * @param value
	 *            The value to be encoded as byte string.
	 * @param length
	 *            The length of the text string.
	 * @param buffer
	 *            The response buffer.
	 * @param bOffset
	 *            Offset, where to start writing in the response buffer.
	 * @return bOffset + encoded length of text string.
	 * @see <a href="https://tools.ietf.org/html/rfc7049#section-2.1">https://tools.ietf.org/html/rfc7049#section-2.1</a>
	 */
	public short setTextString(byte[] value, short length, byte[] buffer, short bOffset) {
		byte b = Constants.CBOR_MAJOR_TYPE_TEXT_STRING << 5;
		
		if (length < Constants.CBOR_LENGTH_1BYTE) {
			b |= (byte) (length & 0x1F);
			buffer[bOffset] = b;
		} else if (Constants.CBOR_LENGTH_1BYTE <= length && length <= 0xFF) {
			b |= Constants.CBOR_LENGTH_1BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) (length & 0xFF);
		} else if (0xFF < length || (length >> 15) == 1) {
			b |= Constants.CBOR_LENGTH_2BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) ((length >> 8) & 0xFF);
			bOffset += 1;
			buffer[bOffset] = (byte) (length & 0xFF);
		}

		bOffset += 1;
		bOffset = Util.arrayCopy(value, (short) 0, buffer, bOffset, length);

		return bOffset;
	}

	/**
	 * Encodes the number of elements of an <b>array type</b> (MajorType 4) as short as possible. Elements have to be encoded separately with the corresponding
	 * functions. <i>Elements of the array could be of different types.</i><br>
	 * <br>
	 * <b> Only arrays, whose number of elements can be encoded in max. 2 Bytes are accepted.</b>
	 * 
	 * @param value
	 *            The number of elements contained in the array.
	 * @param buffer
	 *            The response buffer.
	 * @param bOffset
	 *            Offset, where to start writing in the response buffer.
	 * @return bOffset + encoded length of array type.
	 * @see <a href="https://tools.ietf.org/html/rfc7049#section-2.1">https://tools.ietf.org/html/rfc7049#section-2.1</a>
	 */
	public short setArrayType(short value, byte[] buffer, short bOffset) {
		byte b = (byte) (Constants.CBOR_MAJOR_TYPE_ARRAY << 5);
		
		if (value < Constants.CBOR_LENGTH_1BYTE) {
			b |= (byte) (value & 0x1F);
			buffer[bOffset] = b;
		} else if (Constants.CBOR_LENGTH_1BYTE <= value && value <= 0xFF) {
			b |= Constants.CBOR_LENGTH_1BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) (value & 0xFF);
		} else if (0xFF < value || (value >> 15) == 1) {
			b |= Constants.CBOR_LENGTH_2BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) ((value >> 8) & 0xFF);
			bOffset += 1;
			buffer[bOffset] = (byte) (value & 0xFF);
		}
		
		return (short) (bOffset + 1);
	}

	/**
	 * Encodes the number of pairs (key, value) of a <b>map type</b> (MajorType 5) as short as possible. Pairs have to be encoded separately with the
	 * corresponding functions. <i>Pairs of the map could be of different types.</i><br>
	 * <br>
	 * <b> Only maps, whose number of pairs can be encoded in max. 2 Bytes are accepted.</b>
	 * 
	 * @param value
	 *            The number of pairs contained in the map.
	 * @param buffer
	 *            The response buffer.
	 * @param bOffset
	 *            Offset, where to start writing in the response buffer.
	 * @return bOffset + encoded length of map type.
	 * @see <a href="https://tools.ietf.org/html/rfc7049#section-2.1">https://tools.ietf.org/html/rfc7049#section-2.1</a>
	 */
	public short setMapType(short value, byte[] buffer, short bOffset) {
		byte b = (byte) (Constants.CBOR_MAJOR_TYPE_MAP << 5);
		
		if (value < Constants.CBOR_LENGTH_1BYTE) {
			b |= (byte) (value & 0x1F);
			buffer[bOffset] = b;
		} else if (Constants.CBOR_LENGTH_1BYTE <= value && value <= 0xFF) {
			b |= Constants.CBOR_LENGTH_1BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) (value & 0xFF);
		} else if (0xFF < value || (value >> 15) == 1) {
			b |= Constants.CBOR_LENGTH_2BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) ((value >> 8) & 0xFF);
			bOffset += 1;
			buffer[bOffset] = (byte) (value & 0xFF);
		}
		
		return (short) (bOffset + 1);
	}

	/**
	 * Encodes a <b>simple value</b> (MajorType 7) as short as possible. Following values are specified as simple values:
	 * <ul>
	 * <li>Boolean Values
	 * <li>NULL and UNDEFINED value
	 * <li>Floats
	 * </ul>
	 * <b> Only floats of simple value type {@link Constants#CBOR_SIMPLE_VALUE_1BYTE} and {@link Constants#CBOR_HALF_PRECISION_FLOAT} are supported.</b>
	 * 
	 * @param simpleValueType
	 *            The type of the simple value e.g. {@link Constants#CBOR_FALSE}.
	 * @param value
	 *            The <b>float</b> or <b>SIMPLE_VALUE_1BYTE</b> to be encoded <b>or null</b>.
	 * @param buffer
	 *            The response buffer.
	 * @param bOffset
	 *            Offset, where to start writing in the response buffer.
	 * @return bOffset + encoded length of simple value.
	 * @throws UserException
	 * 		       <ul>
	 *             <li><b>CTAP2_ERR_ENCODING_ERROR</b> when the given simple value can not be encoded correctly.</i>
	 *             </ul>
	 * @see <a href="https://tools.ietf.org/html/rfc7049#section-2.1">https://tools.ietf.org/html/rfc7049#section-2.1</a>
	 */
	public short setSimpleValue(byte simpleValueType, byte[] value, byte[] buffer, short bOffset) throws UserException {
		byte b = (byte) (Constants.CBOR_MAJOR_TYPE_SIMPLE_VALUES << 5);
		
		if (simpleValueType == Constants.CBOR_TRUE
				|| simpleValueType == Constants.CBOR_FALSE
				|| simpleValueType == Constants.CBOR_NULL
				|| simpleValueType == Constants.CBOR_UNDEFINED_VALUE) {
			b |= (byte) (simpleValueType & 0x1F);
			buffer[bOffset] = b;
		} else if (simpleValueType == Constants.CBOR_SIMPLE_VALUE_1BYTE && value != null && (short) value.length == (short) 1 && value[0] >= (byte) 32) {
			b |= Constants.CBOR_SIMPLE_VALUE_1BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) (value[0] & 0xFF);
		} else if (simpleValueType == Constants.CBOR_HALF_PRECISION_FLOAT && value != null && (short) value.length == (short) 2) {
			b |= Constants.CBOR_HALF_PRECISION_FLOAT;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) ((simpleValueType >> 8) & 0xFF);
			bOffset += 1;
			buffer[bOffset] = (byte) (simpleValueType & 0xFF);
		} else {
			UserException.throwIt(Constants.CTAP2_ERR_ENCODING_ERROR);
		}
		
		return (short) (bOffset + 1);
	}

	/**
	 * Encodes only the given <b>MajorType</b> and its length as short as possible.
	 * 
	 * <b> Only length values that can be encoded in max. 2 Bytes are accepted.</b>
	 * 
	 * @param majorType
	 *            The Major Type to be encoded.
	 * @param length
	 *            The length of the following value.
	 * @param buffer
	 *            The response buffer.
	 * @param bOffset
	 *            Offset, where to start writing in the response buffer.
	 * @return bOffset + encoded length of MajorType.
	 */
	public short setMajorType(byte majorType, short length, byte[] buffer, short bOffset) {
		byte b = (byte) (majorType << 5);

		if (length < Constants.CBOR_LENGTH_1BYTE) {
			b |= (byte) (length & 0x1F);
			buffer[bOffset] = b;
		} else if (Constants.CBOR_LENGTH_1BYTE <= length && length <= 0xFF) {
			b |= Constants.CBOR_LENGTH_1BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) (length & 0xFF);
		} else if (0xFF < length || (length >> 15) == 1) {
			b |= Constants.CBOR_LENGTH_2BYTE;
			buffer[bOffset] = b;
			bOffset += 1;
			buffer[bOffset] = (byte) ((length >> 8) & 0xFF);
			bOffset += 1;
			buffer[bOffset] = (byte) (length & 0xFF);
		}

		return (short) (bOffset + 1);
	}

	/**
	 * Writes the given value to the response buffer.
	 * 
	 * @param value
	 *            The value to be written.
	 * @param buffer
	 *            The response buffer.
	 * @param bOffset
	 *            Offset, where to start writing in the response buffer.
	 * @return bOffset + 1
	 */
	public short setByte(byte value, byte[] buffer, short bOffset) {
		buffer[bOffset] = value;

		return (short) (bOffset + 1);
	}

	/**
	 * Writes the given byte array to the response buffer.
	 * 
	 * @param value
	 *            The buffer containing the value.
	 * @param valueOffset
	 *            The offset where the value starts.
	 * @param length
	 *            The length of the value.
	 * @param buffer
	 *            The response buffer.
	 * @param bOffset
	 *            Offset, where to start writing the byte in response buffer.
	 * @return bOffset + length
	 */
	public short setBytes(byte[] value, short valueOffset, short length, byte[] buffer, short bOffset) {
		bOffset = Util.arrayCopy(value, valueOffset, buffer, bOffset, length);

		return bOffset;
	}

	/**
	 * Sets all necessary values for the outgoing response. The response can now be returned.
	 * 
	 * @param apdu
	 *            The APDU to respond to.
	 * @param bOffset
	 *            Length of the response.
	 */
	public void send(APDU apdu, short bOffset) {
		apdu.setOutgoingLength(bOffset);
		apdu.sendBytes((short) 0, bOffset);
	}

	/**
	 * Prepares the response APDU by splitting it into short APDUs if necessary and setting all necessary values for the outgoing response. The short response
	 * APDU can now be returned.<br>
	 * <br>
	 * Used when short APDU invoked the command on the card. <br>
	 * <br>
	 * <b>Note:</b> The response APDU prepared, has a max length of 238 Bytes + 2 ISO SW Bytes. <i>This function has to be called multiple times, if the
	 * response is longer than 238 Bytes!</i> <br>
	 * <br>
	 * 
	 * @param apdu
	 *            The APDU to respond to.
	 * @param buffer
	 *            The buffer containing the response.
	 * @param bMessageStartOffset
	 *            The offset, where the next APDU in the chain has to start.
	 * @param bMessageEndOffset
	 *            The offset of the overall end of the message in the buffer.
	 * @return Offset where the response was splitted (byte not contained in current response).
	 */
	public short sendShortAPDUChain(APDU apdu, byte[] buffer, short bMessageStartOffset, short bMessageEndOffset) {
		byte[] responseBuffer = apdu.getBuffer();
		short oldOffset = bMessageStartOffset;

		// Pending response is longer than the response message buffer.
		if ((short) (bMessageStartOffset + 238) < bMessageEndOffset) {
			bMessageStartOffset += Util.arrayCopy(buffer, bMessageStartOffset, responseBuffer, (short) 0, (short) (240 - 2));
		}
		// Pending response is smaller or fits exactly in the response message buffer. Only possible for the last response APDU in the chain.
		else if ((short) (bMessageEndOffset - bMessageStartOffset) <= (short) 238) {
			bMessageStartOffset += Util.arrayCopy(buffer, bMessageStartOffset, responseBuffer, (short) 0, (short) (bMessageEndOffset - bMessageStartOffset));
		}

		apdu.setOutgoingLength((short) (bMessageStartOffset - oldOffset));
		apdu.sendBytes((short) 0, (short) (bMessageStartOffset - oldOffset));

		return bMessageStartOffset;
	}
}
