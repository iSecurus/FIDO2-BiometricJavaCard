/**
 * Copyright (C) 2021 Malte Kruse
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

import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * HMAC class supporting HMAC-SHA256, HMAC-SHA384 and HMAC-SHA512.
 * 
 * Thanks for the guidance and help to Paul Bastian!
 * 
 * @author Malte Kruse
 * @version v1.0, 22.02.2021
 * @see <a href="https://tools.ietf.org/html/rfc2104">https://tools.ietf.org/html/rfc2104</a>
 * @see <a href="https://tools.ietf.org/html/rfc4868">https://tools.ietf.org/html/rfc4868</a>
 * 
 */
public class HMAC {
	
	/*
	 * Paddings according rfc2104
	 */
	private static byte IPAD = 0x36;
	private static byte OPAD = 0x5c;
	
	private short blocksize;
	private short hmac_size;
	
	private MessageDigest sha;
	
	private byte[] key_ipad;
	private byte[] key_opad;
	
	private byte[] buffer;
	
	/**
	 * Instantiates the HMAC algorithm by defining the hash algorithm to use. <br/><br/>
	 * Supported hash algorithms: <br/>
	 * <ul>
	 * <li>MessageDigest.ALG_SHA_256</li>
	 * <li>MessageDigest.ALG_SHA_384</li>
	 * <li>MessageDigest.ALG_SHA_512</li>
	 * </ul>
	 * 
	 * @param algorithm 
	 * 			Hash algorithm to use.
	 */
	public HMAC(byte algorithm) {
		this.sha = MessageDigest.getInstance(algorithm, false);
		
		switch(algorithm) {
		case MessageDigest.ALG_SHA_256:
			this.blocksize = 64;
			hmac_size = 32;
			break;
		case MessageDigest.ALG_SHA_384:
			this.blocksize = 128;
			hmac_size = 48;
			break;
		case MessageDigest.ALG_SHA_512:
			this.blocksize = 128;
			hmac_size = 64;
			break;
		}
		
		this.key_ipad = new byte[blocksize];
		this.key_opad = new byte[blocksize];
		this.buffer = new byte[hmac_size];
	}
	
	/**
	 * Prepares the encryption key used for HMAC.
	 * 
	 * @param buffer
	 * 			The buffer containing the encryption key.
	 * @param offset
	 * 			Offset into the buffer at with the encryption key begins.
	 * @param length
	 * 			The length of the key.
	 */
	public void init(byte[] buffer, short offset, short length) {
		if(length > blocksize) {
			length = sha.doFinal(buffer, offset, length, this.buffer, (short) 0);
			buffer = this.buffer;
		}
		
		for(short i = 0; i < length; i++) {
			key_ipad[i] = (byte) (buffer[(short)(offset + i)] ^ IPAD);
			key_opad[i] = (byte) (buffer[(short)(offset + i)] ^ OPAD);
		}
		
		Util.arrayFillNonAtomic(key_ipad, length, (short) (blocksize - length), IPAD);
		Util.arrayFillNonAtomic(key_opad, length, (short) (blocksize - length), OPAD);
	}
	
	/**
	 * Performs the HMAC algorithm.
	 * 	
	 * @param inBuff
	 * 			Input buffer containing the data to calculate HMAC for.
	 * @param inOffset
	 * 			Offset into the input buffer at witch to begin calculating HMAC.
	 * @param inLength
	 * 			Length of the data within the input buffer to calculate HMAC for.
	 * @param outBuff
	 * 			The output buffer for the calculated HMAC.
	 * @param outOffset
	 * 			Offset into the output buffer at witch to begin writing the calculated HMAC.
	 * @return length of the calculated HMAC
	 */
	public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
		
		sha.update(key_ipad, (short) 0, blocksize);
		sha.doFinal(inBuff, inOffset, inLength, buffer, (short) 0);
		sha.reset();
		
		sha.update(key_opad, (short) 0, blocksize);
		sha.doFinal(buffer, (short) 0, sha.getLength(), outBuff, outOffset);
		sha.reset();
				
		return hmac_size;
	}
	
	/**
	 * Resets the HMAC object to its initial state for further use.
	 */
	public void reset() {
		Util.arrayFillNonAtomic(buffer, (short) 0, (short) sha.getLength(), (byte) 0x00);
		Util.arrayFillNonAtomic(key_ipad, (short) 0, (short) sha.getLength(), (byte) 0x00);
		Util.arrayFillNonAtomic(key_opad, (short) 0, (short) sha.getLength(), (byte) 0x00);
	}
	
	/**
	 * Returning the size of the HMAC.	
	 * 
	 * @return The resulting size of the calculated HMAC  
	 */
	public short getHMACSize() {
		return hmac_size;
	}
}
