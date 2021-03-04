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

import javacard.security.ECKey;

/**
 * ECKeyBuilder class used to configure the curve parameters of an elliptic curve key.
 * 
 * 
 * @author Malte Kruse
 * @version v1.0, 15.08.2019
 *
 */
public class ECKeyBuilder {

	/**
	 * Set the curve parameters of an ECKey to the ones of the Secp251r1 curve.
	 * 
	 * @param key
	 *            The key to be configured as Secp251r1 curve key.
	 */
	protected static void setSecp251r1CurveParameters(ECKey key) {
		key.setA(Constants.SECP256R1_A, (short) 0, (short) Constants.SECP256R1_A.length);
		key.setB(Constants.SECP256R1_B, (short) 0, (short) Constants.SECP256R1_B.length);
		key.setFieldFP(Constants.SECP256R1_FP, (short) 0, (short) Constants.SECP256R1_FP.length);
		key.setG(Constants.SECP256R1_G, (short) 0, (short) Constants.SECP256R1_G.length);
		key.setR(Constants.SECP256R1_R, (short) 0, (short) Constants.SECP256R1_R.length);
		key.setK(Constants.SECP256R1_K);
	}
}
