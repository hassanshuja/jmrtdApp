/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2023  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: AAAPDUSender.java 1878 2023-07-31 13:19:51Z martijno $
 */

package org.jmrtd.protocol;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.jmrtd.APDULevelAACapable;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ISO7816;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.util.Hex;

/**
 * A low-level APDU sender to support the Active Authentication protocol.
 *
 * @author The JMRTD team
 *
 * @version $Revision: 1878 $
 *
 * @since 0.7.0
 */
public class AAAPDUSender implements APDULevelAACapable {

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd.protocol");

  private SecureMessagingAPDUSender secureMessagingSender;

  /**
   * Creates an APDU sender for tranceiving Active Authentication protocol APDUs.
   *
   * @param service the card service for tranceiving APDUs
   */
  public AAAPDUSender(CardService service) {
    this.secureMessagingSender = new SecureMessagingAPDUSender(service);
  }

  /**
   * Sends an {@code INTERNAL AUTHENTICATE} command to the passport.
   * This is part of AA.
   *
   * @param wrapper secure messaging wrapper
   * @param signatureLength the (expected) length of the signature in bits
   * @param rndIFD the challenge to send
   *
   * @return the response from the passport (status word removed)
   *
   * @throws CardServiceException on tranceive error
   */
  public synchronized byte[] sendInternalAuthenticate(APDUWrapper wrapper, int signatureLength, byte[] rndIFD) throws CardServiceException {
    if (rndIFD == null || rndIFD.length != 8) {
      throw new IllegalArgumentException("rndIFD wrong length");
    }

    int le = signatureLength <= 231 * 8 ? 256 : 65536;
    CommandAPDU commandAPDU = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, rndIFD, le);

    ResponseAPDU responseAPDU = null;
    short sw = -1;
    try {
      responseAPDU = secureMessagingSender.transmit(wrapper, commandAPDU);
      sw = (short)responseAPDU.getSW();
    } catch (CardServiceException cse) {
      LOGGER.log(Level.INFO, "Exception during transmission of command APDU = " + Hex.bytesToHexString(commandAPDU.getBytes()), cse);
      sw = (short)cse.getSW();
    }

    if (sw == ISO7816.SW_NO_ERROR && responseAPDU != null) {
      return responseAPDU.getData();
    }

    if ((sw & 0xFF00) == 0x6100 && le == 256) {
      byte[] normalLengthResponse = responseAPDU == null ? null : responseAPDU.getData();

      /* Something is wrong with that length. Try different length. */
      commandAPDU = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, rndIFD, 65536);
      responseAPDU = secureMessagingSender.transmit(wrapper, commandAPDU);
      byte[] extendedLengthResponse = responseAPDU == null ? null : responseAPDU.getData();

      if (normalLengthResponse == null && extendedLengthResponse == null) {
        throw new CardServiceException("Internal Authenticate failed", sw);
      }
      if (normalLengthResponse != null && extendedLengthResponse == null) {
        return normalLengthResponse;
      }
      if (normalLengthResponse == null && extendedLengthResponse != null) {
        return extendedLengthResponse;
      }

      /* Both are non-null. Send the one with the most data. */
      if (normalLengthResponse.length > extendedLengthResponse.length) {
        return normalLengthResponse;
      } else {
        return extendedLengthResponse;
      }
    } else if (responseAPDU != null && responseAPDU.getData() != null) {
      /* If we got some data, return it, independent of what the status is. */
      LOGGER.warning("Internal Authenticate may not have succeeded, got status word " + Integer.toHexString(sw & 0xFFFF));
      return responseAPDU.getData();
    }

    throw new CardServiceException("Internal Authenticate failed", sw);
  }
}
