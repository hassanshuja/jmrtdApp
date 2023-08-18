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
 * $Id: APDULevelAACapable.java 1878 2023-07-31 13:19:51Z martijno $
 */

package org.jmrtd;

import net.sf.scuba.smartcards.APDUWrapper;
import net.sf.scuba.smartcards.CardServiceException;

/**
 * The low-level capability of sending APDUs for the Active Authentication protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1878 $
 */
public interface APDULevelAACapable {

  /**
   * Sends an {@code INTERNAL AUTHENTICATE} command to the ICC.
   * This method will remove the status word from the response.
   *
   * @param wrapper the secure messaging wrapper to use
   * @param signatureLength the length of the public key in bits
   * @param rndIFD the challenge to send
   *
   * @return the response from the ICC
   *
   * @throws CardServiceException on tranceive error
   */
  byte[] sendInternalAuthenticate(APDUWrapper wrapper, int signatureLength, byte[] rndIFD) throws CardServiceException;
}
