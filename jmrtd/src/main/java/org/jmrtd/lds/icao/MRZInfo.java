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
 * $Id: MRZInfo.java 1875 2023-06-21 14:46:26Z martijno $
 */

package org.jmrtd.lds.icao;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

import org.jmrtd.lds.AbstractLDSInfo;

import net.sf.scuba.data.Gender;

/**
 * Data structure for storing the MRZ information
 * as found in DG1. Based on ICAO Doc 9303 (Seventh edition)
 * part 4 (TD3),
 * part 5 (TD1),
 * part 6 (TD2),
 * and part 7 (MRV-A, MRV-B).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1875 $
 */
public class MRZInfo extends AbstractLDSInfo {

  private static final long serialVersionUID = 7054965914471297804L;

  /**
   * The type of document (MRZ), determining the number of lines,
   * number of characters per line, and positions and lengths of fields,
   * and check-digits.
   */
  private enum DocumentType {

    /** Unspecified document type (do not use, choose ID1 or ID3). */
    UNKNOWN(DOC_TYPE_UNSPECIFIED),

    /** MROTD 3 lines of 30 characters, as per part 5. */
    TD1(DOC_TYPE_ID1),

    /** MROTD 2 lines of 36 characters, as per part 6. */
    TD2(DOC_TYPE_ID2),

    /** MRP 2 lines of 44 characters, as per part 4. */
    TD3(DOC_TYPE_ID3),

    /** MRV type A. */
    MRVA(4),

    /** MRV type B. */
    MRVB(5);

    private int code;

    /**
     * Constructs a document type.
     *
     * @param code numeric code for compatibility with old constants
     */
    DocumentType(int code) {
      this.code = code;
    }

    /**
     * Returns the numeric code identifying this type.
     *
     * @return the numeric code
     */
    public int getCode() {
      return code;
    }
  }

  /** Unspecified document type (do not use, choose ID1 or ID3). */
  public static final int DOC_TYPE_UNSPECIFIED = 0;

  /** ID1 document type for credit card sized identity cards. Specifies a 3-line MRZ, 30 characters wide. */
  public static final int DOC_TYPE_ID1 = 1;

  /** ID2 document type. Specifies a 2-line MRZ, 36 characters wide. */
  public static final int DOC_TYPE_ID2 = 2;

  /** ID3 document type for passport booklets. Specifies a 2-line MRZ, 44 characters wide. */
  public static final int DOC_TYPE_ID3 = 3;

  /** All valid characters in MRZ. */
  private static final String MRZ_CHARS = "<0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  private DocumentType documentType;
  private String documentCode;
  private String issuingState;
  private String primaryIdentifier;
  private String secondaryIdentifier;
  private String nationality;
  private String documentNumber;
  private String dateOfBirth;
  private Gender gender;
  private String dateOfExpiry;
  private char documentNumberCheckDigit;
  private char dateOfBirthCheckDigit;
  private char dateOfExpiryCheckDigit;
  private char personalNumberCheckDigit; /* NOTE: Over optionalData1, but only for TD3. When empty we prefer '<' over '0'. */
  private char compositeCheckDigit;
  private String optionalData1; /* NOTE: For TD1 holds personal number for some issuing states (e.g. NL), but is used to hold (part of) document number for others. */
  private String optionalData2;

  /**
   * Creates a new 3-line, 30 character (TD1) MRZ compliant with ICAO Doc 9303 (seventh edition) part 5.
   *
   * @param documentCode document code (1 or 2 digit, has to start with "I", "C", or "A")
   * @param issuingState issuing state as 3 alpha string
   * @param primaryIdentifier card holder last name
   * @param secondaryIdentifier card holder first name(s)
   * @param documentNumber document number
   * @param nationality nationality as 3 alpha string
   * @param dateOfBirth date of birth in yyMMdd format
   * @param gender gender, must not be {@code null}
   * @param dateOfExpiry date of expiry in yyMMdd format
   * @param optionalData1 optional data in line 1 of maximum length 15
   * @param optionalData2 optional data in line 2 of maximum length 11
   *
   * @return the 3-line MRZ
   */
  public static MRZInfo createTD1MRZInfo(String documentCode,
      String issuingState,
      String documentNumber,
      String optionalData1,
      String dateOfBirth,
      Gender gender,
      String dateOfExpiry,
      String nationality,
      String optionalData2,
      String primaryIdentifier,
      String secondaryIdentifier) {
    return new MRZInfo(DocumentType.TD1,
        documentCode,
        issuingState,
        documentNumber,
        optionalData1,
        dateOfBirth,
        gender,
        dateOfExpiry,
        nationality,
        optionalData2,
        primaryIdentifier,
        secondaryIdentifier);
  }

  /**
   * Creates a new 2-line, 36 character (TD2) MRZ compliant with ICAO Doc 9303 (seventh edition) part 6.
   *
   * @param documentCode document code (1 or 2 digit, has to start with "P" or "V")
   * @param issuingState issuing state as 3 alpha string
   * @param primaryIdentifier card holder last name
   * @param secondaryIdentifier card holder first name(s)
   * @param documentNumber document number
   * @param nationality nationality as 3 alpha string
   * @param dateOfBirth date of birth
   * @param gender gender, must not be {@code null}
   * @param dateOfExpiry date of expiry
   * @param optionalData either empty or optional data of maximal length 9
   *
   * @return the 2-line MRZ
   */
  public static MRZInfo createTD2MRZInfo(String documentCode, String issuingState,
      String primaryIdentifier, String secondaryIdentifier,
      String documentNumber, String nationality, String dateOfBirth,
      Gender gender, String dateOfExpiry, String optionalData) {
    return new MRZInfo(DocumentType.TD2,
        documentCode,
        issuingState,
        documentNumber,
        optionalData,
        dateOfBirth,
        gender,
        dateOfExpiry,
        nationality,
        null,
        primaryIdentifier,
        secondaryIdentifier);
  }

  /**
   * Creates a new 2-line, 44 character (TD3) MRZ compliant with ICAO Doc 9303 (seventh edition) part 4.
   *
   * @param documentCode document code (1 or 2 digit, has to start with "P")
   * @param issuingState issuing state as 3 alpha string
   * @param primaryIdentifier card holder last name
   * @param secondaryIdentifier card holder first name(s)
   * @param documentNumber document number
   * @param nationality nationality as 3 alpha string
   * @param dateOfBirth date of birth
   * @param gender gender, must not be {@code null}
   * @param dateOfExpiry date of expiry
   * @param personalNumber either empty, or a personal number of maximum length 14, or other optional data of exact length 15
   *
   * @return the 2-line MRZ
   */
  public static MRZInfo createTD3MRZInfo(String documentCode, String issuingState,
      String primaryIdentifier, String secondaryIdentifier,
      String documentNumber, String nationality, String dateOfBirth,
      Gender gender, String dateOfExpiry, String personalNumber) {
    return new MRZInfo(DocumentType.TD3,
        documentCode,
        issuingState,
        documentNumber,
        personalNumberToOptionalData(personalNumber),
        dateOfBirth,
        gender,
        dateOfExpiry,
        nationality,
        null,
        primaryIdentifier,
        secondaryIdentifier);
  }

  /**
   * Creates a new 2-line, 44 character (MRV-A) MRZ compliant with ICAO Doc 9303 (seventh edition) part 7.
   *
   * @param documentCode document code (1 or 2 digit, has to start with "V")
   * @param issuingState issuing state as 3 alpha string
   * @param primaryIdentifier card holder last name
   * @param secondaryIdentifier card holder first name(s)
   * @param documentNumber document number
   * @param nationality nationality as 3 alpha string
   * @param dateOfBirth date of birth
   * @param gender gender, must not be {@code null}
   * @param dateOfExpiry date of expiry
   * @param optionalData optional data at discretion of issuing state
   *
   * @return the 2-line MRZ
   */
  public static MRZInfo createMRVAMRZInfo(String documentCode, String issuingState,
      String primaryIdentifier, String secondaryIdentifier,
      String documentNumber, String nationality, String dateOfBirth,
      Gender gender, String dateOfExpiry, String optionalData) {
    return new MRZInfo(DocumentType.MRVA,
        documentCode,
        issuingState,
        documentNumber,
        optionalData,
        dateOfBirth,
        gender,
        dateOfExpiry,
        nationality,
        null,
        primaryIdentifier,
        secondaryIdentifier);
  }

  /**
   * Creates a new 2-line, 36 character (MRV-B) MRZ compliant with ICAO Doc 9303 (seventh edition) part 7.
   *
   * @param documentCode document code (1 or 2 digit, has to start with "V")
   * @param issuingState issuing state as 3 alpha string
   * @param primaryIdentifier card holder last name
   * @param secondaryIdentifier card holder first name(s)
   * @param documentNumber document number
   * @param nationality nationality as 3 alpha string
   * @param dateOfBirth date of birth
   * @param gender gender, must not be {@code null}
   * @param dateOfExpiry date of expiry
   * @param optionalData optional data at discretion of issuing state
   *
   * @return the 2-line MRZ
   */
  public static MRZInfo createMRVBMRZInfo(String documentCode, String issuingState,
      String primaryIdentifier, String secondaryIdentifier,
      String documentNumber, String nationality, String dateOfBirth,
      Gender gender, String dateOfExpiry, String optionalData) {
    return new MRZInfo(DocumentType.MRVB,
        documentCode,
        issuingState,
        documentNumber,
        optionalData,
        dateOfBirth,
        gender,
        dateOfExpiry,
        nationality,
        null,
        primaryIdentifier,
        secondaryIdentifier);
  }

  /**
   * Creates a new 2-line MRZ compliant with ICAO Doc 9303 (pre-seventh edition) part 1 vol 1.
   *
   * @param documentCode document code (1 or 2 digit, has to start with "P" or "V")
   * @param issuingState issuing state as 3 alpha string
   * @param primaryIdentifier card holder last name
   * @param secondaryIdentifier card holder first name(s)
   * @param documentNumber document number
   * @param nationality nationality as 3 alpha string
   * @param dateOfBirth date of birth
   * @param gender gender, must not be {@code null}
   * @param dateOfExpiry date of expiry
   * @param personalNumber either empty, or a personal number of maximum length 14, or other optional data of exact length 15
   *
   * @deprecated Use the corresponding factory method {@link #createTD1MRZInfo(String, String, String, String, String, Gender, String, String, String, String, String)}
   */
  @Deprecated
  public MRZInfo(String documentCode, String issuingState,
      String primaryIdentifier, String secondaryIdentifier,
      String documentNumber, String nationality, String dateOfBirth,
      Gender gender, String dateOfExpiry, String personalNumber) {
    this(getDocumentTypeFromDocumentCode(documentCode),
        documentCode,
        issuingState,
        documentNumber,
        personalNumberToOptionalData(personalNumber),
        dateOfBirth,
        gender,
        dateOfExpiry,
        nationality,
        null,
        primaryIdentifier,
        secondaryIdentifier);
  }

  /**
   * Creates a new 3-line MRZ compliant with ICAO Doc 9303 (pre-seventh edition) part 3 vol 1.
   *
   * @param documentCode document code (1 or 2 digit, has to start with "I", "C", or "A")
   * @param issuingState issuing state as 3 alpha string
   * @param primaryIdentifier card holder last name
   * @param secondaryIdentifier card holder first name(s)
   * @param documentNumber document number
   * @param nationality nationality as 3 alpha string
   * @param dateOfBirth date of birth in YYMMDD format
   * @param gender gender, must not be {@code null}
   * @param dateOfExpiry date of expiry in YYMMDD format
   * @param optionalData1 optional data in line 1 of maximum length 15
   * @param optionalData2 optional data in line 2 of maximum length 11
   *
   * @deprecated Use the corresponding factory method {@link #createTD3MRZInfo(String, String, String, String, String, String, String, Gender, String, String)}
   */
  @Deprecated
  public MRZInfo(String documentCode,
      String issuingState,
      String documentNumber,
      String optionalData1,
      String dateOfBirth,
      Gender gender,
      String dateOfExpiry,
      String nationality,
      String optionalData2,
      String primaryIdentifier,
      String secondaryIdentifier) {
    this(getDocumentTypeFromDocumentCode(documentCode),
        documentCode,
        issuingState,
        documentNumber,
        optionalData1,
        dateOfBirth,
        gender,
        dateOfExpiry,
        nationality,
        optionalData2,
        primaryIdentifier,
        secondaryIdentifier);
  }

  /**
   * Creates a new MRZ based on an input stream.
   *
   * @param inputStream contains the contents (value) of DG1 (without the tag and length)
   * @param length the length of the MRZInfo structure
   */
  public MRZInfo(InputStream inputStream, int length) {
    try {
      readObject(inputStream, length);
    } catch (IOException ioe) {
      throw new IllegalArgumentException(ioe);
    }
  }

  /**
   * Creates a new MRZ based on the text input.
   * The text input may contain newlines, which will be ignored.
   *
   * @param str input text
   */
  public MRZInfo(String str) {
    if (str == null) {
      throw new IllegalArgumentException("Null string");
    }
    str = str.trim().replace("\n", "");
    try {
      readObject(new ByteArrayInputStream(str.getBytes("UTF-8")), str.length());
    } catch (UnsupportedEncodingException uee) {
      /* NOTE: never happens, UTF-8 is supported. */
      throw new IllegalStateException("Exception", uee);
    } catch (IOException ioe) {
      throw new IllegalArgumentException("Exception", ioe);
    }
  }

  /**
   * Constructs an MRZInfo object from components.
   *
   * @param documentType the document-type
   * @param documentCode the document-code
   * @param issuingState the issuing state 3-alpha string
   * @param documentNumber the document number
   * @param optionalData1 optional data or personal number including check digit
   * @param dateOfBirth date of birth in yyMMdd format
   * @param gender the gender
   * @param dateOfExpiry the date of expiry in yyMMdd format
   * @param nationality the nationality 3 alpha string
   * @param optionalData2 optional optional data 2
   * @param primaryIdentifier the primary identifier
   * @param secondaryIdentifier the secondary identifiers
   */
  private MRZInfo(DocumentType documentType,
      String documentCode,
      String issuingState,
      String documentNumber,
      String optionalData1,
      String dateOfBirth,
      Gender gender,
      String dateOfExpiry,
      String nationality,
      String optionalData2,
      String primaryIdentifier,
      String secondaryIdentifier) {

    this.documentType = documentType;

    if (!isDocumentCodeConsistentWithDocumentType(documentType, documentCode)) {
      throw new IllegalArgumentException("Wrong document code");
    }

    if (!isOptionalDataConsistentWithDocumentType(documentType, optionalData1, optionalData2)) {
      throw new IllegalArgumentException("Wrong optional data length");
    }

    if (gender == null) {
      throw new IllegalArgumentException("Gender must not be null");
    }

    this.documentCode = trimTrailingFillerChars(documentCode);
    this.issuingState = issuingState;
    this.primaryIdentifier = trimTrailingFillerChars(primaryIdentifier).replace("<", " ");
    this.secondaryIdentifier = trimTrailingFillerChars(secondaryIdentifier).replace("<", " ");
    this.documentNumber = trimTrailingFillerChars(documentNumber);
    this.nationality = nationality;
    this.dateOfBirth = dateOfBirth;
    this.gender = gender;
    this.dateOfExpiry = dateOfExpiry;
    this.optionalData1 = optionalData1 == null ? "" : trimTrailingFillerChars(optionalData1);
    this.optionalData2 = optionalData2 == null ? null : trimTrailingFillerChars(optionalData2);
    checkDigit();
  }

  /**
   * Returns the date of birth of the passport holder.
   *
   * @return date of birth
   */
  public String getDateOfBirth() {
    return dateOfBirth;
  }

  /**
   * Returns the date of expiry.
   *
   * @return the date of expiry
   */
  public String getDateOfExpiry() {
    return dateOfExpiry;
  }

  /**
   * Returns the document number.
   *
   * @return document number
   */
  public String getDocumentNumber() {
    return documentNumber;
  }

  /**
   * Returns the document type.
   *
   * @return document type
   *
   * @deprecated Clients should determine type based on {@link #getDocumentCode()}
   */
  @Deprecated
  public int getDocumentType() {
    return documentType.getCode();
  }

  /**
   * Returns the document code.
   *
   * @return document type
   */
  public String getDocumentCode() {
    return documentCode;
  }

  /**
   * Returns the issuing state as a 3 letter code.
   *
   * @return the issuing state
   */
  public String getIssuingState() {
    return mrzFormat(issuingState, 3);
  }

  /**
   * Returns the passport holder's last name.
   *
   * @return name
   */
  public String getPrimaryIdentifier() {
    return primaryIdentifier;
  }

  /**
   * Returns the document holder's first names.
   *
   * @return the secondary identifier
   */
  public String getSecondaryIdentifier() {
    return secondaryIdentifier;
  }

  /**
   * Returns the document holder's first names.
   *
   * @return first names
   */
  public String[] getSecondaryIdentifierComponents() {
    return secondaryIdentifier.split(" |<");
  }

  /**
   * Returns the passport holder's nationality as a 3 digit code.
   *
   * @return a country
   */
  public String getNationality() {
    return mrzFormat(nationality, 3);
  }

  /**
   * Returns the personal number (if a personal number is encoded in optional data 1).
   *
   * @return personal number
   */
  public String getPersonalNumber() {
    if (optionalData1 == null) {
      return null;
    }
    if (optionalData1.length() > 14) {
      return trimTrailingFillerChars(optionalData1.substring(0, 14));
    } else {
      return trimTrailingFillerChars(optionalData1);
    }
  }

  /**
   * Returns the passport holder's gender.
   *
   * @return gender
   */
  public Gender getGender() {
    return gender;
  }

  /**
   * Returns the contents of the first optional data field for ID-1 and ID-3 style MRZs.
   *
   * @return optional data 1
   */
  public String getOptionalData1() {
    return optionalData1;
  }

  /**
   * Returns the contents of the second optional data field for ID-1 style MRZs.
   *
   * @return optional data 2
   */
  public String getOptionalData2() {
    return optionalData2;
  }

  /**
   * Sets the document code.
   *
   * @param documentCode the new document code
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setDocumentCode(String documentCode) {
    this.documentCode = documentCode;
    this.documentType = getDocumentTypeFromDocumentCode(documentCode);
    if (documentType == DocumentType.TD1 && optionalData2 == null) {
      optionalData2 = "";
    }
    /* FIXME: need to adjust some other lengths if we go from ID1 to ID3 or back... */
  }

  /**
   * Sets the document number.
   *
   * @param documentNumber new document number
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber.trim();
    checkDigit();
  }

  /**
   * Sets the passport holder's last name.
   *
   * @param primaryIdentifier new primary identifier
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setPrimaryIdentifier(String primaryIdentifier) {
    this.primaryIdentifier = trimTrailingFillerChars(primaryIdentifier).replace("<", " ");
    checkDigit();
  }

  /**
   * Sets the passport holder's first names.
   *
   * @param secondaryIdentifiers new secondary identifiers
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setSecondaryIdentifierComponents(String[] secondaryIdentifiers) {
    if (secondaryIdentifiers == null) {
      this.secondaryIdentifier = null;
    } else {
      StringBuilder stringBuilder = new StringBuilder();
      for (int i = 0; i < secondaryIdentifiers.length; i++) {
        stringBuilder.append(secondaryIdentifiers[i]);
        if (i < secondaryIdentifiers.length - 1) {
          stringBuilder.append('<');
        }
      }
    }
    checkDigit();
  }

  /**
   * Sets the passport holder's first names.
   *
   * @param secondaryIdentifiers new secondary identifiers
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setSecondaryIdentifiers(String secondaryIdentifiers) {
    readSecondaryIdentifiers(secondaryIdentifiers.trim());
    checkDigit();
  }

  /**
   * Sets the date of birth.
   *
   * @param dateOfBirth new date of birth
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setDateOfBirth(String dateOfBirth) {
    this.dateOfBirth = dateOfBirth;
    checkDigit();
  }

  /**
   * Sets the date of expiry.
   *
   * @param dateOfExpiry new date of expiry
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setDateOfExpiry(String dateOfExpiry) {
    this.dateOfExpiry = dateOfExpiry;
    checkDigit();
  }

  /**
   * Sets the issuing state.
   *
   * @param issuingState new issuing state
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setIssuingState(String issuingState) {
    this.issuingState = issuingState;
    checkDigit();
  }

  /**
   * Sets the personal number. Replacing any optional data 1.
   *
   * @param personalNumber new personal number
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setPersonalNumber(String personalNumber) {
    if (personalNumber == null || personalNumber.length() > 14) {
      throw new IllegalArgumentException("Wrong personal number");
    }
    this.optionalData1 = mrzFormat(personalNumber, 14);
    this.personalNumberCheckDigit = checkDigit(this.optionalData1);
  }

  /**
   * Sets the passport holder's nationality.
   *
   * @param nationality new nationality
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setNationality(String nationality) {
    this.nationality = nationality;
    checkDigit();
  }

  /**
   * Sets the contents for the second optional data field for ID-1 style MRZs.
   *
   * @param optionalData2 optional data 2
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setOptionalData2(String optionalData2) {
    this.optionalData2 = trimTrailingFillerChars(optionalData2);
    checkDigit();
  }

  /**
   * Sets the gender.
   *
   * @param gender new gender
   *
   * @deprecated Class will become immutable
   */
  @Deprecated
  public void setGender(Gender gender) {
    if (gender == null) {
      throw new IllegalArgumentException("Gender must not be null");
    }
    this.gender = gender;
    checkDigit();
  }

  /**
   * Creates a textual representation of this MRZ.
   * This is the 2 or 3 line representation
   * (depending on the document type) as it
   * appears in the document. All lines end in
   * a newline char.
   *
   * @return the MRZ as text
   *
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    try {
      String str = new String(getEncoded(), "UTF-8");
      switch(str.length()) {
        case 90: /* ID1 */
          return str.substring(0, 30) + "\n"
          + str.substring(30, 60) + "\n"
          + str.substring(60, 90) + "\n";
        case 72: /* ID2 */
          return str.substring(0, 36) + "\n"
          + str.substring(36, 72) + "\n";
        case 88: /* ID3 */
          return str.substring(0, 44) + "\n"
          + str.substring(44, 88) + "\n";
        default:
          return str;
      }
    } catch (UnsupportedEncodingException uee) {
      throw new IllegalStateException(uee);
    }
  }

  /**
   * Returns the hash code for this MRZ info.
   *
   * @return the hash code
   */
  @Override
  public int hashCode() {
    return 2 * toString().hashCode() + 53;
  }

  /**
   * Whether this MRZ info is identical to some other object.
   *
   * @param obj the other object
   *
   * @return a boolean
   */
  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }
    if (!(obj.getClass().equals(this.getClass()))) {
      return false;
    }

    MRZInfo other = (MRZInfo)obj;

    return equalsModuloFillerChars(documentCode, other.documentCode)
        && equalsModuloFillerChars(issuingState, other.issuingState)
        && equalsModuloFillerChars(primaryIdentifier, other.primaryIdentifier)
        && equalsModuloFillerChars(secondaryIdentifier, other.secondaryIdentifier)
        && equalsModuloFillerChars(nationality, other.nationality)
        && equalsModuloFillerChars(documentNumber, other.documentNumber)
        && (equalsModuloFillerChars(optionalData1, other.optionalData1) || equalsModuloFillerChars(getPersonalNumber(), other.getPersonalNumber()))
        && ((dateOfBirth == null && other.dateOfBirth == null) || dateOfBirth != null && dateOfBirth.equals(other.dateOfBirth))
        && ((gender == null && other.gender == null) || gender != null && gender.equals(other.gender))
        && ((dateOfExpiry == null && other.dateOfExpiry == null) || dateOfExpiry != null && dateOfExpiry.equals(other.dateOfExpiry))
        && equalsModuloFillerChars(optionalData2, other.optionalData2);
  }

  /**
   * Computes the 7-3-1 check digit for part of the MRZ.
   *
   * @param str a part of the MRZ.
   *
   * @return the resulting check digit (in '0' - '9')
   */
  public static char checkDigit(String str) {
    return checkDigit(str, false);
  }

  /* ONLY PRIVATE METHODS BELOW */

  /**
   * Reads the object value from a stream.
   *
   * @param inputStream the stream to read from
   * @param length the length of the value
   *
   * @throws IOException on error reading from the stream
   */
  private void readObject(InputStream inputStream, int length) throws IOException {
    DataInputStream dataIn = inputStream instanceof DataInputStream ? (DataInputStream)inputStream : new DataInputStream(inputStream);

    /* line 1, pos 1 to 2, Document code, all types. */
    this.documentCode = trimTrailingFillerChars(readString(dataIn, 2));
    this.documentType = getDocumentType(this.documentCode, length);
    switch (this.documentType) {
      case TD1:
        readObjectTD1(dataIn);
        break;
      case TD2:
        /* Fall through... */
      case MRVB:
        readObjectTD2orMRVB(dataIn);
        break;
      case MRVA:
        /* Fall through... */
      case TD3:
        /* Fall through... */
      default:
        /* Assume it's a ID3 document, i.e. 2-line MRZ. */
        readObjectTD3OrMRVA(dataIn);
        break;
    }
  }

  /**
   * Reads the object value from a stream after document-code has already
   * been read, and it is determined that we are dealing with a TD1 style MRZ.
   *
   * @param inputStream the stream to read from
   *
   * @throws IOException on error reading from the stream
   */
  private void readObjectTD1(InputStream inputStream) throws IOException {
    DataInputStream dataIn = inputStream instanceof DataInputStream ? (DataInputStream)inputStream : new DataInputStream(inputStream);

    /* line 1, pos 3 to 5 Issuing State or organization */
    this.issuingState = readCountryCode(dataIn);

    /* line 1, pos 6 to 14 Document number */
    this.documentNumber = readString(dataIn, 9);

    /* line 1, pos 15 Check digit */
    this.documentNumberCheckDigit = (char)dataIn.readUnsignedByte();

    /* line 1, pos 16 to 30, Optional data elements */
    String rawOptionalData1 = readString(dataIn, 15);
    this.optionalData1 = trimTrailingFillerChars(rawOptionalData1);

    if (documentNumberCheckDigit == '<' && !optionalData1.isEmpty()) {
      /* Interpret personal number as part of document number, see note j. */
      int extendedDocumentNumberEnd = optionalData1.indexOf('<');
      if (extendedDocumentNumberEnd < 0) {
        extendedDocumentNumberEnd = optionalData1.length();
      }

      String documentNumberRemainder = optionalData1.substring(0, extendedDocumentNumberEnd - 1);
      this.documentNumber += documentNumberRemainder;
      this.documentNumberCheckDigit = optionalData1.charAt(extendedDocumentNumberEnd - 1);

      this.optionalData1 = optionalData1.substring(Integer.min(extendedDocumentNumberEnd + 1, optionalData1.length()));
    }
    this.documentNumber = trimTrailingFillerChars(this.documentNumber);

    /* line 2, pos 1 to 6, Date of birth */
    this.dateOfBirth = readDate(dataIn);

    /* line 2, pos 7, Check digit */
    this.dateOfBirthCheckDigit = (char)dataIn.readUnsignedByte();

    /* line 2, pos 8, Sex */
    this.gender = readGender(dataIn);

    /* line 2, Pos 9 to 14, Date of expiry */
    this.dateOfExpiry = readDate(dataIn);

    /* line 2, pos 15, Check digit */
    this.dateOfExpiryCheckDigit = (char)dataIn.readUnsignedByte();

    /* line 2, pos 16 to 18, Nationality */
    this.nationality = readCountryCode(dataIn);

    /* line 2, pos 19 to 29, Optional data elements */
    this.optionalData2 = trimTrailingFillerChars(readString(dataIn, 11));

    /* line 2, pos 30, Overall check digit */
    this.compositeCheckDigit = (char)dataIn.readUnsignedByte();

    /* line 3 */
    readNameIdentifiers(readString(dataIn, 30));
  }

  /**
   * Reads the object value from a stream after document-code has already
   * been read, and it is determined that we are dealing with a TD2 or MRV-B style MRZ.
   *
   * @param inputStream the stream to read from
   *
   * @throws IOException on error reading from the stream
   */
  private void readObjectTD2orMRVB(InputStream inputStream) throws IOException {
    DataInputStream dataIn = inputStream instanceof DataInputStream ? (DataInputStream)inputStream : new DataInputStream(inputStream);

    /* line 1, pos 3 to 5 */
    this.issuingState = readCountryCode(dataIn);

    /* line 1, pos 6 to 36 */
    readNameIdentifiers(readString(dataIn, 31));

    /* line 2 */
    this.documentNumber = trimTrailingFillerChars(readString(dataIn, 9));
    this.documentNumberCheckDigit = (char)dataIn.readUnsignedByte();
    this.nationality = readCountryCode(dataIn);
    this.dateOfBirth = readDate(dataIn);
    this.dateOfBirthCheckDigit = (char)dataIn.readUnsignedByte();
    this.gender = readGender(dataIn);
    this.dateOfExpiry = readDate(dataIn);
    this.dateOfExpiryCheckDigit = (char)dataIn.readUnsignedByte();
    if (documentType == DocumentType.MRVB) {
      this.optionalData1 = trimTrailingFillerChars(readString(dataIn, 8));
    } else if (documentType == DocumentType.TD2){
      this.optionalData1 = trimTrailingFillerChars(readString(dataIn, 7));

      if (documentNumberCheckDigit == '<' && !optionalData1.isEmpty()) {
        /* Interpret optional data as part of document number, see note j. */
        this.documentNumber += optionalData1.substring(0, optionalData1.length() - 1);
        this.documentNumberCheckDigit = optionalData1.charAt(optionalData1.length() - 1);
        this.optionalData1 = "";
      }
    }
    this.documentNumber = trimTrailingFillerChars(this.documentNumber);

    if (documentType == DocumentType.TD2) {
      this.compositeCheckDigit = (char)dataIn.readUnsignedByte();
    }
  }

  /**
   * Reads the object value from a stream after document-code has already
   * been read, and it is determined that we are dealing with a TD3 or MRV-A style MRZ.
   *
   * @param inputStream the stream to read from
   *
   * @throws IOException on error reading from the stream
   */
 private void readObjectTD3OrMRVA(InputStream inputStream) throws IOException {
    DataInputStream dataIn = inputStream instanceof DataInputStream ? (DataInputStream)inputStream : new DataInputStream(inputStream);

    /* line 1, pos 3 to 5 */
    this.issuingState = readCountryCode(dataIn);

    /* line 1, pos 6 to 44 */
    readNameIdentifiers(readString(dataIn, 39));

    /* line 2 */
    this.documentNumber = trimTrailingFillerChars(readString(dataIn, 9));
    this.documentNumberCheckDigit = (char)dataIn.readUnsignedByte();
    this.nationality = readCountryCode(dataIn);
    this.dateOfBirth = readDate(dataIn);
    this.dateOfBirthCheckDigit = (char)dataIn.readUnsignedByte();
    this.gender = readGender(dataIn);
    this.dateOfExpiry = readDate(dataIn);
    this.dateOfExpiryCheckDigit = (char)dataIn.readUnsignedByte();
    if (documentType == DocumentType.MRVA) {
      this.optionalData1 = trimTrailingFillerChars(readString(dataIn, 16));
    } else {
      this.optionalData1 = trimTrailingFillerChars(readString(dataIn, 14));
      this.personalNumberCheckDigit = (char)dataIn.readUnsignedByte();
      this.compositeCheckDigit = (char)dataIn.readUnsignedByte();
    }
  }

  /**
   * Writes the MRZ to an output stream.
   * This just outputs the MRZ characters, and does not add newlines.
   *
   * @param outputStream the output stream to write to
   */
  @Override
  public void writeObject(OutputStream outputStream) throws IOException {
    switch (documentType) {
      case TD1:
        writeObjectTD1(outputStream);
        break;
      case TD2:
        /* Fall through. */
      case MRVB:
        writeObjectTD2OrMRVB(outputStream);
        break;
      case TD3:
        /* Fall through. */
      case MRVA:
        writeObjectTD3OrMRVA(outputStream);
        break;
      default:
        throw new IllegalStateException("Unsupported document type");
    }
  }

  /**
   * Tests equality of two MRZ string while ignoring extra filler characters.
   *
   * @param str1 an MRZ string
   * @param str2 another MRZ string
   *
   * @return a boolean indicating whether the strings are equal modulo filler characters
   */
  public static boolean equalsModuloFillerChars(String str1, String str2) {
    if (str1 == str2) {
      return true;
    }
    if (str1 == null) {
      str1 = "";
    }
    if (str2 == null) {
      str2 = "";
    }

    int length = Math.max(str1.length(), str2.length());
    return mrzFormat(str1, length).equals(mrzFormat(str2, length));
  }

  /**
   * Writes this MRZ to stream.
   *
   * @param outputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  private void writeObjectTD1(OutputStream outputStream) throws IOException {
    DataOutputStream dataOut = outputStream instanceof DataOutputStream ? (DataOutputStream)outputStream : new DataOutputStream(outputStream);

    /* top line */
    writeDocumentType(dataOut);
    writeCountryCode(issuingState, dataOut);

    boolean isExtendedDocumentNumber = documentNumber.length() > 9;
    if (isExtendedDocumentNumber) {
      /*
       * If document number has more than 9 character, the 9 principal
       * character shall be shown in the MRZ in character positions 1 to 9.
       * They shall be followed by a filler character instead of a check
       * digit to indicate a truncated number. The remaining character of
       * the document number shall be shown at the beginning of the field
       * reserved of optional data element (character position 29 to 35 of
       * the lower machine readable line) followed by a check digit and a
       * filler character.
       *
       * Corresponds to Doc 9303 (pre-seventh edition) pt 3 vol 1 page V-10 (note j) (FIXED by Paulo Assumcao)
       *
       * Also see R3-p1_v2_sIV_0041 in Supplement to Doc 9303, release 11.
       */
      writeString(documentNumber.substring(0, 9), dataOut, 9);
      dataOut.write('<'); /* NOTE: instead of check digit */
      writeString(documentNumber.substring(9) + Character.toString(documentNumberCheckDigit) + "<" + optionalData1, dataOut, 15);
    } else {
      writeString(documentNumber, dataOut, 9); /* FIXME: max size of field */
      dataOut.write(documentNumberCheckDigit);
      writeString(optionalData1, dataOut, 15); /* FIXME: max size of field */
    }

    /* middle line */
    writeDateOfBirth(dataOut);
    dataOut.write(dateOfBirthCheckDigit);
    writeGender(dataOut);
    writeDateOfExpiry(dataOut);
    dataOut.write(dateOfExpiryCheckDigit);
    writeCountryCode(nationality, dataOut);
    writeString(optionalData2, dataOut, 11);
    dataOut.write(compositeCheckDigit);

    /* bottom line */
    writeName(dataOut, 30);
  }

  /**
   * Writes this MRZ to stream.
   *
   * @param outputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  private void writeObjectTD2OrMRVB(OutputStream outputStream) throws IOException {
    DataOutputStream dataOut = outputStream instanceof DataOutputStream ? (DataOutputStream)outputStream : new DataOutputStream(outputStream);

    /* top line */
    writeDocumentType(dataOut);
    writeCountryCode(issuingState, dataOut);
    writeName(dataOut, 31);

    /* bottom line */

    boolean isExtendedDocumentNumber = documentType == DocumentType.TD2 && documentNumber.length() > 9 && equalsModuloFillerChars(optionalData1, "");
    if (isExtendedDocumentNumber) {
      writeString(documentNumber.substring(0, 9), dataOut, 9);
      dataOut.write('<'); /* NOTE: instead of check digit */
    } else {
      writeString(documentNumber, dataOut, 9); /* FIXME: max size of field */
      dataOut.write(documentNumberCheckDigit);
    }

    writeCountryCode(nationality, dataOut);
    writeDateOfBirth(dataOut);
    dataOut.write(dateOfBirthCheckDigit);
    writeGender(dataOut);
    writeDateOfExpiry(dataOut);
    dataOut.write(dateOfExpiryCheckDigit);
    if (documentType == DocumentType.MRVB) {
      writeString(optionalData1, dataOut, 8);
    } else if (isExtendedDocumentNumber) {
      writeString(documentNumber.substring(9) + documentNumberCheckDigit + "<", dataOut, 7);
      dataOut.write(compositeCheckDigit);
    } else {
      writeString(optionalData1, dataOut, 7);
      dataOut.write(compositeCheckDigit);
    }
  }

  /**
   * Writes this MRZ to stream.
   *
   * @param outputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  private void writeObjectTD3OrMRVA(OutputStream outputStream) throws IOException {
    DataOutputStream dataOut = outputStream instanceof DataOutputStream ? (DataOutputStream)outputStream : new DataOutputStream(outputStream);

    /* top line */
    writeDocumentType(dataOut);
    writeCountryCode(issuingState, dataOut);
    writeName(dataOut, 39);

    /* bottom line */
    writeString(documentNumber, dataOut, 9);
    dataOut.write(documentNumberCheckDigit);
    writeCountryCode(nationality, dataOut);
    writeDateOfBirth(dataOut);
    dataOut.write(dateOfBirthCheckDigit);
    writeGender(dataOut);
    writeDateOfExpiry(dataOut);
    dataOut.write(dateOfExpiryCheckDigit);
    if (documentType == DocumentType.MRVA) {
      writeString(optionalData1, dataOut, 16);
    } else {
      // Must be TD3.
      writeString(optionalData1, dataOut, 14);
      dataOut.write(personalNumberCheckDigit);
      dataOut.write(compositeCheckDigit);
    }
  }

  /**
   * Sets the name identifiers (primary and secondary identifier) based on
   * the name in the MRZ.
   *
   * @param mrzNameString the name field as it occurs in the MRZ
   */
  private void readNameIdentifiers(String mrzNameString) {
    int delimIndex = mrzNameString.indexOf("<<");
    if (delimIndex < 0) {
      /* Only a primary identifier. */
      primaryIdentifier = trimTrailingFillerChars(mrzNameString).replace("<", " ");
      this.secondaryIdentifier = "";
      return;
    }
    primaryIdentifier = trimTrailingFillerChars(mrzNameString.substring(0, delimIndex)).replace("<", " ");
    String rest = mrzNameString.substring(delimIndex + 2);
    readSecondaryIdentifiers(rest);
  }

  /**
   * Sets the secondary identifier.
   *
   * @param secondaryIdentifier the new secondary identifier
   */
  private void readSecondaryIdentifiers(String secondaryIdentifier) {
    this.secondaryIdentifier = trimTrailingFillerChars(secondaryIdentifier).replace("<", " ");
  }

  /**
   * Writes a MRZ string to a stream, optionally formatting the MRZ string.
   *
   * @param string the string to write
   * @param dataOutputStream the stream to write to
   * @param width the width of the MRZ field (the string will be augmented with trailing fillers)
   *
   * @throws IOException on error writing to the stream
   */
  private void writeString(String string, DataOutputStream dataOutputStream, int width) throws IOException {
    dataOutputStream.write(mrzFormat(string, width).getBytes("UTF-8"));
  }

  /**
   * Writes the issuing state to an stream.
   *
   * @param dataOutputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  private static void writeCountryCode(String countryCode, DataOutputStream dataOutputStream) throws IOException {
    dataOutputStream.write(mrzFormat(countryCode, 3).getBytes("UTF-8"));
  }

  /**
   * Writes the date of expiry to a stream.
   *
   * @param dateOutputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  private void writeDateOfExpiry(DataOutputStream dateOutputStream) throws IOException {
    dateOutputStream.write(dateOfExpiry.getBytes("UTF-8"));
  }

  /**
   * Writes the gender to a stream.
   *
   * @param dataOutputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  private void writeGender(DataOutputStream dataOutputStream) throws IOException {
    dataOutputStream.write(genderToString(gender).getBytes("UTF-8"));
  }

  /**
   * Writes the data of birth to a stream.
   *
   * @param dataOutputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  private void writeDateOfBirth(DataOutputStream dataOutputStream) throws IOException {
    dataOutputStream.write(dateOfBirth.getBytes("UTF-8"));
  }

  /**
   * Writes the name to a stream.
   *
   * @param dataOutputStream the stream to write to
   * @param width the width of the field
   *
   * @throws IOException on error writing to the stream
   */
  private void writeName(DataOutputStream dataOutputStream, int width) throws IOException {
    dataOutputStream.write(nameToString(primaryIdentifier, secondaryIdentifier, width).getBytes("UTF-8"));
  }

  /**
   * Write the document type to a stream.
   *
   * @param dataOutputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  private void writeDocumentType(DataOutputStream dataOutputStream) throws IOException {
    writeString(documentCode, dataOutputStream, 2);
  }

  /**
   * Converts a gender to a string to be used in an MRZ.
   *
   * @param gender the gender
   *
   * @return a string to be used in an MRZ
   */
  private static String genderToString(Gender gender) {
    switch (gender) {
      case MALE:
        return "M";
      case FEMALE:
        return "F";
      default:
        return "<";
    }
  }

  /**
   * Encodes the personal number as optional data in case of TD3 style MRZ.
   * If the number does not yet include a check-digit it will be added.
   *
   * @param personalNumber the personal number (or optional data)
   *
   * @return the optional data to include in the MRZ
   */
  private static String personalNumberToOptionalData(String personalNumber) {
    if (personalNumber == null || equalsModuloFillerChars(personalNumber, "")) {
      /* optional data field is not used */
      return "";
    } else if (personalNumber.length() == 15) {
      /* it's either a personalNumber with check digit included, or some other optional data. FIXME: Is this case possible? */
      return personalNumber;
    } else if (personalNumber.length() <= 14) {
      /* we'll assume it's a personalNumber without check digit, and we add the check digit ourselves */
      return mrzFormat(personalNumber, 14);
    } else {
      throw new IllegalArgumentException("Wrong personal number: " + personalNumber);
    }
  }

  /**
   * Converts the name (primary and secondary identifier) to a single MRZ formatted name
   * field of the given length.
   *
   * @param primaryIdentifier the primary identifier part of the name
   * @param secondaryIdentifier the secondary identifier part of the name
   * @param width the width of the resulting MRZ formatted string
   *
   * @return the string containing the MRZ formatted name field
   */
  private static String nameToString(String primaryIdentifier, String secondaryIdentifier, int width) {
    String[] primaryComponents = primaryIdentifier.split(" |<");
    String[] secondaryComponents = secondaryIdentifier == null || secondaryIdentifier.trim().isEmpty() ? new String[0] : secondaryIdentifier.split(" |<");

    StringBuilder name = new StringBuilder();
    boolean isFirstPrimaryComponent = true;
    for (String primaryComponent: primaryComponents) {
      if (isFirstPrimaryComponent) {
        isFirstPrimaryComponent = false;
      } else {
        name.append('<');
      }
      name.append(primaryComponent);
    }

    if (secondaryIdentifier != null && !secondaryIdentifier.trim().isEmpty()) {
      name.append("<<");
      boolean isFirstSecondaryComponent = true;
      for (String secondaryComponent: secondaryComponents) {
        if (isFirstSecondaryComponent) {
          isFirstSecondaryComponent = false;
        } else {
          name.append('<');
        }
        name.append(secondaryComponent);
      }
    }

    return mrzFormat(name.toString(), width);
  }

  /**
   * Reads the issuing state as a three letter string.
   *
   * @param inputStream the stream to read from
   *
   * @return a string of length 3 containing an abbreviation
   *         of the issuing state or organization
   *
   * @throws IOException error reading from the stream
   */
  private static String readCountryCode(DataInputStream inputStream) throws IOException {
    return trimTrailingFillerChars(readString(inputStream, 3));
  }

  /**
   * Reads the 1 letter gender information.
   *
   * @param inputStream input source
   *
   * @return the gender of the passport holder
   *
   * @throws IOException if something goes wrong
   */
  private Gender readGender(DataInputStream inputStream) throws IOException {
    String genderStr = readString(inputStream, 1);
    if ("M".equalsIgnoreCase(genderStr)) {
      return Gender.MALE;
    }
    if ("F".equalsIgnoreCase(genderStr)) {
      return Gender.FEMALE;
    }
    return Gender.UNKNOWN;
  }

  /**
   * Reads a date.
   * Result is typically in {@code "yyMMdd"} format.
   *
   * @param inputStream the stream to read from
   *
   * @return the date of birth
   *
   * @throws IOException if something goes wrong
   * @throws NumberFormatException if a data could not be constructed
   */
  private String readDate(DataInputStream inputStream) throws IOException, NumberFormatException {
    return readString(inputStream, 6);
  }

  /**
   * Reads a fixed length string from a stream.
   *
   * @param inputStream the stream to read from
   * @param count the fixed length
   *
   * @return the string that was read
   *
   * @throws IOException on error reading from the stream
   */
  private static String readString(DataInputStream inputStream, int count) throws IOException {
    byte[] data = new byte[count];
    inputStream.readFully(data);
    return new String(data).trim();
  }

  /**
   * Returns the composite part over which the composite check digit is computed.
   *
   * @param documentType the type of document, either {@code DOC_TYPE_ID1} or {@code DOC_TYPE_ID3}
   *
   * @return a string with the composite part
   */
  private String getComposite(DocumentType documentType) {
    StringBuilder composite = new StringBuilder();
    int documentNumberLength = documentNumber.length();

    switch (documentType) {
      case TD1:
        /*
         * Upper line:
         * 6-30, i.e., documentNumber, documentNumberCheckDigit, optionaldata1(15)
         *
         * Middle line:
         * 1-7, i.e., dateOfBirth, dateOfBirthCheckDigit
         * 9-15, i.e., dateOfExpiry, dateOfExpiryCheckDigit
         * 19-29, i.e., optionalData2(11)
         */
        if (documentNumberLength <= 9) {
          composite.append(mrzFormat(documentNumber, 9));
          composite.append(documentNumberCheckDigit);
          composite.append(mrzFormat(optionalData1, 15));
        } else {
          /* Document number, first 9 characters. */
          composite.append(documentNumber.substring(0, 9));
          composite.append("<"); /* Filler instead of check digit. */

          /* Remainder of document number. */
          String documentNumberRemainder = documentNumber.substring(9);
          composite.append(documentNumberRemainder);
          composite.append(documentNumberCheckDigit);
          composite.append('<');

          /* Remainder of optional data 1 (removing any prefix). */
          String optionalData1Remainder = mrzFormat(optionalData1, 15 - 2 - documentNumberRemainder.length());
          composite.append(optionalData1Remainder);
        }
        composite.append(dateOfBirth);
        composite.append(dateOfBirthCheckDigit);
        composite.append(dateOfExpiry);
        composite.append(dateOfExpiryCheckDigit);
        composite.append(mrzFormat(optionalData2, 11));
        return composite.toString();
      case TD2:
        /* Composite check digit lower line: 1-10, 14-20, 22-35. */
        composite.append(documentNumber);
        composite.append(documentNumberCheckDigit);
        composite.append(dateOfBirth);
        composite.append(dateOfBirthCheckDigit);
        composite.append(dateOfExpiry);
        composite.append(dateOfExpiryCheckDigit);
        composite.append(mrzFormat(optionalData1, 7));
        return composite.toString();
      case MRVB:
        /* No composite checkdigit for MRV-B. */
        return null;
      case TD3:
        /* Composite check digit lower line: 1-10, 14-20, 22-43. */
        composite.append(mrzFormat(documentNumber, 9));
        composite.append(documentNumberCheckDigit);
        composite.append(dateOfBirth);
        composite.append(dateOfBirthCheckDigit);
        composite.append(dateOfExpiry);
        composite.append(dateOfExpiryCheckDigit);
        composite.append(mrzFormat(optionalData1, 14));
        composite.append(personalNumberCheckDigit);
        return composite.toString();
      case MRVA:
        /* No composite checkdigit for MRV-A. */
        return null;
      default:
        throw new IllegalStateException("Unsupported document type");
    }
  }

  /**
   * Updates the check digit fields for document number,
   * date of birth, date of expiry, and composite.
   */
  private void checkDigit() {
    this.documentNumberCheckDigit = checkDigit(documentNumber);
    this.dateOfBirthCheckDigit = checkDigit(dateOfBirth);
    this.dateOfExpiryCheckDigit = checkDigit(dateOfExpiry);

    if (documentType == DocumentType.TD3 && optionalData1.length() < 15) {
      this.personalNumberCheckDigit = checkDigit(mrzFormat(optionalData1, 14), true); /* FIXME: Uses '<' over '0'. Where specified? */
    }

    this.compositeCheckDigit = checkDigit(getComposite(documentType));
  }

  /**
   * Reformats the input string such that it
   * only contains ['A'-'Z'], ['0'-'9'], '<' characters
   * by replacing other characters with '<'.
   * Also extends to the given length by adding '<' to the right.
   *
   * @param str the input string
   * @param width the (minimal) width of the result
   *
   * @return the reformatted string
   */
  private static String mrzFormat(String str, int width) {
    if (str == null) {
      return "";
    }
    if (str.length() > width) {
      throw new IllegalArgumentException("Argument too wide (" + str.length() + " > " + width + ")");
    }
    str = str.toUpperCase().trim();
    StringBuilder result = new StringBuilder();
    for (int i = 0; i < str.length(); i++) {
      char c = str.charAt(i);
      if (MRZ_CHARS.indexOf(c) == -1) {
        result.append('<');
      } else {
        result.append(c);
      }
    }
    while (result.length() < width) {
      result.append("<");
    }
    return result.toString();
  }

  /**
   * Determines the document-type.
   *
   * @param documentCode the document-code
   * @param length the length of the complete MRZ (excluding whitespace)
   *
   * @return the document-type enum value
   */
  private static DocumentType getDocumentType(String documentCode, int length) {
    if (documentCode == null || documentCode.length() < 1 || documentCode.length() > 2) {
      throw new IllegalArgumentException("Was expecting 1 or 2 digit document code, got " + documentCode);
    }

    switch (length) {
      case 90:
        /* Document-code must start with C, I, or A. */
        return DocumentType.TD1;
      case 72:
        if (documentCode.startsWith("V")) {
          return DocumentType.MRVB;
        } else {
          /* Document-code must start with C, I, or A. */
          return DocumentType.TD2;
        }
      case 88:
        if (documentCode.startsWith("V")) {
          return DocumentType.MRVA;
        } else {
          /* Document-code must start with P. */
          return DocumentType.TD3;
        }
      default:
        return DocumentType.UNKNOWN;
    }
  }

  /*
   * NOTE: Can be removed once deprecated methods are gone.
   */
  /**
   * Determines the document type based on the document code (the first two characters of the MRZ).
   *
   * ICAO Doc 9303 part 3 vol 1 defines MRTDs with 3-line MRZs,
   * in this case the document code starts with "A", "C", or "I"
   * according to note j to Section 6.6 (page V-9).
   *
   * ICAO Doc 9303 part 2 defines MRVs with 2-line MRZs,
   * in this case the document code starts with "V".
   *
   * ICAO Doc 9303 part 1 vol 1 defines MRPs with 2-line MRZs,
   * in this case the document code starts with "P"
   * according to Section 9.6 (page IV-15).
   *
   * @param documentCode a two letter code
   *
   * @return a document type, one of {@link #DOC_TYPE_ID1}, {@link #DOC_TYPE_ID2},
   * 			{@link #DOC_TYPE_ID3}, or {@link #DOC_TYPE_UNSPECIFIED}
   */
  private static DocumentType getDocumentTypeFromDocumentCode(String documentCode) {
    if (documentCode.startsWith("A")
        || documentCode.startsWith("C")
        || documentCode.startsWith("I")) {
      /* MRTD according to ICAO Doc 9303 (seventh edition) part 5 or 6. NOTE: Could also be TD2. */
      return DocumentType.TD1;
    } else if (documentCode.startsWith("V")) {
      /* MRV according to ICAO Doc 9303 (old) part 2. NOTE: Could also be MRVA. */
      return DocumentType.MRVB;
    } else if (documentCode.startsWith("P")) {
      /* MRP according to ICAO Doc 9303 (old) part 1 vol 1 */
      return DocumentType.TD3;
    }
    return DocumentType.UNKNOWN;
  }

  /**
   * Replaces '<' with ' ' and trims leading and trailing whitespace.
   *
   * @param str the string to read from
   *
   * @return a trimmed string
   */
  private static String trimTrailingFillerChars(String str) {
    if (str == null) {
      str = "";
    }
    byte[] chars = str.trim().getBytes();
    for (int i = chars.length - 1; i >= 0; i--) {
      if (chars[i] == '<') {
        chars[i] = ' ';
      } else {
        break;
      }
    }
    return (new String(chars)).trim();
  }

  /**
   * Checks if the document-code is consistent with the given document-type.
   *
   * @param documentType the document-type
   * @param documentCode the document-code
   *
   * @return a boolean
   */
  private static boolean isDocumentCodeConsistentWithDocumentType(DocumentType documentType, String documentCode) {
    if (documentCode == null) {
      return false;
    }

    if (documentCode.length() != 1 && documentCode.length() != 2) {
      return false;
    }

    switch (documentType) {
      case TD1:
        /* Fall through... */
      case TD2:
        return documentCode.startsWith("C") || documentCode.startsWith("I") || documentCode.startsWith("A");
      case TD3:
        return documentCode.startsWith("P");
      case MRVA:
        /* Fall through... */
      case MRVB:
        return documentCode.startsWith("V");
      default:
          return false;
    }
  }

  /**
   * Checks if the optional data is consistent with the given document-type.
   *
   * @param documentType the document-type
   * @param optionalData1 optional data 1 or personal number
   * @param optionalData2 optional data 2 or {@code null} if not present
   *
   * @return a boolean
   */
  private static boolean isOptionalDataConsistentWithDocumentType(DocumentType documentType, String optionalData1, String optionalData2) {
    switch (documentType) {
      case TD1:
        return (optionalData1 == null || optionalData1.length() <= 15) && (optionalData2 == null || optionalData2.length() <= 11);
      case TD2:
        return (optionalData1 == null || optionalData1.length() <= 7) && optionalData2 == null;
      case MRVB:
        return (optionalData1 == null || optionalData1.length() <= 8) && optionalData2 == null;
      case TD3:
        return (optionalData1 == null || optionalData1.length() <= 15) && optionalData2 == null;
      case MRVA:
        return (optionalData1 == null || optionalData1.length() <= 16) && optionalData2 == null;
      default:
          return false;
    }
  }

  /**
   * Computes the 7-3-1 check digit for part of the MRZ.
   * If {@code preferFillerOverZero} is {@code true} then '<' will be
   * returned on check digit 0.
   *
   * @param str a part of the MRZ
   * @param preferFillerOverZero a boolean indicating whether fillers should be preferred
   *
   * @return the resulting check digit (in '0' - '9', '<')
   */
  private static char checkDigit(String str, boolean preferFillerOverZero) {
    try {
      byte[] chars = str == null ? new byte[] { } : str.getBytes("UTF-8");
      int[] weights = { 7, 3, 1 };
      int result = 0;
      for (int i = 0; i < chars.length; i++) {
        result = (result + weights[i % 3] * decodeMRZDigit(chars[i])) % 10;
      }
      String checkDigitString = Integer.toString(result);
      if (checkDigitString.length() != 1) {
        throw new IllegalStateException("Error in computing check digit."); /* NOTE: Never happens. */
      }
      char checkDigit = (char)checkDigitString.getBytes("UTF-8")[0];
      if (preferFillerOverZero && checkDigit == '0') {
        checkDigit = '<';
      }
      return checkDigit;
    } catch (NumberFormatException nfe) {
      /* NOTE: never happens. */
      throw new IllegalStateException("Error in computing check digit", nfe);
    } catch (UnsupportedEncodingException usee) {
      /* NOTE: never happens. */
      throw new IllegalStateException("Error in computing check digit", usee);
    } catch (Exception e) {
      throw new IllegalArgumentException("Error in computing check digit", e);
    }
  }

  /**
   * Looks up the numerical value for MRZ characters. In order to be able
   * to compute check digits.
   *
   * @param ch a character from the MRZ.
   *
   * @return the numerical value of the character.
   *
   * @throws NumberFormatException if {@code ch} is not a valid MRZ character
   */
  private static int decodeMRZDigit(byte ch) {
    switch (ch) {
      case '<':
      case '0':
        return 0;
      case '1':
        return 1;
      case '2':
        return 2;
      case '3':
        return 3;
      case '4':
        return 4;
      case '5':
        return 5;
      case '6':
        return 6;
      case '7':
        return 7;
      case '8':
        return 8;
      case '9':
        return 9;
      case 'a':
      case 'A':
        return 10;
      case 'b':
      case 'B':
        return 11;
      case 'c':
      case 'C':
        return 12;
      case 'd':
      case 'D':
        return 13;
      case 'e':
      case 'E':
        return 14;
      case 'f':
      case 'F':
        return 15;
      case 'g':
      case 'G':
        return 16;
      case 'h':
      case 'H':
        return 17;
      case 'i':
      case 'I':
        return 18;
      case 'j':
      case 'J':
        return 19;
      case 'k':
      case 'K':
        return 20;
      case 'l':
      case 'L':
        return 21;
      case 'm':
      case 'M':
        return 22;
      case 'n':
      case 'N':
        return 23;
      case 'o':
      case 'O':
        return 24;
      case 'p':
      case 'P':
        return 25;
      case 'q':
      case 'Q':
        return 26;
      case 'r':
      case 'R':
        return 27;
      case 's':
      case 'S':
        return 28;
      case 't':
      case 'T':
        return 29;
      case 'u':
      case 'U':
        return 30;
      case 'v':
      case 'V':
        return 31;
      case 'w':
      case 'W':
        return 32;
      case 'x':
      case 'X':
        return 33;
      case 'y':
      case 'Y':
        return 34;
      case 'z':
      case 'Z':
        return 35;
      default:
        throw new NumberFormatException("Could not decode MRZ character " + ch + " ('" + Character.toString((char) ch) + "')");
    }
  }
}
