namespace AgentGuard.Pii;

/// <summary>
/// Well-known PII entity type identifiers, for use with <see cref="PiiOptions.Entities"/>, the
/// per-entity <see cref="PiiOptions.Operators"/> map, and detection results. These are plain
/// <c>string</c> constants (not an enum) because the entity-type vocabulary is open: custom
/// recognizers and the optional NER add-on can introduce their own types, and the value flows as a
/// string through detection, anonymization, structured/batch results, and configuration. Use these
/// for discoverability and typo-safety; a custom string is always still valid.
/// </summary>
public static class PiiEntities
{
    // generic recognizers (always on)

    /// <summary>A payment card number (Luhn-validated).</summary>
    public const string CreditCard = "CREDIT_CARD";

    /// <summary>An email address (FQDN-checked).</summary>
    public const string EmailAddress = "EMAIL_ADDRESS";

    /// <summary>An International Bank Account Number (mod-97 validated).</summary>
    public const string IbanCode = "IBAN_CODE";

    /// <summary>A cryptocurrency address (base58 double-SHA256 or bech32/bech32m).</summary>
    public const string Crypto = "CRYPTO";

    /// <summary>An IPv4 or IPv6 address.</summary>
    public const string IpAddress = "IP_ADDRESS";

    /// <summary>A URL.</summary>
    public const string Url = "URL";

    /// <summary>A MAC (hardware) address.</summary>
    public const string MacAddress = "MAC_ADDRESS";

    /// <summary>A phone number (parsed via libphonenumber).</summary>
    public const string PhoneNumber = "PHONE_NUMBER";

    // United States pack (always on)

    /// <summary>US Social Security Number.</summary>
    public const string UsSsn = "US_SSN";

    /// <summary>US Individual Taxpayer Identification Number.</summary>
    public const string UsItin = "US_ITIN";

    /// <summary>US ABA bank routing number (checksum-validated).</summary>
    public const string AbaRoutingNumber = "ABA_ROUTING_NUMBER";

    /// <summary>US bank account number.</summary>
    public const string UsBankNumber = "US_BANK_NUMBER";

    /// <summary>US driver's license number.</summary>
    public const string UsDriverLicense = "US_DRIVER_LICENSE";

    /// <summary>US passport number.</summary>
    public const string UsPassport = "US_PASSPORT";

    /// <summary>US National Provider Identifier (Luhn-validated).</summary>
    public const string UsNpi = "US_NPI";

    /// <summary>US Medicare Beneficiary Identifier.</summary>
    public const string UsMbi = "US_MBI";

    /// <summary>US DEA / medical license number (checksum-validated).</summary>
    public const string MedicalLicense = "MEDICAL_LICENSE";

    // United Kingdom pack (opt-in via PiiCountries.Uk)

    /// <summary>UK National Insurance Number.</summary>
    public const string UkNino = "UK_NINO";

    /// <summary>UK NHS number (mod-11 validated).</summary>
    public const string UkNhs = "UK_NHS";

    /// <summary>UK postcode.</summary>
    public const string UkPostcode = "UK_POSTCODE";

    /// <summary>UK passport number.</summary>
    public const string UkPassport = "UK_PASSPORT";

    /// <summary>UK driving licence number.</summary>
    public const string UkDrivingLicence = "UK_DRIVING_LICENCE";

    /// <summary>UK vehicle registration plate.</summary>
    public const string UkVehicleRegistration = "UK_VEHICLE_REGISTRATION";

    // Germany pack (opt-in via PiiCountries.De)

    /// <summary>German national identity card number (ICAO check digit).</summary>
    public const string DeIdCard = "DE_ID_CARD";

    /// <summary>German tax identification number (ISO-7064 validated).</summary>
    public const string DeTaxId = "DE_TAX_ID";

    /// <summary>German passport number (ICAO check digit).</summary>
    public const string DePassport = "DE_PASSPORT";

    /// <summary>German postal code (PLZ).</summary>
    public const string DePlz = "DE_PLZ";

    /// <summary>German social security number.</summary>
    public const string DeSocialSecurity = "DE_SOCIAL_SECURITY";

    /// <summary>German VAT identification number (ISO-7064, non-strict).</summary>
    public const string DeVatId = "DE_VAT_ID";

    /// <summary>German driving licence number (Führerschein).</summary>
    public const string DeFuehrerschein = "DE_FUEHRERSCHEIN";

    /// <summary>German vehicle registration plate (Kfz-Kennzeichen).</summary>
    public const string DeKfz = "DE_KFZ";

    /// <summary>German tax number (Steuernummer).</summary>
    public const string DeTaxNumber = "DE_TAX_NUMBER";

    /// <summary>German commercial register number (Handelsregisternummer).</summary>
    public const string DeHandelsregister = "DE_HANDELSREGISTER";

    // India pack (opt-in via PiiCountries.In)

    /// <summary>Indian Aadhaar number (Verhoeff-validated).</summary>
    public const string InAadhaar = "IN_AADHAAR";

    /// <summary>Indian Permanent Account Number.</summary>
    public const string InPan = "IN_PAN";

    /// <summary>Indian GST identification number.</summary>
    public const string InGstin = "IN_GSTIN";

    /// <summary>Indian passport number.</summary>
    public const string InPassport = "IN_PASSPORT";

    /// <summary>Indian voter ID (EPIC) number.</summary>
    public const string InVoter = "IN_VOTER";

    /// <summary>Indian vehicle registration number.</summary>
    public const string InVehicleRegistration = "IN_VEHICLE_REGISTRATION";

    // Italy pack (opt-in via PiiCountries.It)

    /// <summary>Italian fiscal code (Codice Fiscale).</summary>
    public const string ItFiscalCode = "IT_FISCAL_CODE";

    /// <summary>Italian VAT code (Partita IVA).</summary>
    public const string ItVatCode = "IT_VAT_CODE";

    /// <summary>Italian driver's license number.</summary>
    public const string ItDriverLicense = "IT_DRIVER_LICENSE";

    /// <summary>Italian identity card number.</summary>
    public const string ItIdentityCard = "IT_IDENTITY_CARD";

    /// <summary>Italian passport number.</summary>
    public const string ItPassport = "IT_PASSPORT";

    // Spain pack (opt-in via PiiCountries.Es)

    /// <summary>Spanish NIF / DNI national ID (mod-23 validated).</summary>
    public const string EsNif = "ES_NIF";

    /// <summary>Spanish NIE foreigner ID (mod-23 validated).</summary>
    public const string EsNie = "ES_NIE";

    /// <summary>Spanish passport number.</summary>
    public const string EsPassport = "ES_PASSPORT";

    // named-entity recognition (optional ONNX add-on - see RedactPiiWithNer)

    /// <summary>A person's name. Detected only by the optional GLiNER NER add-on.</summary>
    public const string Person = "PERSON";

    /// <summary>A location or place. Detected only by the optional GLiNER NER add-on.</summary>
    public const string Location = "LOCATION";

    /// <summary>An organization or company. Detected only by the optional GLiNER NER add-on.</summary>
    public const string Organization = "ORGANIZATION";

    /// <summary>A date or time expression. Detected only by the optional GLiNER NER add-on.</summary>
    public const string DateTime = "DATE_TIME";
}
