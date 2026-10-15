"""Which law to cite, what the deadline is, and who to escalate to.

This is data, not legal advice. Keep it current with PRs; each entry is small.
"""

from __future__ import annotations

from dataclasses import dataclass, field

US_STATE_NAMES = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California",
    "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware", "DC": "District of Columbia",
    "FL": "Florida", "GA": "Georgia", "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois",
    "IN": "Indiana", "IA": "Iowa", "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana",
    "ME": "Maine", "MD": "Maryland", "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota",
    "MS": "Mississippi", "MO": "Missouri", "MT": "Montana", "NE": "Nebraska", "NV": "Nevada",
    "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico", "NY": "New York",
    "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma", "OR": "Oregon",
    "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina", "SD": "South Dakota",
    "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont", "VA": "Virginia",
    "WA": "Washington", "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming",
    "PR": "Puerto Rico",
}

# States with a comprehensive consumer privacy law that grants a right to delete.
# (act name, code citation, in force from)
US_STATE_LAWS: dict[str, tuple[str, str, str]] = {
    "CA": ("California Consumer Privacy Act, as amended by the CPRA", "Cal. Civ. Code § 1798.100 et seq.", "2020-01-01"),
    "VA": ("Virginia Consumer Data Protection Act", "Va. Code § 59.1-575 et seq.", "2023-01-01"),
    "CO": ("Colorado Privacy Act", "C.R.S. § 6-1-1301 et seq.", "2023-07-01"),
    "CT": ("Connecticut Data Privacy Act", "Conn. Gen. Stat. § 42-515 et seq.", "2023-07-01"),
    "UT": ("Utah Consumer Privacy Act", "Utah Code § 13-61-101 et seq.", "2023-12-31"),
    "TX": ("Texas Data Privacy and Security Act", "Tex. Bus. & Com. Code ch. 541", "2024-07-01"),
    "OR": ("Oregon Consumer Privacy Act", "ORS 646A.570 et seq.", "2024-07-01"),
    "MT": ("Montana Consumer Data Privacy Act", "Mont. Code Ann. § 30-14-2801 et seq.", "2024-10-01"),
    "IA": ("Iowa Consumer Data Protection Act", "Iowa Code ch. 715D", "2025-01-01"),
    "DE": ("Delaware Personal Data Privacy Act", "Del. Code tit. 6, ch. 12D", "2025-01-01"),
    "NH": ("New Hampshire Privacy Act", "N.H. Rev. Stat. ch. 507-H", "2025-01-01"),
    "NJ": ("New Jersey Data Privacy Act", "N.J. Stat. § 56:8-166.4 et seq.", "2025-01-15"),
    "NE": ("Nebraska Data Privacy Act", "Neb. Rev. Stat. § 87-1101 et seq.", "2025-01-01"),
    "TN": ("Tennessee Information Protection Act", "Tenn. Code Ann. § 47-18-3201 et seq.", "2025-07-01"),
    "MN": ("Minnesota Consumer Data Privacy Act", "Minn. Stat. § 325M.10 et seq.", "2025-07-31"),
    "MD": ("Maryland Online Data Privacy Act", "Md. Code, Com. Law § 14-4601 et seq.", "2025-10-01"),
    "IN": ("Indiana Consumer Data Protection Act", "Ind. Code art. 24-15", "2026-01-01"),
    "KY": ("Kentucky Consumer Data Protection Act", "Ky. Rev. Stat. § 367.3611 et seq.", "2026-01-01"),
    "RI": ("Rhode Island Data Transparency and Privacy Protection Act", "R.I. Gen. Laws ch. 6-48.1", "2026-01-01"),
}

EU_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT",
    "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
    # EEA members apply the GDPR too.
    "IS", "LI", "NO",
}

# National data protection authorities (complaint landing pages).
EU_DPAS: dict[str, tuple[str, str]] = {
    "AT": ("Datenschutzbehörde", "https://www.dsb.gv.at"),
    "BE": ("Autorité de protection des données / Gegevensbeschermingsautoriteit", "https://www.dataprotectionauthority.be"),
    "DE": ("your state's Landesdatenschutzbehörde (or the BfDI)", "https://www.bfdi.bund.de"),
    "DK": ("Datatilsynet", "https://www.datatilsynet.dk"),
    "ES": ("Agencia Española de Protección de Datos (AEPD)", "https://www.aepd.es"),
    "FI": ("Office of the Data Protection Ombudsman", "https://tietosuoja.fi"),
    "FR": ("Commission nationale de l'informatique et des libertés (CNIL)", "https://www.cnil.fr/fr/plaintes"),
    "IE": ("Data Protection Commission", "https://www.dataprotection.ie"),
    "IT": ("Garante per la protezione dei dati personali", "https://www.garanteprivacy.it"),
    "NL": ("Autoriteit Persoonsgegevens", "https://autoriteitpersoonsgegevens.nl"),
    "NO": ("Datatilsynet", "https://www.datatilsynet.no"),
    "PL": ("Urząd Ochrony Danych Osobowych (UODO)", "https://uodo.gov.pl"),
    "PT": ("Comissão Nacional de Proteção de Dados (CNPD)", "https://www.cnpd.pt"),
    "SE": ("Integritetsskyddsmyndigheten (IMY)", "https://www.imy.se"),
}
EDPB_MEMBERS_URL = "https://www.edpb.europa.eu/about-edpb/about-edpb/members_en"

CANADA_PROVINCES = {
    "AB": "Alberta", "BC": "British Columbia", "MB": "Manitoba", "NB": "New Brunswick",
    "NL": "Newfoundland and Labrador", "NS": "Nova Scotia", "NT": "Northwest Territories",
    "NU": "Nunavut", "ON": "Ontario", "PE": "Prince Edward Island", "QC": "Quebec",
    "SK": "Saskatchewan", "YT": "Yukon",
}

AU_STATES = {
    "ACT": "Australian Capital Territory", "NSW": "New South Wales", "NT": "Northern Territory",
    "QLD": "Queensland", "SA": "South Australia", "TAS": "Tasmania", "VIC": "Victoria",
    "WA": "Western Australia",
}

COUNTRY_NAMES = {
    "US": "United States", "GB": "United Kingdom", "CA": "Canada", "AU": "Australia",
    "AT": "Austria", "BE": "Belgium", "BG": "Bulgaria", "HR": "Croatia", "CY": "Cyprus",
    "CZ": "Czechia", "DK": "Denmark", "EE": "Estonia", "FI": "Finland", "FR": "France",
    "DE": "Germany", "GR": "Greece", "HU": "Hungary", "IE": "Ireland", "IT": "Italy",
    "LV": "Latvia", "LT": "Lithuania", "LU": "Luxembourg", "MT": "Malta", "NL": "Netherlands",
    "PL": "Poland", "PT": "Portugal", "RO": "Romania", "SK": "Slovakia", "SI": "Slovenia",
    "ES": "Spain", "SE": "Sweden", "IS": "Iceland", "LI": "Liechtenstein", "NO": "Norway",
}


@dataclass(frozen=True)
class Regulator:
    name: str
    url: str


@dataclass(frozen=True)
class Law:
    key: str  # letter template family
    short: str  # e.g. "CCPA"
    title: str  # full act name
    citation: str
    deadline_days: int
    extension_days: int
    regulators: tuple[Regulator, ...]
    region_label: str
    template: str
    extra: dict[str, str] = field(default_factory=dict)


def regions_for_country(country: str) -> dict[str, str]:
    country = (country or "").upper()
    if country == "US":
        return US_STATE_NAMES
    if country == "CA":
        return CANADA_PROVINCES
    if country == "AU":
        return AU_STATES
    return {}


def resolve_law(country: str, region: str | None = None) -> Law:
    country = (country or "US").upper()
    region = (region or "").upper() or None

    if country == "US":
        state_name = US_STATE_NAMES.get(region or "", "")
        if region == "CA":
            return Law(
                key="us_ca", short="CCPA", title=US_STATE_LAWS["CA"][0], citation=US_STATE_LAWS["CA"][1],
                deadline_days=45, extension_days=45,
                regulators=(
                    Regulator("California Privacy Protection Agency", "https://cppa.ca.gov/webapplications/complaint"),
                    Regulator("California Attorney General", "https://oag.ca.gov/contact/consumer-complaint-against-business-or-company"),
                ),
                region_label="California", template="us_ccpa",
            )
        if region in US_STATE_LAWS:
            act, cite, _ = US_STATE_LAWS[region]
            return Law(
                key="us_state", short=act, title=act, citation=cite,
                deadline_days=45, extension_days=45,
                regulators=(Regulator(f"{state_name} Attorney General", "https://www.naag.org/find-my-ag/"),),
                region_label=state_name, template="us_state",
            )
        return Law(
            key="us_none", short="Consumer request", title="", citation="",
            deadline_days=45, extension_days=0,
            regulators=(
                Regulator("Federal Trade Commission", "https://reportfraud.ftc.gov/"),
                Regulator(f"{state_name or 'your state'} Attorney General", "https://www.naag.org/find-my-ag/"),
            ),
            region_label=state_name or "United States", template="us_generic",
        )

    if country in EU_COUNTRIES:
        dpa_name, dpa_url = EU_DPAS.get(country, ("your national data protection authority", EDPB_MEMBERS_URL))
        return Law(
            key="gdpr", short="GDPR", title="General Data Protection Regulation (EU) 2016/679",
            citation="Regulation (EU) 2016/679", deadline_days=30, extension_days=60,
            regulators=(Regulator(dpa_name, dpa_url),),
            region_label=COUNTRY_NAMES.get(country, country), template="gdpr",
        )

    if country == "GB":
        return Law(
            key="uk_gdpr", short="UK GDPR", title="UK General Data Protection Regulation and Data Protection Act 2018",
            citation="UK GDPR; Data Protection Act 2018", deadline_days=30, extension_days=60,
            regulators=(Regulator("Information Commissioner's Office (ICO)", "https://ico.org.uk/make-a-complaint/"),),
            region_label="United Kingdom", template="gdpr",
            extra={"uk": "1"},
        )

    if country == "CA":
        if region == "QC":
            return Law(
                key="quebec", short="Law 25",
                title="Act respecting the protection of personal information in the private sector (as amended by Law 25)",
                citation="CQLR c. P-39.1", deadline_days=30, extension_days=0,
                regulators=(
                    Regulator("Commission d'accès à l'information du Québec", "https://www.cai.gouv.qc.ca"),
                    Regulator("Office of the Privacy Commissioner of Canada", "https://www.priv.gc.ca/en/report-a-concern/"),
                ),
                region_label="Quebec", template="canada", extra={"quebec": "1"},
            )
        return Law(
            key="pipeda", short="PIPEDA",
            title="Personal Information Protection and Electronic Documents Act",
            citation="S.C. 2000, c. 5", deadline_days=30, extension_days=30,
            regulators=(Regulator("Office of the Privacy Commissioner of Canada", "https://www.priv.gc.ca/en/report-a-concern/"),),
            region_label=CANADA_PROVINCES.get(region or "", "Canada"), template="canada",
        )

    if country == "AU":
        return Law(
            key="au_privacy", short="Privacy Act 1988", title="Privacy Act 1988 (Cth) and the Australian Privacy Principles",
            citation="Privacy Act 1988 (Cth)", deadline_days=30, extension_days=0,
            regulators=(Regulator("Office of the Australian Information Commissioner (OAIC)", "https://www.oaic.gov.au/privacy/privacy-complaints"),),
            region_label=AU_STATES.get(region or "", "Australia"), template="australia",
        )

    # Anywhere else: send a polite request with no statutory citation.
    return Law(
        key="generic", short="Privacy request", title="", citation="", deadline_days=30, extension_days=0,
        regulators=(), region_label=COUNTRY_NAMES.get(country, country), template="us_generic",
    )


def supports_drop(country: str, region: str | None) -> bool:
    """California's Delete Request and Opt-out Platform (one request -> every registered broker)."""
    return (country or "").upper() == "US" and (region or "").upper() == "CA"


DROP_URL = "https://consumer.drop.privacy.ca.gov"


def broker_serves(broker_regions: list[str], country: str) -> bool:
    country = (country or "").upper()
    if not broker_regions or "*" in broker_regions:
        return True
    if country in broker_regions:
        return True
    if "EU" in broker_regions and country in EU_COUNTRIES:
        return True
    if "UK" in broker_regions and country == "GB":
        return True
    return False
