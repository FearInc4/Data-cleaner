"""One-time actions that cut spam and exposure, by country. Progress is stored in settings."""

from __future__ import annotations

from dataclasses import dataclass

from ..jurisdictions import EU_COUNTRIES


@dataclass(frozen=True)
class Item:
    id: str
    category: str  # calls, texts, email, mail, credit, search, accounts
    title: str
    url: str | None
    why: str
    countries: tuple[str, ...] = ("*",)
    states: tuple[str, ...] = ()


ITEMS: list[Item] = [
    # --- California DROP ---
    Item("ca-drop", "search", "Use California's DROP to reach every registered broker at once",
         "https://consumer.drop.privacy.ca.gov",
         "One verified request goes to every registered data broker, and they must re-check it every 45 days. Data Cleaner still handles unregistered sites.",
         ("US",), ("CA",)),
    # --- Search engines ---
    Item("google-rays", "search", "Turn on Google 'Results about you'", "https://myactivity.google.com/results-about-you",
         "Google monitors search results for your phone, email and address and lets you request removal."),
    Item("bing-removal", "search", "Bing content removal", "https://www.bing.com/webmaster/tools/contentremoval",
         "Request removal of outdated results after a broker deletes a page."),
    # --- Calls & texts ---
    Item("us-dnc", "calls", "Register on the National Do Not Call Registry", "https://www.donotcall.gov",
         "Legitimate telemarketers must stop calling after 31 days, and later calls become reportable violations.", ("US",)),
    Item("us-report", "calls", "Report illegal calls to the FTC", "https://reportfraud.ftc.gov",
         "Reports feed the public complaint data this app uses to build blocklists.", ("US",)),
    Item("us-7726", "texts", "Forward spam texts to 7726 (SPAM)", None,
         "Carriers use these reports to block senders network-wide. Works on AT&T, Verizon, T-Mobile and most MVNOs.", ("US", "CA", "GB")),
    Item("carrier-tools", "calls", "Turn on your carrier's free spam blocking", None,
         "AT&T ActiveArmor, Verizon Call Filter, T-Mobile Scam Shield and US Cellular Call Guard all have free tiers that block likely fraud.", ("US",)),
    Item("phone-settings", "calls", "Silence unknown callers / enable call screening", None,
         "iPhone: Settings → Phone → Silence Unknown Callers (or Screen Unknown Callers). Android/Pixel: Phone → Settings → Spam and Call Screen."),
    Item("port-pin", "accounts", "Set a carrier port-out PIN / number lock", None,
         "Stops SIM-swap attackers moving your number. This matters most if your phone number appears in breaches."),
    Item("ca-dncl", "calls", "Register on Canada's National Do Not Call List", "https://lnnte-dncl.gc.ca", "", ("CA",)),
    Item("uk-tps", "calls", "Register with the Telephone Preference Service (TPS)", "https://www.tpsonline.org.uk", "", ("GB",)),
    Item("uk-mps", "mail", "Register with the Mailing Preference Service (MPS)", "https://www.mpsonline.org.uk", "", ("GB",)),
    Item("uk-open-register", "search", "Opt out of the open electoral register", "https://www.gov.uk/electoral-register/opt-out-of-the-open-register",
         "192.com and other UK people-search sites buy the open register.", ("GB",)),
    Item("au-dnc", "calls", "Register on Australia's Do Not Call Register", "https://www.donotcall.gov.au", "", ("AU",)),
    Item("fr-bloctel", "calls", "Register with Bloctel", "https://www.bloctel.gouv.fr", "", ("FR",)),
    Item("de-robinson", "mail", "Join the Robinsonliste", "https://www.robinsonliste.de", "", ("DE", "AT")),
    Item("es-lista-robinson", "calls", "Join the Lista Robinson", "https://www.listarobinson.es", "", ("ES",)),
    Item("it-rpo", "calls", "Register with the Registro Pubblico delle Opposizioni", "https://www.registrodelleopposizioni.it", "", ("IT",)),
    Item("eu-object", "email", "Object to direct marketing (Art. 21 GDPR)", None,
         "Any company emailing you marketing must stop when you object. Data Cleaner's GDPR letters include this.", tuple(sorted(EU_COUNTRIES)) + ("GB",)),
    # --- Mail ---
    Item("us-prescreen", "mail", "Opt out of prescreened credit and insurance offers", "https://www.optoutprescreen.com",
         "Five years online, or permanent by mailing the signed form. Cuts junk mail and identity-theft risk from stolen offers.", ("US",)),
    Item("us-dmachoice", "mail", "DMAchoice (direct mail)", "https://www.dmachoice.org", "Small fee; covers most member mailers.", ("US",)),
    Item("us-catalogchoice", "mail", "CatalogChoice", "https://www.catalogchoice.org", "Free catalog cancellations.", ("US",)),
    Item("us-valpak", "mail", "Remove your address from Valpak", "https://www.valpak.com/remove-address", "", ("US",)),
    # --- Credit / identity ---
    Item("us-freeze", "credit", "Freeze your credit (free)", "https://www.consumerfinance.gov/consumer-tools/credit-reports-and-scores/",
         "Freeze at Equifax, Experian, TransUnion, plus Innovis and ChexSystems. Unfreeze temporarily when you need credit.", ("US",)),
    Item("us-ippin", "credit", "Get an IRS Identity Protection PIN", "https://www.irs.gov/identity-theft-fraud-scams/get-an-identity-protection-pin",
         "Blocks fraudulent tax returns filed with your SSN.", ("US",)),
    # --- Email hygiene ---
    Item("aliases", "email", "Use a unique email alias per site", "https://simplelogin.io",
         "SimpleLogin and addy.io are open source and self-hostable. When a site leaks or sells your address, kill that alias."),
    Item("unsubscribe", "email", "Run the inbox unsubscribe helper", "/spam#unsubscribe",
         "Data Cleaner finds senders with standard unsubscribe headers and unsubscribes in one click."),
]


def items_for(country: str, region: str | None) -> list[Item]:
    country = (country or "").upper()
    region = (region or "").upper()
    out = []
    for item in ITEMS:
        if "*" not in item.countries and country not in item.countries:
            continue
        if item.states and region not in item.states:
            continue
        out.append(item)
    return out
