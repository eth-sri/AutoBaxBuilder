import os

import pandas as pd
import requests
from bs4 import BeautifulSoup

from agent.config import MITRE_TOP_25, args, logger


def fetch_cwe_info(cwe_id: int):
    """Fetches CWE information from MITRE's website."""
    url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        return {"error": f"Failed to fetch CWE-{cwe_id}: {str(e)}"}

    soup = BeautifulSoup(response.text, "html.parser")

    name_elem = soup.find("h2")
    name = name_elem.text.split(":")[1].strip() if name_elem else "Name not found"

    desc_div = soup.find("div", id="Description")
    if desc_div:
        desc = desc_div.find("td")  # type: ignore
        description = (
            " ".join(desc.text.split("\n")).strip() if desc else "Description not found"
        )
    else:
        description = "Description not found"

    alternate_term_div = soup.find("div", id="Alternate_Terms")
    if alternate_term_div:
        alternate_terms = alternate_term_div.find_all("td", class_="subheading")  # type: ignore
        alternate_terms = [term.text.strip() for term in alternate_terms]
    else:
        alternate_terms = []

    return {
        "cwe_id": cwe_id,
        "name": name,
        "description": description,
        "alternate_terms": ", ".join(alternate_terms),
    }


def save_to_csv(data: list, save_path: str) -> None:
    """Save CWE data to a CSV file.

    Args:
        data: List of dictionaries containing CWE information
        save_path: Path where the CSV file should be saved
    """
    df = pd.DataFrame(data)
    df.set_index("cwe_id", inplace=True)

    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    df.to_csv(save_path)
    logger.info(f"Saved {len(data)} CWE entries to {save_path}")


def fetch_cwes(cwe_ids: list = MITRE_TOP_25) -> None:
    """Fetch and save CWE information for multiple CWE IDs."""
    if os.path.exists(os.path.join(args.path, "cwe_db.csv")):
        pass
    else:
        results = []
        for cwe_id in cwe_ids:
            info = fetch_cwe_info(cwe_id)

            if "error" in info:
                logger.error(f"Encountered error when fetching CWE-{cwe_id}")
                continue
            results.append(info)

        if results:
            save_to_csv(results, os.path.join(args.path, "cwe_db.csv"))
