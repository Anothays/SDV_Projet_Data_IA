"""Point d'entrée : lance le pipeline ANSSI/CVE (étapes 1 à 4)."""

from anssi_cve.pipeline import run


def main():
    run()


if __name__ == "__main__":
    main()
