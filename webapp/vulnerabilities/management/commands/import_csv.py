"""Commande ``import_csv`` : charge ``data/consolidated.csv`` dans SQLite.

Réutilise ``anssi_cve.config.OUTPUT_CSV`` (pipeline étapes 1-4) pour localiser le
CSV. Le nettoyage reproduit la logique défensive du notebook (étape 5) : scores
numériques bornés, date typée, sentinelle « Non disponible » conservée côté texte.

Schéma normalisé : une ligne CSV = un couple (bulletin × CVE). On déduplique les
CVE (par ``cve_id``) et les bulletins (par ``id_anssi``), puis on recrée les liens
Many-to-Many. Idempotent : la commande vide les tables avant de recharger.

Usage : ``uv run python webapp/manage.py import_csv [--csv CHEMIN]``.
"""

from pathlib import Path

import pandas as pd
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from anssi_cve import config
from vulnerabilities.models import Bulletin, Cve

# Colonnes texte : on conserve les valeurs telles quelles (sentinelle incluse).
TEXT_COLUMNS = [
    "titre_anssi",
    "type_bulletin",
    "base_severity",
    "type_cwe",
    "editeur",
    "produit",
    "versions_affectees",
    "lien_bulletin",
    "description",
]


class Command(BaseCommand):
    help = "Importe data/consolidated.csv dans la base SQLite (tables Cve + Bulletin)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--csv",
            type=str,
            default=str(config.OUTPUT_CSV),
            help="Chemin du CSV consolidé (défaut : anssi_cve.config.OUTPUT_CSV).",
        )

    def handle(self, *args, **options):
        csv_path = Path(options["csv"])
        if not csv_path.exists():
            raise CommandError(
                f"CSV introuvable : {csv_path}. Lance d'abord le pipeline "
                "(`uv run python -m anssi_cve.pipeline`)."
            )

        self.stdout.write(f"Lecture de {csv_path} …")
        df = self._load_and_clean(csv_path)
        self.stdout.write(
            f"  {len(df)} lignes nettoyées | "
            f"{df['cve_id'].nunique()} CVE | {df['id_anssi'].nunique()} bulletins"
        )

        with transaction.atomic():
            self._reset_tables()
            self._import_cves(df)
            self._import_bulletins(df)
            n_links = self._import_links(df)

        self.stdout.write(
            self.style.SUCCESS(
                f"Import terminé : {Cve.objects.count()} CVE, "
                f"{Bulletin.objects.count()} bulletins, {n_links} liens."
            )
        )

    # ------------------------------------------------------------------ étapes

    def _load_and_clean(self, csv_path: Path) -> pd.DataFrame:
        """Charge le CSV et applique le nettoyage défensif (cf. notebook étape 5)."""
        df = pd.read_csv(csv_path, dtype=str)
        df = df.drop_duplicates().reset_index(drop=True)

        # Scores → numériques, valeurs non convertibles en NaN, bornés par sécurité.
        df["score_cvss"] = pd.to_numeric(df["score_cvss"], errors="coerce").clip(0, 10)
        df["score_epss"] = pd.to_numeric(df["score_epss"], errors="coerce").clip(0, 1)

        # Date → datetime aware (USE_TZ=True) ; non parsable → NaT.
        df["date_publication"] = pd.to_datetime(
            df["date_publication"], errors="coerce", utc=True
        )

        # Texte : pas de NaN résiduel, espaces parasites retirés (faux doublons).
        for col in TEXT_COLUMNS:
            df[col] = df[col].fillna("").astype(str).str.strip()

        return df

    def _reset_tables(self) -> None:
        """Vide les tables pour un import idempotent (les liens M2M tombent en cascade)."""
        Bulletin.objects.all().delete()
        Cve.objects.all().delete()

    def _import_cves(self, df: pd.DataFrame) -> None:
        """Crée une ligne Cve par ``cve_id`` distinct (1ʳᵉ occurrence)."""
        unique = df.drop_duplicates("cve_id")
        objs = [
            Cve(
                cve_id=row.cve_id,
                score_cvss=_num(row.score_cvss),
                base_severity=row.base_severity,
                type_cwe=row.type_cwe,
                score_epss=_num(row.score_epss),
                description=row.description,
                editeur=row.editeur,
                produit=row.produit,
                versions_affectees=row.versions_affectees,
            )
            for row in unique.itertuples(index=False)
        ]
        Cve.objects.bulk_create(objs, batch_size=2000)

    def _import_bulletins(self, df: pd.DataFrame) -> None:
        """Crée une ligne Bulletin par ``id_anssi`` distinct."""
        unique = df.drop_duplicates("id_anssi")
        objs = [
            Bulletin(
                id_anssi=row.id_anssi,
                titre_anssi=row.titre_anssi,
                type_bulletin=row.type_bulletin,
                date_publication=_dt(row.date_publication),
                lien_bulletin=row.lien_bulletin,
            )
            for row in unique.itertuples(index=False)
        ]
        Bulletin.objects.bulk_create(objs, batch_size=2000)

    def _import_links(self, df: pd.DataFrame) -> int:
        """Recrée les liens Bulletin↔CVE depuis les couples distincts du CSV."""
        cve_pk = dict(Cve.objects.values_list("cve_id", "pk"))
        bulletin_pk = dict(Bulletin.objects.values_list("id_anssi", "pk"))
        through = Bulletin.cves.through

        pairs = df[["id_anssi", "cve_id"]].drop_duplicates()
        links = [
            through(bulletin_id=bulletin_pk[id_anssi], cve_id=cve_pk[cve_id])
            for id_anssi, cve_id in pairs.itertuples(index=False, name=None)
        ]
        through.objects.bulk_create(links, batch_size=5000, ignore_conflicts=True)
        return len(links)


def _num(value) -> float | None:
    """Convertit une valeur pandas en float ou ``None`` (NaN → None)."""
    return None if pd.isna(value) else float(value)


def _dt(value):
    """Convertit un Timestamp pandas en datetime Python, ``None`` si NaT."""
    return None if pd.isna(value) else value.to_pydatetime()
