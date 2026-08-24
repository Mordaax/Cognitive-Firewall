"""Case-scoped HMAC lookup and AES-GCM encrypted reversible mapping."""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import func, select

from cognitive_firewall.storage.db import Database, MappingRow


class SqlMappingStore:
    def __init__(self, db: Database, *, encryption_key: bytes, hmac_key: bytes):
        if len(encryption_key) != 32 or len(hmac_key) < 32:
            raise ValueError(
                "mapping keys must be at least 32 bytes; encryption key must be exactly 32 bytes"
            )
        self.db = db
        self._aead = AESGCM(encryption_key)
        self._hmac_key = hmac_key

    def _digest(self, case_id: str, category: str, value: str) -> str:
        message = f"{case_id}\0{category}\0{value}".encode("utf-8")
        return hmac.new(self._hmac_key, message, hashlib.sha256).hexdigest()

    def get_or_create(self, case_id: str, category: str, normalized_value: str) -> str:
        digest = self._digest(case_id, category, normalized_value)
        with self.db.session() as session:
            existing = session.scalar(
                select(MappingRow).where(
                    MappingRow.case_id == case_id,
                    MappingRow.category == category,
                    MappingRow.digest == digest,
                )
            )
            if existing is not None:
                return existing.token
            count = (
                session.scalar(
                    select(func.count())
                    .select_from(MappingRow)
                    .where(MappingRow.case_id == case_id, MappingRow.category == category)
                )
                or 0
            )
            case_tag = (
                hmac.new(self._hmac_key, case_id.encode(), hashlib.sha256).hexdigest()[:6].upper()
            )
            token = f"{category.upper()}_{case_tag}_{count + 1:02}"
            nonce = os.urandom(12)
            associated = f"{case_id}\0{category}\0{digest}".encode()
            ciphertext = self._aead.encrypt(nonce, normalized_value.encode(), associated)
            session.add(
                MappingRow(
                    id=uuid.uuid4().hex,
                    case_id=case_id,
                    category=category,
                    digest=digest,
                    token=token,
                    nonce=nonce,
                    ciphertext=ciphertext,
                )
            )
            session.commit()
            return token

    def reidentify(self, case_id: str, token: str) -> str:
        with self.db.session() as session:
            row = session.scalar(
                select(MappingRow).where(MappingRow.case_id == case_id, MappingRow.token == token)
            )
            if row is None:
                raise KeyError("mapping not found")
            associated = f"{row.case_id}\0{row.category}\0{row.digest}".encode()
            return self._aead.decrypt(row.nonce, row.ciphertext, associated).decode()
