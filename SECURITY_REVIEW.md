# Security Hardening - Review Document

## Résumé des changements

Ce document résume le durcissement sécurité apporté à `borgmatic-api-nextcloud-aio` pour isoler Node-RED des opérations dangereuses.

---

## 1. Architecture de tokens à 3 rôles

### Fichiers modifiés
- `borgmatic_api_app/config.py`
- `borgmatic_api_app/auth.py`

### Changements

| Token | Rôle | Accès |
|-------|------|-------|
| `API_ADMIN_TOKEN` | `TokenRole.ADMIN` | Accès complet : admin, config, locks, passphrase, actions |
| `API_ACTION_TOKEN` | `TokenRole.ACTION` | Actions prédéfinies uniquement + lecture |
| `API_READ_TOKEN` | `TokenRole.READ` | Statut, health, polling jobs, logs |

### Décorateurs ajoutés (`auth.py`)

```python
@require_role(TokenRole.ADMIN)           # Admin uniquement
@require_role(TokenRole.ADMIN, TokenRole.ACTION)  # Admin ou Action
@require_role(TokenRole.READ, TokenRole.ADMIN)    # Read ou Admin
@require_admin()   # Shortcut ADMIN
@require_action()  # Shortcut ACTION + ADMIN
@require_read()    # Shortcut READ + ADMIN
```

### Compatibilité rétro
- Mode legacy (`SECURE_MODE=false`): `API_TOKEN` agit comme admin (comportement existant préservé)
- Mode sécurisé (`SECURE_MODE=true`): exige `API_ADMIN_TOKEN` + `API_ACTION_TOKEN` + `API_READ_TOKEN`

---

## 2. Système d'actions prédéfinies

### Fichiers créés
- `borgmatic_api_app/actions.py` — `ActionStore`, `ActionPolicy`, validation stricte
- `borgmatic_api_app/routes/actions.py` — Endpoints `/actions/*`
- `actions-policy.example.yaml` — Exemple de fichier de politiques

### Fonctionnement

1. Les actions sont définies dans un fichier YAML (`ACTIONS_POLICY_PATH`)
2. Chaque action a des paramètres figés (repo, timeouts, flags)
3. Node-RED appelle `POST /actions/<name>/run` sans fournir de paramètres sensibles
4. Validation stricte au chargement : noms alphanumériques, types autorisés, URLs SSH valides

### Endpoints nouveaux

| Endpoint | Méthode | Rôle requis | Description |
|----------|---------|-------------|-------------|
| `/actions` | GET | READ+ | Liste les actions disponibles |
| `/actions/<name>` | GET | READ+ | Détails d'une action (cible masquée) |
| `/actions/<name>/run` | POST | ACTION+ | Exécute l'action (sync) |
| `/actions/<name>/run/async` | POST | ACTION+ | Exécute l'action (async SSE) |

### Protection
- `target_display` masque les credentials dans les réponses (ex: `ssh://***:22/...`)
- Le payload Node-RED ne contient ni repo, ni config, ni paramètres sensibles
- Types d'action autorisés : `nextcloud_aio_backup` uniquement

---

## 3. Flags de sécurité ENABLE_*

### Fichiers modifiés
- `borgmatic_api_app/config.py` — 5 flags ajoutés
- `borgmatic_api_app/routes/legacy.py` — `_check_security_flag()` + appels

### Flags

| Flag | Défaut | Contrôle |
|------|--------|----------|
| `ENABLE_ADMIN_ENDPOINTS` | `true` | `/emergency/shutdown` |
| `ENABLE_CONFIG_WRITE` | `true` | `/configs/*` PUT/DELETE, `/nextcloud/backup-target` POST |
| `ENABLE_BREAK_LOCK` | `true` | `/borgmatic-locks/break/*`, `/borgmatic-locks/emergency-break-all` |
| `ENABLE_PASSPHRASE_CHANGE` | `true` | `/repositories/*/passphrase/change` |
| `ENABLE_ARBITRARY_TARGETS` | `true` | `/nextcloud/daily-backup/run-for-target*`, `/nextcloud/backup-target` POST |

### Endpoints protégés

| Endpoint | Flag(s) |
|----------|---------|
| `/emergency/shutdown` POST | `enable_admin_endpoints` |
| `/configs/<label>` PUT | `enable_config_write` |
| `/configs/<label>` DELETE | `enable_config_write` |
| `/nextcloud/backup-target` POST | `enable_config_write` + `enable_arbitrary_targets` |
| `/nextcloud/daily-backup/run-for-target` POST | `enable_arbitrary_targets` |
| `/nextcloud/daily-backup/run-for-target/async` POST | `enable_arbitrary_targets` |
| `/borgmatic-locks/break/<label>` POST | `enable_break_lock` |
| `/borgmatic-locks/emergency-break-all` POST | `enable_break_lock` |
| `/repositories/<label>/passphrase/change` POST | `enable_passphrase_change` |

---

## 4. Audit log structuré

### Fichier créé
- `borgmatic_api_app/audit.py` — `AuditLogger`

### Fonctionnalités
- Logs JSON, une entrée par ligne
- Événements : `action_start`, `action_complete`, `action_fail`
- Champs : `action_name`, `source_ip`, `token_role`, `job_id`, `target_repo`, `result`, `exit_code`, `duration_sec`
- Destination : fichier (`AUDIT_LOG_PATH`) et/ou stdout (`AUDIT_STDOUT`)

---

## 5. Intégration

### Fichiers modifiés
- `borgmatic_api_app/services.py` — Ajout `actions_store`, `audit_logger`, `executor`
- `borgmatic_api_app/app.py` — Initialisation ActionStore + AuditLogger + blueprint actions

---

## 6. Configuration

### Variables d'environnement nouvelles

```bash
SECURE_MODE=false
API_ADMIN_TOKEN=change-me-admin
API_ACTION_TOKEN=change-me-action
API_READ_TOKEN=change-me-read
ENABLE_ADMIN_ENDPOINTS=true
ENABLE_CONFIG_WRITE=true
ENABLE_BREAK_LOCK=true
ENABLE_PASSPHRASE_CHANGE=true
ENABLE_ARBITRARY_TARGETS=true
ACTIONS_POLICY_PATH=/etc/borgmatic-api/allowed_actions.yaml
AUDIT_LOG_PATH=
AUDIT_STDOUT=true
```

---

## Scénario d'usage recommandé

### Configuration Node-RED

```bash
# Node-RED reçoit UNIQUEMENT :
API_ACTION_TOKEN=xxx    # Pour déclencher des actions
API_READ_TOKEN=yyy      # Pour poller le statut
```

### Workflow Node-RED

```
Node-RED
  -> POST /actions/nextcloud-backup-happy/run/async
     (token: API_ACTION_TOKEN)
  -> Réponse: { job_id, sse_url, poll_url }
  -> GET /events/poll/{job_id}
     (token: API_READ_TOKEN)
  -> Attend { event: "success" | "fail" }
```

### Surface d'attaque si Node-RED est compromis

| Avec API_ACTION_TOKEN | Possible |
|-----------------------|----------|
| Déclencher une action prédéfinie | ✅ Oui |
| Changer la cible de sauvegarde | ❌ Non |
| Casser un lock Borg | ❌ Non |
| Changer une passphrase | ❌ Non |
| Modifier une config | ❌ Non |
| Emergency shutdown | ❌ Non |
| Lire le statut / poll jobs | ✅ Oui (si API_READ_TOKEN aussi) |

---

## Tests unitaires

### Fichier créé
- `tests/test_security.py`

### Couverture
- Config : SECURE_MODE validation, mode legacy
- Auth : tokens admin/action/read, header invalide
- Actions : validation policy, noms, types, URLs SSH, masquage credentials
- Audit : écriture stdout, écriture fichier

---

## Fichiers modifiés/créés

| Fichier | Statut |
|---------|--------|
| `borgmatic_api_app/config.py` | Modifié |
| `borgmatic_api_app/auth.py` | Modifié |
| `borgmatic_api_app/actions.py` | **Créé** |
| `borgmatic_api_app/audit.py` | **Créé** |
| `borgmatic_api_app/routes/actions.py` | **Créé** |
| `borgmatic_api_app/routes/legacy.py` | Modifié |
| `borgmatic_api_app/services.py` | Modifié |
| `borgmatic_api_app/app.py` | Modifié |
| `tests/test_security.py` | **Créé** |
| `.env.example` | Modifié |
| `actions-policy.example.yaml` | **Créé** |
| `SECURITY_REVIEW.md` | **Créé** |

---

## Points d'attention pour l'audit

1. **Migration progressive** : Le mode legacy est préservé par défaut (`SECURE_MODE=false`). Les utilisateurs existants ne sont pas impactés.

2. **Activation du mode sécurisé** : Requiert `SECURE_MODE=true` + les 3 tokens. L'API refuse de démarrer si un token est manquant en mode sécurisé.

3. **Dépendance circulaire** : `services.py` utilise `TYPE_CHECKING` pour importer `ActionStore` et `AuditLogger` et éviter les imports circulaires.

4. **Thread pool** : Un `ThreadPoolExecutor(max_workers=4)` est créé dans `app.py` pour l'exécution async des actions.

5. **Compatibilité backward** : Les endpoints legacy continuent de fonctionner avec `_require_auth()` (mode legacy). Les nouveaux endpoints `/actions/*` utilisent `@require_action()`.