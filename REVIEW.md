# Revue du projet

## Aperçu général
- Projet : **Borgmatic API for Nextcloud AIO**
- Objectif : fournir une API REST sécurisée pour piloter Borgmatic et Nextcloud AIO, avec diffusion SSE.
- Stack principale : Python (Flask), Gunicorn, Docker.

## Points forts
1. **Sécurité prise en compte** :
   - Validation stricte des commandes `docker exec` avec liste blanche et blocage explicite des shells/commandes dangereuses.
   - Double authentification via en-tête `X-From-NodeRed` + token Bearer distinct lecture/écriture.
   - Garde-fou imposant des passphrases distinctes pour Borg et SSH.
2. **Fonctionnalités avancées pour Borgmatic** :
   - Suivi temps réel via SSE et poll, tampons thread-safe avec GC.
   - Gestion complète : création d'archives, dry-run, extract, check, prune, mount, etc.
   - Outils pour inspecter les configurations (redaction, validation, vérification du format spécifique Nextcloud AIO).
3. **Déploiement simplifié** :
   - Dockerfile basé sur l’image officielle Borgmatic, entrypoint robuste qui prépare l’environnement.
   - Exemple docker-compose détaillé (volumes, sécurité, variables d’environnement).

## Points d’attention / risques
1. **Monolithe de plus de 1200 lignes** dans `borgmatic_api.py`, ce qui complique la maintenance, les tests unitaires et la contribution extérieure.
2. **Absence de tests automatisés et de CI/CD** : difficile de garantir la non-régression et la qualité continue.
3. **Gestion du rate limiting en mémoire de processus** :
   - Implémentation simple basée sur un `defaultdict` global non protégé par verrou ; sous Gunicorn multi-threads cela peut introduire des conditions de course mineures.
   - Limites non persistantes : un redémarrage ou un worker supplémentaire réinitialise l’état.
4. **Sécurité Docker** :
   - Le montage du socket Docker (`/var/run/docker.sock`) reste sensible ; l’usage d’un proxy dédié est prévu mais mériterait une documentation renforcée sur la configuration recommandée.
5. **Gestion des secrets** : le README mentionne la génération de tokens, mais aucun mécanisme n’impose leur présence (valeur vide par défaut) ; prévoir un démarrage bloquant si les tokens ne sont pas configurés.
6. **Manque de supervision/observabilité** : pas de métriques Prometheus ni de logs structurés pour suivre l’activité ou les erreurs côté API.

## Recommandations
1. **Refactoriser en modules** (`auth.py`, `borgmatic.py`, `docker.py`, `routes/`) pour alléger le fichier principal et faciliter les tests.
2. **Ajouter une suite de tests** (unitaires + intégration) et un workflow CI GitHub pour exécuter linting (flake8/ruff), formatage (black) et tests.
3. **Sécuriser davantage la configuration** :
   - Rendre obligatoires `API_TOKEN`/`API_READ_TOKEN` au démarrage (erreur si valeurs vides).
   - Documenter un mode socket-proxy par défaut dans docker-compose pour éviter l’accès direct au socket Docker.
4. **Améliorer le rate limiting** : remplacer par une solution thread-safe (ex : `collections.deque` protégée par verrou) ou un middleware dédié (Redis, Flask-Limiter) pour gérer plusieurs workers.
5. **Observabilité** : ajouter un endpoint de métriques ou au minimum des logs JSON pour exploitation par des outils externes.
6. **Documentation** :
   - Corriger quelques coquilles (ex. commande `bashcurl` dans README) et préciser les dépendances Python côté développement.
   - Ajouter un schéma d’architecture et des scénarios d’usage Node-RED.

## Conclusion
Le projet offre une couverture fonctionnelle riche pour piloter Borgmatic/Nextcloud AIO avec des garde-fous pertinents. Une phase d’industrialisation (modularisation, tests, observabilité, documentation) permettrait d’assurer sa maintenabilité et sa sécurité dans la durée.
