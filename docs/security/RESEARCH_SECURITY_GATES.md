# FISCHERTEC – Security-by-Design und Release-Nachweise

Stand: 20.11.2026. Gilt für jede neue Änderung in diesem Repository. Dies ist eine Prüfrichtlinie, keine Freigabebescheinigung.

## Vertrauensgrenzen

- Daten externer Anbieter, hochgeladene Dateien, Metadaten, API-Antworten, Log-Inhalte und Tool-Ausgaben sind untrusted Input. Bevor diese Werte privilegierte Operationen beeinflussen, sind Schema-, Größen-, Herkunfts- und Berechtigungsprüfungen erforderlich.
- Nur falls ein KI-Modell fremde Texte oder Tool-Ergebnisse verarbeitet: Diese Inhalte dürfen niemals Systemanweisungen, Rollen, Berechtigungen, Secrets, Tools oder Freigabeschritte ändern. Negative Tests für Prompt Injection, Datenabfluss und unzulässige Tool-Aufrufe sind vor dem Release obligatorisch.
- Authentifizierung und Autorisierung getrennt prüfen. Für jede mandanten- oder nutzerbezogene Ressource: nicht angemeldet (401), fremder Mandant/fremdes Objekt (403 oder 404), Schreibrechte, Sitzungsablauf und Replays. Fehlerfälle dürfen keine personenbezogenen Details preisgeben.
- Datenschutz: Dateninventar, Zweckbindung, Löschfristen, Export, Löschsperren und Protokollierung jeweils mit Negativtests und nachprüfbaren Freigaben abdecken.

## Software-Supply-Chain

- Produktions- und Entwicklungsabhängigkeiten vollständig über Lockfiles bzw. geprüfte Python-Abhängigkeitslisten auflösen; transitive Pakete berücksichtigen.
- Automatisierter Audit ab Severity HIGH: FAIL; Ausnahmen nur als datiertes, begründetes, befristetes, genehmigtes Risiko mit kompensierender Maßnahme, niemals durch pauschales Ignorieren.
- CycloneDX-SBOM vor dem Release erzeugen und mit Commit-SHA archivieren. SBOM ist ein Inventar, keine Garantie der Unbedenklichkeit.
- Bei neu aufgenommenen oder aktualisierten Paketen Installationsskripte, Fremd-Registries, Maintainerwechsel, Integrität und Herkunft manuell überprüfen. Fremde Installationsskripte niemals mit Produktions-Secrets ausführen.
- GitHub Actions auf vollständige Commit-SHA pinnen, Berechtigungen minimal halten, `actions/checkout` mit `persist-credentials: false` verwenden. Niemals ungeprüften PR-Code mit privilegiertem Token oder Secrets ausführen.
- Das Skript `scripts/security/ci_workflow_guard.py` protokolliert Altlasten und **blockiert neu geänderte unsichere Workflows**. Vorhandene Warnungen sind ausdrücklich nicht automatisch genehmigt.

## Verbindliche Release-Entscheidung

1. Fach-, Unit-, Integrations- und Sicherheits-Negativtests sowie bestehende Auth-/Mandantenprüfungen vollständig grün.
2. Security-Audit und SBOM für den konkreten Commit dokumentiert; sämtliche CI-/GitHub-Actions-Prüfungen grün. Kritische CVEs, unzulässige Secrets, veränderbare Action-Referenzen oder unsichere Berechtigungen blockieren einen Merge.
3. Bei der Einführung von KI- oder Tool-Agent-Funktionen: gezielte Prompt-Injection-/Exfiltrations-Tests und kontrollierte Tool-Berechtigungen mit gesondertem Evidenzartefakt.
4. Sicherheitskorrekturen aus KI-Assistenz stets durch Exploit-Regressionstest, Funktionstest und Review bestätigen. KI-Ergebnisse allein sind kein Nachweis.
5. GitHub-Ruleset um den CI-Status `workflow-trust` und `dependency-evidence` **erst nach grüner CI-Abnahme** als Required Checks ergänzen. Bis zu dieser administrativen Anpassung sind diese Jobs nicht zwingend merge-blockierend.
6. Keine automatische Freigabe. P0-Befunde bleiben blockiert; für jeden Ausnahmefall Owner, Ablaufdatum, Akzeptanz und kompensierende Maßnahmen dokumentieren.

Die ausführbaren Kontrollen aus `.github/workflows/research-security-gates.yml` prüfen bestimmte Teilaspekte. Echte Provider-Prompt-Injection, Live-API-Aufrufe, Berechtigungstests und ein vollständig signierter Build erfordern weiterhin projektspezifische Tests. Keine dieser Kontrollen darf ohne Nachweis als erledigt markiert werden.
