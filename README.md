# Warum ich dich liebe ❤️

Eine kleine, moderne Liebes-Webseite für Sara, Spitzname Dîlemin.

## Lokal öffnen

Du brauchst keine Installation.

1. Öffne den Ordner `sara`.
2. Öffne `index.html` direkt im Browser.
3. Für Safari auf dem iPhone kannst du den Ordner auch per GitHub Pages veröffentlichen.

## GitHub Pages Anleitung

1. Lade den Ordner `sara` in dein GitHub-Repository hoch.
2. Gehe auf GitHub zu `Settings`.
3. Öffne `Pages`.
4. Wähle bei `Build and deployment` die Quelle `Deploy from a branch`.
5. Wähle deinen Branch, zum Beispiel `main`.
6. Wenn die Dateien im Ordner `sara` liegen, wähle als Ordner `/sara`, falls GitHub diese Option anbietet. Sonst verschiebe `index.html`, `style.css`, `script.js` und optional `song.mp3` in den Hauptordner des Repos.
7. Speichern und kurz warten, bis GitHub Pages den Link anzeigt.

## Eigene Musik einfügen

1. Lege deine Musikdatei in diesen Ordner.
2. Benenne sie genau `song.mp3`.
3. Die Musik startet erst, wenn jemand auf den Button `musik 🎵` drückt.
4. Wenn `song.mp3` fehlt, bleibt die Seite trotzdem funktionsfähig.

## Songtitel ändern

Öffne `script.js` und ändere ganz oben diese Zeile:

```js
const songTitle = "HIER SONG EINTRAGEN";
```

Beispiel:

```js
const songTitle = "TV Girl - Lovers Rock";
```

Der Songtitel erscheint automatisch unter dem Musikbutton.

## Texte ändern

Öffne `script.js`. Ganz oben findest du den Bereich:

```js
HIER KANNST DU ALLES ÄNDERN
```

Dort kannst du ändern:

- Name
- Spitzname
- Startdatum
- Liebessätze
- schönste Momente
- finale Nachricht
- Mini-Texte
- Songtitel

Neue Liebessätze fügst du in `loveReasons` ein:

```js
"dein neuer satz",
```

Neue Erinnerungen fügst du in `bestMoments` ein:

```js
"deine neue erinnerung",
```

## Dateien hochladen

Für die fertige Webseite brauchst du diese Dateien:

- `index.html`
- `style.css`
- `script.js`
- `README.md`
- optional `song.mp3`

Alles funktioniert ohne Frameworks, ohne Libraries, ohne Backend und ohne APIs.
