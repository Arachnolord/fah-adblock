# Hilfsprogramme für Erweiterungen

Optionale Go-Programme, die eine Erweiterung unter `src/erweiterungen/<name>/` als Kindprozess startet.
Jeder Unterordner mit `go.mod` wird beim Docker-Bau übersetzt und landet als `/app/bin/<ordner>-bruecke` im Image.
Ohne Unterordner bleibt alles wie gehabt.
