# NetSentinel IDS

NetSentinel IDS je prototipni sistem za demonstracijo zaznavanja omrežnih
groženj. Uporablja C++ zaledje, REST/WebSocket API in PyQt grafični vmesnik.

## Lokalni demonstracijski zagon

Zahteve:

- Windows 10/11
- Python 3.10 ali novejši
- CMake in C++ razvojno okolje
- Npcap za zajem dejanskega prometa
- prevedeno zaledje v mapi `build`

Namestitev Python odvisnosti:

```powershell
.\.venv\Scripts\python.exe -m pip install -r .\gui\requirements.txt
```

Prevajanje:

```powershell
cmake -S . -B build -DNPCAP_SDK_DIR=C:\dev\npcap-sdk-1.16
cmake --build build --config Release
```

Zagon:

```powershell
.\RUN_FULL.bat
```

Za varno zapiranje lokalne demonstracije uporabi gumb **Izhod** v glavnem
oknu. Ta ustavi zaledje, zapre grafični vmesnik in omogoči zaprtje zagonskih
konzol.

## Omejitve

Projekt je namenjen lokalni demonstraciji in diplomski predstavitvi. Ne
predstavlja produkcijsko pripravljenega sistema za zaščito omrežij. Odzivi so
demonstracijski in ne spreminjajo pravil sistemskega požarnega zidu.

Podrobnejša slovenska navodila so v [README_SLO.md](README_SLO.md).
