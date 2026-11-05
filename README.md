# NetSentinel IDS

Prototip sistema za zaznavanje in obravnavo omrežnih groženj za lokalno
demonstracijo v okviru diplomske naloge.

## Vsebina

- C++ zaledje za zajem in obdelavo omrežnih tokov,
- REST in WebSocket komunikacija,
- PyQt grafični vmesnik,
- prikaz alarmov, tokov in analitike,
- PostgreSQL arhiviranje incidentov,
- lokalni demonstracijski odzivi.

## Zahteve

- Windows 10 ali 11,
- Python 3.10 ali novejši,
- CMake in C++ razvojno okolje,
- Npcap SDK,
- PostgreSQL samo za prikaz arhiviranja incidentov.

## Namestitev in zagon

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\gui\requirements.txt
cmake -S . -B build -DNPCAP_SDK_DIR=C:\dev\npcap-sdk-1.16
cmake --build build --config Release
.\RUN_FULL.bat
```

Zaganjalnik uporabi simulator dogodkov, zato za prikaz ni potreben dejanski
napad. Za zajem prometa v živo mora biti nameščen Npcap.

## PostgreSQL

PostgreSQL je izbiren. Nastavitve ustvari iz `.env.example` in jih shrani v
lokalno datoteko `.env.local`, ki se ne objavi na GitHubu.

```powershell
psql -h localhost -p 5432 -U postgres -d postgres -f .\scripts\postgres_demo_setup.sql
.\RUN_DB_CHECK.bat
```

## Preverjanje

```powershell
.\.venv\Scripts\python.exe -m compileall -q gui setup_infrastructure.py
```

Za varno zapiranje uporabi gumb **Izhod** v glavnem oknu. Odzivni modul je
demonstracijski in ne spreminja pravil sistemskega požarnega zidu.

Diplomska naloga in dispozicija sta v mapi `docs/`.
