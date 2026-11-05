# NetSentinel IDS

NetSentinel IDS je diplomski projekt za demonstracijo sistema za zaznavanje omreznih grozenj. Projekt zdruzuje C++ backend za zajem oziroma obdelavo tokov, REST/WebSocket API, PyQt namizni vmesnik, analitiko, demonstracijske odzive in izbirno PostgreSQL arhiviranje.

Kratek sklep: projekt je primeren za diplomski prikaz kot raziskovalno-inženirski prototip. Ni dokazano produkcijsko pripravljen sistem. Najbolj prepričljiv del je integracija zaledja, API-ja, grafičnega vmesnika, testnih tokov, odzivnega modula in PostgreSQL-arhiviranja incidentov. Odzivi so demonstracijski in ne spreminjajo pravil požarnega zidu.

## Kaj projekt dokazuje

- C++ backend lahko izpostavi REST API in WebSocket kanal za stanje, tokove, alarme in konfiguracijo.
- GUI prikazuje stanje sistema, tokove, alarme, analitiko, nastavitve in demonstracijske odzive.
- Demonstracijski način uporablja sintetični simulator napadov, zato je ponovljiv tudi brez realnega omrežnega napada.
- Če je na voljo Npcap, se hkrati obdeluje tudi dejanski lokalni promet. Zaključeni nesimulirani tokovi so prikazani kot nizko tveganje; zaradi omejitve se nizko-tveganjski alarm ustvari največ enkrat na 10 sekund.
- Zagon lahko ponovljivo prikaže zajem paketov ali simulirane omrežne dogodke.
- Analitični prikazi so namenjeni demonstraciji prototipa, zato jih ni smiselno posploševati kot produkcijsko varnostno zagotovilo.

## Kaj projekt ne dokazuje

- Ne dokazuje produkcijske varnosti, visoke razpolozljivosti ali skladnosti.
- `ResponseEngine` ne spreminja dejanskih firewall pravil; blokade, izolacije in rate-limit akcije so logirani oziroma interni demo odzivi.
- C++ `PostgreSQLArchiver` realno pise incidente v PostgreSQL, kadar je backend zgrajen z `libpq`, je baza dosegljiva in je `POSTGRES_ENABLED=1`. Python `PostgreSQLManager` podpira realen PostgreSQL za analitiko, ce je okolje pravilno konfigurirano.

## Zahteve

Priporoceno okolje za demo:

- Windows 10/11
- Pythonovo virtualno okolje v korenu projekta
- Python 3.10 ali novejsi
- Npcap za live capture na Windows
- CMake 3.18+
- Boost.System in Npcap SDK za C++ build na Windows
- PostgreSQL 16 ali novejsi, ce zelis prikazati arhiviranje incidentov

Python odvisnosti:

```powershell
.\.venv\Scripts\python.exe -m pip install -r .\gui\requirements.txt
```

## Preverjanje

Sintakticni pregled Python kode:

```powershell
.\.venv\Scripts\python.exe -m compileall -q gui setup_infrastructure.py
```

Pregled opcijske infrastrukture in baze:

```powershell
.\.venv\Scripts\python.exe .\setup_infrastructure.py
```

Opomba: repozitorij trenutno nima avtomatiziranih testov pytest. Zato pri zagovoru ne navajaj pokritosti s testi, razen če jih dodaš pred oddajo.

## Zagon demonstracijskega načina

Najstabilnejša pot za zagovor je demonstracija s simulatorjem:

```powershell
.\RUN_FULL.bat
```

Za prikaz brez simulatorja v `.env.local` nastavi `NETSENTINEL_SIMULATE_ATTACKS=0`. Npcap mora biti nameščen, izbrana naprava pa mora biti dosegljiva; sicer se backend brez simulatorja ustavi z napako inicializacije zajema.

V nastavitvah omrežnega vmesnika `Samodejno` izbere aktiven Wi-Fi ali Ethernet vmesnik. Vrednost `wlan0` izbere Wi-Fi, `eth0` oziroma `eth1` pa Ethernet. Izbira se shrani v `.env.local` in začne veljati ob naslednjem zagonu zaledja; zagnan zajem se ne preklopi med delovanjem.

V zavihku **Alarmi** je na voljo incidentni zapisnik. Zapisnik se shrani v uporabniški profil Windows (`%LOCALAPPDATA%\NetSentinelIDS\incident_journal.json`) in vsebuje tudi ročne spremembe statusa alarma.

Izbrani alarm lahko z gumbom **Pošlji v avtomatizacijo** pošlješ v odzivni modul. Uspešen odziv visoko- ali kritično-tveganega alarma ga označi kot `ACKNOWLEDGED`, uspešen odziv nizko-tveganega alarma pa kot `RESOLVED`; rezultat se zabeleži v incidentnem zapisniku. Odzivni modul uporablja varne demonstracijske izvedbe in ne spreminja sistemskega požarnega zidu.

Avtomatizacija je ob zagonu v **ročnem načinu**. V zavihku **Avtomatizacija** jo lahko s stikalom preklopiš v **samodejni način**, kjer se novi alarmi obdelajo samodejno. V ročnem načinu se obdelajo samo alarmi, ki jih operater pošlje z gumbom v zavihku **Alarmi**.

Skripta pričakuje prevedeno zaledje C++ v eni od poti:

- `build_check_thesis_vcpkg\Release\NetSentinelIDS.exe`
- `build\Debug\NetSentinelIDS.exe`
- `build\Release\NetSentinelIDS.exe`
- `build\NetSentinelIDS.exe`

Če zaledje še ni prevedeno:

```powershell
cmake -S . -B build -DNPCAP_SDK_DIR=C:\dev\npcap-sdk-1.16
cmake --build build --config Release
```

Na tem računalniku `CMakeLists.txt` sam uporabi `C:\dev\vcpkg\scripts\buildsystems\vcpkg.cmake`, če je prisoten. Če CMake javi napako zaradi Boost, preveri vcpkg oziroma namesti Boost.System. To ni napaka koncepta diplomske naloge, ampak manjkajoča sistemska razvojna odvisnost.

## PostgreSQL demo

Za podatkovni del projekta je najčistejši prikaz tabela `incidents`, v katero zaledje C++ zapisuje vsak peti simulirani napad. Lokalna datoteka `.env.local` ni del repozitorija; za uporabo PostgreSQL jo ustvari iz `.env.example`.

```text
host=localhost
port=5432
database=netsentinel_db
user=netsentinel_user
password=admin
```

Ce lokalni PostgreSQL servis ze obstaja in ima drugo geslo, popravi uporabnika/bazo s superuser racunom:

```powershell
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" -h localhost -p 5432 -U postgres -d postgres -f .\scripts\postgres_demo_setup.sql
```

Nato preveri:

```powershell
.\.venv\Scripts\python.exe .\setup_infrastructure.py
```

Lahko uporabis tudi:

```powershell
.\RUN_DB_CHECK.bat
```

Za demonstracijo NetSentinel v pgAdminu uporabi lokalno konfiguriranega uporabnika in bazo. Gesel ne zapisuj v repozitorij ali dokumentacijo.

## Pomembni endpointi

- `GET /api/status`
- `GET /api/config`
- `POST /api/config`
- `GET /api/alerts`
- `GET /api/alerts/history`
- `POST /api/alerts/{id}/acknowledge`
- `POST /api/alerts/{id}/resolve`
- `GET /api/flows`
- `GET /api/statistics`
- `POST /api/shutdown` (lokalni varen izhod za demonstracijo)
- `WS /ws`

## Zapiranje demonstracije

Za zapiranje celotne lokalne demonstracije uporabi gumb **Izhod** v glavnem oknu.
Gumb najprej zahteva ustavitev C++ zaledja, nato zapre grafični vmesnik. Zagonska
skripta uporablja `cmd /c`, zato se po koncu procesov zapreta tudi pripadajoči
konzoli.

## Priporocena formulacija za zagovor

"NetSentinel IDS je prototipni sistem, ki demonstrira celoten tok od zajema oziroma simulacije omreznega dogodka, preko API komunikacije in vizualizacije, do lokalnega odzivnega mehanizma. Sistem ni predstavljen kot produkcijski IDS, ampak kot preverljiv diplomski prototip z jasno locenimi realnimi, simuliranimi in eksperimentalnimi deli."

Dodatno gradivo:

- diplomska naloga in dispozicija sta v mapi `docs/`
- izvorna koda je razdeljena na `src/`, `include/`, `gui/` in `scripts/`
