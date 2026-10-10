# DNS Test

Natywna, polskojęzyczna aplikacja desktopowa do porównywania serwerów DNS w swojej sieci. Docelowy system: **Windows 11 x64**.

## Pobieranie

Gotowy **`dns_test_v1.1.0.exe`** jest w [Releases](https://github.com/donald7373/dns-test/releases/latest).

Do uruchomienia wystarczy jeden plik EXE. Nie instalujesz Pythona ani Qt. Aplikacja ma własne okno — nie otwiera przeglądarki, nie uruchamia serwera HTTP ani okna konsoli. Nie wymaga administratora i **nie zmienia systemowych ustawień DNS**.

Archiwum `dns_test_windows_v1.1.0.zip` dodatkowo zawiera instrukcję, kod, przepis odbudowy i informacje o licencjach bibliotek. Sprawdź SHA256 pobranego EXE względem pliku `.sha256` z tego samego wydania.

## Funkcje

- Wybór i dodawanie własnych serwerów DNS; do 32 serwerów IPv4/IPv6.
- Rzeczywiste zapytania UDP/53 i przejście na TCP po obciętej odpowiedzi.
- Pomiar A/AAAA, konfigurowalne domeny, rozgrzewka, liczba prób i timeout.
- Natywne wykresy rysowane przez QPainter, ranking i aktualizacja wyników podczas testu.
- Mediana, średnia, P95, minimum, maksimum, jitter i skuteczność odpowiedzi.
- Błędy i timeouty nie są traktowane jako udane, szybkie odpowiedzi.
- Rekomendacje po zakończeniu pomiaru, z uwzględnieniem skuteczności.
- Zatrzymywanie testu, eksport CSV UTF-8 BOM, import/eksport konfiguracji JSON i zapamiętywanie ustawień.
- Odczyt DNS-ów systemowych wykonywany poza wątkiem interfejsu.

## Jak używać

1. Uruchom EXE dwuklikiem.
2. Zaznacz DNS-y lub dodaj własne adresy.
3. Wybierz domeny i parametry pomiaru.
4. Rozpocznij test i porównaj ranking oraz wykresy.
5. Zapisz wyniki CSV. Ewentualną zmianę ustawień DNS wykonujesz samodzielnie w systemie.

Wyniki zależą od Twojej sieci, domen, cache resolverów i obciążenia serwerów. To klasyczny DNS — nie DoH/DoT, test DNSSEC ani ocena prywatności dostawcy. Wpisane domeny są wysyłane do zaznaczonych DNS-ów.

## Stan weryfikacji i bezpieczeństwo

Wersja 1.1.0 została zbudowana jako rzeczywisty Windows PE32+ x86-64, w trybie GUI/onefile/windowed, bez UPX, przy użyciu Windows Python 3.13.12, PyInstaller 6.20.0 i PySide6-Essentials/shiboken6 6.8.3.

- **19 testów** silnika i interfejsu przeszło pod Windowsowym Pythonem w Wine.
- Rzeczywisty EXE uruchomiono osobno, w katalogu zawierającym wyłącznie ten EXE.
- Sprawdzono natywne okno Qt (`windows`), wykresy, ranking, rekomendację, prawdziwe odpowiedzi DNS oraz obsługę SERVFAIL i eksport CSV.
- **Nie przeprowadzono jeszcze testu bezpośrednio na Windows 11.** Systemowy odczyt konfiguracji DNS wymaga weryfikacji na tym systemie.
- **EXE nie ma zaufanego podpisu wydawcy.** Nie gwarantujemy braku ostrzeżeń SmartScreen/Defender. Testy funkcjonalne nie zastępują skanowania antywirusowego. Nie wyłączaj zabezpieczeń systemu, aby uruchomić aplikację.

Repozytorium i wydanie nie zawierają zapisanych ustawień użytkownika, danych uwierzytelniających ani lokalnych logów pomiarów.

## Kod i odbudowa

Aplikacja jest zawarta w pojedynczym pliku `dns_test_v1.1.0.py`. Wersja przeglądarkowa nie jest częścią tego wydania ani zależnością aplikacji.

Na Windows z Pythonem 3.13 x64:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements_v1.1.0.txt
.\.venv\Scripts\python.exe -m unittest discover -v -p test_dns_native_v1_1_0.py
.\.venv\Scripts\python.exe -m PyInstaller --onefile --windowed --noupx --clean --noconfirm --name dns_test_v1.1.0 --version-file windows_version_v1.1.0.txt --exclude-module PySide6.QtWebEngineCore --exclude-module PySide6.QtWebEngineWidgets --exclude-module PySide6.QtWebEngineQuick --exclude-module http.server --exclude-module webbrowser dns_test_v1.1.0.py
```

Wynik odbudowy: `dist/dns_test_v1.1.0.exe`. Ta komenda nie podpisuje kodu; wykorzystuje domyślną ikonę. Szczegóły znajdują się w `odbudowa_windows_v1.1.0.txt`.

## Biblioteki

Oryginalne, niezmodyfikowane Qt/PySide6/shiboken6, CPython i PyInstaller. Teksty licencji i metadane są w folderze `licencje`. Ten projekt nie zakłada komercyjnej licencji Qt; metadane PySide6/shiboken6 opisują alternatywne licencjonowanie LGPL/GPL. Informacje o źródłach bibliotek i wymianie zgodnych wersji znajdują się w instrukcji odbudowy.
