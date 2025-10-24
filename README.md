# Eknriptovani fajl sistem
**EFS (Encrypted File System)** je jednostavan sistem koji omogućava čuvanje i dijeljenje datoteka među korisnicima 
korištenjem principa simetrične i asimetrične kriptografije.
Aplikacija omogućava prijavu korisnika na sistem pomoću korisničkog imena, lozinke i validnog digitalnog sertifikata, 
otpremanje fajla na sistem (enkriptovanje), preuzimanje fajla sa sistema (dekriptovanje), kao i provjeru integriteta sadržaja fajla.

## Funkcionalnosti
* Prijava korisnika pomoću korisničkog imena, lozinke i digitalnog sertifikata (izdavanje digitalnog sertifikata je eksterno za sistem);
* Pregled, dodavanje i preuzimanje datoteka u okviru home direktorijuma korisnika.
* Pregled sadržaja, dodavanje i brisanje foldera u okviru home direktorijuma korisnika.
* Automatska enkripcija i dekripcija fajlova prilikom dodavanja i preuzimanja.
* Provjera integriteta datoteka pomoću heš funkcija i **digitalnog otiska**.
* Dijeljeni direktorijum za razmjenu fajlova među korisnicima sistema.
* Mogućnost rada sa fajlovima različitih formata (tekstualni, PDF, slikovni fajlovi)
* Validacija sertifikata pomoću CA sertifikata i CRL liste (koji su generisani eksterno za posmatrani sistem)

## Kriptografski algoritmi
Aplikacija koristi koncept **digitalne envelope** - kombinuje simetrične i asimetrične algoritme radi optimizacije brzine i sigurnosti.
* Simetrična enkripcija: varijante AES algoritma > AES-128, AES-192, AES-256
* Asimetrična enkripcija: RSA
* Heš funkcije: SHA-256, SHA-512, MD5

## Struktura sistema
* Svaki korisnik ima svoj *home* direktorijum, čiji je naziv jednak korisničkom imenu vlasnika
* Datoteke su enkriptovane i dostupne samo vlasniku
* Postoji zajednički *shared* direktorijum za međusobno dijeljenje fajlova
* CA sertifikat, CRL lista, korisnički sertifikati i privatni ključevi su smješteni u **krz** folderu

## Testni nalozi
Svi korisnički nalozi su testni i prate sljedeći format:  
* korisničko ime: _korisnik*_ (* = redni broj),  
* lozinka: _lozinka*_ (* = redni broj).  

## Sigurnosna napomena
Sistem nije zadužen za izdavanje korisničkih sertifikata, pa su, radi demonstracije, oni generisani prije pokretanja aplikacije.
Dodjeljuju se korisnicima prilikom registrovanja na sistem prema rednom broju u korisničkom imenu, uz provjeru validnosti sertifikata.
Dakle, privatni ključevi, CA sertifikat, CRL liste i korisnički sertifikati nisu stvarni bezbjednosni entiteti, već su generisani isključivo za potrebe testiranja aplikacije.
* Napomena: sertifikati imaju ograničen period važenja.

## Tehnologije i alati
Java - programski jezik  
OpenSSL + WSL (Windows Subsystem for Linux) - za kriptografske operacije  
Eclipse IDE - razvojno okruženje

# Autorska prava
© 2025 Aleksandra Vučićević
