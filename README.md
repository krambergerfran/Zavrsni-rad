# Mehanizmi zaštite privatnosti u EUDI novčanicima (Završni rad)

Ovaj repozitorij sadrži praktični dio završnog rada na temu zaštite privatnosti unutar Europskog novčanika za digitalni identitet (EUDI Wallet). Fokus je na implementaciji **IHV (Issuer-Holder-Verifier)** sustava s naglaskom na **selektivno otkrivanje (SD)** i **nepovezivost (Unlinkability)**.

## Ključne funkcionalnosti sustava

### 1. Selektivno otkrivanje (Selective Disclosure)
Korištenjem `sd-jwt-python` biblioteke, sustav omogućuje korisniku (Holderu) da otkrije samo nužne atribute iz vjerodajnice, čime se poštuje načelo minimizacije podataka.

### 2. Nepovezivost (Unlinkability) kroz Batch Issuance
Implementiran je mehanizam **Batch Issuance** (grupno izdavanje unikatnih tokena). 
- **Cilj**: Postizanje *Presentation Unlinkability* i *Verifier/Verifier Unlinkability*.
- **Rezultat**: Čak i ako dva različita Verifiera razmijene podatke, ne mogu matematički dokazati da se radi o istoj osobi jer svaki dobiva unikatni, nepovezivi token.

### 3. Offline Revocation (Statusne liste)
Za osiguravanje **Issuer/Verifier nepovezivosti**, sustav koristi statusne liste. Izdavatelj objavljuje listu opozvanih tokena koju Verifier provjerava lokalno, čime se sprečava Izdavatelj da prati *kada* i *gdje* korisnik koristi svoju vjerodajnicu (sprječavanje "phone-home" efekta).

## Analiza modela napada
U radu se testira scenarij u kojem **dva neovisna Verifiera pokušavaju korelirati podatke** o istom korisniku.
- **Ishod**: Zahvaljujući Batch Issuance mehanizmu i unikatnim potpisima unutar svakog tokena, korelacija identiteta je onemogućena, čime je dokazana visoka razina privatnosti sustava.

## Arhitektura (Flask API)
Sustav simulira distribuirani eIDAS ekosustav:
- `issuer.py`: Port 5001 (Batch Issuance & Status Lists)
- `verifier.py`: Port 5002 (Verification & Revocation Check)
- `holder.py`: Wallet management & Presentation generation

## Pokretanje projekta
1. `pip install -r requirements.txt`
2. Pokrenite svaki servis u zasebnom terminalu:
   - `python issuer.py`
   - `python verifier.py`
   - `python holder.py`
